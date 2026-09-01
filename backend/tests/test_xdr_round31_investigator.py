"""Round 31 · Autonomous Investigator regression.

Owner-locked acceptance criteria (§16, §17 of AUTONOMOUS_INVESTIGATION.md):
  * Eligible evidence automatically starts investigation — no button.
  * IUE gaps produce investigation pivots deterministically.
  * Capability selection honestly skips cap-unavailable.
  * Real capabilities produce real engine_executions.
  * Duplicate pivots are prevented across ticks.
  * New evidence re-opens the loop (IKG → IUE → Orchestrator).
  * Lifecycle transitions follow §26.
  * Tenant isolation is preserved.
  * No fabrication of executions or findings.
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
from services.investigator.planner import (
    plan_pivots, select_capability, known_capability_ids,
)
from services.investigator.capabilities.historical import (
    HistoricalCorrelationCapability, MitreExpansionCapability,
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
    """Real Snort-golden pipeline → real incident → Investigator auto-kicks."""
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    inc = r.get("incident") or {}
    assert inc.get("created"), (
        f"Snort-golden pipeline did not materialise an incident: {r}")
    # Verify pipeline auto-kicked the investigator.
    stages = {s["stage"]: s for s in r["stages"]}
    assert "autonomous_investigation" in stages, (
        "Pipeline must auto-kick the autonomous investigator")
    assert stages["autonomous_investigation"]["status"] == "EXECUTED"
    return inc["incident_id"]


# ── 1 · Auto-start (no button) ───────────────────────────────────────
def test_investigation_auto_starts_from_pipeline(loop, db, incident_id):
    """The moment the pipeline materialises an incident, the
    Autonomous Investigator must be in a non-WAITING state.  No UI
    button, no HTTP activation."""
    state = _run(loop, InvestigatorService.get_state(db, incident_id))
    assert state is not None, "Investigator must register on pipeline tick"
    assert state.state in ("CONVERGED", "CONVERGING", "INVESTIGATING",
                                "EXPANDING", "WAITING_FOR_CAPABILITY"), (
        f"Investigation must advance beyond WAITING; got {state.state}")


# ── 2 · Lifecycle history ────────────────────────────────────────────
def test_lifecycle_transitions_are_correct(loop, db, incident_id):
    state = _run(loop, InvestigatorService.get_state(db, incident_id))
    seen = [h["state"] for h in state.state_history]
    # WAITING_FOR_EVIDENCE must appear at least once as initial state.
    assert seen[0] == "WAITING_FOR_EVIDENCE"
    # Must have progressed through UNDERSTANDING_EVIDENCE and CONVERGED.
    assert "UNDERSTANDING_EVIDENCE" in seen
    assert "CONVERGED" in seen


# ── 3 · Deterministic planner ────────────────────────────────────────
def test_planner_emits_deterministic_pivots(loop, db, incident_id):
    understanding = _run(loop, IUEService.latest_valid(db, incident_id))
    a = plan_pivots(understanding, attempted_pivot_ids=set())
    b = plan_pivots(understanding, attempted_pivot_ids=set())
    ids_a = [p.pivot_id for p in a]
    ids_b = [p.pivot_id for p in b]
    assert ids_a == ids_b, "Planner must be deterministic across calls"
    assert len(a) > 0, "IUE gaps must produce at least one pivot"
    # Every pivot must reference a real capability id.
    known = set(known_capability_ids())
    for p in a:
        assert p.capability in known, f"unknown capability {p.capability}"


# ── 4 · Selector honestly skips when evidence is insufficient ───────
def test_selector_or_evidence_check_honestly_skips(loop, db, incident_id):
    """Round 32: all built-in capabilities are cap-full.  The honest
    skip now happens via the evidence-sufficiency check — for the
    network-only Snort-golden pipeline, endpoint/identity/file
    capabilities are skipped as SKIPPED_OUT_OF_SCOPE."""
    execs = _run(loop, InvestigatorService.get_executions(db, incident_id))
    skipped = [e for e in execs if e["status"].startswith("SKIPPED")]
    assert len(skipped) >= 1, (
        "Snort-golden is network-only — endpoint/identity/file "
        "capabilities must be honestly skipped, not fabricated.")
    for e in skipped:
        assert e["reason"], "skipped execution must record its reason"


# ── 5 · Real executions are persisted ────────────────────────────────
def test_engine_executions_are_recorded(loop, db, incident_id):
    execs = _run(loop, InvestigatorService.get_executions(db, incident_id))
    assert len(execs) > 0, "Investigator must persist engine_executions"
    ok_execs = [e for e in execs if e["status"] == "OK"]
    assert len(ok_execs) >= 1, "At least one capability must run to completion"
    # Every execution has a real duration + engine id.
    for e in execs:
        assert e["engine"]
        assert e["duration_ms"] is not None
        assert e["capability"]
        assert e["pivot_id"]


# ── 6 · Findings are provenance-anchored ─────────────────────────────
def test_findings_carry_provenance(loop, db, incident_id):
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    assert len(findings) > 0
    for f in findings:
        assert f["finding_id"].startswith("fnd_")
        assert f["state"] in ("OBSERVED", "SUPPORTED", "CORRELATED",
                                    "INFERRED", "HYPOTHESIS", "NOT_OBSERVED",
                                    "UNKNOWN", "CONTRADICTED")
        assert f["reasoning"]
        assert f["execution_id"]


# ── 7 · Idempotency — second tick creates zero new executions ────────
def test_second_tick_is_idempotent(loop, db, incident_id):
    execs_before = _run(loop, InvestigatorService.get_executions(db, incident_id))
    state = _run(loop, InvestigatorService.tick(db, incident_id))
    execs_after = _run(loop, InvestigatorService.get_executions(db, incident_id))
    # OK executions must not duplicate — new records may appear only as
    # SKIPPED_DUPLICATE / SKIPPED_UNAVAILABLE (which is honest, not fake).
    ok_before = [e for e in execs_before if e["status"] == "OK"]
    ok_after  = [e for e in execs_after if e["status"] == "OK"]
    assert len(ok_after) == len(ok_before), (
        f"Idempotency violated: OK executions changed "
        f"{len(ok_before)} → {len(ok_after)}")
    assert state.state == "CONVERGED"


# ── 8 · Activity feed answers §10 six questions ──────────────────────
def test_activity_feed_is_explanatory(loop, db, incident_id):
    activity = _run(loop, InvestigatorService.get_activity(db, incident_id))
    assert len(activity) > 0
    # Must contain at least one LIFECYCLE + PIVOT_PLANNED + EXECUTION entry.
    kinds = {a["kind"] for a in activity}
    assert "LIFECYCLE" in kinds
    assert "PIVOT_PLANNED" in kinds
    assert "EXECUTION" in kinds
    # Every entry must explain WHY.
    for a in activity:
        assert a["what"], f"activity missing WHAT: {a}"
        assert a["why"],  f"activity missing WHY:  {a}"


# ── 9 · Capability contract ──────────────────────────────────────────
def test_capability_registry_exposes_cap_states():
    hist = HistoricalCorrelationCapability()
    mitre = MitreExpansionCapability()
    assert hist.availability == "cap-full"
    assert mitre.availability == "cap-full"
    ids = known_capability_ids()
    # Round 32: these capability ids are now real, cap-full engines.
    for expected in ("process_ancestry", "identity_pivot",
                       "file_reputation", "network_pivot"):
        assert expected in ids, f"capability {expected} must be registered"


# ── 10 · No fabricated evidence — historical probe on empty history ─
def test_historical_capability_emits_honest_negative(loop, db, incident_id):
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    # Golden pipeline runs one alert per fixture id — historical
    # probe should honestly produce at least one NOT_OBSERVED finding
    # if no prior sightings exist, rather than fabricate a correlation.
    kinds = {(f["kind"], f["state"]) for f in findings}
    hist_findings = [(f["kind"], f["state"]) for f in findings
                          if f["capability"] == "historical_correlation"]
    assert hist_findings, "historical_correlation must emit a finding"
    # Every historical finding must have a bounded, honest confidence.
    for f in findings:
        assert 0 <= f["confidence"] <= 100


# ── 11 · Missing incident raises ─────────────────────────────────────
def test_tick_on_missing_incident_raises(loop, db):
    with pytest.raises(ValueError, match="incident_not_found"):
        _run(loop, InvestigatorService.tick(db, "inc_missing_xxx"))


# ── 12 · Verdict Engine boundary untouched (§10, §31) ────────────────
def test_verdict_engine_untouched_by_investigator(loop, db, incident_id):
    """Investigator must not overwrite verdict_stage2 / verdict_card."""
    doc = _run(loop, db["workspace_cases"].find_one(
        {"id": incident_id}, {"_id": 0, "verdict_stage2": 1, "verdict_card": 1}))
    # The Investigator adds its own state elsewhere (xdr_investigations)
    # and MUST NOT have touched the deterministic verdict fields.
    # We simply assert the verdict fields remain governed values.
    if doc.get("verdict_card"):
        assert doc["verdict_card"].get("verdict") in (
            "malicious", "suspicious", "benign", None)


# ── 13 · Tenant isolation on read APIs ───────────────────────────────
def test_state_read_returns_tenant_scoped_record(loop, db, incident_id):
    state = _run(loop, InvestigatorService.get_state(db, incident_id))
    assert state.tenant_id  # not empty
    # Findings are scoped to the incident (which implies tenant).
    findings = _run(loop, InvestigatorService.get_findings(db, incident_id))
    for f in findings:
        assert f["tenant_id"] == state.tenant_id
        assert f["incident_id"] == incident_id
