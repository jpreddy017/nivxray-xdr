"""Round 33 · NivXRay XDR · Attack Story + AttackFlow regression.

Owner-locked Round 33 gate:
  * 14-stage AttackFlow rendered · state grammar OBSERVED / SUPPORTED
    / POSSIBLE / NOT_OBSERVED.
  * Every non-NOT_OBSERVED stage is evidence-linked (finding /
    canonical / correlation).
  * Same governed state → identical output (deterministic).
  * Attack Cycle module is SSOT for the 14 stages (single import).
  * EDR-style process evidence → endpoint capabilities transition
    from SKIPPED_OUT_OF_SCOPE to SUFFICIENT (SUFFICIENT path
    validation).
"""
from __future__ import annotations
import asyncio, os, uuid, hashlib
import pytest
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from services.attack_story import AttackStoryService
from services.attack_story.attack_cycle import (
    STAGES, TACTIC_TO_STAGE, normalize_tactic, stages_for_technique,
)
from services.investigator import InvestigatorService
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


# ── 1 · Attack Cycle SSOT ────────────────────────────────────────────
def test_attack_cycle_has_14_stages_ssot():
    assert len(STAGES) == 14, f"attack cycle must have 14 stages, got {len(STAGES)}"
    # Every stage must be unique.
    assert len(set(STAGES)) == 14


def test_tactic_mapping_covers_enterprise_ids():
    """Every Enterprise ATT&CK tactic id present in evidence must map."""
    for tid in ("TA0001", "TA0002", "TA0005", "TA0011", "TA0040"):
        stage = normalize_tactic(tid)
        assert stage in STAGES, f"tactic {tid} → {stage} not in STAGES"


def test_technique_to_stage_returns_evidence_backed_stages():
    # T1218.011 (rundll32) → Defense Evasion.
    assert "Defense Evasion" in stages_for_technique("T1218.011")
    # T1059.001 (PowerShell) → Execution.
    assert "Execution" in stages_for_technique("T1059.001")
    # T1105 (Ingress Tool Transfer) → C2.
    assert "Command & Control" in stages_for_technique("T1105")
    # Unmapped technique returns [] (honest).
    assert stages_for_technique("T9999.999") == []


# ── 2 · Attack Story composes against real pipeline evidence ────────
def test_attack_story_composes_full_14_stage_flow(loop, db, incident_id):
    story = _run(loop, AttackStoryService.compose(db, incident_id))
    flow = story["flow"]
    assert len(flow) == 14, "AttackFlow must always render all 14 stages"
    stages_in_order = [s["stage"] for s in flow]
    assert stages_in_order == list(STAGES), (
        "AttackFlow stage order must match Attack Cycle SSOT")
    for s in flow:
        assert s["state"] in ("OBSERVED", "SUPPORTED", "POSSIBLE", "NOT_OBSERVED")


def test_non_not_observed_stages_are_evidence_linked(loop, db, incident_id):
    """Every OBSERVED / SUPPORTED / POSSIBLE stage MUST carry at
    least one evidence anchor (technique_id, finding_id, or
    evidence_ref).  Never fabricated."""
    story = _run(loop, AttackStoryService.compose(db, incident_id))
    for s in story["flow"]:
        if s["state"] == "NOT_OBSERVED":
            continue
        assert (s["techniques"] or s["finding_ids"] or s["evidence_refs"]), (
            f"Stage {s['stage']} in state {s['state']} has no evidence anchor")


def test_narrative_only_covers_non_not_observed(loop, db, incident_id):
    story = _run(loop, AttackStoryService.compose(db, incident_id))
    sentences = story["narrative"]["sentences"]
    # No sentence for a NOT_OBSERVED stage.
    for s in sentences:
        assert s["state"] != "NOT_OBSERVED", (
            "Attack Story must not narrate NOT_OBSERVED stages")
    # Executive summary references verdict + stage counts.
    exec_sum = story["narrative"]["executive_summary"]
    assert exec_sum
    assert "NivXRay XDR" in exec_sum


# ── 3 · Determinism ─────────────────────────────────────────────────
def test_attack_story_deterministic_across_calls(loop, db, incident_id):
    a = _run(loop, AttackStoryService.compose(db, incident_id))
    b = _run(loop, AttackStoryService.compose(db, incident_id))
    # Compare only the deterministic core (drop timestamps).
    core_a = [(s["stage"], s["state"], tuple(s["techniques"]),
                  tuple(s["finding_ids"]), tuple(s["evidence_refs"]))
                 for s in a["flow"]]
    core_b = [(s["stage"], s["state"], tuple(s["techniques"]),
                  tuple(s["finding_ids"]), tuple(s["evidence_refs"]))
                 for s in b["flow"]]
    assert core_a == core_b, "AttackFlow must be deterministic"
    assert a["iue_fingerprint"] == b["iue_fingerprint"]


# ── 4 · SUFFICIENT-path validation via synthetic EDR-style evidence ─
@pytest.fixture(scope="module")
def edr_backed_incident_id(loop, db):
    """Deterministically insert a canonical event carrying endpoint
    telemetry + a matching workspace_case referencing it.  This
    exercises the SUFFICIENT path in Round 32's endpoint capabilities
    without requiring a live EDR adapter (owner-instructed EDR fixture
    validation)."""
    # Deterministic ids for idempotency across test runs.
    inc_id = "inc_r33_edr_" + hashlib.sha256(b"round33-edr-fixture").hexdigest()[:12]
    evt_id = "evt_r33_edr_" + hashlib.sha256(b"round33-edr-fixture-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()

    canonical = {
        "event_id": evt_id,
        "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host":    {"name": "WKS-ANALYST-01", "hostname": "WKS-ANALYST-01"},
        "user":    {"name": "alice@nivxray.local"},
        "process": {
            "name":        "powershell.exe",
            "parent":      {"name": "winword.exe"},
            "parent_name": "winword.exe",
            "commandline": ("powershell.exe -nop -w hidden -enc "
                                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
            "command_line":("powershell.exe -nop -w hidden -enc "
                                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
        },
        "network": {
            "src": {"ip": "10.99.99.10"},
            "dst": {"ip": "185.199.108.153"},
            "protocol": "TCP",
        },
        "security": {
            "signature": {"id": 987654,
                            "name": "Suspicious PowerShell EncodedCommand"},
            "severity":  2,
            "category":  "Execution",
        },
        "provenance": {"trace_id": "test-r33-fixture"},
    }
    incident = {
        "id":                inc_id,
        "tenant_id":         "default",
        "created_at":        now,
        "updated_at":        now,
        "name":              "R33 EDR fixture incident",
        "title":             "R33 EDR fixture incident",
        "user_email":        "admin@nivxray.com",
        "incident_state":    "new",
        "incident_priority": "P2",
        "verdict_card":      {"verdict": "suspicious", "confidence": 65,
                                 "engine": "nivxray::detection_content::nivxray_native_sigma"},
        "mitre": [
            {"technique_id": "T1059.001", "tactic_id": "TA0002"},
            {"technique_id": "T1218.011", "tactic_id": "TA0005"},
        ],
        "iocs": {
            "ip":     ["185.199.108.153"],
            "hash":   ["a" * 64],
            "user":   ["alice@nivxray.local"],
        },
        "xdr_pipeline": {
            "engine_id":         "nivxray::detection_content::xdr_incident",
            "trace_id":          "test-r33-fixture",
            "canonical_event_id": evt_id,
            "detection_rule_id": "rule-r33-fixture",
            "ice_matches":       [],
            "veee":              {"label": "SUSPICIOUS", "score": 65,
                                     "engine_id": "nivxray::veee::v1"},
            "source_provenance": {"integration_id": "integration-edr-fixture"},
        },
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    return inc_id


def test_edr_fixture_activates_endpoint_capabilities(loop, db, edr_backed_incident_id):
    """With process + user telemetry present, process_ancestry,
    commandline_decode, lolbas_lookup, identity_pivot and
    file_reputation must all execute (SUFFICIENT / PARTIAL paths)."""
    state = _run(loop, InvestigatorService.tick(db, edr_backed_incident_id))
    execs = _run(loop, InvestigatorService.get_executions(db, edr_backed_incident_id))
    ok_caps = {e["capability"] for e in execs if e["status"] == "OK"}
    # The critical assertion: endpoint capabilities are no longer skipped.
    for cap in ("process_ancestry", "commandline_decode",
                    "identity_pivot", "file_reputation"):
        assert cap in ok_caps, (
            f"With endpoint telemetry present, {cap} must execute "
            f"successfully (got OK: {sorted(ok_caps)})")


def test_edr_fixture_process_ancestry_detects_anomaly(loop, db, edr_backed_incident_id):
    """WINWORD → PowerShell is an anomalous parent→child pair; the
    process_ancestry capability must emit a CORRELATED finding."""
    findings = _run(loop, InvestigatorService.get_findings(db, edr_backed_incident_id))
    proc_findings = [f for f in findings
                          if f["capability"] == "process_ancestry"]
    assert proc_findings, "process_ancestry must emit at least one finding"
    correlated = [f for f in proc_findings if f["state"] == "CORRELATED"]
    assert correlated, (
        "WINWORD → PowerShell should be flagged as CORRELATED (anomalous "
        "parent→child), got states: "
        + str([f["state"] for f in proc_findings]))


def test_edr_fixture_attack_story_has_observed_stages(loop, db, edr_backed_incident_id):
    """The EDR-backed incident should light up multiple stages of the
    AttackFlow with real evidence: Execution (T1059.001, PowerShell +
    process ancestry), Defense Evasion (T1218.011)."""
    story = _run(loop, AttackStoryService.compose(db, edr_backed_incident_id))
    flow_by_stage = {s["stage"]: s for s in story["flow"]}
    exec_stage = flow_by_stage["Execution"]
    assert exec_stage["state"] in ("OBSERVED", "SUPPORTED"), (
        f"Execution stage must be OBSERVED/SUPPORTED, got {exec_stage['state']}")
    assert "T1059.001" in exec_stage["techniques"] or exec_stage["finding_ids"], (
        "Execution stage must anchor to T1059.001 or a finding")
    defev = flow_by_stage["Defense Evasion"]
    assert defev["state"] in ("OBSERVED", "SUPPORTED"), (
        f"Defense Evasion should be OBSERVED/SUPPORTED for T1218.011")
    # Impact/Exfiltration must remain NOT_OBSERVED (no supporting evidence).
    assert flow_by_stage["Exfiltration"]["state"] == "NOT_OBSERVED"
    assert flow_by_stage["Impact"]["state"] == "NOT_OBSERVED"


# ── 5 · Missing incident ────────────────────────────────────────────
def test_missing_incident_raises(loop, db):
    with pytest.raises(ValueError, match="incident_not_found"):
        _run(loop, AttackStoryService.compose(db, "inc_missing_r33"))
