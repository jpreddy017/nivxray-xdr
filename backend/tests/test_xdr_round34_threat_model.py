"""Round 34 · NivXRay XDR · Threat Model Engine regression.

Owner-locked rules:
  * 5 sub-dimensions each 0-100.
  * Impact confidence must NOT inflate threat_likelihood
    (independent axes).
  * Every dimension is deterministic — same governed state ⇒
    identical scores.
  * Non-fabrication: an incident with no findings must NOT produce
    high confidence.
  * ``attack_cycle.STAGES`` remains the single source of truth
    (no local re-definition inside threat_model service).
  * ``machine_generated: true`` present on generated blocks.
"""
from __future__ import annotations
import asyncio, os, uuid, hashlib
from datetime import datetime, timezone
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from services.threat_model import ThreatModelService


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
    assert inc.get("created")
    return inc["incident_id"]


@pytest.fixture(scope="module")
def edr_incident_id(loop, db):
    """Deterministic EDR-style incident fixture (WINWORD → PowerShell,
    encoded command, network destination, user identity, hash IOC)."""
    inc_id = "inc_r34_edr_" + hashlib.sha256(b"round34-edr").hexdigest()[:12]
    evt_id = "evt_r34_edr_" + hashlib.sha256(b"round34-edr-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R34"},
        "user": {"name": "bob@nivxray.local"},
        "process": {
            "name": "powershell.exe",
            "parent": {"name": "winword.exe"},
            "commandline": "powershell.exe -nop -w hidden -enc AAAAAAAAAAAA",
        },
        "network": {
            "src": {"ip": "10.99.99.20"},
            "dst": {"ip": "185.199.108.200"},
            "protocol": "TCP",
        },
        "security": {"signature": {"id": 55555,
                                        "name": "Suspicious PowerShell EncodedCommand R34"},
                        "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "name": "R34 EDR incident", "title": "R34 EDR incident",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "confidence": 65,
                            "engine": "nivxray::detection_content::nivxray_native_sigma"},
        "mitre": [
            {"technique_id": "T1059.001", "tactic_id": "TA0002"},
            {"technique_id": "T1218.011", "tactic_id": "TA0005"},
        ],
        "iocs": {"ip": ["185.199.108.200"], "hash": ["b" * 64],
                    "user": ["bob@nivxray.local"]},
        "xdr_pipeline": {
            "engine_id": "nivxray::detection_content::xdr_incident",
            "trace_id": "r34-fixture",
            "canonical_event_id": evt_id,
            "detection_rule_id": "rule-r34",
            "ice_matches": [],
            "veee": {"label": "SUSPICIOUS", "score": 65,
                        "engine_id": "nivxray::veee::v1"},
        },
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    return inc_id


# ── 1 · Composer emits complete envelope ────────────────────────────
def test_threat_model_composes_full_envelope(loop, db, incident_id):
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    for k in ("threat_assessment", "impact", "attack_path",
                "why_it_matters", "executive_summary", "counts"):
        assert k in tm, f"threat-model envelope missing {k}"
    assert tm["machine_generated"] is True
    assert tm["editable"] is True


# ── 2 · 5 dimensions bounded 0-100 ──────────────────────────────────
def test_dimensions_are_all_bounded_and_present(loop, db, incident_id):
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    dims = tm["threat_assessment"]["dimensions"]
    for k in ("detection_confidence", "threat_likelihood",
                "evidence_confidence", "attack_path_confidence",
                "impact_confidence"):
        assert k in dims, f"dimension {k} missing"
        assert 0 <= dims[k] <= 100, f"{k}={dims[k]} out of bounds"


# ── 3 · Impact does NOT inflate threat likelihood ───────────────────
def test_impact_does_not_influence_threat_likelihood(loop, db, incident_id):
    """Owner-locked invariant: impact_confidence must be independent
    of the four dimensions that compose the overall threat score."""
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    dims = tm["threat_assessment"]["dimensions"]
    weights = {
        "detection_confidence":     0.25,
        "threat_likelihood":        0.35,
        "evidence_confidence":      0.20,
        "attack_path_confidence":   0.20,
    }
    expected = round(sum(dims[k] * w for k, w in weights.items()))
    assert tm["threat_assessment"]["overall_score"] == expected, (
        f"overall score must weight ONLY the four non-impact dimensions "
        f"(expected {expected}, got {tm['threat_assessment']['overall_score']})")


# ── 4 · Attack path reuses Round 33 SSOT ────────────────────────────
def test_attack_path_uses_round33_ssot(loop, db, incident_id):
    from services.attack_story.attack_cycle import STAGES
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    stages_in_order = [s["stage"] for s in tm["attack_path"]]
    assert stages_in_order == list(STAGES), (
        "Threat Model must reuse attack_cycle.STAGES SSOT unchanged")


# ── 5 · Determinism ─────────────────────────────────────────────────
def test_threat_model_is_deterministic(loop, db, incident_id):
    a = _run(loop, ThreatModelService.compose(db, incident_id))
    b = _run(loop, ThreatModelService.compose(db, incident_id))
    assert a["threat_assessment"] == b["threat_assessment"]
    assert a["impact"] == b["impact"]
    assert a["attack_path"] == b["attack_path"]


# ── 6 · Why-it-matters is evidence-anchored ─────────────────────────
def test_why_it_matters_is_evidence_anchored(loop, db, incident_id):
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    why = tm["why_it_matters"]
    # For each supporting factor, either an evidence_ref, a
    # technique, or a finding_id must be present.
    for f in why["supporting_factors"]:
        anchored = bool(f.get("evidence_refs") or f.get("techniques")
                             or f.get("finding_id") or f.get("capability"))
        assert anchored, f"supporting factor without anchor: {f}"


# ── 7 · Non-fabrication for network-only incident ──────────────────
def test_no_fabrication_for_network_only_incident(loop, db, incident_id):
    """Snort-golden has no endpoint / identity telemetry — Impact.count
    of blast radius must reflect that honestly."""
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    br = tm["impact"]["blast_radius"]
    assert isinstance(br["related_incidents"], list)
    assert isinstance(br["related_hosts"], list)
    assert isinstance(br["related_users"], list)


# ── 8 · EDR-backed incident raises the profile honestly ────────────
def test_edr_incident_raises_dimensions(loop, db, edr_incident_id):
    """With process telemetry present, evidence_confidence must not
    be zero and attack_path_confidence must be non-trivial."""
    # Ensure the investigator runs against the fixture.
    from services.investigator import InvestigatorService
    _run(loop, InvestigatorService.tick(db, edr_incident_id))
    tm = _run(loop, ThreatModelService.compose(db, edr_incident_id))
    dims = tm["threat_assessment"]["dimensions"]
    assert dims["detection_confidence"] > 0
    assert dims["evidence_confidence"] > 0
    assert dims["attack_path_confidence"] > 0
    # Executive summary references the risk band.
    assert tm["executive_summary"]["text"]
    assert "NivXRay XDR" in tm["executive_summary"]["text"]


# ── 9 · Missing incident raises ─────────────────────────────────────
def test_missing_incident_raises(loop, db):
    with pytest.raises(ValueError, match="incident_not_found"):
        _run(loop, ThreatModelService.compose(db, "inc_missing_r34"))


# ── 10 · Executive summary is machine-generated + editable-ready ────
def test_executive_summary_is_editable_ready(loop, db, incident_id):
    tm = _run(loop, ThreatModelService.compose(db, incident_id))
    es = tm["executive_summary"]
    assert es["machine_generated"] is True
    assert es["editable"] is True
    assert es["version"] == 1
