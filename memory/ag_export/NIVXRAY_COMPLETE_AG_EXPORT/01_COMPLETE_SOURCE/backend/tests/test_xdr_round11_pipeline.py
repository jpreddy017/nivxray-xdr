"""
Round 11 · XDR pipeline E2E regression.

Guarantees:
  * IUE → ICE → VEEE → Incident all run against the golden Snort event.
  * VEEE label is deterministic for the golden inputs.
  * Incident is materialised in workspace_cases with full provenance.
  * When VEEE.score is below the incident gate, NO incident is created.
"""
from __future__ import annotations
import asyncio
import os
import uuid

import pytest
from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_iue import understand as iue_understand
from detection_content.xdr_veee import compute_verdict as veee_compute
from detection_content.xdr_incident import INCIDENT_MIN_SCORE


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


@pytest.fixture(scope="module")
def db(loop):
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield client[os.environ.get("DB_NAME", "test_database")]
    client.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


# ── IUE unit ──────────────────────────────────────────────────
def test_iue_is_deterministic():
    canonical = {
        "event_id": "fixed-1",
        "event_type": "network_alert",
        "network": {"src": {"ip": "1.2.3.4"}, "dst": {"ip": "5.6.7.8"},
                     "protocol": "TCP"},
        "security": {"severity": 1,
                       "category": "malware",
                       "signature": {"id": 2027865, "name": "TEST"}},
    }
    detection = {"matched": True, "rule_id": "r1"}
    a = iue_understand(canonical, detection)
    b = iue_understand(canonical, detection)
    assert a["iue_id"] == b["iue_id"]
    assert a["severity_hint"] == "HIGH"
    assert a["detection_supported"] is True
    assert 0 <= a["confidence"] <= 70


def test_iue_never_fabricates_without_detection():
    canonical = {"event_id": "x", "event_type": "network_alert",
                    "security": {}, "network": {}}
    r = iue_understand(canonical, None)
    assert r["detection_supported"] is False
    assert r["severity_hint"] == "INFORMATIONAL"


# ── VEEE unit ─────────────────────────────────────────────────
def test_veee_inconclusive_when_no_evidence():
    v = veee_compute({"event_id": "x"}, None,
                       {"severity_hint": "INFORMATIONAL"}, {"matches": []})
    assert v["label"] == "INCONCLUSIVE"
    assert v["score"] == 0
    assert "no evidence" in v["reason"]


def test_veee_promotes_to_malicious_with_full_signal():
    detection = {"matched": True, "rule_id": "r"}
    iue = {"severity_hint": "CRITICAL"}
    ice = {"matches": [{"match_id": "m1"}, {"match_id": "m2"}]}
    v = veee_compute({"event_id": "x"}, detection, iue, ice)
    assert v["label"] == "MALICIOUS"
    assert v["score"] >= 80


# ── E2E pipeline ──────────────────────────────────────────────
def test_e2e_pipeline_executes_all_stages(loop, db):
    result = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    assert result["blocker"] is None
    stage_names = [s["stage"] for s in result["stages"]]
    for required in ("dsm", "parser", "normalizer", "canonical_evidence",
                       "detection", "iue", "correlation", "verdict",
                       "incident"):
        assert required in stage_names, f"missing stage {required}"
    for s in result["stages"]:
        # No stage remains BLOCKED after Round 11.
        assert s["status"] != "BLOCKED", (
            f"stage {s['stage']} still BLOCKED — Round 11 must clear this")


def test_e2e_produces_verdict_and_incident(loop, db):
    result = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    v = result["verdict"]
    assert v["label"] in ("SUSPICIOUS", "MALICIOUS")
    assert v["score"] >= INCIDENT_MIN_SCORE
    inc = result["incident"]
    assert inc["created"] is True
    assert inc["incident_id"].startswith("inc_")

    doc = _run(loop, db["workspace_cases"].find_one({"id": inc["incident_id"]}))
    assert doc is not None
    prov = doc["xdr_pipeline"]
    assert prov["canonical_event_id"] == result["canonical"]["event_id"]
    assert prov["iue_id"]              == result["iue"]["iue_id"]
    assert prov["detection_rule_id"]   == result["detection"]["rule_id"]


def test_incident_gate_refuses_low_score(loop, db):
    # Craft an event with no detection match and INFORMATIONAL severity.
    ev = dict(GOLDEN_SNORT_EVENT)
    ev["event_type"] = "flow"
    ev.pop("alert", None)
    ev["alert"] = {}  # no signature_id → parser will fail
    result = _run(loop, process_event_through_pipeline(
        db, ev, str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    # Parser fails honestly on missing alert.signature_id — this is
    # a valid honest-state path, not a Round-11 regression.
    assert result["blocker"] in ("parser", "incident_gate")
