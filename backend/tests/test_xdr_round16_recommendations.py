"""Round 16 · P0.7.3 · Threat Family + Recommendation Synthesis."""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_threat_family import classify
from detection_content.xdr_recommendation_synthesis import (
    synthesize, filter_playbooks, APPLICABLE, NOT_APPLICABLE,
    CAPABILITY_UNAVAILABLE, ALREADY_EXECUTED,
)


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


def _fresh(loop, db):
    return _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))


def test_threat_family_stage_executes(loop, db):
    r = _fresh(loop, db)
    stage = next(s for s in r["stages"] if s["stage"] == "threat_family")
    assert stage["status"] == "EXECUTED"
    loop_out = r.get("closed_loop") or {}
    assert loop_out.get("threat_family") in ("C2", "MALWARE", "UNKNOWN")


def test_family_never_forced_when_no_signal():
    # Empty context → UNKNOWN.
    from detection_content.xdr_threat_family import _score, _collect_feats
    feats = _collect_feats(None, None, [], [], None)
    assert _score(feats) == {}


def test_pua_family_scores_from_signature():
    from detection_content.xdr_threat_family import _score
    feats = {"signature_name": "PUA/Adware PCAppStore observed",
                "severity_hint": "LOW", "ips": [],
                "observations": [], "ice_matches": 0}
    s = _score(feats)
    assert "PUA_ADWARE" in s
    assert s["PUA_ADWARE"][0] >= 40


def test_ransomware_family_scores_from_signature():
    from detection_content.xdr_threat_family import _score
    feats = {"signature_name": "LockBit ransomware behavior detected",
                "severity_hint": "HIGH", "ips": [],
                "observations": [], "ice_matches": 0}
    s = _score(feats)
    assert "RANSOMWARE" in s
    assert s["RANSOMWARE"][0] >= 40


def test_synthesized_recommendations_bind_to_real_entities(loop, db):
    r = _fresh(loop, db)
    synth = (r["closed_loop"]["recommendations"]
              .get("synthesized") or [])
    assert synth, "must synthesize at least one recommendation"
    for reco in synth:
        assert reco.get("target_entity") is not None
        assert reco["target_entity"].get("value")
        assert reco["applicability"] in (
            APPLICABLE, NOT_APPLICABLE, CAPABILITY_UNAVAILABLE,
            ALREADY_EXECUTED)


def test_capability_unavailable_when_firewall_not_wired(loop, db):
    r = _fresh(loop, db)
    synth = (r["closed_loop"]["recommendations"]
              .get("synthesized") or [])
    ip_blocks = [reco for reco in synth
                       if reco["suggested_action"] == "IP_BLOCK"]
    assert ip_blocks, "IP_BLOCK candidate must appear for C2 family"
    for r_ in ip_blocks:
        assert r_["applicability"] == CAPABILITY_UNAVAILABLE, (
            "IP_BLOCK must honestly report CAPABILITY_UNAVAILABLE "
            "since no firewall integration is configured")


def test_playbook_applicability_matches_family(loop, db):
    r = _fresh(loop, db)
    pbs = r["closed_loop"]["playbooks"]
    by_id = {p["id"]: p for p in pbs}
    # Golden Snort event is Discord/TLS SNI → C2 family
    assert by_id["C2_CONTAINMENT"]["applicability"] == APPLICABLE
    assert by_id["PUA_CLEANUP"]["applicability"] == NOT_APPLICABLE
    assert by_id["RANSOMWARE_CONTAINMENT"]["applicability"] == NOT_APPLICABLE


def test_recompute_is_idempotent_for_family(loop, db):
    r = _fresh(loop, db)
    inc_id = r["incident"]["incident_id"]
    fam1 = _run(loop, classify(db, inc_id))
    fam2 = _run(loop, classify(db, inc_id))
    assert fam1["family"] == fam2["family"]
    assert fam1["score"]  == fam2["score"]
