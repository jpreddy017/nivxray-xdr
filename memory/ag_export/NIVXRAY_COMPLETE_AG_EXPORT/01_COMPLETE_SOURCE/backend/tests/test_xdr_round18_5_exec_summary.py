"""
Round 18.5 · Executive Summary Composer + Analyst Decision Persistence
─────────────────────────────────────────────────────────────────────

Validates:
  1. Deterministic composer produces conclusion-first prose from
     IUE + VEEE + Threat Family + entities + framework mappings +
     observations.
  2. Confirmed facts vs Insufficient evidence are explicitly separated
     — nothing fabricated.
  3. Same inputs → byte-identical output (deterministic).
  4. Analyst decision endpoint snapshots risk_analysis verbatim into
     the audit trail.
  5. Exclusion decisions carry `safer_alternative_chosen` and
     `was_exclusion` flags; ordinary mitigations do not.
"""
from __future__ import annotations
import asyncio, os, uuid, json
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_executive_summary import compose


@pytest.fixture(scope="module", autouse=True)
def _init_deps_db():
    """Router functions read from `deps.db` — bind a real Motor client
    once for the whole test module."""
    from deps import validate_config, init_database
    validate_config()
    init_database()
    yield


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def snort_incident(loop, db):
    """Push the Golden Snort event through the full pipeline once."""
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    return (r.get("closed_loop") or {}).get("incident_id")


# ── Composer shape + prose contract ─────────────────────────────

def test_composer_returns_ready_for_real_incident(loop, db, snort_incident):
    out = _run(loop, compose(db, snort_incident))
    assert out["state"] == "READY"
    assert out["incident_id"] == snort_incident
    assert out["engine_id"].endswith("executive_summary_composer")
    es = out["executive_summary"]
    for k in ("prose", "lead", "confidence_line", "evidence_line"):
        assert es.get(k), f"executive_summary.{k} missing"


def test_composer_returns_missing_for_unknown_incident(loop, db):
    out = _run(loop, compose(db, "inc_does_not_exist"))
    assert out["state"] == "MISSING"


def test_lead_sentence_names_verdict_and_family(loop, db, snort_incident):
    out = _run(loop, compose(db, snort_incident))
    lead = out["executive_summary"]["lead"].lower()
    # The Snort golden event verdict + family are always present.
    assert "incident is" in lead
    # Family narrative comes from a locked dictionary — must be
    # human-readable text, never the raw ENUM.
    for raw in ("c2", "command"):
        if raw in lead:
            break
    else:
        pytest.fail(f"lead does not mention C2 family narrative: {lead}")


def test_composer_confirmed_and_insufficient_are_disjoint(loop, db,
                                                                            snort_incident):
    out = _run(loop, compose(db, snort_incident))
    conf = out["confirmed_facts"]
    insuff = out["insufficient_evidence"]
    # Both are lists of prose lines, deterministic and non-overlapping.
    assert isinstance(conf, list) and isinstance(insuff, list)
    assert not (set(conf) & set(insuff)), \
        "confirmed and insufficient must be disjoint"
    # For the Snort golden event we have canonical evidence → at least
    # ONE confirmed fact must be present.
    assert conf, "confirmed_facts must be non-empty for a real incident"


def test_composer_supports_have_evidence_pointers(loop, db,
                                                                    snort_incident):
    out = _run(loop, compose(db, snort_incident))
    supp = out["supporting_evidence"] or []
    # Every fact carries source + claim, and where possible an evidence_id.
    for f in supp:
        assert f.get("claim"),  f
        assert f.get("source"), f
    # For Snort golden event, at least the detection-rule fact must be
    # present.
    assert any("rule" in f["claim"].lower() or
                    "detection" in f["source"].lower()
                    for f in supp), supp


def test_composer_is_deterministic(loop, db, snort_incident):
    """Same inputs → byte-identical prose + supports + technical."""
    a = _run(loop, compose(db, snort_incident))
    b = _run(loop, compose(db, snort_incident))
    for key in ("executive_summary", "technical_summary",
                        "supporting_evidence", "confirmed_facts",
                        "insufficient_evidence"):
        assert json.dumps(a[key], sort_keys=True) == \
                    json.dumps(b[key], sort_keys=True), key


def test_technical_summary_is_machine_derived(loop, db, snort_incident):
    out = _run(loop, compose(db, snort_incident))
    tech = out["technical_summary"]
    # Round-trippable machine block — verdict fields must be present
    # even when null (honest state).
    for k in ("verdict_label", "verdict_score", "threat_family",
                    "iue_severity_hint", "entity_counts",
                    "active_framework_mappings", "canonical_event_id"):
        assert k in tech, f"technical_summary missing {k}"
    # entity_counts must be a dict of int counts.
    for v in tech["entity_counts"].values():
        assert isinstance(v, int)


# ── Analyst decision persistence ────────────────────────────────

def test_decision_snapshots_risk_analysis(loop, db):
    """POST /recommendations/{id}/decision must persist the
    risk_analysis snapshot verbatim into decision_history so the
    audit trail proves the analyst saw the trade-off."""
    from routers.content_supply_chain import recommendation_decision
    reco_id = f"reco-test-{uuid.uuid4().hex[:8]}"
    risk_snapshot = {
        "engine_id":         "nivxray::xdr::mitigation_intelligence",
        "engine_version":    "1.0.0",
        "exclusion_type":    "Path Exclusion",
        "scope":             "filesystem_subtree",
        "detection_method":  "TETRA · file scanning",
        "affected_engine":   "TETRA · Cloud IOC",
        "visibility_impact": "All files ... unscanned",
        "security_risk":     "HIGH",
        "safer_alternative": "Exclude the hash instead of the path.",
        "approval_policy":   "APPROVAL_REQUIRED",
        "warning_banner":    "HIGH RISK — ...",
        "analyst_decision":  None,
    }
    payload = {
        "decision":                 "ACCEPTED",
        "reason":                   "vendor asked for it",
        "suggested_action":         "PATH_EXCLUSION_ADD",
        "risk_analysis_snapshot":   risk_snapshot,
        "safer_alternative_chosen": "SAFER_ALT",
    }
    res = _run(loop, recommendation_decision(
        reco_id, payload, user={"email": "analyst@example.com"}))
    assert res["ok"] is True
    assert res["was_exclusion"] is True
    assert res["risk_analysis_snapshotted"] is True
    assert res["safer_alternative_chosen"] == "SAFER_ALT"
    # ── Verify persisted trail ─────────────────────────────
    doc = _run(loop, db["xdr_recommendations"].find_one(
        {"recommendation_id": reco_id}, {"_id": 0}))
    assert doc is not None
    assert doc["state"] == "ACCEPTED"
    assert doc["was_exclusion"] is True
    assert doc["last_risk_snapshot"]["security_risk"] == "HIGH"
    assert doc["safer_alternative_chosen"] == "SAFER_ALT"
    hist = doc["decision_history"]
    assert hist and hist[-1]["risk_analysis_snapshot"] == risk_snapshot
    assert hist[-1]["safer_alternative_chosen"] == "SAFER_ALT"
    assert hist[-1]["was_exclusion"] is True


def test_decision_ordinary_mitigation_has_no_exclusion_flags(loop, db):
    from routers.content_supply_chain import recommendation_decision
    reco_id = f"reco-test-{uuid.uuid4().hex[:8]}"
    payload = {
        "decision":         "ACCEPTED",
        "reason":           "block the C2",
        "suggested_action": "IP_BLOCK",
    }
    res = _run(loop, recommendation_decision(
        reco_id, payload, user={"email": "analyst@example.com"}))
    assert res["ok"] is True
    assert res["was_exclusion"] is False
    assert res["risk_analysis_snapshotted"] is False
    doc = _run(loop, db["xdr_recommendations"].find_one(
        {"recommendation_id": reco_id}, {"_id": 0}))
    assert doc["was_exclusion"] is False
    assert doc.get("last_risk_snapshot") in (None, {})
    assert doc.get("safer_alternative_chosen") is None


def test_decision_rejects_invalid_verb(loop, db):
    from routers.content_supply_chain import recommendation_decision
    res = _run(loop, recommendation_decision(
        "reco-x", {"decision": "IGNORE"},
        user={"email": "a@example.com"}))
    assert res.get("ok") is False


def test_decision_history_grows_on_second_call(loop, db):
    from routers.content_supply_chain import recommendation_decision
    reco_id = f"reco-test-{uuid.uuid4().hex[:8]}"
    _run(loop, recommendation_decision(
        reco_id, {"decision": "ACCEPTED", "suggested_action": "IP_BLOCK"},
        user={"email": "a@example.com"}))
    _run(loop, recommendation_decision(
        reco_id, {"decision": "SUPERSEDED",
                        "suggested_action": "IP_BLOCK",
                        "reason": "better option available"},
        user={"email": "a@example.com"}))
    doc = _run(loop, db["xdr_recommendations"].find_one(
        {"recommendation_id": reco_id}, {"_id": 0}))
    assert doc["state"] == "SUPERSEDED"
    hist = doc["decision_history"]
    assert len(hist) == 2
    assert hist[0]["to"] == "ACCEPTED"
    assert hist[1]["from"] == "ACCEPTED"
    assert hist[1]["to"] == "SUPERSEDED"
