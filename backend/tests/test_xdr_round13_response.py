"""
Round 13 · P0.7 · Response Fabric regression.

Guarantees:
  * Response stage flips to EXECUTED post-incident.
  * Action Registry reports honest capability_available flags.
  * SUSPICIOUS golden run → decision=DIRECT_ACTION_AVAILABLE with
    OSINT_ENRICH_IP · execution SUCCEEDED (real adapter).
  * Actions without configured integrations report NOT_CONFIGURED.
  * INCONCLUSIVE verdicts yield NO_RESPONSE_JUSTIFIED.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_action_registry import list_actions, registry_summary
from detection_content.xdr_response_decision import (
    decide, recommend, build_response_context,
)
from detection_content.xdr_response_fabric import orchestrate


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


def _run(loop, coro): return loop.run_until_complete(coro)


# ── Registry ─────────────────────────────────────────────────
def test_action_registry_has_osint_actions():
    actions = {a["action_id"]: a for a in list_actions()}
    for a in ("OSINT_ENRICH_IP", "OSINT_ENRICH_URL",
                "OSINT_ENRICH_DOMAIN", "OSINT_ENRICH_HASH"):
        assert a in actions, f"missing {a}"
        assert actions[a]["capability_available"] is True


def test_action_registry_edr_not_configured():
    actions = {a["action_id"]: a for a in list_actions()}
    # No EDR integration wired in preview.
    for a in ("ENDPOINT_ISOLATE", "IP_BLOCK", "COLLECT_FORENSIC_SNAPSHOT"):
        assert actions[a]["capability_available"] is False


# ── Decision engine ──────────────────────────────────────────
def test_decision_no_response_when_inconclusive():
    ctx = {"state": "READY", "verdict": {"label": "INCONCLUSIVE"},
             "entities": [], "provenance": {}}
    d = decide(ctx, [])
    assert d["decision"] == "NO_RESPONSE_JUSTIFIED"


def test_decision_capability_unavailable_when_no_integration():
    ctx = {"state": "READY",
             "verdict": {"label": "MALICIOUS"},
             "entities": [{"kind": "ipv4", "value": "1.2.3.4",
                              "role": "source"}],
             "provenance": {}, "ice_matches": 2}
    recos = recommend(ctx)
    # Ensure at least one reco maps to a currently-unwired action.
    ip_block = [r for r in recos if r.get("suggested_action") == "IP_BLOCK"]
    assert ip_block, "MALICIOUS entity must produce an IP_BLOCK reco"


# ── E2E ───────────────────────────────────────────────────────
def test_e2e_response_stage_executes(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    stage = next(s for s in r["stages"] if s["stage"] == "response")
    assert stage["status"] == "EXECUTED"
    resp = r["response"]
    assert resp["state"] == "READY"
    assert len(resp["recommendations"]) >= 1


def test_e2e_osint_executor_succeeds(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    resp = r["response"]
    d    = resp["decision"]
    ex   = resp["execution"]
    assert d["decision"] == "DIRECT_ACTION_AVAILABLE"
    assert d["required_action"] == "OSINT_ENRICH_IP"
    assert ex["state"] == "SUCCEEDED"
    assert ex["adapter_result"] is not None


def test_orchestrator_persists_audit_and_timeline(loop, db):
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    inc_id = r["incident"]["incident_id"]
    # Audit row present in the tamper-evident chain.
    audits = _run(loop, db["xdr_audit_log"].count_documents(
        {"correlation_id": inc_id}))
    assert audits >= 1
    tls = _run(loop, db["xdr_response_timeline"].count_documents(
        {"incident_id": inc_id}))
    assert tls >= 1
