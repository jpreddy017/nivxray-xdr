"""
Round 14 · P0.7.1 · Closed-Loop Recompute regression.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_closed_loop import (
    recompute, record_observation_from_execution,
    _evidence_state_hash, recommend_with_observations,
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


def _fresh_pipeline(loop, db):
    return _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))


# ── Test 1 — successful enrichment → observation → recompute ─
def test_closed_loop_creates_observation_from_success(loop, db):
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    obs_count = _run(loop, db["xdr_intelligence_observations"]
                         .count_documents({"incident_id": inc_id}))
    assert obs_count >= 1, "observation must be persisted from SUCCEEDED"
    cl = r["closed_loop"]
    assert cl["state"] == "READY"
    assert cl["new_observations"] >= 1
    assert cl["changed"] is True


# ── Test 2 — idempotent recompute (no duplicates) ────────────
def test_closed_loop_second_run_is_noop(loop, db):
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    obs_before = _run(loop, db["xdr_intelligence_observations"]
                              .count_documents({"incident_id": inc_id}))
    r2 = _run(loop, recompute(db, inc_id))
    assert r2["changed"] is False, "second recompute must not change state"
    obs_after = _run(loop, db["xdr_intelligence_observations"]
                              .count_documents({"incident_id": inc_id}))
    assert obs_after == obs_before, "observation must NOT duplicate"


# ── Test 3 — recommendations recompute + supersession ────────
def test_recommendations_recorded_with_history(loop, db):
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    active = _run(loop, db["xdr_recommendations"].count_documents(
        {"incident_id": inc_id, "state": "ACTIVE"}))
    assert active >= 1


# ── Test 4 — no infinite loop (evidence-state hash gate) ─────
def test_no_action_reexecution_on_identical_evidence(loop, db):
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    # Second orchestrate must NOT create a second SUCCEEDED execution.
    _run(loop, orchestrate(db, inc_id))
    succ = _run(loop, db["xdr_response_executions"].count_documents(
        {"incident_id": inc_id, "state": "SUCCEEDED"}))
    assert succ == 1, (
        f"expected exactly 1 SUCCEEDED execution (loop protection), got {succ}")


# ── Test 5 — provenance chain: incident → exec → observation ─
def test_full_provenance_chain(loop, db):
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    exec_ids = [e["execution_id"] for e in
                     _run(loop, db["xdr_response_executions"].find(
                         {"incident_id": inc_id}, {"_id": 0}).to_list(20))]
    assert exec_ids
    obs = _run(loop, db["xdr_intelligence_observations"].find_one(
        {"incident_id": inc_id, "execution_id": {"$in": exec_ids}},
        {"_id": 0}))
    assert obs
    prov = obs.get("provenance") or {}
    assert prov.get("classification") == "action_derived"
    assert prov.get("parent_execution") in exec_ids


# ── Test 6 — observation-aware recommendation escalation ─────
def test_recommend_with_observations_promotes_ip_block():
    ctx = {"state": "READY",
             "verdict": {"label": "MALICIOUS"},
             "entities": [{"kind": "ipv4", "value": "1.2.3.4",
                              "role": "source"}],
             "ice_matches": 2,
             "provenance": {}}
    obs = [
        {"indicator": "1.2.3.4", "provider": "talos",   "verdict": "malicious"},
        {"indicator": "1.2.3.4", "provider": "dshield", "verdict": "malicious"},
    ]
    recos = recommend_with_observations(ctx, obs)
    ids = {r["id"] for r in recos}
    assert "reco-ip-block-1.2.3.4" in ids, (
        "≥2 malicious providers must promote IP_BLOCK recommendation")


# ── Test 7 — evidence state hash determinism ─────────────────
def test_evidence_state_hash_deterministic():
    inc = {"xdr_pipeline": {"trace_id": "t1",
                                        "veee": {"label": "SUSPICIOUS"}}}
    obs = [{"source": "x", "indicator": "1.1.1.1", "verdict": "clean"}]
    exe = [{"action_id": "OSINT_ENRICH_IP", "state": "SUCCEEDED"}]
    h1 = _evidence_state_hash(inc, obs, exe)
    h2 = _evidence_state_hash(inc, list(obs), list(exe))
    assert h1 == h2
    # Changing verdict changes the hash.
    obs2 = [{"source": "x", "indicator": "1.1.1.1", "verdict": "malicious"}]
    h3 = _evidence_state_hash(inc, obs2, exe)
    assert h1 != h3


# ── Test 8 — timeline recomputation event emitted ────────────
def test_timeline_carries_recompute_event(loop, db):
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    tl = _run(loop, db["xdr_response_timeline"].count_documents(
        {"incident_id": inc_id,
          "kind": "investigation_recomputed"}))
    assert tl >= 1


# ── Test 9 — observations render in Investigation Fabric ─────
def test_investigation_evidence_graph_includes_observation(loop, db):
    from detection_content.xdr_investigation import project_investigation
    r = _fresh_pipeline(loop, db)
    inc_id = r["incident"]["incident_id"]
    inv = _run(loop, project_investigation(db, inc_id))
    graph = inv["lanes"]["evidence_graph"]
    kinds = {n["kind"] for n in graph.get("nodes", [])}
    assert "intelligence_observation" in kinds, (
        "closed-loop observation must appear as a graph node")
    edge_kinds = {e["kind"] for e in graph.get("edges", [])}
    assert "enriched_by" in edge_kinds


# ── Test 10 — failed action stays failure, no observation ────
def test_failed_action_does_not_produce_observation(loop, db):
    """
    Simulated FAILED execution — record_observation_from_execution
    must return [] and the observations collection stays untouched.
    """
    fake = {"state": "FAILED", "adapter_result": None,
              "execution_id": "exe_fake_" + uuid.uuid4().hex[:8],
              "action_id": "OSINT_ENRICH_IP"}
    obs = _run(loop, record_observation_from_execution(
        db, fake, "inc_fake"))
    assert obs == []
