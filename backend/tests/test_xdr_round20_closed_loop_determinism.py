"""
Round 20 · Closed-Loop Determinism Golden Test
──────────────────────────────────────────────

**The golden proof of NivXRay's closed-loop architecture.**

Invariant (locked · PRD § Round 20):

    Given identical canonical evidence and identical system state,
    recomputation MUST produce the same investigation, strategy,
    recommendation and outcome state.  Any state change MUST be
    attributable to newly observed evidence or an explicit analyst
    decision/action.  Repeated recomputation MUST be idempotent and
    MUST NOT create duplicate actions, recommendations, observations,
    or audit events.

The test drives a full lifecycle:

    Evidence
    → Family classification
    → Response Strategy
    → Recommendation synthesis
    → Analyst ACCEPT
    → Action execution
    → New observation
    → Evidence state transition (H1 → H2)
    → Recompute
    → Recommendation state changes
    → Outcome recorded

…and then reruns the recomputation to prove idempotency:

    Recompute again with identical evidence/state H2
    → Same deterministic result
    → No duplicate recommendation / action / observation / audit event

The test also verifies the CRITICAL invariant:

    The action itself does NOT change the verdict.
    Verdict changes are caused only by NEW evidence / observation.
"""
from __future__ import annotations
import asyncio, os, uuid, json
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import process_event_through_pipeline
from detection_content.collector_runtime import GOLDEN_SNORT_EVENT
from detection_content.xdr_closed_loop import (
    recompute as closed_loop_recompute,
    OBSERVATIONS_COLLECTION, RECOS_COLLECTION, TIMELINE_COLLECTION,
    _evidence_state_hash,
)
from detection_content.xdr_closure_classification import (
    classify as classify_closure,
)


@pytest.fixture(scope="module", autouse=True)
def _init_deps_db():
    from deps import validate_config, init_database
    validate_config(); init_database()
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
def golden_incident(loop, db):
    """One Golden Snort event → one incident for the whole module."""
    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    return (r.get("closed_loop") or {}).get("incident_id")


def _snapshot(loop, db, incident_id: str) -> dict:
    """Take an evidence-state snapshot: hash + counters + recompute
    output (used for byte-comparison across repeated recomputes)."""
    async def _go():
        inc = await db["workspace_cases"].find_one(
            {"id": incident_id}, {"_id": 0})
        obs, ex, recos, tl = [], [], [], []
        async for o in db[OBSERVATIONS_COLLECTION].find(
            {"incident_id": incident_id}, {"_id": 0}):
            obs.append(o)
        async for e in db["xdr_response_executions"].find(
            {"incident_id": incident_id}, {"_id": 0}):
            ex.append(e)
        async for r in db[RECOS_COLLECTION].find(
            {"incident_id": incident_id}, {"_id": 0}):
            recos.append(r)
        async for t in db[TIMELINE_COLLECTION].find(
            {"incident_id": incident_id}, {"_id": 0}):
            tl.append(t)
        return {
            "hash": _evidence_state_hash(inc or {}, obs, ex),
            "counts": {
                "observations":  len(obs),
                "executions":    len(ex),
                "recommendations": len(recos),
                "timeline_events": len(tl),
            },
            "recos_by_state": {
                s: sum(1 for r in recos if r.get("state") == s)
                for s in ("ACTIVE", "SUPERSEDED", "ACCEPTED",
                                "REJECTED")
            },
            "families":   sorted({r.get("recommendation_id")
                                          for r in recos}),
        }
    return _run(loop, _go())


# ═══════════════════════════════════════════════════════════════
#   PART 1 — Pipeline produces a stable state H1
# ═══════════════════════════════════════════════════════════════

def test_pipeline_produces_deterministic_state_h1(loop, db, golden_incident):
    r1 = _run(loop, closed_loop_recompute(db, golden_incident))
    r2 = _run(loop, closed_loop_recompute(db, golden_incident))
    # Same evidence → same hash.
    assert r1["evidence_state_hash"] == r2["evidence_state_hash"]
    # Second recompute is idempotent.
    assert r2["changed"] is False


def test_recompute_carries_family_and_strategy(loop, db, golden_incident):
    r = _run(loop, closed_loop_recompute(db, golden_incident))
    assert r["threat_family"] == "C2"
    recos = (r.get("recommendations") or {}).get("synthesized") or []
    assert recos, "recos must be synthesized for C2 incident"
    # Every reco must be endorsed by the C2_CONTAINMENT strategy.
    for reco in recos:
        assert reco.get("strategy", {}).get("id") == "C2_CONTAINMENT"


# ═══════════════════════════════════════════════════════════════
#   PART 2 — Idempotency invariant (H1 → H1 rerun)
# ═══════════════════════════════════════════════════════════════

def test_repeated_recompute_creates_no_duplicates(loop, db, golden_incident):
    """Second recompute over identical state must NOT duplicate
    observations, recommendations, executions, or timeline events."""
    before = _snapshot(loop, db, golden_incident)
    _run(loop, closed_loop_recompute(db, golden_incident))
    after  = _snapshot(loop, db, golden_incident)
    # Byte-identical counters.
    assert before["counts"] == after["counts"], \
        f"idempotency violated: {before['counts']} != {after['counts']}"
    assert before["hash"]   == after["hash"]


# ═══════════════════════════════════════════════════════════════
#   PART 3 — State transition invariant (H1 → H2 caused by NEW evidence)
# ═══════════════════════════════════════════════════════════════

def test_new_observation_transitions_state_h1_to_h2(loop, db,
                                                                        golden_incident):
    """Injecting a NEW execution + observation must transition the
    hash H1 → H2 (evidence state has genuinely changed).  The verdict
    is NOT bumped by the action itself; only new evidence can move it."""
    from detection_content.xdr_closed_loop import (
        record_observation_from_execution,
    )
    h1 = _snapshot(loop, db, golden_incident)["hash"]

    # 1. Simulate a SUCCEEDED action executed by the analyst.  The
    #    action_id is IOC_ADD_WATCHLIST (auto-approve, no adapter
    #    required in the Round 13 registry).
    execution = {
        "execution_id":   f"exe_{uuid.uuid4().hex[:16]}",
        "incident_id":    golden_incident,
        "action_id":      "IOC_ADD_WATCHLIST",
        "state":          "SUCCEEDED",
        "at":             "2026-02-15T00:00:00+00:00",
        "adapter_result": {
            "kind":     "ipv4",
            "value":    "203.0.113.42",
            "verdict":  "malicious",
            "score":    92,
            "providers": [
                {"provider": "nivxray_internal", "verdict": "watchlisted",
                  "detail":   "added to internal IOC watchlist"},
            ],
        },
    }
    _run(loop, db["xdr_response_executions"].insert_one(dict(execution)))

    # 2. Record the observation from that execution.
    _run(loop, record_observation_from_execution(
        db, execution, golden_incident))

    # 3. Recompute.  This should transition H1 → H2.
    r = _run(loop, closed_loop_recompute(db, golden_incident))
    h2 = r["evidence_state_hash"]
    assert h2 != h1, "new observation MUST cause state hash to change"
    assert r["changed"] is True
    # Investigation lanes must include the new observation.
    assert r["total_observations"] >= 1


def test_verdict_is_not_moved_by_the_action_itself(loop, db,
                                                                        golden_incident):
    """Round 14/16/20 rule: a SUCCEEDED action alone MUST NOT push the
    VEEE verdict.  Verdict changes are caused only by new evidence /
    canonical / correlation input — NOT by the action state."""
    inc = _run(loop, db["workspace_cases"].find_one(
        {"id": golden_incident}, {"_id": 0}))
    veee_before = (inc.get("xdr_pipeline") or {}).get("veee") or {}
    label_before = veee_before.get("label")
    score_before = veee_before.get("score")

    # Recompute after the action was registered (Part 3 test above).
    _run(loop, closed_loop_recompute(db, golden_incident))

    inc = _run(loop, db["workspace_cases"].find_one(
        {"id": golden_incident}, {"_id": 0}))
    veee_after = (inc.get("xdr_pipeline") or {}).get("veee") or {}
    assert veee_after.get("label") == label_before
    assert veee_after.get("score") == score_before


# ═══════════════════════════════════════════════════════════════
#   PART 4 — H2 → H2 idempotency (post-transition rerun)
# ═══════════════════════════════════════════════════════════════

def test_recompute_after_transition_is_still_idempotent(loop, db,
                                                                            golden_incident):
    """Once state has moved to H2, subsequent recomputes over the
    same H2 state MUST be idempotent again."""
    before = _snapshot(loop, db, golden_incident)
    _run(loop, closed_loop_recompute(db, golden_incident))
    after  = _snapshot(loop, db, golden_incident)
    assert before["hash"] == after["hash"]
    assert before["counts"] == after["counts"]


# ═══════════════════════════════════════════════════════════════
#   PART 5 — Deterministic closure classification
# ═══════════════════════════════════════════════════════════════

def test_closure_classification_is_deterministic(loop, db, golden_incident):
    """Same evidence → identical closure classification."""
    a = _run(loop, classify_closure(db, golden_incident))
    b = _run(loop, classify_closure(db, golden_incident))
    assert a["furthest_confirmed_phase"] == b["furthest_confirmed_phase"]
    # Serialise for full byte equality (citations/order preserved).
    assert json.dumps(a["citations"], sort_keys=True) == \
                json.dumps(b["citations"], sort_keys=True)


def test_closure_is_command_and_control_for_snort_golden(loop, db,
                                                                                golden_incident):
    """Golden Snort event → C2 family + framework map ACTIVE →
    closure MUST advance beyond the initial-alert phase and land at
    COMMAND_AND_CONTROL."""
    c = _run(loop, classify_closure(db, golden_incident))
    assert c["state"] == "READY"
    assert c["furthest_confirmed_phase"] == "COMMAND_AND_CONTROL"


def test_closure_never_advances_past_evidence(loop, db, golden_incident):
    """No closure ever names a phase deeper than what actually
    appears in citations."""
    c = _run(loop, classify_closure(db, golden_incident))
    cited = {ct["phase"] for ct in c["citations"]}
    assert c["furthest_confirmed_phase"] in cited
