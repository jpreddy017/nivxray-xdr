"""G-41 · the two temporal indexes, and the plan proof for the real paging shape.

WHAT THIS IS FOR. `observation_us` only pays for itself if the index SUPPLIES the
order. Without the compound index the server would select on identity and then
sort 122,477 rows in memory — the same blocking sort that made a bounded `LIMIT`
return the wrong newest N in the first place, just with a correct key.

So two things are proven here, and the second matters more than the first:
  * exactly the two declared temporal indexes are created, by name and key
    order, and the existing `event_time` pair is left untouched (the
    transitional read still needs it until the legacy path is deleted);
  * every shape the Device Trajectory paging read actually executes — first
    page, resume cursor, bounded window — is an IXSCAN on the intended index
    with NO COLLSCAN and NO blocking SORT, with the tenant and identity
    predicates still present.

The filter and sort come from `production_adapter.branch_query`, the same
function the read calls. A plan proof against a reconstructed query proves
nothing about production, so the reconstruction is deliberately impossible here.

Preview database, throwaway collections, dropped per test. No production index,
no production read or write, no KUSHU, no DESKTOP.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import migration_control as mc  # noqa: E402
from edr_plane import temporal_authority as ta  # noqa: E402
from edr_plane import temporal_read_plan as trp  # noqa: E402
from edr_plane.canonical_index_contract import (TARGET_CANONICAL_INDEXES,
                                                TARGET_TEMPORAL_INDEXES)  # noqa: E402
from edr_trajectory import production_adapter as pa  # noqa: E402

TENANT = "ten_g41_idx"
EP = "ep_g41_idx"


def stamped(i):
    doc = {"tenant_id": TENANT, "event_time": f"2026-09-27 23:{i % 60:02d}:38.144",
           "event_id": f"ix{i:04d}",
           "additional_fields": {"endpoint_id": EP, "activity_type": "process"},
           "host": {"hostname": "host-ix", "host_id": "host-ix"},
           "provenance": {"collector_id": EP},
           "event": {"command_line": f"cmd {i}"}}
    ta.stamp(doc)
    return doc


@pytest_asyncio.fixture
async def env(monkeypatch):
    name = f"g41_idx_{uuid.uuid4().hex[:10]}"
    runs = f"g41_idx_runs_{uuid.uuid4().hex[:8]}"
    locks = f"g41_idx_locks_{uuid.uuid4().hex[:8]}"
    database = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    monkeypatch.setattr(mc, "CANONICAL_COLLECTION", name)
    monkeypatch.setattr(trp, "CANONICAL_COLLECTION", name)
    monkeypatch.setattr(mc, "RUNS", runs)
    monkeypatch.setattr(mc, "LOCKS", locks)
    await database[name].insert_many([stamped(i) for i in range(60)])
    yield database, database[name]
    for c in (name, runs, locks):
        await database[c].drop()


async def _names(coll):
    return {i["name"]: tuple(tuple(kv) for kv in i["key"].items())
            async for i in coll.list_indexes()}


# ── the contract itself ──────────────────────────────────────────────────

def test_the_contract_declares_exactly_two_temporal_indexes_with_a_total_order():
    assert len(TARGET_TEMPORAL_INDEXES) == 2
    for spec in TARGET_TEMPORAL_INDEXES:
        keys = [k for k, _ in spec["key"]]
        directions = [d for _, d in spec["key"]]
        assert keys[0] == "tenant_id", "the tenant partition is the equality prefix"
        assert keys[2] == "observation_us"
        assert keys[3] == "_id", "a total order, so a tie group cannot shuffle"
        assert directions[2:] == [-1, -1], "newest-first, supplied by the index"
        assert "observationus" in spec["name"]
    fields = [s["identity_field"] for s in TARGET_TEMPORAL_INDEXES]
    assert len(set(fields)) == 2, "one index per identity branch"


def test_the_temporal_contract_does_not_replace_the_event_time_contract():
    """The transitional read still needs the event_time pair."""
    temporal = {s["name"] for s in TARGET_TEMPORAL_INDEXES}
    legacy = {s["name"] for s in TARGET_CANONICAL_INDEXES}
    assert not (temporal & legacy)
    assert len(legacy) == 2


def test_both_operations_are_registered_in_the_closed_registry():
    assert mc.OP_ENSURE_TEMPORAL_INDEXES in mc.OPERATIONS
    assert mc.OP_EXPLAIN_TEMPORAL_READ_PLAN in mc.OPERATIONS
    assert mc.OP_ENSURE_TEMPORAL_INDEXES in mc.allowed_operations()


# ── creation ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_mode_creates_nothing(env):
    db, coll = env
    before = await _names(coll)
    out = await mc._op_ensure_canonical_temporal_indexes(db, mode="report")
    assert all(i["state"] == mc.INDEX_WOULD_CREATE for i in out["indexes"])
    assert all(i["created"] is False for i in out["indexes"])
    assert await _names(coll) == before
    assert out["ok"] is True


@pytest.mark.asyncio
async def test_apply_creates_exactly_the_two_declared_indexes(env):
    db, coll = env
    out = await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")
    assert [i["state"] for i in out["indexes"]] == [mc.INDEX_CREATED] * 2
    assert out["existing_indexes_changed"] is False, "_id_ untouched"
    assert out["refusals"] == []
    assert out["ok"] is True

    live = await _names(coll)
    for spec in TARGET_TEMPORAL_INDEXES:
        assert spec["name"] in live
        assert live[spec["name"]] == tuple(tuple(kv) for kv in spec["key"]), \
            "key ORDER is the query shape, not a preference"
    assert len(live) == 3, "_id_ plus exactly the two temporal indexes"


@pytest.mark.asyncio
async def test_apply_is_idempotent(env):
    db, coll = env
    await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")
    first = await _names(coll)
    out = await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")
    assert [i["state"] for i in out["indexes"]] == [mc.INDEX_PRESENT] * 2
    assert out["ok"] is True
    assert await _names(coll) == first


@pytest.mark.asyncio
async def test_a_name_collision_on_a_different_key_refuses(env):
    db, coll = env
    spec = TARGET_TEMPORAL_INDEXES[0]
    await coll.create_index([("tenant_id", 1)], name=spec["name"])
    out = await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")
    states = {i["name"]: i["state"] for i in out["indexes"]}
    assert states[spec["name"]] == mc.INDEX_NAME_CONFLICT
    assert out["refusals"] == [spec["name"]]
    assert out["ok"] is False, "it must never silently drop and rebuild"


# ── the plan proof ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_every_paging_shape_is_an_index_scan_with_no_blocking_sort(env):
    db, coll = env
    await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")

    out = await trp.op_explain_temporal_read_plan(db, mode="report")
    assert out["temporal_key"] == "observation_us"
    assert out["tiebreak"] == "_id"
    assert len(out["branches"]) == 2
    assert out["ok"] is True

    for branch in out["branches"]:
        assert branch["ok"] is True, branch
        assert set(branch["shapes"]) == {"first_page", "resume_cursor",
                                         "bounded_window"}
        for label, shape in branch["shapes"].items():
            c = shape["checks"]
            assert c["ixscan_present"] is True, f"{label} must use an index"
            assert c["no_collscan"] is True, f"{label} must not scan"
            assert c["no_blocking_sort"] is True, \
                f"{label} must take its order FROM the index"
            assert c["index_name_matches"] is True, \
                f"{label} used {shape['index_used']}"
            assert c["key_order_matches_contract"] is True
            assert shape["tenant_predicate_present"] is True
            assert shape["identity_predicate_present"] is True
            assert shape["sort"] == [["observation_us", -1], ["_id", -1]]


@pytest.mark.asyncio
async def test_without_the_indexes_the_proof_fails_loudly(env):
    """The proof must be capable of failing, or it proves nothing."""
    db, coll = env
    out = await trp.op_explain_temporal_read_plan(db, mode="report")
    assert out["ok"] is False
    stages = out["branches"][0]["shapes"]["first_page"]["stages"]
    assert "COLLSCAN" in stages or "SORT" in stages


@pytest.mark.asyncio
async def test_the_explained_shape_is_the_shape_the_read_executes(env):
    """`branch_query` is shared, so the two cannot drift apart."""
    db, coll = env
    flt = pa.branches(pa.STORE_CANONICAL, [EP], TENANT)[0]
    q, sort = pa.branch_query(flt, "observation_us", comparable=True,
                              tiebreak=pa.TEMPORAL_TIEBREAK_KEY)
    assert sort == [("observation_us", -1), ("_id", -1)]
    assert q["tenant_id"] == TENANT
    assert "observation_us" in q


@pytest.mark.asyncio
async def test_the_plan_proof_writes_nothing(env):
    db, coll = env
    await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")
    before = await coll.find({}).to_list(None)
    indexes = await _names(coll)
    for mode in ("report", "apply"):
        out = await trp.op_explain_temporal_read_plan(db, mode=mode)
        assert out["ok"] is True
    assert await coll.find({}).to_list(None) == before
    assert await _names(coll) == indexes, "explain never creates an index"


@pytest.mark.asyncio
async def test_a_branch_with_no_sample_holds_instead_of_passing_vacuously(env):
    db, coll = env
    await mc._op_ensure_canonical_temporal_indexes(db, mode="apply")
    await coll.update_many({}, {"$unset": {"host.hostname": ""}})
    out = await trp.op_explain_temporal_read_plan(db, mode="report")
    held = [b for b in out["branches"] if b.get("hold")]
    assert held and held[0]["hold"] == trp.HOLD_NO_SAMPLE
    assert out["ok"] is False, "an unprovable branch is not a passing branch"


@pytest.mark.asyncio
async def test_through_the_control_plane_with_the_lock_and_audit(env):
    db, coll = env
    rec = await mc.run_migration(db, operation=mc.OP_ENSURE_TEMPORAL_INDEXES,
                                 mode="apply", actor="owner@x")
    assert rec["state"] == mc.STATE_COMPLETED
    assert rec["result"]["ok"] is True

    plan = await mc.run_migration(db,
                                  operation=mc.OP_EXPLAIN_TEMPORAL_READ_PLAN,
                                  mode="report", actor="owner@x")
    assert plan["state"] == mc.STATE_COMPLETED
    assert plan["result"]["ok"] is True
    assert await db[mc.LOCKS].count_documents({}) == 0, "lock released"
