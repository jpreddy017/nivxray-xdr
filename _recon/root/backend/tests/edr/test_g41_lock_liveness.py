"""G-41 · the lock takeover, corrected. Age opens the question; liveness answers.

THE DEFECT THIS SUITE EXISTS FOR, observed in production on 2026-10-03.
`LOCK_STALE_AFTER` was 30 minutes. The real backfill of 122,477 rows took ~42.
So a perfectly healthy worker was declared stale, a concurrently-issued REPORT
took its lock away, and its run record was flipped to FAILED — while the worker
carried on writing for another twenty minutes with the lock table EMPTY. The
single-writer guarantee was gone, and any further invocation would not have been
refused. No evidence was damaged (the per-row guard requires `observation_us`
absent, so a second writer could not double-write a row), but the property was
lost by accident.

ELAPSED AGE CANNOT TELL A DEAD WORKER FROM A SLOW ONE. The correction:

  * age makes a lock ELIGIBLE for takeover, nothing more;
  * two independent liveness signals can save the holder — its own heartbeat,
    renewed on the lock while it works, and the operation's observable progress
    (the newest row the backfill wrote);
  * the takeover is conditioned on the exact heartbeat it judged, so a beat
    landing mid-decision keeps the lock;
  * and the heartbeat ABORTS its own run when the lock is gone, so a takeover
    actually stops the writer instead of orphaning it.

Preview database, throwaway collections, dropped per test. No production read or
write, no migration against production, no KUSHU, no DESKTOP.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import timedelta

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import migration_control as mc  # noqa: E402

OP = "t_lock_probe_op"


@pytest_asyncio.fixture
async def env(monkeypatch):
    runs = f"g41_lk_runs_{uuid.uuid4().hex[:8]}"
    locks = f"g41_lk_locks_{uuid.uuid4().hex[:8]}"
    database = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    monkeypatch.setattr(mc, "RUNS", runs)
    monkeypatch.setattr(mc, "LOCKS", locks)
    monkeypatch.setattr(mc, "HEARTBEAT_SEC", 0.05)
    state = {"calls": 0, "progress": None, "block": None}

    async def probe(db, *, mode, run_id=""):
        state["calls"] += 1
        if state["block"] is not None:
            await state["block"].wait()
        return {"ok": True, "mode": mode}

    async def liveness(db):
        return state["progress"]

    mc.OPERATIONS[OP] = probe
    mc.LIVENESS[OP] = liveness
    try:
        yield database, database[runs], database[locks], state
    finally:
        mc.OPERATIONS.pop(OP, None)
        mc.LIVENESS.pop(OP, None)
        await database[runs].drop()
        await database[locks].drop()


def _old(minutes):
    return mc._iso(mc._now() - timedelta(minutes=minutes))


async def _hold(locks, *, run_id, age_min, beat_min=None):
    doc = {"_id": OP, "migration_run_id": run_id, "actor": "other",
           "acquired_at": _old(age_min)}
    doc["heartbeat_at"] = _old(beat_min if beat_min is not None else age_min)
    await locks.insert_one(doc)


async def _wait_for_lock(locks, *, timeout=5.0):
    """The run acquires its lock on its first database round trip; wait for it
    rather than guessing a sleep that is fast enough on one machine only."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        held = await locks.find_one({})
        if held:
            return held
        await asyncio.sleep(0.02)
    raise AssertionError("the run never acquired its lock")


# ── the defect itself: a slow but living holder keeps its lock ────────────

@pytest.mark.asyncio
async def test_a_long_running_holder_that_is_still_writing_keeps_its_lock(env):
    """THE regression. 42 minutes of age, 30-minute threshold — but the ledger
    shows a row written seconds ago, so it is alive and must not be touched."""
    db, runs, locks, state = env
    await _hold(locks, run_id="live_worker", age_min=42)
    state["progress"] = mc._now()                      # wrote a row just now

    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_REFUSED
    assert rec["refusal_reason"] == mc.REFUSED_CONCURRENT
    assert rec["conflict"]["holder_alive"] is True
    assert rec["conflict"]["stale"] is False, \
        "eligible by age, but demonstrably working — not stale"
    assert (await locks.find_one({}))["migration_run_id"] == "live_worker"
    assert state["calls"] == 0, "the second run never executed"


@pytest.mark.asyncio
async def test_a_holder_whose_own_heartbeat_is_fresh_keeps_its_lock(env):
    """Even with NO progress signal at all, its heartbeat defends it."""
    db, runs, locks, state = env
    await _hold(locks, run_id="beating", age_min=90, beat_min=0)
    state["progress"] = None

    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_REFUSED
    assert rec["conflict"]["stale"] is False
    assert (await locks.find_one({}))["migration_run_id"] == "beating"


@pytest.mark.asyncio
async def test_progress_older_than_the_threshold_does_not_save_a_dead_holder(env):
    db, runs, locks, state = env
    await _hold(locks, run_id="dead", age_min=90)
    state["progress"] = mc._now() - timedelta(minutes=45)   # stopped long ago
    await runs.insert_one({"migration_run_id": "dead", "operation": OP,
                           "mode": "apply", "state": mc.STATE_RUNNING})

    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_COMPLETED, "a genuinely dead lock is reclaimed"
    assert rec["lock_takeover"]["holder_run_id"] == "dead"
    dead = await runs.find_one({"migration_run_id": "dead"})
    assert dead["state"] == mc.STATE_FAILED
    assert dead["failure"] == mc.TAKEOVER_STALE_LOCK
    assert "no observable progress" in dead["failure_detail"]


@pytest.mark.asyncio
async def test_a_dead_holder_with_no_progress_signal_at_all_is_reclaimed(env):
    db, runs, locks, state = env
    await _hold(locks, run_id="ghost", age_min=90)
    state["progress"] = None
    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_COMPLETED
    assert rec["lock_takeover"]["holder_run_id"] == "ghost"
    assert await locks.count_documents({}) == 0, "released after the run"


@pytest.mark.asyncio
async def test_a_young_lock_is_never_eligible_however_dead_it_looks(env):
    db, runs, locks, state = env
    await _hold(locks, run_id="recent", age_min=1)
    state["progress"] = None
    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_REFUSED
    assert rec["conflict"]["stale"] is False
    assert (await locks.find_one({}))["migration_run_id"] == "recent"


@pytest.mark.asyncio
async def test_a_heartbeat_landing_mid_decision_keeps_the_lock(env):
    """The delete is conditioned on the exact heartbeat that was judged."""
    db, runs, locks, state = env
    await _hold(locks, run_id="racer", age_min=90)
    judged = await locks.find_one({}, {"_id": 0})
    holder = await mc._holder_state(db, OP, judged)
    assert holder["stale"] is True, "eligible at the moment of judgement"

    await locks.update_one({"_id": OP},
                           {"$set": {"heartbeat_at": mc._iso(mc._now())}})
    took = await mc._takeover_stale(db, OP, "newcomer", "me", holder)
    assert took is False, "it beat between the decision and the write"
    assert (await locks.find_one({}))["migration_run_id"] == "racer"


@pytest.mark.asyncio
async def test_a_liveness_probe_that_raises_does_not_decide_by_crashing(env):
    db, runs, locks, state = env

    async def broken(db):
        raise RuntimeError("probe exploded")

    mc.LIVENESS[OP] = broken
    await _hold(locks, run_id="unknown", age_min=90)
    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_COMPLETED, \
        "an unreadable probe falls back to the heartbeat, it does not crash"


# ── the other half: a takeover must STOP the writer ──────────────────────

@pytest.mark.asyncio
async def test_a_running_operation_renews_its_own_lock(env):
    db, runs, locks, state = env
    state["block"] = asyncio.Event()
    task = asyncio.ensure_future(
        mc.run_migration(db, operation=OP, mode="apply", actor="owner"))
    first = (await _wait_for_lock(locks))["heartbeat_at"]
    await asyncio.sleep(mc.HEARTBEAT_SEC * 4)
    later = (await locks.find_one({}))["heartbeat_at"]
    assert later > first, "the heartbeat advanced while the work ran"
    state["block"].set()
    rec = await task
    assert rec["state"] == mc.STATE_COMPLETED
    assert await locks.count_documents({}) == 0


@pytest.mark.asyncio
async def test_losing_the_lock_aborts_the_run_instead_of_orphaning_it(env):
    """The 2026-10-03 orphan, made impossible: the worker notices and stops."""
    db, runs, locks, state = env
    state["block"] = asyncio.Event()
    task = asyncio.ensure_future(
        mc.run_migration(db, operation=OP, mode="apply", actor="owner"))
    await _wait_for_lock(locks)

    await locks.delete_many({})                 # somebody took it
    rec = await asyncio.wait_for(task, timeout=5)

    assert rec["state"] == mc.STATE_FAILED
    assert rec["failure"] == "LockLost"
    record = await runs.find_one({"migration_run_id": rec["migration_run_id"]})
    assert record["state"] == mc.STATE_FAILED
    assert record["failure"] == "LockLost"
    state["block"].set()


@pytest.mark.asyncio
async def test_a_run_whose_lock_was_taken_over_stops_writing(env):
    db, runs, locks, state = env
    state["block"] = asyncio.Event()
    task = asyncio.ensure_future(
        mc.run_migration(db, operation=OP, mode="apply", actor="owner"))
    victim = (await _wait_for_lock(locks))["migration_run_id"]

    # simulate a takeover by another run: same _id, different holder
    await locks.delete_many({})
    await locks.insert_one({"_id": OP, "migration_run_id": "thief",
                            "actor": "other", "acquired_at": mc._iso(mc._now()),
                            "heartbeat_at": mc._iso(mc._now())})
    rec = await asyncio.wait_for(task, timeout=5)
    assert rec["failure"] == "LockLost"
    assert rec["migration_run_id"] == victim
    assert (await locks.find_one({}))["migration_run_id"] == "thief", \
        "the victim must not delete a lock it no longer owns"
    state["block"].set()


@pytest.mark.asyncio
async def test_a_normal_short_run_is_unaffected(env):
    db, runs, locks, state = env
    rec = await mc.run_migration(db, operation=OP, mode="report", actor="me")
    assert rec["state"] == mc.STATE_COMPLETED
    assert rec["result"] == {"ok": True, "mode": "report"}
    assert await locks.count_documents({}) == 0
    assert state["calls"] == 1


@pytest.mark.asyncio
async def test_a_failing_operation_still_releases_the_lock(env):
    db, runs, locks, state = env

    async def boom(db, *, mode, run_id=""):
        raise RuntimeError("deliberate")

    mc.OPERATIONS[OP] = boom
    rec = await mc.run_migration(db, operation=OP, mode="apply", actor="me")
    assert rec["state"] == mc.STATE_FAILED
    assert rec["failure"] == "RuntimeError"
    assert await locks.count_documents({}) == 0


@pytest.mark.asyncio
async def test_the_real_backfill_registers_a_progress_signal(env):
    """The liveness probe must be wired to the operation that needed it."""
    from edr_plane import observation_us_migration as m
    assert m.OP_BACKFILL_OBSERVATION_US in mc.LIVENESS
    assert mc.HEARTBEAT_SEC * 4 < mc.LOCK_STALE_AFTER.total_seconds(), \
        "a live holder must never even become eligible"
