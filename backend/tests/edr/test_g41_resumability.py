"""G-41 · APPLY resumability, proven. The original population never moves.

THE WEAKNESS THIS SUITE EXISTS FOR. A 122,477-row APPLY that dies half way left
evidence perfectly consistent — each row is an independent guarded update — but
the migration could not CONTINUE: the next attempt saw fewer candidates than
`EXPECTED_CANDIDATES` and refused. The only escape would have been to edit the
expectation down to the residual, i.e. to weaken the one invariant that makes
this migration safe. That is a trap, not a safety gate.

THE FIX, and the whole of it: runs are disposable, the POPULATION is not. Every
ledger row carries `population_id`, so a continuation can PROVE what a previous
run completed and assert

    written_before + remaining_candidates == ORIGINAL_POPULATION (122,477)

`EXPECTED_CANDIDATES` is never edited. On a first run `written_before` is 0 and
this is bit-for-bit the old exact-population gate; on a continuation it is
strictly stronger than a bare count, because a row that VANISHED and a row that
JOINED both break the sum.

Preview database, throwaway collections, dropped per test. No production read or
write, no APPLY against production, no index, no deploy, no KUSHU, no DESKTOP.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import migration_control as mc  # noqa: E402
from edr_plane import observation_us_migration as m  # noqa: E402
from edr_plane import temporal_authority as ta  # noqa: E402

POP = 12          # the fixture's "122,477"
TENANT = "ten_g41_resume"


def evidence(i):
    return {"tenant_id": TENANT, "event_time": f"2026-09-27 23:55:{i:02d}.144",
            "event_id": f"ev{i:04d}", "ingest_time": "2026-09-30T00:00:00+00:00",
            "additional_fields": {"endpoint_id": "ep1", "activity_type": "process"},
            "host": {"hostname": "h1", "host_id": "h1"},
            "provenance": {"collector_id": "c1", "endpoint_identity": {"state": "RESOLVED"}},
            "event": {"command_line": f"cmd {i}"}}


@pytest_asyncio.fixture
async def env(monkeypatch):
    name = f"g41_res_{uuid.uuid4().hex[:10]}"
    ledger = f"g41_res_ledger_{uuid.uuid4().hex[:8]}"
    runs = f"g41_res_runs_{uuid.uuid4().hex[:8]}"
    locks = f"g41_res_locks_{uuid.uuid4().hex[:8]}"
    database = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    monkeypatch.setattr(m, "CANONICAL_COLLECTION", name)
    monkeypatch.setattr(m, "LEDGER", ledger)
    monkeypatch.setattr(m, "EXPECTED_CANDIDATES", POP)
    monkeypatch.setattr(mc, "RUNS", runs)
    monkeypatch.setattr(mc, "LOCKS", locks)
    await database[name].insert_many([evidence(i) for i in range(POP)])
    yield database, database[name], database[ledger], database[runs], database[locks]
    for c in (name, ledger, runs, locks):
        await database[c].drop()


class interrupt_after:
    """Kill the run mid-flight, exactly as a dead worker would.

    Deliberately NOT `monkeypatch`: these tests undo the interruption and keep
    going, and `monkeypatch.undo()` would also revert the fixture's collection
    and expectation patches — which silently restores EXPECTED_CANDIDATES to the
    real 122,477 and makes every later assertion meaningless.
    """

    def __init__(self, n, *, on_call=None):
        """`n` counts PARSE calls, and the eligibility census parses every
        candidate before the write loop begins — so a death after `k` writes is
        `POP + k`, not `k`."""
        self.n, self.calls, self.on_call = n, 0, on_call
        self.real = ta.to_epoch_us

    def __enter__(self):
        def hook(value):
            self.calls += 1
            if self.on_call:
                self.on_call(self.calls)
            if self.calls > self.n:
                raise RuntimeError("worker died")
            return self.real(value)
        m.ta.to_epoch_us = hook
        return self

    def __exit__(self, *exc):
        m.ta.to_epoch_us = self.real
        return False


async def candidates(coll):
    return await coll.count_documents(m.CANDIDATE_SELECTOR)


# ── 1 · the uninterrupted run is unchanged ───────────────────────────────

@pytest.mark.asyncio
async def test_an_uninterrupted_run_completes_the_whole_population(env):
    db, coll, ledger, *_ = env
    out = await m.op_backfill_observation_us(db, mode="apply", run_id="r1")
    assert out["written"] == POP
    assert out["population_written_total"] == POP
    assert out["residual_candidates"] == 0
    assert out["skipped_changed_under_run"] == 0
    assert out["skipped_unparseable"] == 0
    assert out["ok"] is True
    v = await m.op_verify_observation_us(db, mode="report", run_id="r1")
    assert (v["checked"], v["disagreeing"], v["collateral_diverged"]) == (POP, 0, 0)
    assert v["ok"] is True


@pytest.mark.asyncio
async def test_a_first_run_still_demands_the_exact_original_population(env):
    """written_before == 0, so the accounting gate IS the old exact gate."""
    db, coll, *_ = env
    await coll.delete_one({"event_id": "ev0000"})
    out = await m.op_backfill_observation_us(db, mode="apply", run_id="r1")
    assert out["gates"]["population_accounted"] is False
    assert out["hold"] == m.HOLD_DRIFT
    assert out["written"] == 0
    assert await candidates(coll) == POP - 1, "nothing was written"


# ── 2-3 · interruption, then safe resume ─────────────────────────────────

@pytest.mark.asyncio
async def test_an_interrupted_run_leaves_rows_whole_and_the_rest_untouched(env):
    db, coll, ledger, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    done = await coll.count_documents({ta.OBSERVATION_US: {"$exists": True}})
    assert done == 5, "five whole rows, not four-and-a-half"
    assert await candidates(coll) == POP - 5
    for d in await coll.find({ta.OBSERVATION_US: {"$exists": True}}).to_list(None):
        assert d[ta.OBSERVATION_US] == ta.to_epoch_us(d["event_time"])
        assert d["additional_fields"][ta.STATE_KEY] == ta.STATE_DERIVED
    assert await ledger.count_documents(m._written_query()) == 5


@pytest.mark.asyncio
async def test_the_same_population_resumes_and_finishes(env):
    db, coll, ledger, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["written_before"] == 5
    assert out["observed_candidates"] == POP - 5
    assert out["gates"]["population_accounted"] is True
    assert out["gates"]["candidate_population_exact"] is False, \
        "a legitimate continuation has fewer candidates left — and proceeds anyway"
    assert out["written_this_run"] == POP - 5
    assert out["population_written_total"] == POP
    assert out["residual_candidates"] == 0
    assert out["ok"] is True
    assert m.EXPECTED_CANDIDATES == POP, "the original population never moved"

    v = await m.op_verify_observation_us(db, mode="report", run_id="resume")
    assert (v["checked"], v["disagreeing"], v["collateral_diverged"]) == (POP, 0, 0)
    assert v["ok"] is True


@pytest.mark.asyncio
async def test_resume_never_rewrites_an_already_written_row(env):
    db, coll, ledger, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    first = {str(d["_id"]): d for d in
             await coll.find({ta.OBSERVATION_US: {"$exists": True}}).to_list(None)}

    await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    for doc_id, before in first.items():
        after = await coll.find_one({"_id": before["_id"]})
        assert after == before, "an already-migrated row must be left alone"
        prov = after["provenance"][m.PROVENANCE_KEY]
        assert prov["migration_run_id"] == "dead", "provenance still names run 1"


# ── 4 · repeated resume / idempotency ────────────────────────────────────

@pytest.mark.asyncio
async def test_resuming_a_finished_population_is_a_no_op(env):
    db, coll, ledger, *_ = env
    await m.op_backfill_observation_us(db, mode="apply", run_id="r1")
    snapshot = await coll.find({}).to_list(None)

    for run in ("r2", "r3"):
        out = await m.op_backfill_observation_us(db, mode="apply", run_id=run)
        assert out["written_before"] == POP
        assert out["observed_candidates"] == 0
        assert out["gates"]["population_accounted"] is True
        assert out["written_this_run"] == 0
        assert out["population_written_total"] == POP
        assert out["residual_candidates"] == 0
        assert out["ok"] is True
    assert await coll.find({}).to_list(None) == snapshot
    assert await ledger.count_documents(m._written_query()) == POP


# ── 5-7 · what must HOLD ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_row_that_vanished_mid_migration_holds(env):
    db, coll, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    await coll.delete_one(m.CANDIDATE_SELECTOR)      # 5 written + 6 left != 12

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["gates"]["population_accounted"] is False
    assert out["hold"] == m.HOLD_DRIFT
    assert out["written"] == 0


@pytest.mark.asyncio
async def test_an_unexpected_extra_candidate_holds(env):
    """New live evidence arrives STAMPED, so it cannot join. An unstamped
    arrival is precisely the anomaly this gate must refuse."""
    db, coll, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    await coll.insert_one(evidence(999))             # 5 + 8 != 12

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["gates"]["population_accounted"] is False
    assert out["hold"] == m.HOLD_DRIFT


@pytest.mark.asyncio
async def test_live_stamped_evidence_during_the_migration_is_ignored(env):
    db, coll, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    live = evidence(9)
    live["event_id"] = "ev0500"
    live["event_time"] = "2026-10-01T10:19:58.863Z"
    m.ta.stamp(live)                                  # the production writer path
    m.ta.assert_stamped(live)
    await coll.insert_one(live)

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["observed_candidates"] == POP - 5, "stamped arrivals are not candidates"
    assert out["gates"]["population_accounted"] is True
    assert out["population_written_total"] == POP
    assert out["residual_candidates"] == 0
    assert out["ok"] is True
    kept = await coll.find_one({"event_id": "ev0500"})
    assert kept["provenance"].get(m.PROVENANCE_KEY) is None, \
        "a live row is not part of the historical population"


@pytest.mark.asyncio
async def test_a_failclosed_unplaceable_arrival_holds_the_resume(env):
    """The writer is fail-closed: an unreadable `event_time` is stored with
    `observation_us` ABSENT and state UNPLACEABLE. Such a row IS a new
    candidate, so it both breaks the accounting sum and fails the parse gate —
    the one way live ingest can reopen a closed population, and it HOLDS."""
    db, coll, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    bad = evidence(9)
    bad["event_id"] = "ev0900"
    bad["event_time"] = "23:55:500.144"               # unreadable
    m.ta.stamp(bad)
    assert ta.OBSERVATION_US not in bad, "fail-closed: no invented instant"
    await coll.insert_one(bad)

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["gates"]["all_candidates_parse"] is False
    assert out["gates"]["population_accounted"] is False
    assert out["hold"] == m.HOLD_DRIFT
    assert out["written"] == 0


@pytest.mark.asyncio
async def test_an_unparseable_candidate_holds_the_whole_run(env):
    db, coll, *_ = env
    await coll.update_one({"event_id": "ev0003"},
                          {"$set": {"event_time": "not-a-timestamp"}})
    out = await m.op_backfill_observation_us(db, mode="apply", run_id="r1")
    assert out["gates"]["all_candidates_parse"] is False
    assert out["hold"] == m.HOLD_DRIFT
    assert out["written"] == 0
    assert await candidates(coll) == POP


@pytest.mark.asyncio
async def test_event_time_changing_under_the_run_skips_that_row(env):
    """The guard is `event_time unchanged`. A row whose evidence moved between
    the cursor read and its update is SKIPPED — never stamped from a stale read —
    and the run then refuses to claim success."""
    db, coll, ledger, *_ = env
    sync = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]][coll.name]

    def race(call_number):
        # the eligibility census parses every candidate first, so the write loop
        # starts at call POP+1; moving the 3rd WRITE's evidence after its parse
        # but before its guarded update is exactly the race the guard exists for
        if call_number == POP + 3:
            sync.update_one({"event_id": "ev0002"},
                            {"$set": {"event_time": "2026-09-28T00:00:00Z"}})

    with interrupt_after(10_000, on_call=race):
        out = await m.op_backfill_observation_us(db, mode="apply", run_id="r1")
    sync.database.client.close()

    assert out["skipped_changed_under_run"] == 1
    assert out["written_this_run"] == POP - 1
    assert out["population_written_total"] == POP - 1
    assert out["residual_candidates"] == 1
    assert out["ok"] is False, "a skipped row must not be reported as success"

    moved = await coll.find_one({"event_id": "ev0002"})
    assert ta.OBSERVATION_US not in moved, "never stamped from a stale read"
    assert moved["event_time"] == "2026-09-28T00:00:00Z", "evidence left as found"

    # and the population still accounts for it, so a later run can finish it
    again = await m.op_backfill_observation_us(db, mode="report", run_id="probe")
    assert again["written_before"] == POP - 1
    assert again["observed_candidates"] == 1
    assert again["gates"]["population_accounted"] is True


@pytest.mark.asyncio
async def test_corrupt_prior_state_in_the_ledger_holds(env):
    db, coll, ledger, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    await ledger.update_one(m._written_query(),
                            {"$unset": {"prior.collateral_digest": ""}})

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["gates"]["ledger_integrity"] is False
    assert out["hold"] == m.HOLD_DRIFT
    assert out["written"] == 0


@pytest.mark.asyncio
async def test_a_duplicated_written_ledger_row_holds(env):
    db, coll, ledger, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")
    row = await ledger.find_one(m._written_query())
    del row["_id"]
    row["migration_run_id"] = "phantom"
    await ledger.insert_one(row)                      # same doc_id twice

    out = await m.op_backfill_observation_us(db, mode="apply", run_id="resume")
    assert out["gates"]["ledger_integrity"] is False
    assert out["hold"] == m.HOLD_DRIFT


@pytest.mark.asyncio
async def test_report_mode_shows_the_resume_position_and_writes_nothing(env):
    db, coll, *_ = env
    with interrupt_after(POP + 5), pytest.raises(RuntimeError):
        await m.op_backfill_observation_us(db, mode="apply", run_id="dead")

    out = await m.op_backfill_observation_us(db, mode="report", run_id="probe")
    assert out["original_population"] == POP
    assert out["written_before"] == 5
    assert out["observed_candidates"] == POP - 5
    assert out["would_write"] == POP - 5
    assert out["written"] == 0
    assert out["ok"] is True
    assert await candidates(coll) == POP - 5, "report wrote nothing"


# ── 8 · the lock: stale may be taken over, live may not ──────────────────

@pytest.mark.asyncio
async def test_a_live_lock_is_never_taken(env):
    db, coll, ledger, runs, locks = env
    await locks.insert_one({"_id": m.OP_BACKFILL_OBSERVATION_US,
                            "migration_run_id": "alive", "actor": "other",
                            "acquired_at": mc._iso(mc._now())})
    rec = await mc.run_migration(db, operation=m.OP_BACKFILL_OBSERVATION_US,
                                 mode="report", actor="me")
    assert rec["state"] == mc.STATE_REFUSED
    assert rec["refusal_reason"] == mc.REFUSED_CONCURRENT
    assert rec["conflict"]["stale"] is False
    assert (await locks.find_one({}))["migration_run_id"] == "alive"


@pytest.mark.asyncio
async def test_a_stale_lock_is_taken_over_and_both_runs_record_it(env):
    db, coll, ledger, runs, locks = env
    old = mc._now() - mc.LOCK_STALE_AFTER - timedelta(minutes=1)
    await locks.insert_one({"_id": m.OP_BACKFILL_OBSERVATION_US,
                            "migration_run_id": "dead_worker", "actor": "other",
                            "acquired_at": mc._iso(old)})
    await runs.insert_one({"migration_run_id": "dead_worker",
                           "operation": m.OP_BACKFILL_OBSERVATION_US,
                           "mode": "apply", "state": mc.STATE_RUNNING})

    rec = await mc.run_migration(db, operation=m.OP_BACKFILL_OBSERVATION_US,
                                 mode="report", actor="me")
    assert rec["state"] == mc.STATE_COMPLETED
    live = await runs.find_one({"migration_run_id": rec["migration_run_id"]})
    assert live["lock_takeover"]["holder_run_id"] == "dead_worker"
    assert live["lock_takeover"]["stale"] is True
    dead = await runs.find_one({"migration_run_id": "dead_worker"})
    assert dead["state"] == mc.STATE_FAILED
    assert dead["failure"] == mc.TAKEOVER_STALE_LOCK
    assert await locks.count_documents({}) == 0, "released after the run"


@pytest.mark.asyncio
async def test_a_takeover_does_not_touch_a_completed_run_record(env):
    db, coll, ledger, runs, locks = env
    old = mc._now() - mc.LOCK_STALE_AFTER - timedelta(minutes=1)
    await locks.insert_one({"_id": m.OP_BACKFILL_OBSERVATION_US,
                            "migration_run_id": "ghost", "actor": "other",
                            "acquired_at": mc._iso(old)})
    await runs.insert_one({"migration_run_id": "ghost",
                           "operation": m.OP_BACKFILL_OBSERVATION_US,
                           "mode": "apply", "state": mc.STATE_COMPLETED,
                           "result": {"written": 3}})
    rec = await mc.run_migration(db, operation=m.OP_BACKFILL_OBSERVATION_US,
                                 mode="report", actor="me")
    assert rec["state"] == mc.STATE_COMPLETED
    ghost = await runs.find_one({"migration_run_id": "ghost"})
    assert ghost["state"] == mc.STATE_COMPLETED, "a finished run is not rewritten"
    assert ghost["result"] == {"written": 3}


# ── 9 · end to end through the control plane, interrupted then resumed ───

@pytest.mark.asyncio
async def test_through_the_control_plane_interrupt_then_resume_then_verify(env):
    db, coll, ledger, runs, locks = env
    with interrupt_after(POP + 5):
        dead = await mc.run_migration(db, operation=m.OP_BACKFILL_OBSERVATION_US,
                                      mode="apply", actor="owner@x")
    assert dead["state"] == mc.STATE_FAILED
    assert await locks.count_documents({}) == 0, "the lock is released on failure"

    good = await mc.run_migration(db, operation=m.OP_BACKFILL_OBSERVATION_US,
                                  mode="apply", actor="owner@x")
    assert good["state"] == mc.STATE_COMPLETED
    assert good["result"]["population_written_total"] == POP
    assert good["result"]["residual_candidates"] == 0
    assert good["result"]["ok"] is True

    ver = await mc.run_migration(db, operation=m.OP_VERIFY_OBSERVATION_US,
                                 mode="report", actor="owner@x")
    assert ver["result"]["checked"] == POP
    assert ver["result"]["disagreeing"] == 0
    assert ver["result"]["collateral_diverged"] == 0
    assert ver["result"]["ok"] is True
    assert await coll.count_documents({ta.OBSERVATION_US: {"$exists": False}}) == 0
