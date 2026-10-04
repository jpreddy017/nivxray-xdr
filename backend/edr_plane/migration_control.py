"""Bounded production migration control — the ONLY server-side write path for
the canonical identity migration.

This is deliberately NOT a database console. There is no caller-supplied
collection, index specification, filter, update, pipeline or command anywhere in
this module. The migration surface is a CLOSED REGISTRY of named operations
compiled into the backend; a caller may only name one of them and choose
whether to REPORT or APPLY.

Guarantees, each covered by a test:
  * closed registry — an unknown operation is refused and audited, never run;
  * no parameters — an operation takes nothing from the caller but the mode;
  * idempotent — an exact index that already exists is VERIFIED, not rebuilt;
  * non-destructive — nothing is ever dropped, renamed or altered, and a
    same-name/different-key index is REFUSED rather than resolved;
  * single-writer — a lock document makes concurrent duplicate requests
    CONFLICT instead of racing, and it is released even on failure;
  * audited — requested/started/completed/failed/refused are durable records
    naming the authenticated actor, with no secret and no connection detail;
  * secret-free — results carry index names, key patterns and states only.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from pymongo.errors import DuplicateKeyError

from edr_plane import (identity_backfill, observation_us_migration,
                       temporal_read_plan)
from edr_plane.canonical_index_contract import (CANONICAL_COLLECTION,
                                                TARGET_CANONICAL_INDEXES,
                                                TARGET_TEMPORAL_INDEXES)

RUNS = "e3_migration_runs"
LOCKS = "e3_migration_locks"

OP_ENSURE_IDENTITY_INDEXES = "ensure_canonical_identity_indexes"

MODE_REPORT = "report"
MODE_APPLY = "apply"
MODES = (MODE_REPORT, MODE_APPLY)

STATE_REQUESTED = "REQUESTED"
STATE_RUNNING = "RUNNING"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"
STATE_REFUSED = "REFUSED"

REFUSED_UNKNOWN_OPERATION = "UNKNOWN_MIGRATION_OPERATION"
REFUSED_UNKNOWN_MODE = "UNKNOWN_MIGRATION_MODE"
REFUSED_CONCURRENT = "MIGRATION_ALREADY_RUNNING"
TAKEOVER_STALE_LOCK = "STALE_LOCK_TAKEOVER"
LOCK_LOST = "LOCK_LOST"

#: Age at which a lock BECOMES ELIGIBLE for takeover. Eligible is not the same
#: as dead.
#:
#: 2026-10-03, learned the hard way: a healthy 42-minute backfill was declared
#: stale at 30 minutes and had its lock taken from underneath it, leaving a
#: lock-less writer mutating canonical evidence while the lock table sat empty.
#: ELAPSED AGE CANNOT TELL A DEAD WORKER FROM A SLOW ONE. So age only opens the
#: question; two independent liveness signals answer it, and either one saves
#: the holder:
#:   * its own heartbeat, renewed on the lock while it works, and
#:   * the operation's observable progress (`LIVENESS`), e.g. the newest row the
#:     backfill wrote.
#: A holder that is provably working keeps its lock no matter how long it takes.
LOCK_STALE_AFTER = timedelta(minutes=30)

#: How often a running operation renews its lock. Must be comfortably shorter
#: than LOCK_STALE_AFTER so a live holder is never even eligible.
HEARTBEAT_SEC = 30

#: operation name -> async (db) -> Optional[datetime] of its last observable
#: progress. Registered by the operation itself; absent means "no progress
#: signal", and then only the heartbeat protects the holder.
LIVENESS: Dict[str, Any] = dict(observation_us_migration.LIVENESS)

INDEX_CREATED = "CREATED_VERIFIED"
INDEX_PRESENT = "ALREADY_PRESENT_VERIFIED"
INDEX_WOULD_CREATE = "WOULD_CREATE"
INDEX_NAME_CONFLICT = "NAME_CONFLICT_REFUSED"
INDEX_UNVERIFIED = "CREATED_BUT_UNVERIFIED"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _existing(coll) -> Dict[str, Tuple[Tuple[str, Any], ...]]:
    out: Dict[str, Tuple[Tuple[str, Any], ...]] = {}
    async for idx in coll.list_indexes():
        out[idx["name"]] = tuple(tuple(kv) for kv in idx["key"].items())
    return out


async def _ensure_one(coll, spec: Dict[str, Any], *, apply_changes: bool,
                      legacy_background: bool) -> Dict[str, Any]:
    before = await _existing(coll)
    want = tuple(tuple(kv) for kv in spec["key"])
    same_key = [n for n, key in before.items() if key == want]
    if same_key:
        return {"name": same_key[0], "state": INDEX_PRESENT,
                "key": [list(kv) for kv in want], "created": False}
    if spec["name"] in before:
        return {"name": spec["name"], "state": INDEX_NAME_CONFLICT,
                "key": [list(kv) for kv in before[spec["name"]]],
                "created": False}
    if not apply_changes:
        return {"name": spec["name"], "state": INDEX_WOULD_CREATE,
                "key": [list(kv) for kv in want], "created": False}
    kwargs: Dict[str, Any] = {"name": spec["name"]}
    if legacy_background:
        kwargs["background"] = True
    started = time.perf_counter()
    await coll.create_index([(k, v) for k, v in want], **kwargs)
    after = await _existing(coll)
    verified = after.get(spec["name"]) == want
    return {"name": spec["name"],
            "state": INDEX_CREATED if verified else INDEX_UNVERIFIED,
            "key": [list(kv) for kv in (after.get(spec["name"]) or want)],
            "created": True,
            "build_ms": int((time.perf_counter() - started) * 1000)}


async def _op_ensure_canonical_identity_indexes(db, *, mode: str,
                                                run_id: str = "") -> Dict[str, Any]:
    """Ensure EXACTLY the two declared target canonical indexes. The collection
    and both specifications come from the compiled contract — never from a
    caller."""
    coll = db[CANONICAL_COLLECTION]
    try:
        version = (await db.client.server_info())["version"]
        major, minor = (int(p) for p in version.split(".")[:2])
    except Exception:
        version, major, minor = "unknown", 4, 4
    legacy_background = (major, minor) < (4, 2)
    before = await _existing(coll)
    results: List[Dict[str, Any]] = []
    for spec in TARGET_CANONICAL_INDEXES:
        results.append(await _ensure_one(
            coll, spec, apply_changes=(mode == MODE_APPLY),
            legacy_background=legacy_background))
    after = await _existing(coll)
    unchanged = all(after.get(name) == key for name, key in before.items())
    refused = [r for r in results if r["state"] == INDEX_NAME_CONFLICT]
    return {
        "collection": CANONICAL_COLLECTION,
        "server_version": version,
        "build_mode": ("legacy_background" if legacy_background
                       else "hybrid_non_blocking"),
        "indexes": results,
        "indexes_before": sorted(before),
        "indexes_after": sorted(after),
        "existing_indexes_changed": not unchanged,
        "refusals": [r["name"] for r in refused],
        "ok": (not refused) and unchanged,
    }


#: G-41 · the two temporal indexes, and the plan proof for the paging shape the
#: Device Trajectory read actually executes. Separate operations from the
#: event_time pair above: that one must keep working while the transitional read
#: still exists, so neither is allowed to replace the other.
OP_ENSURE_TEMPORAL_INDEXES = "ensure_canonical_temporal_indexes"
OP_EXPLAIN_TEMPORAL_READ_PLAN = temporal_read_plan.OP_EXPLAIN_TEMPORAL_READ_PLAN


async def _op_ensure_canonical_temporal_indexes(db, *, mode: str,
                                                run_id: str = "") -> Dict[str, Any]:
    """Ensure EXACTLY the two declared temporal indexes. Both specifications
    come from the compiled contract — never from a caller."""
    coll = db[CANONICAL_COLLECTION]
    try:
        version = (await db.client.server_info())["version"]
        major, minor = (int(p) for p in version.split(".")[:2])
    except Exception:
        version, major, minor = "unknown", 4, 4
    legacy_background = (major, minor) < (4, 2)
    before = await _existing(coll)
    results: List[Dict[str, Any]] = []
    for spec in TARGET_TEMPORAL_INDEXES:
        results.append(await _ensure_one(
            coll, spec, apply_changes=(mode == MODE_APPLY),
            legacy_background=legacy_background))
    after = await _existing(coll)
    unchanged = all(after.get(name) == key for name, key in before.items())
    refused = [r for r in results if r["state"] == INDEX_NAME_CONFLICT]
    return {
        "collection": CANONICAL_COLLECTION,
        "server_version": version,
        "build_mode": ("legacy_background" if legacy_background
                       else "hybrid_non_blocking"),
        "indexes": results,
        "indexes_before": sorted(before),
        "indexes_after": sorted(after),
        #: the event_time pair must survive untouched: the transitional read
        #: still uses it until the legacy path is deleted
        "existing_indexes_changed": not unchanged,
        "refusals": [r["name"] for r in refused],
        "ok": (not refused) and unchanged,
    }


#: The closed registry. Adding an operation is a code change, reviewed like any
#: other. A later bounded identity-backfill operation registers HERE; nothing
#: about this framework lets a caller invent one.
OPERATIONS = {OP_ENSURE_IDENTITY_INDEXES: _op_ensure_canonical_identity_indexes,
              OP_ENSURE_TEMPORAL_INDEXES: _op_ensure_canonical_temporal_indexes,
              **identity_backfill.OPERATIONS,
              **observation_us_migration.OPERATIONS,
              **temporal_read_plan.OPERATIONS}

OP_BACKFILL_IDENTITY = identity_backfill.OP_BACKFILL
OP_REVERT_IDENTITY_BACKFILL = identity_backfill.OP_REVERT
OP_EXPLAIN_IDENTITY_READ_PLAN = identity_backfill.OP_EXPLAIN


def allowed_operations() -> List[str]:
    return sorted(OPERATIONS)


async def _audit(db, record: Dict[str, Any]) -> None:
    await db[RUNS].insert_one(dict(record))


async def _audit_update(db, migration_run_id: str, patch: Dict[str, Any]) -> None:
    await db[RUNS].update_one({"migration_run_id": migration_run_id},
                              {"$set": dict(patch)})


def _parse_iso(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def _last_progress(db, operation: str) -> Optional[datetime]:
    probe = LIVENESS.get(operation)
    if probe is None:
        return None
    try:
        return await probe(db)
    except Exception:          # a liveness probe must never decide by crashing
        return None


async def _holder_state(db, operation: str, held: Dict[str, Any]
                        ) -> Dict[str, Any]:
    """Is the holder eligible for takeover, and is it nonetheless alive?"""
    now = _now()
    #: the heartbeat is the holder's own claim to be working; before the first
    #: beat lands, `acquired_at` stands in for it
    beat = _parse_iso(held.get("heartbeat_at")) or _parse_iso(held.get("acquired_at"))
    beat_age = (now - beat) if beat else None
    eligible = bool(beat_age and beat_age > LOCK_STALE_AFTER)

    progress = await _last_progress(db, operation)
    progress_age = (now - progress) if progress else None
    working = bool(progress_age is not None and progress_age <= LOCK_STALE_AFTER)

    return {"holder_run_id": held.get("migration_run_id"),
            "holder_actor": held.get("actor"),
            "acquired_at": held.get("acquired_at"),
            "heartbeat_at": held.get("heartbeat_at"),
            "last_progress_at": _iso(progress) if progress else None,
            "holder_alive": working,
            #: age merely opens the question; observable progress closes it
            "stale": eligible and not working}


async def _acquire(db, operation: str, run_id: str, actor: str
                   ) -> Tuple[bool, Optional[Dict[str, Any]]]:
    now = _iso(_now())
    try:
        await db[LOCKS].insert_one({
            "_id": operation, "migration_run_id": run_id,
            "actor": actor, "acquired_at": now, "heartbeat_at": now})
        return True, None
    except DuplicateKeyError:
        held = await db[LOCKS].find_one({"_id": operation}, {"_id": 0})
        if not held:
            return False, {"holder_run_id": None, "stale": False,
                           "holder_alive": False}
        return False, await _holder_state(db, operation, held)


async def _takeover_stale(db, operation: str, run_id: str, actor: str,
                          holder: Dict[str, Any]) -> bool:
    """Claim a lock whose holder is eligible AND shows no sign of life.

    Conditioned on BOTH the holder's run id and the exact heartbeat we judged,
    so a holder that beats between the decision and this write keeps its lock.
    One last liveness read first: the cheapest possible way to avoid stomping a
    live single-writer.
    """
    if await _last_progress(db, operation) is not None:
        fresh = await db[LOCKS].find_one({"_id": operation}, {"_id": 0})
        if fresh and (await _holder_state(db, operation, fresh))["holder_alive"]:
            return False

    res = await db[LOCKS].delete_one({
        "_id": operation,
        "migration_run_id": holder["holder_run_id"],
        "heartbeat_at": holder.get("heartbeat_at")})
    if res.deleted_count != 1:
        return False
    now = _iso(_now())
    try:
        await db[LOCKS].insert_one({
            "_id": operation, "migration_run_id": run_id, "actor": actor,
            "acquired_at": now, "heartbeat_at": now,
            "took_over_from": holder["holder_run_id"]})
    except DuplicateKeyError:
        return False
    if holder.get("holder_run_id"):
        await db[RUNS].update_one(
            {"migration_run_id": holder["holder_run_id"],
             "state": STATE_RUNNING},
            {"$set": {"state": STATE_FAILED, "completed_at": _iso(_now()),
                      "failure": TAKEOVER_STALE_LOCK,
                      "failure_detail": f"lock taken over by {run_id}: no "
                                        f"heartbeat and no observable progress "
                                        f"for more than {LOCK_STALE_AFTER}"}})
    return True


class LockLost(RuntimeError):
    """This run no longer holds the lock, so it must stop writing NOW."""


async def _heartbeat(db, operation: str, run_id: str) -> None:
    """Renew the lock while the operation works; abort the run if it is gone.

    This is the half that makes a takeover MEAN something: before, a takeover
    removed the lock and the orphaned worker carried on writing regardless.
    """
    while True:
        await asyncio.sleep(HEARTBEAT_SEC)
        res = await db[LOCKS].update_one(
            {"_id": operation, "migration_run_id": run_id},
            {"$set": {"heartbeat_at": _iso(_now())}})
        if res.matched_count != 1:
            raise LockLost(f"lock for {operation} is no longer held by {run_id}")


async def _run_guarded(db, operation: str, run_id: str, mode: str) -> Any:
    work = asyncio.ensure_future(OPERATIONS[operation](db, mode=mode,
                                                       run_id=run_id))
    beat = asyncio.ensure_future(_heartbeat(db, operation, run_id))
    try:
        done, _ = await asyncio.wait({work, beat},
                                     return_when=asyncio.FIRST_COMPLETED)
        if beat in done:                      # only ever finishes by raising
            work.cancel()
            try:
                await work
            except (asyncio.CancelledError, Exception):
                pass
            beat.result()
        return work.result()
    finally:
        for task in (beat, work):
            if not task.done():
                task.cancel()
        await asyncio.gather(beat, work, return_exceptions=True)


async def _release(db, operation: str, run_id: str) -> None:
    await db[LOCKS].delete_one({"_id": operation, "migration_run_id": run_id})


async def run_migration(db, *, operation: str, mode: str, actor: str
                        ) -> Dict[str, Any]:
    """Execute one NAMED migration operation. `actor` is the authenticated
    principal, recorded for audit. No secret is read, returned or logged."""
    run_id = "mig_" + uuid.uuid4().hex[:16]
    requested_at = _iso(_now())
    base = {"migration_run_id": run_id, "operation": operation, "mode": mode,
            "actor": actor, "requested_at": requested_at,
            "state": STATE_REQUESTED}

    if operation not in OPERATIONS:
        rec = {**base, "state": STATE_REFUSED,
               "refusal_reason": REFUSED_UNKNOWN_OPERATION,
               "completed_at": _iso(_now())}
        await _audit(db, rec)
        return rec
    if mode not in MODES:
        rec = {**base, "state": STATE_REFUSED,
               "refusal_reason": REFUSED_UNKNOWN_MODE,
               "completed_at": _iso(_now())}
        await _audit(db, rec)
        return rec

    await _audit(db, base)
    acquired, holder = await _acquire(db, operation, run_id, actor)
    took_over = None
    if not acquired and holder and holder.get("stale"):
        if await _takeover_stale(db, operation, run_id, actor, holder):
            acquired, took_over = True, holder
    if not acquired:
        patch = {"state": STATE_REFUSED,
                 "refusal_reason": REFUSED_CONCURRENT,
                 "conflict": holder, "completed_at": _iso(_now())}
        await _audit_update(db, run_id, patch)
        return {**base, **patch}

    started_at = _iso(_now())
    if took_over:
        base = {**base, "lock_takeover": took_over}
    await _audit_update(db, run_id, {"state": STATE_RUNNING,
                                     "started_at": started_at,
                                     **({"lock_takeover": took_over}
                                        if took_over else {})})
    try:
        result = await _run_guarded(db, operation, run_id, mode)
    except Exception as exc:
        patch = {"state": STATE_FAILED, "completed_at": _iso(_now()),
                 "failure": type(exc).__name__,
                 "failure_detail": str(exc)[:300]}
        await _audit_update(db, run_id, patch)
        await _release(db, operation, run_id)
        return {**base, "started_at": started_at, **patch}
    finally:
        await _release(db, operation, run_id)

    patch = {"state": STATE_COMPLETED, "completed_at": _iso(_now()),
             "result": result}
    await _audit_update(db, run_id, patch)
    return {**base, "started_at": started_at, **patch}


async def recent_runs(db, *, limit: int = 20) -> List[Dict[str, Any]]:
    cur = db[RUNS].find({}, {"_id": 0}).sort("requested_at", -1).limit(
        max(1, min(int(limit), 100)))
    return [doc async for doc in cur]
