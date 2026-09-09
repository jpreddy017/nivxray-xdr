"""P1.1 · Automated FileStore retention sweep (ADR-0010d).

Idempotent, single-worker asyncio background job that periodically
invokes :pymeth:`services.files.store.FileStore.sweep_expired`.

Design constraints (owner-locked 2026-08-11):

* **No naïve GridFS TTL** — a Mongo TTL index on ``fs.files`` leaves
  orphaned ``fs.chunks`` behind. We use an application-controlled
  sweep that deletes ``(GridFS object + chunks + index row)`` atomically
  from the store's perspective.
* **Pinned files survive** — ``FileStore.sweep_expired`` only touches
  rows whose ``pinned_cases`` list is empty.
* **Idempotent** — safe to run repeatedly; a re-issued sweep on the
  same corpus is a no-op.
* **Hot-reload safe** — guarded from double-firing on FastAPI reload
  by an import-scope singleton reference.
* **Fault-tolerant** — a sweep exception is logged and swallowed; the
  next tick still runs.
* **Multi-worker note** — at current single-worker scale no advisory
  lock is required. Documented residual limitation for P5.

Environment:

    NIVX_FILES_SWEEP_INTERVAL_S   # seconds between sweeps, default 86400
    NIVX_FILES_SWEEP_ENABLED      # "0" disables the loop entirely
"""
from __future__ import annotations
import asyncio
import logging
import os

log = logging.getLogger("nivx.files.retention_sweeper")

_task: asyncio.Task | None = None  # module-scope guard — hot-reload safe


def _interval_seconds() -> int:
    try:
        return max(60, int(os.environ.get("NIVX_FILES_SWEEP_INTERVAL_S", "86400")))
    except (TypeError, ValueError):
        return 86400


def _enabled() -> bool:
    return os.environ.get("NIVX_FILES_SWEEP_ENABLED", "1") not in ("0", "false", "False", "off")


async def _sweep_loop(store) -> None:
    interval = _interval_seconds()
    log.info(f"[files.retention] sweep loop armed · interval={interval}s")
    while True:
        try:
            await asyncio.sleep(interval)
            summary = await store.sweep_expired()
            log.info(f"[files.retention] sweep result: {summary}")
        except asyncio.CancelledError:
            log.info("[files.retention] sweep loop cancelled")
            raise
        except Exception as e:  # noqa: BLE001
            # Never let a sweep failure crash the API worker.
            log.warning(f"[files.retention] sweep failed: {type(e).__name__}: {e}")


def start_retention_sweeper(db) -> asyncio.Task | None:
    """Start the retention sweep background task.

    Idempotent: subsequent calls with an already-running task return
    the existing task without spawning a duplicate. Returns ``None``
    when sweeps are disabled by env.
    """
    global _task
    if not _enabled():
        log.info("[files.retention] sweep disabled by NIVX_FILES_SWEEP_ENABLED=0")
        return None
    if _task is not None and not _task.done():
        return _task
    from services.files.store import FileStore
    store = FileStore(db)
    loop = asyncio.get_event_loop()
    _task = loop.create_task(_sweep_loop(store), name="nivx-files-retention")
    return _task


async def stop_retention_sweeper() -> None:
    """Cancel the sweep task cleanly at application shutdown."""
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001
        pass
    _task = None
