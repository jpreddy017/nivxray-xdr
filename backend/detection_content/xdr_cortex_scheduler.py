"""
Round 26.5b · Cortex Poller Scheduler.
======================================

Per-integration scheduled REST poller.  Consumes the Round 26
executor (single vault-backed path) and the Round 26.5 promotion
policy.  Never fabricates healthy state.

Locked invariants (owner · Round 26.5):
  · One integration → one active poll at a time (asyncio.Lock).
  * `poll_enabled=False` on the integration → scheduler skips it
    silently (no fake healthy tick).
  · Retry with capped exponential backoff (base 15s, max 15min);
    every attempt is audited.
  · Scheduler failure NEVER writes a green health signal.  It
    writes `outcome=FAILED · reason=<real reason>` to
    `xdr_cortex_scheduler_audit`.
  * On graceful shutdown all in-flight polls are awaited before
    the tasks are cancelled.

Storage:
  · `xdr_integrations` — reads `poll_enabled`, `poll_interval_seconds`.
  · `xdr_cortex_scheduler_audit` — append-only per-tick trail.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from typing import Optional

log = logging.getLogger("nivxray.xdr.cortex_scheduler")

INTEGRATIONS   = "xdr_integrations"
SCHED_AUDIT    = "xdr_cortex_scheduler_audit"
VENDOR         = "palo_alto_cortex_xdr"

DEFAULT_INTERVAL_SECONDS = 300     # 5-min default poll cadence
MIN_INTERVAL_SECONDS     = 30
BACKOFF_BASE             = 15
BACKOFF_MAX              = 900     # 15 minutes


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


class CortexPollerScheduler:
    """One instance per process.  Constructed at app startup; owns
    all per-integration asyncio locks + tasks."""

    def __init__(self, db) -> None:
        self._db = db
        self._locks: dict[str, asyncio.Lock] = {}
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    def _lock(self, integration_id: str) -> asyncio.Lock:
        if integration_id not in self._locks:
            self._locks[integration_id] = asyncio.Lock()
        return self._locks[integration_id]

    async def _audit(self, *, integration_id: str, outcome: str,
                          detail: Optional[str] = None,
                          rows_parsed: Optional[int] = None,
                          rows_inserted: Optional[int] = None,
                          rows_duplicate: Optional[int] = None,
                          attempt: int = 1,
                          backoff_seconds: Optional[int] = None) -> None:
        await self._db[SCHED_AUDIT].insert_one({
            "integration_id":  integration_id,
            "at":              _iso_now(),
            "outcome":         outcome,   # OK / SKIPPED / FAILED / DISABLED
            "detail":          detail,
            "rows_parsed":     rows_parsed,
            "rows_inserted":   rows_inserted,
            "rows_duplicate":  rows_duplicate,
            "attempt":         attempt,
            "backoff_seconds": backoff_seconds,
        })

    async def _tick_one(self, rec: dict) -> None:
        # Local import to avoid a cycle at module load.
        from routers.xdr_cortex_ingest_routes import cortex_poll   # noqa: WPS433

        integration_id = rec["integration_id"]
        if not rec.get("active"):
            return
        if rec.get("poll_enabled") is False:
            await self._audit(integration_id=integration_id,
                                  outcome="DISABLED",
                                  detail="poll_enabled=False")
            return
        interval = int(rec.get("poll_interval_seconds")
                             or DEFAULT_INTERVAL_SECONDS)
        interval = max(MIN_INTERVAL_SECONDS, interval)
        # Non-overlap.
        lock = self._lock(integration_id)
        if lock.locked():
            await self._audit(integration_id=integration_id,
                                  outcome="SKIPPED",
                                  detail="previous_poll_in_flight")
            return
        async with lock:
            # Direct call into the operator-triggered handler to
            # reuse the exact same code path.  The handler already
            # advances the checkpoint deterministically.
            try:
                result = await cortex_poll(integration_id, limit=100)
                await self._audit(integration_id=integration_id,
                                      outcome="OK",
                                      detail=result.get("checkpoint_advanced_to")
                                                and f"checkpoint→{result['checkpoint_advanced_to']}",
                                      rows_parsed=result.get("rows_parsed"),
                                      rows_inserted=result.get("rows_inserted"),
                                      rows_duplicate=result.get("rows_duplicate"))
            except Exception as e:                                 # noqa: BLE001
                # Backoff computation is per-attempt.  We DO NOT
                # mutate a "healthy" state on failure — the failure
                # is the state.
                attempt = 1 + int((rec.get("_poll_failures") or 0))
                backoff = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** (attempt - 1)))
                await self._audit(integration_id=integration_id,
                                      outcome="FAILED",
                                      detail=str(e),
                                      attempt=attempt,
                                      backoff_seconds=backoff)
                await self._db[INTEGRATIONS].update_one(
                    {"integration_id": integration_id, "vendor": VENDOR},
                    {"$set": {"_poll_failures": attempt,
                                 "_last_poll_error": str(e),
                                 "updated_at": _iso_now()}},
                )
                return
        # Reset failure counter on success.
        await self._db[INTEGRATIONS].update_one(
            {"integration_id": integration_id, "vendor": VENDOR},
            {"$set": {"_poll_failures": 0,
                          "_last_poll_success": _iso_now(),
                          "updated_at": _iso_now()},
              "$unset": {"_last_poll_error": ""}},
        )

    async def _due(self, rec: dict) -> bool:
        """Determine whether an integration is due for a poll.  A
        record with no prior success is always due; otherwise the
        cadence is `poll_interval_seconds` since the last success
        with backoff after failures."""
        interval = max(MIN_INTERVAL_SECONDS,
                            int(rec.get("poll_interval_seconds")
                                 or DEFAULT_INTERVAL_SECONDS))
        last = rec.get("_last_poll_success")
        if not last:
            return True
        try:
            last_dt = _dt.datetime.fromisoformat(last)
        except ValueError:
            return True
        now = _dt.datetime.now(_dt.timezone.utc)
        elapsed = (now - last_dt).total_seconds()
        failures = int(rec.get("_poll_failures") or 0)
        backoff  = 0 if failures == 0 else min(
            BACKOFF_MAX, BACKOFF_BASE * (2 ** (failures - 1)))
        return elapsed >= max(interval, backoff)

    async def _loop(self) -> None:
        log.info("cortex scheduler: loop started")
        try:
            while not self._stopping.is_set():
                try:
                    cursor = self._db[INTEGRATIONS].find(
                        {"vendor": VENDOR, "active": True}, {"_id": 0})
                    async for rec in cursor:
                        if self._stopping.is_set():
                            break
                        if await self._due(rec):
                            # Fire-and-forget the tick to keep the
                            # scheduler loop non-blocking; each tick
                            # is guarded by the per-integration lock.
                            asyncio.create_task(self._tick_one(rec))
                except Exception as e:                              # noqa: BLE001
                    log.warning("cortex scheduler: loop error (%s)", e)
                try:
                    await asyncio.wait_for(self._stopping.wait(),
                                                    timeout=15)
                except asyncio.TimeoutError:
                    pass
        finally:
            log.info("cortex scheduler: loop stopped")

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=30)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None


_SCHEDULER_SINGLETON: Optional[CortexPollerScheduler] = None


def get_scheduler(db) -> CortexPollerScheduler:
    global _SCHEDULER_SINGLETON                                    # noqa: PLW0603
    if _SCHEDULER_SINGLETON is None:
        _SCHEDULER_SINGLETON = CortexPollerScheduler(db)
    return _SCHEDULER_SINGLETON
