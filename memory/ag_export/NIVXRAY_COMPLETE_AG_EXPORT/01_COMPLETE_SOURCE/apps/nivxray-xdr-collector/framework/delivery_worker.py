"""
Delivery worker · Phase B.5.

One background asyncio task drains the outbox at `poll_interval_seconds`
cadence.  On each tick it:

  1. Pulls a batch of QUEUED / RETRYING rows whose `next_attempt_at`
     is in the past.
  2. Marks them DELIVERING.
  3. Sends the batch to the authoritative NivXRay ingest endpoint
     via `IngestClient`.
  4. Marks DELIVERED / RETRYING / DEAD_LETTER per the outcome.

The worker survives ingest outages and its own crashes — on restart
Outbox.__init__ resets DELIVERING → QUEUED so the batch is retried
against an idempotent ingest endpoint.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from framework.delivery import IngestClient, IngestOutcome
from framework.outbox   import Outbox, OutboxRow


class DeliveryWorker:
    def __init__(self, outbox: Outbox, ingest: IngestClient,
                    batch_size: int = 50,
                    poll_interval_seconds: float = 2.0) -> None:
        self.outbox     = outbox
        self.ingest     = ingest
        self.batch_size = batch_size
        self.interval   = poll_interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self.ticks         = 0
        self.tick_last_at: Optional[str] = None
        self.tick_last_error: Optional[str] = None

    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.running():
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._stop_event:
            self._stop_event.set()
        if self._task:
            self._task.cancel()
            try:     await self._task
            except (asyncio.CancelledError, Exception): pass
            self._task = None

    async def tick_once(self) -> dict:
        """Run a single drain cycle.  Exposed so tests can advance the
        worker deterministically."""
        return await self._drain_batch()

    async def _loop(self) -> None:
        try:
            while not (self._stop_event and self._stop_event.is_set()):
                try:
                    await self._drain_batch()
                except Exception as e:                          # noqa: BLE001
                    self.tick_last_error = f"{type(e).__name__}: {e}"
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            return

    async def _drain_batch(self) -> dict:
        import datetime as _dt
        rows = self.outbox.next_batch(limit=self.batch_size)
        self.ticks += 1
        self.tick_last_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        if not rows:
            return {"ticks": self.ticks, "drained": 0}

        ids = [r.id for r in rows]
        self.outbox.mark_delivering(ids)

        # Send envelopes.  Phase B.5 delivers per-row so per-row
        # status is authoritative; batch optimisation lands in Phase C.
        delivered_ids   = []
        retrying_counts = 0
        dead_counts     = 0
        for r in rows:
            env = r.to_envelope()
            result = await self.ingest.deliver([env])
            out    = result.get("outcome")
            if out == IngestOutcome.OK:
                delivered_ids.append(r.id)
            elif out == IngestOutcome.RETRYABLE:
                self.outbox.mark_retry(r.id,
                                            error=str(result.get("reason") or "retryable"))
                retrying_counts += 1
            else:  # FATAL
                self.outbox.mark_dead(r.id,
                                          error=str(result.get("reason") or "fatal"))
                dead_counts += 1
        if delivered_ids:
            self.outbox.mark_delivered(delivered_ids)
        return {"ticks":     self.ticks,
                 "drained":   len(rows),
                 "delivered": len(delivered_ids),
                 "retrying":  retrying_counts,
                 "dead":      dead_counts}

    def status(self) -> dict:
        return {
            "running":         self.running(),
            "ticks":           self.ticks,
            "last_tick_at":    self.tick_last_at,
            "last_tick_error": self.tick_last_error,
            "batch_size":      self.batch_size,
            "poll_interval":   self.interval,
        }
