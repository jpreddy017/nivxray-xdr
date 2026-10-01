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

from framework.delivery    import (DeliveryClassification, IngestClient,
                                   IngestOutcome)
from framework.health_gate import DeliveryHealthGate, GateState
from framework.outbox      import Outbox, OutboxRow, OutboxStatus


class DeliveryWorker:
    def __init__(self, outbox: Outbox, ingest: IngestClient,
                    batch_size: int = 50,
                    poll_interval_seconds: float = 2.0,
                    health_gate: Optional[DeliveryHealthGate] = None) -> None:
        self.outbox     = outbox
        self.ingest     = ingest
        self.batch_size = batch_size
        self.interval   = poll_interval_seconds
        #: G1-R3 · destination health, so a dead endpoint cannot consume every
        #: event's per-event retry budget. R3.1 · by default it is DURABLE in
        #: the outbox store, so a restart does not rediscover a known outage
        #: from CLOSED and burn another threshold of real attempts.
        self.gate       = health_gate or DeliveryHealthGate(store=outbox)
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
        self.ticks += 1
        self.tick_last_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

        # G1-R3 · while the destination is known-unavailable, claim nothing.
        # No row is touched, so no retry budget is consumed and nothing can be
        # stranded in DELIVERING.
        if not self.gate.allow_delivery():
            return {"ticks": self.ticks, "drained": 0, "delivered": 0,
                     "retrying": 0, "dead": 0,
                     "gate": self.gate.state,
                     "gate_skipped": True,
                     "seconds_until_probe": self.gate.seconds_until_probe()}

        probing = self.gate.state == GateState.HALF_OPEN
        limit = self.gate.probe_limit() or self.batch_size
        rows = self.outbox.next_batch(limit=limit)
        if not rows:
            return {"ticks": self.ticks, "drained": 0,
                     "gate": self.gate.state}
        if probing:
            self.gate.note_probe()

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
            classification = result.get("classification")
            if out == IngestOutcome.OK:
                delivered_ids.append(r.id)
                self.gate.record_success()
            elif out == IngestOutcome.RETRYABLE:
                reason = str(result.get("reason") or "retryable")
                detail = result.get("failure_detail")
                # R3: a retryable/unattributed failure is evidence about the
                # DESTINATION. Record it before touching the row, so a gate
                # that opens mid-batch stops the remaining attempts.
                self.gate.record_destination_failure(reason)
                new_status = self.outbox.mark_retry(r.id, error=reason,
                                                        detail=detail)
                if new_status == OutboxStatus.DEAD_LETTER:
                    # G1-R1: bounded retries were exhausted. That is a
                    # truthful terminal disposition and is NOT the same thing
                    # as an authoritative refusal — say so on the row.
                    exhausted = dict(detail or {})
                    exhausted["disposition"] = "RETRIES_EXHAUSTED"
                    self.outbox.mark_dead(
                        r.id, error=f"{reason} | retries exhausted",
                        detail=exhausted or None)
                    dead_counts += 1
                else:
                    retrying_counts += 1
                if self.gate.state == GateState.OPEN:
                    # Stop spending the rest of the batch on a destination we
                    # now know is unavailable. Unclaimed rows are released
                    # back to QUEUED, untouched and uncounted.
                    remaining = [row.id for row in rows
                                 if row.id not in delivered_ids
                                 and row.id != r.id]
                    if remaining:
                        self.outbox.release_delivering(remaining)
                    break
            else:  # FATAL — an application-attributed refusal only
                self.outbox.mark_dead(r.id,
                                          error=str(result.get("reason") or "fatal"),
                                          detail=result.get("failure_detail"))
                dead_counts += 1
                # The destination answered correctly about this event, so it is
                # healthy: a stream of bad events must not stall good ones.
                if classification == DeliveryClassification.AUTHORITATIVE_TERMINAL:
                    self.gate.record_event_refusal(
                        str(result.get("reason") or "fatal"))
        if delivered_ids:
            self.outbox.mark_delivered(delivered_ids)
        return {"ticks":     self.ticks,
                 "drained":   len(rows),
                 "delivered": len(delivered_ids),
                 "retrying":  retrying_counts,
                 "dead":      dead_counts,
                 "gate":      self.gate.state,
                 "probe":     probing}

    def status(self) -> dict:
        return {
            "running":         self.running(),
            "ticks":           self.ticks,
            "last_tick_at":    self.tick_last_at,
            "last_tick_error": self.tick_last_error,
            "batch_size":      self.batch_size,
            "poll_interval":   self.interval,
            "health_gate":     self.gate.status(),
        }
