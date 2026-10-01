"""Durable delivery worker · the permanent protocol.

    LOCAL JOURNAL DURABLE -> READY -> DISPATCHING -> BACKEND CLAIMED
      -> BACKEND DISPOSITION -> AUTHORITATIVE RECEIPT
      -> LOCAL RECEIPT VERIFIED -> DELIVERED

and, when the transport fails after the request may have reached the backend:

    DISPATCHING -> UNKNOWN_COMMIT_STATE -> RECONCILE(stable delivery_key)
      -> canonical evidence      -> DELIVERED / VERIFIED
      -> retained-raw (B4)       -> DELIVERED / VERIFIED (NOT canonical)
      -> proven absence          -> RETRYABLE
      -> authoritative refusal   -> TERMINAL_ACCOUNTED
      -> unavailable / ambiguous -> stays UNKNOWN_COMMIT_STATE

WHAT IS DIFFERENT FROM `DeliveryWorker`
    The legacy worker marks a row DELIVERED on HTTP 2xx. That is the exact
    correctness gap R5/R6 had to repair by hand: 2xx proves the destination
    accepted a batch, not that the authoritative plane committed and evidenced
    this delivery. Here a 2xx only moves the row to UNKNOWN_COMMIT_STATE; the
    row becomes DELIVERED only after a verified authoritative receipt.
    `DeliveryWorker` is kept unchanged for the legacy path and is not used by
    this protocol.

WHAT THIS WORKER NEVER DOES
    it never marks a row delivered without a verified receipt . it never
    retries a delivery whose commit state is unknown . it never re-issues a
    delivery identity . it never collapses retained raw into canonical
    evidence . it never bypasses the R3.1 delivery-health gate for delivery .
    it never touches the acquisition bookmark (acquisition advances only on
    `DELIVERED`, which now means receipt-verified).
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from framework import receipts
from framework.delivery import (CommitState, DeliveryClassification,
                                IngestClient, IngestOutcome)
from framework.health_gate import DeliveryHealthGate, GateState
from framework.identity import collector_id
from framework.outbox import Outbox, OutboxRow, OutboxStatus
from framework.receipt_client import ReceiptClient, ReceiptUnavailable

#: After this long a DISPATCHING row cannot still be in flight, so its commit
#: state is unknown and belongs to reconciliation. Must exceed the ingest
#: timeout by a wide margin.
DEFAULT_DISPATCH_LEASE_SECONDS = 300.0


class DurableDeliveryWorker:
    def __init__(self, outbox: Outbox, ingest: IngestClient,
                    receipt_client: Optional[ReceiptClient] = None, *,
                    batch_size: int = 50,
                    health_gate: Optional[DeliveryHealthGate] = None,
                    collector: Optional[str] = None,
                    poll_interval_seconds: float = 2.0,
                    dispatch_lease_seconds: float =
                        DEFAULT_DISPATCH_LEASE_SECONDS) -> None:
        self.outbox = outbox
        self.ingest = ingest
        self.receipts = receipt_client or ReceiptClient()
        self.batch_size = batch_size
        self.gate = health_gate or DeliveryHealthGate(store=outbox)
        self.collector = collector or collector_id()
        self.dispatch_lease_seconds = dispatch_lease_seconds
        self.interval = poll_interval_seconds
        self.ticks = 0
        self.tick_last_error: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self.verification_failures: List[Dict[str, Any]] = []

    # ── receipts ──────────────────────────────────────────────────────
    async def _receipts_for(self, rows: List[OutboxRow]
                            ) -> Dict[str, Dict[str, Any]]:
        """Verified receipts per local row id. Unanswered rows are absent.

        A verification failure is recorded and the row is simply left out, so
        a mismatched or unbindable disposition can never advance anything.
        """
        if not rows:
            return {}
        tenants = {r.tenant_id for r in rows}
        if len(tenants) != 1:
            raise ReceiptUnavailable(
                "one receipt request must speak about exactly one tenant")
        keys = {r.id: r.delivery_key or receipts.delivery_key_for_envelope(
            r.to_envelope()) for r in rows}
        identities = [receipts.identity_for(r, keys[r.id],
                                            collector_id=self.collector)
                      for r in rows]
        body = await self.receipts.fetch(tenant_id=next(iter(tenants)),
                                         identities=identities,
                                         collector=self.collector)
        authority = body.get("authority") or {}
        by_ref = {}
        for server_row in body.get("rows") or []:
            if isinstance(server_row, dict):
                by_ref[server_row.get("ref")] = server_row
        out: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            server_row = by_ref.get(row.id)
            if server_row is None:
                continue
            try:
                out[row.id] = receipts.verify(
                    row=row, key=keys[row.id],
                    expected_collector=self.collector,
                    authority=authority, server_row=server_row,
                    surface=self.receipts.url)
            except receipts.ReceiptVerificationError as ex:
                self.verification_failures.append(
                    {"ref": row.id, "reason": str(ex)})
        return out

    def _apply(self, row: OutboxRow, receipt: Dict[str, Any]) -> str:
        """One verified receipt -> one local transition. Never a guess."""
        action = receipt.get("local_action")
        if action == receipts.ACTION_DELIVERED:
            if not self.outbox.mark_receipt_verified(row.id, receipt):
                return "NOT_APPLIED"
            return receipts.ACTION_DELIVERED
        if action == receipts.ACTION_TERMINAL:
            self.outbox.mark_terminal_accounted(
                row.id, receipt,
                f"authoritative refusal: {receipt.get('disposition')}")
            return receipts.ACTION_TERMINAL
        if action == receipts.ACTION_RETRYABLE:
            # Absence is PROVEN, so a retry cannot duplicate evidence. It is a
            # real failed attempt, so it consumes the bounded retry budget
            # exactly like any other.
            status = self.outbox.mark_retry(
                row.id,
                error="authoritative absence: no claim, no retained raw and "
                      "no refusal exists for this delivery identity")
            if status == OutboxStatus.DEAD_LETTER:
                self.outbox.mark_dead(
                    row.id, error="retries exhausted after proven absence",
                    detail={"disposition": "RETRIES_EXHAUSTED",
                            "receipt_basis": receipt.get("basis")})
            return receipts.ACTION_RETRYABLE
        # SERVER_IN_PROGRESS / ACCOUNTED_WITHOUT_EVIDENCE / anything unknown.
        self.outbox.mark_unknown_commit(
            row.id, f"unresolved authoritative disposition: "
                    f"{receipt.get('disposition')}",
            detail={"local_action_basis": receipt.get("local_action_basis")})
        return receipts.ACTION_UNKNOWN

    async def _resolve(self, rows: List[OutboxRow]) -> Dict[str, Any]:
        """Fetch, verify and apply receipts for a bounded set of rows."""
        result = {"asked": len(rows), "receipted": 0,
                  receipts.ACTION_DELIVERED: 0, receipts.ACTION_RETRYABLE: 0,
                  receipts.ACTION_TERMINAL: 0, receipts.ACTION_UNKNOWN: 0,
                  "canonical": 0, "retained_raw": 0,
                  "verification_failures": 0, "receipt_error": None}
        if not rows:
            return result
        for row in rows:
            self.outbox.note_reconcile_attempt(row.id)
        before = len(self.verification_failures)
        try:
            verified = await self._receipts_for(rows)
        except ReceiptUnavailable as ex:
            # No authoritative answer: every row stays exactly where it is.
            result["receipt_error"] = str(ex)
            for row in rows:
                if row.status != OutboxStatus.UNKNOWN_COMMIT_STATE:
                    self.outbox.mark_unknown_commit(
                        row.id, f"receipt unavailable: {ex}")
            result[receipts.ACTION_UNKNOWN] = len(rows)
            return result
        result["receipted"] = len(verified)
        for row in rows:
            receipt = verified.get(row.id)
            if receipt is None:
                if row.status != OutboxStatus.UNKNOWN_COMMIT_STATE:
                    self.outbox.mark_unknown_commit(
                        row.id, "no authoritative disposition was returned "
                                "for this delivery identity")
                result[receipts.ACTION_UNKNOWN] += 1
                continue
            applied = self._apply(row, receipt)
            if applied in result:
                result[applied] += 1
            if applied == receipts.ACTION_DELIVERED:
                if receipt.get("canonical"):
                    result["canonical"] += 1
                elif receipt.get("retained_raw"):
                    result["retained_raw"] += 1
        result["verification_failures"] = len(self.verification_failures) - \
            before
        return result

    # ── the two runtime behaviours ───────────────────────────────────
    async def dispatch_once(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """Dispatch ready rows and resolve each one against the authority."""
        if not self.gate.allow_delivery():
            return {"dispatched": 0, "gate": self.gate.state,
                    "gate_skipped": True,
                    "seconds_until_probe": self.gate.seconds_until_probe()}
        probing = self.gate.state == GateState.HALF_OPEN
        size = limit or self.gate.probe_limit() or self.batch_size
        rows = self.outbox.next_batch(limit=size)
        if not rows:
            return {"dispatched": 0, "gate": self.gate.state}
        if probing:
            self.gate.note_probe()

        summary = {"dispatched": 0, "not_sent": 0, "awaiting_receipt": 0,
                   "gate": self.gate.state, "probe": probing,
                   receipts.ACTION_DELIVERED: 0,
                   receipts.ACTION_RETRYABLE: 0,
                   receipts.ACTION_TERMINAL: 0,
                   receipts.ACTION_UNKNOWN: 0,
                   "canonical": 0, "retained_raw": 0,
                   "verification_failures": 0}
        for index, row in enumerate(rows):
            envelope = row.to_envelope()
            key = row.delivery_key or receipts.delivery_key_for_envelope(
                envelope)
            self.outbox.set_delivery_key(row.id, key)
            self.outbox.mark_delivering([row.id])
            result = await self.ingest.deliver([envelope])
            summary["dispatched"] += 1
            commit = result.get("commit_state") or CommitState.UNKNOWN
            reason = str(result.get("reason") or result.get("classification")
                         or "")

            if commit == CommitState.NOT_SENT:
                # Provably never reached the application: no receipt is
                # needed and none is asked for. Ordinary bounded retry.
                self.gate.record_destination_failure(reason or "not_sent")
                status = self.outbox.mark_retry(
                    row.id, error=reason or "not sent",
                    detail=result.get("failure_detail"))
                if status == OutboxStatus.DEAD_LETTER:
                    detail = dict(result.get("failure_detail") or {})
                    detail["disposition"] = "RETRIES_EXHAUSTED"
                    self.outbox.mark_dead(
                        row.id, error=f"{reason} | retries exhausted",
                        detail=detail or None)
                summary["not_sent"] += 1
            else:
                # Sent. Until an authoritative receipt says otherwise the
                # commit state is unknown — including after a 2xx.
                self.outbox.mark_unknown_commit(
                    row.id,
                    f"dispatched, commit state {commit}: "
                    f"{reason or 'awaiting authoritative receipt'}",
                    detail=result.get("failure_detail"))
                summary["awaiting_receipt"] += 1
                fresh = self.outbox.by_id(row.id) or row
                resolved = await self._resolve([fresh])
                for field in (receipts.ACTION_DELIVERED,
                              receipts.ACTION_RETRYABLE,
                              receipts.ACTION_TERMINAL,
                              receipts.ACTION_UNKNOWN,
                              "canonical", "retained_raw",
                              "verification_failures"):
                    summary[field] += resolved.get(field, 0)
                if resolved.get(receipts.ACTION_DELIVERED):
                    self.gate.record_success()
                elif (commit == CommitState.TERMINAL_CLAIMED
                      or resolved.get(receipts.ACTION_TERMINAL)):
                    # The destination answered correctly ABOUT THIS EVENT, so
                    # it is healthy: bad events must not stall good ones.
                    if (result.get("classification")
                            == DeliveryClassification.AUTHORITATIVE_TERMINAL
                            or resolved.get(receipts.ACTION_TERMINAL)):
                        self.gate.record_event_refusal(reason or "refused")
                elif result.get("outcome") != IngestOutcome.OK:
                    self.gate.record_destination_failure(reason or "unknown")

            if self.gate.state == GateState.OPEN:
                remaining = [r.id for r in rows[index + 1:]]
                if remaining:
                    self.outbox.release_delivering(remaining)
                summary["stopped_on_open_gate"] = True
                break

        summary["gate"] = self.gate.state
        return summary

    async def reconcile_once(self, limit: Optional[int] = None
                             ) -> Dict[str, Any]:
        """Resolve every unresolved commit state against the authority.

        This is permanent runtime behaviour, not a recovery script: it runs on
        restart and on every tick, so nothing needs an analyst or manual SQL.
        It is READ-ONLY on the server side, consumes no delivery budget and
        therefore runs even while the delivery-health gate is OPEN.
        """
        size = limit or self.batch_size
        rows = self.outbox.rows_by_status(
            OutboxStatus.UNKNOWN_COMMIT_STATE, limit=size)
        stale = self.outbox.stale_dispatching(self.dispatch_lease_seconds,
                                              limit=max(0, size - len(rows)))
        seen = {r.id for r in rows}
        rows.extend(r for r in stale if r.id not in seen)
        resolved = await self._resolve(rows)
        resolved["stale_dispatching"] = len(stale)
        resolved["gate"] = self.gate.state
        resolved["note"] = ("reconciliation is a read on the authoritative "
                            "plane: it spends no delivery budget and does not "
                            "bypass tenant or credential authority")
        return resolved

    async def tick_once(self) -> Dict[str, Any]:
        """Resolve what is unresolved FIRST, then dispatch what is ready."""
        reconciled = await self.reconcile_once()
        dispatched = await self.dispatch_once()
        return {"reconciled": reconciled, "dispatched": dispatched}

    # ── loop control (same shape as the legacy worker) ───────────────
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
            try:
                await self._task
            except (asyncio.CancelledError, Exception):        # noqa: BLE001
                pass
            self._task = None

    async def _loop(self) -> None:
        try:
            while not (self._stop_event and self._stop_event.is_set()):
                try:
                    self.ticks += 1
                    await self.tick_once()
                except Exception as ex:                        # noqa: BLE001
                    self.tick_last_error = f"{type(ex).__name__}: {ex}"
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            return

    def status(self) -> Dict[str, Any]:
        return {
            "protocol": "durable-delivery-receipt/1",
            "running": self.running(),
            "ticks": self.ticks,
            "last_tick_error": self.tick_last_error,
            "poll_interval": self.interval,
            "collector_id": self.collector,
            "batch_size": self.batch_size,
            "dispatch_lease_seconds": self.dispatch_lease_seconds,
            "health_gate": self.gate.status(),
            "receipt_surface": self.receipts.status(),
            "verification_failures": len(self.verification_failures),
            "invariant": ("no delivery is DELIVERED until an authoritative "
                          "backend disposition is durably evidenced and "
                          "locally verified"),
        }
