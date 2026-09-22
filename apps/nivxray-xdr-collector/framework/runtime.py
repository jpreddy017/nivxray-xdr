"""
CollectorRuntime · Phase B.5.

Owns the collection→outbox→delivery pipeline:

    transport → deliver() → dedup → Outbox.record() → DeliveryWorker

The runtime never claims an event is delivered; only the delivery
worker does, and only after the ingest API returns 2xx.
"""
from __future__ import annotations

import platform
from typing import Any, List

from framework.base       import Connector, Envelope, Health
from framework.acquisition_state import AcquisitionState
from framework.dedup      import DedupCache
from framework.delivery   import IngestClient
from framework.delivery_worker import DeliveryWorker
from framework.m365_activity import M365ManagementActivityConnector
from framework.outbox     import Outbox
from framework.rest_poller import RestPollerConnector
from framework.scheduler  import PollerScheduler
from framework.syslog     import SyslogConnector, SyslogRunner
from framework.webhook    import WebhookConnector
from framework.windows_eventlog import WindowsEventLogConnector
from framework.identity import collector_id


class CollectorRuntime:
    def __init__(self) -> None:
        self.scheduler = PollerScheduler()
        self.syslog    = SyslogRunner()
        self.dedup     = DedupCache()
        self.outbox    = Outbox()
        self.ingest    = IngestClient()
        self.worker    = DeliveryWorker(self.outbox, self.ingest)
        # Durable acquisition state lives in the SAME store as the outbox,
        # so "the vendor gave it to us" and "the ingest accepted it" are
        # decided inside one durability boundary.
        self.acquisition = AcquisitionState(
            connection=self.outbox._conn)          # noqa: SLF001

    def reconcile_acquisition(self) -> dict:
        """Boot + post-delivery reconciliation: commit what was accepted and
        advance only the windows that are genuinely complete."""
        return self.acquisition.reconcile(self.outbox)

    # ── envelope pipeline ────────────────────────────────────
    async def deliver(self, conn: Connector, envs: List[Envelope]) -> None:
        """Enqueue envelopes to the durable outbox.  Delivery to the
        authoritative NivXRay ingest is handled by the delivery
        worker and NEVER reported synchronously as 'delivered'."""
        if not envs:
            return
        for e in envs:
            if e.source_event_id and self.dedup.seen(conn.identity, e.source_event_id):
                conn.metrics.events_duplicated += 1
                continue
            rid, status = self.outbox.record(e)
            conn.metrics.events_accepted += 1
        # An envelope in the outbox is QUEUED, not ACCEPTED. Reconcile so
        # that anything the ingest has since acknowledged can commit.
        if isinstance(conn, M365ManagementActivityConnector):
            self.acquisition.reconcile(self.outbox,
                                       tenant_id=conn.tenant_id,
                                       connector_id_=conn.identity)

    # ── Windows Event Log · Read → Make Durable → Advance ─────
    async def deliver_windows(self, conn: WindowsEventLogConnector,
                              envs: List[Envelope]) -> set:
        """Make the read durable and report WHICH channels are durable.

        The acquisition position may only advance for a channel whose
        records the outbox has accepted. A record the outbox already holds
        (same tenant + connector + source_event_id) is durable too — it is
        the same evidence, not a second one — so the channel still counts.
        """
        durable: set = set()
        for e in envs:
            channel = ((e.raw or {}).get("channel")
                       or (e.canonical or {}).get("channel"))
            if e.source_event_id and self.dedup.seen(conn.identity,
                                                     e.source_event_id):
                conn.metrics.events_duplicated += 1
                if channel:
                    durable.add(channel)
                continue
            rid, _status = self.outbox.record(e)
            if not rid:
                continue
            conn.metrics.events_accepted += 1
            if channel:
                durable.add(channel)
        return durable

    async def _start_windows_eventlog(self, conn: WindowsEventLogConnector
                                       ) -> dict:
        """The production acquisition lifecycle for this connector.

        configuration validation → schedule → Read → Make Durable →
        Advance Acquisition → (stop) → (restart → rehydrate → resume).

        Fail closed: a profile in which NO declared channel is collectible
        never starts, and the connector reports ERROR rather than a healthy
        subscription that can never read anything.
        """
        problems = conn.profile.validate()
        declared = list(conn.profile.channels)
        blocked = {p.get("channel") for p in problems if p.get("channel")}
        if not declared or blocked >= set(declared):
            conn.health = Health.ERROR
            conn.metrics.last_error = "no collectible channel in profile"
            return {"ok": False, "reason": "no_collectible_channel",
                    "collector_id": conn.collector_id,
                    "declared_channels": declared, "problems": problems}

        # G1/S3 · acquisition capability is decided BEFORE a subscription is
        # claimed. On Windows the native bindings are a hard requirement: a
        # connector that cannot bind `EvtSubscribe` can only ever acquire
        # zero events, and reporting that as CONNECTED is the exact silent
        # failure this gate removes. Fail closed instead.
        capability = conn.acquisition_capability()
        if platform.system() == "Windows" and not capability.get("bound"):
            conn.health = Health.ERROR
            conn.metrics.last_error = (
                f"{capability.get('code')}: {capability.get('reason')}")
            return {"ok": False, "reason": "native_binding_unavailable",
                    "collector_id": conn.collector_id,
                    "declared_channels": declared,
                    "acquisition_capability": capability}

        async def _on_envs(c: WindowsEventLogConnector,
                           envs: List[Envelope]) -> None:
            durable = await self.deliver_windows(c, envs)
            # A channel that read OK and returned nothing has no evidence at
            # risk, so its position may advance. A channel that failed to
            # read is NOT in this set and is therefore re-read.
            for channel, report in (c.channel_reports or {}).items():
                if report.get("state") == "READ_OK" \
                        and not report.get("events_read"):
                    durable.add(channel)
            c.advance(durable_channels=durable)

        def _on_error(c: WindowsEventLogConnector, exc: Exception) -> None:
            c.health = Health.ERROR
            c.metrics.last_error = f"{type(exc).__name__}: {exc}"

        await self.scheduler.start(conn, _on_envs, on_error=_on_error,
                                   always_callback=True)
        conn.health = Health.CONNECTED
        return {"ok": True, "mode": "eventlog-subscription",
                "collector_id": conn.collector_id,
                "declared_channels": declared,
                "channel_problems": problems,
                "acquisition_capability": capability,
                "durable_acquisition_state": True,
                "note": ("subscribed channels are read on the interval; a "
                         "position advances only after the outbox holds the "
                         "records")}

    # ── lifecycle ─────────────────────────────────────────────
    async def start(self, conn: Connector) -> dict:
        if isinstance(conn, WindowsEventLogConnector):
            return await self._start_windows_eventlog(conn)
        if isinstance(conn, M365ManagementActivityConnector):
            conn.attach_state(self.acquisition, self.outbox)
            self.reconcile_acquisition()
            await conn.start()

            async def _on_envs(c, envs): await self.deliver(c, envs)
            await self.scheduler.start(conn, _on_envs)
            return {"ok": True, "mode": "polling",
                    "durable_acquisition_state": True,
                    "subscriptions": conn.subscriptions_started}
        if isinstance(conn, RestPollerConnector):
            async def _on_envs(c, envs): await self.deliver(c, envs)
            await self.scheduler.start(conn, _on_envs)
            conn.health = Health.CONNECTED
            return {"ok": True, "mode": "polling"}
        if isinstance(conn, SyslogConnector):
            def _on_line(c, line, remote):
                env = c.envelope_from_line(line, remote=remote)
                c.metrics.events_collected += 1
                import asyncio
                asyncio.get_event_loop().create_task(self.deliver(c, [env]))
            return await self.syslog.start(conn, _on_line)
        if isinstance(conn, WebhookConnector):
            conn.health = Health.CONNECTED
            return {"ok": True, "mode": "webhook",
                     "note": "dispatched via HTTP route"}
        return {"ok": False,
                 "reason": f"unsupported_connector_kind:{type(conn).__name__}"}

    async def stop(self, conn: Connector) -> dict:
        if isinstance(conn, WindowsEventLogConnector):
            await self.scheduler.stop(conn.identity)
            conn.health = Health.DISCONNECTED
            return {"ok": True, "mode": "eventlog-subscription",
                    "collector_id": conn.collector_id,
                    "pending_bookmarks": list(conn._pending.keys())}
        if isinstance(conn, (RestPollerConnector,
                             M365ManagementActivityConnector)):
            await self.scheduler.stop(conn.identity)
            conn.health = Health.DISCONNECTED
            return {"ok": True}
        if isinstance(conn, SyslogConnector):
            r = await self.syslog.stop(conn.identity)
            conn.health = Health.DISCONNECTED
            return r
        if isinstance(conn, WebhookConnector):
            conn.health = Health.DISCONNECTED
            return {"ok": True}
        return {"ok": True}

    # ── delivery worker control ──────────────────────────────
    async def start_worker(self) -> None:
        await self.worker.start()

    async def stop_worker(self) -> None:
        await self.worker.stop()

    # ── test-plane inject ─────────────────────────────────────
    async def handle_inject(self, conn: Connector, payload: Any) -> List[Envelope]:
        envs: List[Envelope]
        if isinstance(conn, WebhookConnector):
            envs = conn.envelopes_from(payload)
        elif isinstance(conn, SyslogConnector):
            line = payload if isinstance(payload, str) else str(payload)
            envs = [conn.envelope_from_line(line, remote="inject")]
        elif isinstance(conn, RestPollerConnector):
            from framework.parsers import get_path, utcnow_iso
            eid = get_path(payload, conn.config.get("event_id_path") or "", default=None)
            ts  = get_path(payload, conn.config.get("timestamp_path") or "", default=None)
            envs = [Envelope(
                tenant_id            = conn.tenant_id,
                source               = conn.label,
                source_event_id      = str(eid) if eid is not None else None,
                connector_id         = conn.identity,
                collector_id         = collector_id(),
                collection_method    = "rest-poll",
                parser_version       = "phaseB.rest-poller.inject.1",
                source_timestamp     = str(ts) if ts else None,
                collection_timestamp = utcnow_iso(),
                event_type           = conn.source_type,
                raw                  = payload if isinstance(payload, dict) else {"value": payload},
                canonical            = {},
            )]
        else:
            envs = []
        conn.metrics.events_collected += len(envs)
        await self.deliver(conn, envs)
        return envs
