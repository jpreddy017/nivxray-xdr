"""
Runtime · wraps scheduler + syslog listeners + dedup + delivery.

The Runtime is the ONLY object that touches:
  • the PollerScheduler (background asyncio tasks)
  • the SyslogRunner    (bound UDP/TCP servers)
  • the DedupCache      (per-connector event-id memory)
  • the IngestClient    (best-effort forwarder to authoritative NivXRay)

Route handlers never call these components directly.  This gives us a
single choke-point to add Phase B.5's durable outbox / DLQ / metrics
without rewriting the routes.
"""
from __future__ import annotations

from typing import Any, List

from framework.base       import Connector, Envelope, Health
from framework.dedup      import DedupCache
from framework.delivery   import IngestClient
from framework.scheduler  import PollerScheduler
from framework.syslog     import SyslogConnector, SyslogRunner
from framework.rest_poller import RestPollerConnector
from framework.webhook    import WebhookConnector


class CollectorRuntime:
    def __init__(self) -> None:
        self.scheduler = PollerScheduler()
        self.syslog    = SyslogRunner()
        self.dedup     = DedupCache()
        self.ingest    = IngestClient()

    # ── envelope pipeline ────────────────────────────────────
    async def deliver(self, conn: Connector, envs: List[Envelope]) -> None:
        if not envs:
            return
        fresh = []
        for e in envs:
            if e.source_event_id and self.dedup.seen(conn.identity, e.source_event_id):
                conn.metrics.events_duplicated += 1
                continue
            fresh.append(e)
        if not fresh:
            return
        result = await self.ingest.deliver(fresh)
        conn.metrics.events_accepted += result.get("delivered", 0)
        # Queued but not delivered is not a failure — Phase B.5 flushes.
        if not result.get("ok") and result.get("queued", 0) == 0:
            conn.metrics.events_failed += len(fresh)

    # ── lifecycle ─────────────────────────────────────────────
    async def start(self, conn: Connector) -> dict:
        if isinstance(conn, RestPollerConnector):
            async def _on_envs(c, envs): await self.deliver(c, envs)
            await self.scheduler.start(conn, _on_envs)
            conn.health = Health.CONNECTED
            return {"ok": True, "mode": "polling"}
        if isinstance(conn, SyslogConnector):
            def _on_line(c, line, remote):
                env = c.envelope_from_line(line, remote=remote)
                c.metrics.events_collected += 1
                # Schedule delivery on the running loop.
                import asyncio
                asyncio.get_event_loop().create_task(self.deliver(c, [env]))
            return await self.syslog.start(conn, _on_line)
        if isinstance(conn, WebhookConnector):
            # Webhooks are "always on" — no listener to start, they are
            # dispatched by the HTTP framework on inbound POST.
            conn.health = Health.CONNECTED
            return {"ok": True, "mode": "webhook", "note": "dispatched via HTTP route"}
        return {"ok": False, "reason": f"unsupported_connector_kind:{type(conn).__name__}"}

    async def stop(self, conn: Connector) -> dict:
        if isinstance(conn, RestPollerConnector):
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

    # ── test-plane inject ─────────────────────────────────────
    async def handle_inject(self, conn: Connector, payload: Any) -> List[Envelope]:
        envs: List[Envelope]
        if isinstance(conn, WebhookConnector):
            envs = conn.envelopes_from(payload)
        elif isinstance(conn, SyslogConnector):
            line = payload if isinstance(payload, str) else str(payload)
            envs = [conn.envelope_from_line(line, remote="inject")]
        elif isinstance(conn, RestPollerConnector):
            # Treat payload as one record already extracted.
            from framework.parsers import get_path, utcnow_iso
            eid = get_path(payload, conn.config.get("event_id_path") or "", default=None)
            ts  = get_path(payload, conn.config.get("timestamp_path") or "", default=None)
            envs = [Envelope(
                tenant_id            = conn.tenant_id,
                source               = conn.label,
                source_event_id      = str(eid) if eid is not None else None,
                connector_id         = conn.identity,
                collector_id         = "collector-local",
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
