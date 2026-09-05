"""
NivXRay XDR Collector Service · Phase B
=======================================

Independently deployable FastAPI service that owns the **collection
and transport plane** for NivXRay XDR.  This service NEVER makes
security decisions — its responsibility ends at "canonical envelope
delivered to the authoritative NivXRay ingestion API".

Architectural boundary (owner-locked):
  ┌──────────────────────────────────────────────────────────────┐
  │ NivXRay XDR Collector Service (this repo/app)                │
  │   • Connector framework · Registry · Runtime                 │
  │   • Phase B transports: REST poller · Webhook · Syslog       │
  │   • Health · checkpoint · provenance · dedup                 │
  └──────────────────────────────────────────────────────────────┘
                        │  canonical envelope  │
                        ▼                      ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Existing NivXRay backend (authoritative intelligence plane)  │
  │   • Canonical Evidence · SSOT · Verdict · IKG · Activity     │
  │   • Process Tree · Trajectory · Command · MITRE              │
  └──────────────────────────────────────────────────────────────┘

Deployment: not Vercel.  Ship as a Docker image + persistent process.
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi                    import FastAPI
from fastapi.middleware.cors    import CORSMiddleware

from framework.registry     import ConnectorRegistry
from framework.runtime      import CollectorRuntime
from framework.store        import ConnectorStore
from framework.rest_poller  import RestPollerConnector
from framework.webhook      import WebhookConnector
from framework.syslog       import SyslogConnector

from routes.connectors       import router as connectors_router
from routes.collectors       import router as collectors_router
from routes.telemetry_health import router as telemetry_health_router
from routes.data_sources     import router as data_sources_router
from routes.webhooks         import router as webhooks_router
from routes.outbox           import router as outbox_router
from routes.preflight        import router as preflight_router


_CLASS_BY_TYPE = {
    "rest":    RestPollerConnector,
    "webhook": WebhookConnector,
    "syslog":  SyslogConnector,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Boot registry + store + runtime ────────────────────
    app.state.registry  = ConnectorRegistry()
    app.state.store     = ConnectorStore()
    app.state.runtime   = CollectorRuntime()
    app.state.instances = {}

    # Rehydrate persisted connectors and auto-start the enabled ones.
    for rec in app.state.store.list():
        cls = _CLASS_BY_TYPE.get(rec.source_type)
        if not cls:
            continue
        try:
            inst = cls(tenant_id=rec.tenant_id, config=rec.config,
                        identity=rec.id)
            app.state.instances[rec.id] = inst
            app.state.registry.register_instance(inst)
            if rec.enabled and os.environ.get("XDR_AUTO_START_CONNECTORS", "1") == "1":
                await app.state.runtime.start(inst)
        except Exception:                                       # noqa: BLE001
            # Refuse to crash boot on a single bad record; the API
            # will surface it as `not_started` for operator repair.
            continue

    # Start the delivery worker (drains outbox → ingest).  Test
    # environments can disable with XDR_DISABLE_DELIVERY_WORKER=1.
    if os.environ.get("XDR_DISABLE_DELIVERY_WORKER") != "1":
        await app.state.runtime.start_worker()

    yield

    # ── Graceful shutdown ─────────────────────────────────
    try:
        await app.state.runtime.stop_worker()
    except Exception:                                           # noqa: BLE001
        pass
    for inst in list(app.state.instances.values()):
        try:
            await app.state.runtime.stop(inst)
        except Exception:                                       # noqa: BLE001
            pass
    try:
        app.state.runtime.outbox.close()
    except Exception:                                           # noqa: BLE001
        pass


app = FastAPI(
    title="NivXRay XDR Collector",
    version="0.2.0-phaseB",
    description="Collection & transport plane for NivXRay XDR.  "
                    "Owns connectors (REST poller · Webhook · Syslog), "
                    "checkpointing, dedup, and forwarding to the "
                    "authoritative NivXRay ingestion API.  Never decides "
                    "verdicts, correlations, or investigation intelligence.",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

# CORS — the XDR Vercel frontend is the only intended browser client.
# In production, tighten via an explicit allow-list env var.
app.add_middleware(
    CORSMiddleware,
    allow_origins=(os.environ.get("XDR_CORS_ORIGINS") or "*").split(","),
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

app.include_router(connectors_router,       prefix="/api/xdr")
app.include_router(collectors_router,       prefix="/api/xdr")
app.include_router(telemetry_health_router, prefix="/api/xdr")
app.include_router(data_sources_router,     prefix="/api/xdr")
app.include_router(webhooks_router,         prefix="/api/xdr")
app.include_router(outbox_router,           prefix="/api/xdr")
app.include_router(preflight_router,        prefix="/api/xdr")


@app.get("/health")
def liveness():
    """Liveness probe.  Never touches downstream systems."""
    runtime = getattr(app.state, "runtime", None)
    running_rest    = len(runtime.scheduler.running())    if runtime else 0
    running_syslog  = len(runtime.syslog.running())       if runtime else 0
    outbox_metrics  = runtime.outbox.metrics()            if runtime else {}
    ingest_status   = runtime.ingest.status()             if runtime else {}
    worker_status   = runtime.worker.status()             if runtime else {}
    return {
        "status":         "ok",
        "service":        "nivxray-xdr-collector",
        "phase":          "B.5",
        "version":        "0.3.0-phaseB5",
        "connectors":     len(getattr(app.state, "instances", {})),
        "rest_running":   running_rest,
        "syslog_running": running_syslog,
        "ingest":         ingest_status,
        "outbox":         outbox_metrics,
        "worker":         worker_status,
    }


@app.get("/")
def root():
    return {
        "service":  "nivxray-xdr-collector",
        "docs":     "/docs",
        "phase":    "B · REST · Webhook · Syslog",
        "boundary": "collection & transport only · never a security decision",
    }
