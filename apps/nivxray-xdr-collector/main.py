"""
NivXRay XDR Collector Service · Phase A skeleton
================================================

Independently deployable FastAPI service that owns the *collection
and transport* plane for NivXRay XDR.  This service NEVER makes
security decisions — its job ends at "canonical envelope delivered
to the authoritative NivXRay ingestion API".

Architectural boundary (owner-locked):
  ┌──────────────────────────────────────────────────────────────┐
  │ NivXRay XDR Collector Service (this repo/app)                │
  │   • ConnectorRegistry / Connector interface                  │
  │   • Collector runtime (scheduling / retry / backpressure)    │
  │   • Health / checkpoint / provenance / dedup                 │
  │   • Inbound receivers: syslog, webhook                       │
  │   • Outbound pollers: REST / API                             │
  │   • Windows collection adapters (WEF / WinRM / WMI)          │
  │   • Vendor adapters (CrowdStrike / Defender / SentinelOne …) │
  └──────────────────────────────────────────────────────────────┘
                        │  canonical envelope  │
                        ▼                      ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Existing NivXRay backend (authoritative intelligence plane)  │
  │   • Canonical Evidence · SSOT · Verdict · IKG · Activity     │
  │   • Process Tree · Trajectory · Command · MITRE              │
  └──────────────────────────────────────────────────────────────┘

Deployment: not Vercel.  Ship as a Docker image + persistent process
runtime (fly.io / Cloud Run / Railway / bare Docker etc).
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.connectors      import router as connectors_router
from routes.collectors      import router as collectors_router
from routes.telemetry_health import router as telemetry_health_router
from routes.data_sources    import router as data_sources_router
from routes.webhooks        import router as webhooks_router
from framework.registry     import ConnectorRegistry

app = FastAPI(
    title="NivXRay XDR Collector",
    version="0.1.0-phaseA",
    description="Native collection / transport plane for NivXRay XDR.  "
                    "This service does NOT compute verdicts, correlations, "
                    "or investigation intelligence — those remain "
                    "authoritative in the existing NivXRay backend.",
    docs_url="/docs",
    redoc_url=None,
)

# CORS — the XDR Vercel frontend is the only intended browser client.
# In production, restrict via an explicit allow-list env var; wide-open
# CORS is a deployment-time misconfiguration, not a Phase-A default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # tighten per-deployment via env
    allow_methods=["GET","POST"],
    allow_headers=["*"],
)

# Boot the singleton connector registry.  Vendor connectors are NOT
# registered in Phase A — the registry is empty by design so the UI
# renders honest NOT CONNECTED / NEVER CONNECTED states.  Vendor
# adapters land in Phases B/C/D.
app.state.registry = ConnectorRegistry()

app.include_router(connectors_router,       prefix="/api/xdr")
app.include_router(collectors_router,       prefix="/api/xdr")
app.include_router(telemetry_health_router, prefix="/api/xdr")
app.include_router(data_sources_router,     prefix="/api/xdr")
app.include_router(webhooks_router,         prefix="/api/xdr")


@app.get("/health")
def liveness():
    """Liveness probe.  Never touches downstream systems."""
    return {"status": "ok", "service": "nivxray-xdr-collector",
              "phase":  "A",  "connectors_registered": len(app.state.registry.list_ids())}


@app.get("/")
def root():
    return {
        "service": "nivxray-xdr-collector",
        "docs":    "/docs",
        "phase":   "A · framework only (no vendor adapters yet)",
        "boundary": "collection & transport only · never a security decision",
    }
