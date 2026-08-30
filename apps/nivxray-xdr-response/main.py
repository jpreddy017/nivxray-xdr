"""
NivXRay XDR Response Engine · Phase 1

Standalone, independently-deployable FastAPI service that owns the
RESPONSE plane.  Boundary:

    ┌────────────────────────────────────────────────┐
    │  Response Engine (this repo/app)               │
    │    · Response Action Registry                  │
    │    · Action Adapters (stubs, then Phase C)     │
    │    · Idempotency / execution state             │
    │    · Approval resolver · Target resolver       │
    │    · Evidence Forwarder → base NivXRay backend │
    └────────────────────────────────────────────────┘
                     │  evidence / audit / timeline
                     ▼
    ┌────────────────────────────────────────────────┐
    │  Base NivXRay backend (authoritative)          │
    │    · SSOT · Verdict · IKG · Investigation      │
    │    · Evidence · Timeline                       │
    └────────────────────────────────────────────────┘

Owner-locked invariants:
  • Every completed execution produces evidence_ref + audit_ref +
    timeline_ref.  If any of those cannot be written, the execution
    fails.
  • This service does NOT read/write SSOT / Verdict / IKG / incident
    state.  It communicates outcomes back through the defined
    Response → Base evidence contract (RESPONSE_INGEST_CONTRACT.md).
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi                 import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from framework.registry     import ActionRegistry
from framework.idempotency  import IdempotencyStore
from framework.forwarder    import EvidenceForwarder
from framework.executor     import Executor

from routes.execute    import router as execute_router
from routes.executions import router as executions_router
from routes.actions    import router as actions_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.registry    = ActionRegistry.default()
    app.state.idempotency = IdempotencyStore()
    app.state.forwarder   = EvidenceForwarder()
    app.state.executor    = Executor(
        registry=app.state.registry,
        idempotency=app.state.idempotency,
        forwarder=app.state.forwarder,
    )
    yield
    try:    app.state.idempotency.close()
    except Exception: pass


app = FastAPI(
    title="NivXRay XDR Response Engine",
    version="0.1.0-phase1",
    description="Response plane · owns action execution and forwards "
                    "evidence/audit/timeline into the authoritative NivXRay "
                    "backend.  Never manipulates SSOT/Verdict/IKG directly.",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=(os.environ.get("XDR_RESPOND_CORS_ORIGINS") or "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(execute_router,    prefix="/api/respond")
app.include_router(executions_router, prefix="/api/respond")
app.include_router(actions_router,    prefix="/api/respond")


@app.get("/health")
def liveness():
    runtime  = getattr(app.state, "executor", None)
    forwarder = getattr(app.state, "forwarder", None)
    return {
        "status":     "ok",
        "service":    "nivxray-xdr-response",
        "phase":      "1",
        "version":    "0.1.0-phase1",
        "actions":    len(app.state.registry.list()) if hasattr(app.state, "registry") else 0,
        "forwarder":  forwarder.status() if forwarder else None,
        "executions": app.state.idempotency.metrics() if hasattr(app.state, "idempotency") else None,
    }


@app.get("/")
def root():
    return {
        "service":  "nivxray-xdr-response",
        "docs":     "/docs",
        "boundary": "response execution · forwards evidence to authoritative NivXRay",
    }
