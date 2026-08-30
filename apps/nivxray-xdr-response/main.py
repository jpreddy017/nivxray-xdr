"""
NivXRay XDR Response Engine · main entrypoint.

Standalone, independently-deployable FastAPI service that owns the
RESPONSE plane.  Boundary:

    ┌────────────────────────────────────────────────┐
    │  Response Engine (this repo/app)               │
    │    · Response Action Registry                  │
    │    · Action Adapters (stubs, then Phase C)     │
    │    · Persisted execution state machine         │
    │    · Approval store · Target resolver          │
    │    · Evidence Forwarder → base NivXRay backend │
    └────────────────────────────────────────────────┘
                     │  evidence / audit / timeline
                     ▼
    ┌────────────────────────────────────────────────┐
    │  Base NivXRay backend (authoritative)          │
    │    · SSOT · Verdict · IKG · Investigation      │
    │    · Evidence · Timeline                       │
    └────────────────────────────────────────────────┘
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi                 import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from framework.registry        import ActionRegistry
from framework.execution_store import ExecutionStore
from framework.forwarder       import EvidenceForwarder
from framework.executor        import Executor

from routes.execute    import router as execute_router
from routes.executions import router as executions_router
from routes.actions    import router as actions_router
from routes.approvals  import router as approvals_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dedicated Response Engine DB — never shared with the Collector.
    default_dir = os.path.join(os.path.dirname(__file__), "data")
    state_dir   = os.environ.get("XDR_RESPOND_STATE_DIR") or default_dir
    app.state.registry  = ActionRegistry.default()
    app.state.store     = ExecutionStore(path=state_dir)
    app.state.forwarder = EvidenceForwarder()
    app.state.executor  = Executor(
        registry=app.state.registry,
        store=app.state.store,
        forwarder=app.state.forwarder,
    )
    yield
    try:    app.state.store.close()
    except Exception: pass


app = FastAPI(
    title="NivXRay XDR Response Engine",
    version="0.2.0-integration",
    description="Response plane · persisted execution state machine + approval "
                    "workflow.  Forwards evidence/audit/timeline into the authoritative "
                    "NivXRay backend.  Never manipulates SSOT/Verdict/IKG directly.",
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
app.include_router(approvals_router,  prefix="/api/respond")


@app.get("/health")
def liveness():
    return {
        "status":     "ok",
        "service":    "nivxray-xdr-response",
        "version":    "0.2.0-integration",
        "actions":    len(app.state.registry.list()) if hasattr(app.state, "registry") else 0,
        "forwarder":  app.state.forwarder.status()  if hasattr(app.state, "forwarder") else None,
        "executions": app.state.store.metrics()     if hasattr(app.state, "store") else None,
    }


@app.get("/")
def root():
    return {
        "service":  "nivxray-xdr-response",
        "docs":     "/docs",
        "boundary": "response execution · forwards evidence to authoritative NivXRay",
    }
