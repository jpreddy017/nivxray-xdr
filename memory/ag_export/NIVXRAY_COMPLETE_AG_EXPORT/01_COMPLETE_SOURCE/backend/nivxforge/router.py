"""NivXForge FastAPI router.

Post-Phase-0: this router IS mounted in `server.py` under `/api`, so
its routes live at `/api/nivxforge/*`. The mount is authorised by
ADR-0005 (read-only Preview endpoints only). Write endpoints require
a separate ADR.

Every route MUST start with `/nivxforge` so all routes land at
`/api/nivxforge/*` when the enclosing app router is mounted at `/api`.
"""

from __future__ import annotations

from fastapi import APIRouter

from nivxforge.config import FORGE_ROUTE_PREFIX
from nivxforge.preview.router import router as preview_router


router = APIRouter(prefix=FORGE_ROUTE_PREFIX, tags=["nivxforge"])


@router.get("/health")
def health() -> dict:
    """Health probe — reflects post-Phase-0 status.

    Returns a static payload; any I/O here would violate the read-only
    Preview boundary.
    """
    return {"status": "ok", "package": "nivxforge", "phase": 0, "mount": "read-only-preview"}


# ADR-0005 · mount the read-only Preview subrouter under /nivxforge/preview/*
router.include_router(preview_router)
