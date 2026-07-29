"""NivXForge FastAPI router — DORMANT in Phase 0.

Decision A1 (approved Feb-2026): this router is defined but NOT
mounted in `server.py`. It exists so that Phase 0 tests can verify
prefix and isolation properties without introducing any runtime
integration with the Workspace application.

Every route MUST start with `/nivxforge` so that when eventually
mounted under `/api`, all routes live at `/api/nivxforge/*`.
"""

from __future__ import annotations

from fastapi import APIRouter

from nivxforge.config import FORGE_ROUTE_PREFIX


router = APIRouter(prefix=FORGE_ROUTE_PREFIX, tags=["nivxforge"])


@router.get("/health")
def health() -> dict:
    """Dormant health probe — reflects Phase 0 status only.

    Not wired into Workspace liveness. Returns a static payload; if this
    ever performs I/O it violates Phase 0 scope.
    """
    return {"status": "dormant", "package": "nivxforge", "phase": 0}
