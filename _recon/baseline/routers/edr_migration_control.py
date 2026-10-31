"""Admin-only migration control surface.

Three routes, no database console. The caller names a compiled operation and a
mode; everything else — collection, index specifications, every query — lives in
`edr_plane.migration_control`. Authentication and authorization reuse the
platform's existing admin principal (`deps.require_admin`), so there is no new
auth logic here and no credential input or output anywhere.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from deps import db, require_admin
from edr_plane import migration_control as mc

router = APIRouter(prefix="/internal/admin/migrations",
                   tags=["internal-admin-migrations"])


class MigrationRequest(BaseModel):
    """The ENTIRE caller-controlled surface: a mode. Nothing else is accepted."""
    model_config = {"extra": "forbid"}
    mode: str = Field(default=mc.MODE_REPORT)


def _actor(user: Dict[str, Any]) -> str:
    return str(user.get("email") or user.get("sub") or "unknown-admin")


@router.get("")
async def list_migrations(limit: int = Query(20, ge=1, le=100),
                          user=Depends(require_admin)):
    """What may be run, and what has been run. No secrets, no connection info."""
    return {"allowed_operations": mc.allowed_operations(),
            "modes": list(mc.MODES),
            "runs": await mc.recent_runs(db, limit=limit)}


@router.post("/ensure-canonical-identity-indexes")
async def ensure_canonical_identity_indexes(
        body: Optional[MigrationRequest] = None, user=Depends(require_admin)):
    """Ensure the two declared target canonical §d indexes. Idempotent."""
    return await _run(mc.OP_ENSURE_IDENTITY_INDEXES,
                      (body or MigrationRequest()).mode, user)


@router.post("/{operation}")
async def run_named_migration(operation: str,
                              body: Optional[MigrationRequest] = None,
                              user=Depends(require_admin)):
    """Run a REGISTERED operation. An unknown name is refused and audited."""
    return await _run(operation, (body or MigrationRequest()).mode, user)


async def _run(operation: str, mode: str, user: Dict[str, Any]):
    record = await mc.run_migration(db, operation=operation, mode=mode,
                                    actor=_actor(user))
    if record["state"] == mc.STATE_REFUSED:
        status = 409 if record["refusal_reason"] == mc.REFUSED_CONCURRENT else 400
        raise HTTPException(status_code=status, detail=record)
    if record["state"] == mc.STATE_FAILED:
        raise HTTPException(status_code=500, detail=record)
    return record
