"""Decoded Artifact Store API — P0.2

Endpoints (all under /api/v2/decoded-artifacts):
  GET  /stats/summary   — total artifacts, total reuses, avg layers, top hits
  GET  /                — recent artifacts (excludes full report body)
  GET  /{sha256}        — full artifact (includes AnalystReport dict)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_current_user

from services.analysis_scope import resolve_analysis_owner

from v2.decoded_artifacts import get_artifact, list_recent, stats

router = APIRouter(prefix="/v2/decoded-artifacts", tags=["decoded-artifacts"])


@router.get("/stats/summary")
async def artifact_stats(request: Request, user=Depends(get_current_user)):
    owner = resolve_analysis_owner(request, user)
    s = await stats(tenant_id=owner.tenant_id)
    return {"ok": True, **s}


@router.get("")
async def artifact_list(request: Request, limit: int = 25, user=Depends(get_current_user)):
    limit = max(1, min(200, int(limit)))
    owner = resolve_analysis_owner(request, user)
    items = await list_recent(limit=limit, tenant_id=owner.tenant_id)
    return {"ok": True, "count": len(items), "items": items}


@router.get("/{sha256}")
async def artifact_get(sha256: str, request: Request, command_binary: str = "", user=Depends(get_current_user)):
    owner = resolve_analysis_owner(request, user)
    try:
        doc = await get_artifact(sha256, tenant_id=owner.tenant_id, command_binary=command_binary)
    except ValueError as exc:
        raise HTTPException(404, detail="artifact not found") from exc
    if not doc:
        raise HTTPException(status_code=404, detail="artifact not found")
    return {"ok": True, "artifact": doc}
