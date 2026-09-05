"""Decoded Artifact Store API — P0.2

Endpoints (all under /api/v2/decoded-artifacts):
  GET  /stats/summary   — total artifacts, total reuses, avg layers, top hits
  GET  /                — recent artifacts (excludes full report body)
  GET  /{sha256}        — full artifact (includes AnalystReport dict)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user

from v2.decoded_artifacts import get_artifact, list_recent, stats

router = APIRouter(prefix="/v2/decoded-artifacts", tags=["decoded-artifacts"])


@router.get("/stats/summary")
async def artifact_stats(user=Depends(get_current_user)):
    s = await stats()
    return {"ok": True, **s}


@router.get("")
async def artifact_list(limit: int = 25, user=Depends(get_current_user)):
    limit = max(1, min(200, int(limit)))
    items = await list_recent(limit=limit)
    return {"ok": True, "count": len(items), "items": items}


@router.get("/{sha256}")
async def artifact_get(sha256: str, user=Depends(get_current_user)):
    doc = await get_artifact(sha256)
    if not doc:
        raise HTTPException(status_code=404, detail="artifact not found")
    return {"ok": True, "artifact": doc}
