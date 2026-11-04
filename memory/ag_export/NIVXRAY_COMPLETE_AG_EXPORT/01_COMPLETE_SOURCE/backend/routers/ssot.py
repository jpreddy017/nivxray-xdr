"""R28.1 · Immutable SSOT dereference endpoint.

``GET /api/ssot/{investigation_id}`` returns the canonical SSOT bundle
addressable by content-hash so Workspace, History, Reports and future
AI consumers all reference the same immutable object.

Restore is Rendering (R28): this endpoint MUST NOT invoke any decoder,
classifier, AI enricher or preprocessor.  It only deserializes,
validates and returns.
"""
from __future__ import annotations
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user
from services.ssot_store import (
    load_ssot, project_artifact_trace,
)

router = APIRouter()


@router.get("/ssot/{investigation_id}")
async def get_ssot(investigation_id: str,
                   include_artifact_trace: bool = True,
                   user=Depends(get_current_user)) -> Dict[str, Any]:
    """Dereference an immutable SSOT record by investigation_id.

    Returns the canonical bundle + optional Artifact Trace projection.
    """
    ssot = load_ssot(investigation_id)
    if not ssot:
        raise HTTPException(status_code=404, detail="investigation_id not found")
    resp: Dict[str, Any] = {
        "investigation_id": ssot.get("investigation_id") or investigation_id,
        "checksum":         ssot.get("checksum"),
        "version":          ssot.get("version"),
        "ssot":             ssot,
    }
    if include_artifact_trace:
        resp["artifact_trace"] = project_artifact_trace(ssot)
    return resp
