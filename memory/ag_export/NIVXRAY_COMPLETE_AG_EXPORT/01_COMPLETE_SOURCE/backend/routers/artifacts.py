"""Artifact Intelligence Layer — public API.

Phase 3 · Cycle A · 2026-02.

Endpoints:
    GET  /api/artifacts/capabilities     — list registered analyzers + availability
    POST /api/artifacts/analyze          — dispatch bytes / history-id / base64 to
                                            the best-matching analyzer
"""
from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from services.artifact_intelligence import dispatch, registered_types
from deps import db, get_current_user

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])


class AnalyzeRequest(BaseModel):
    # One of the three fields below must be provided.
    bytes_b64:  Optional[str] = Field(default=None, description="Base64-encoded raw bytes")
    history_id: Optional[str] = Field(default=None, description="/api/history/{id} record to re-analyze")
    canonical_output: Optional[str] = Field(default=None, description="Latin-1 encoded canonical output from IEDDE")


@router.get("/capabilities")
async def capabilities(user=Depends(get_current_user)) -> Dict[str, Any]:
    """Introspection endpoint — which analyzers are registered and which
    have their parser library installed in this deployment."""
    return {"analyzers": registered_types()}


@router.post("/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(get_current_user)) -> Dict[str, Any]:
    """Route raw bytes to the best-matching artifact analyzer.

    Accepts three input modalities:
      • `bytes_b64`        — base64-encoded raw bytes (primary path)
      • `canonical_output` — latin-1 encoded IEDDE canonical output
      • `history_id`       — pull the binary artifact from a history row

    Always returns an `AnalysisResult.to_dict()` shape — never raises.
    """
    data: Optional[bytes] = None

    if req.bytes_b64:
        try:
            data = base64.b64decode(req.bytes_b64, validate=False)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid base64 in bytes_b64")

    elif req.canonical_output is not None:
        try:
            data = req.canonical_output.encode("latin-1", errors="replace")
        except Exception:
            raise HTTPException(status_code=400, detail="canonical_output not encodable as latin-1")

    elif req.history_id:
        row = await db.investigations.find_one({"id": req.history_id, "user": user["email"]})
        if not row:
            raise HTTPException(status_code=404, detail="history record not found")
        # Pull canonical output from either the top-level artifact or the
        # IEDDE trace.
        canonical = (
            (row.get("canonical_artifact") or {}).get("decoded_output")
            or ((row.get("iedde") or {}).get("canonical_output"))
            or row.get("output")
            or ""
        )
        data = str(canonical).encode("latin-1", errors="replace")

    else:
        raise HTTPException(
            status_code=400,
            detail="request must include one of `bytes_b64`, `canonical_output`, or `history_id`",
        )

    if not data:
        raise HTTPException(status_code=400, detail="empty payload after decoding")

    result = dispatch(data)
    return result.to_dict()
