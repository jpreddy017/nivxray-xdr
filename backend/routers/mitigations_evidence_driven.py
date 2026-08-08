"""``POST /api/decode/mitigations/evidence_driven`` — evidence-driven
recommendations for an analyst input.

Isolated from ``/api/decode/mitigations`` (legacy).  Consumers pick
either the legacy schema (``mitigation.schema_version: 1``) or the
evidence-driven schema (``schema_version: 2``) explicitly — the two
never mix on a single call.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from analysis_core       import deterministic_best_decode
from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations, is_engine_enabled,
)

router = APIRouter(prefix="/decode", tags=["decode"])


class _EDRRequest(BaseModel):
    input: str = Field(..., description="Raw analyst input to decode")


@router.post("/mitigations/evidence_driven")
def post_evidence_driven(body: _EDRRequest) -> Dict[str, Any]:
    text = (body.input or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="empty input")
    try:
        decode_result = deterministic_best_decode(text)
    except Exception as e:
        raise HTTPException(status_code=500,
                              detail=f"decode failed: {e}") from e
    edr = evidence_driven_recommendations(decode_result)
    return {
        "ok":                       True,
        "engine_enabled":           is_engine_enabled(),
        "evidence_recommendations": edr,
    }
