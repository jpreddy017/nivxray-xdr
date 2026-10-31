"""`POST /api/decode/mitigations` — deterministic Mitigation
Recommendations for an analyst input.

Body: `{ "input": "<paste>" }` — the exact same input the analyst
gave to `/api/decode/smart`.  Returns the mitigation payload from
`services.mitigation.derive_mitigations` (schema documented there).
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from analysis_core       import deterministic_best_decode
from services.mitigation import derive_mitigations

router = APIRouter(prefix="/decode", tags=["decode"])


class _MitigationRequest(BaseModel):
    input: str = Field(..., description="Raw analyst input to decode")


@router.post("/mitigations")
def post_mitigations(body: _MitigationRequest) -> Dict[str, Any]:
    text = (body.input or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="empty input")
    # Re-use the exact deterministic decode the workspace already
    # runs — no duplicate work, no LLM.
    try:
        decode_result = deterministic_best_decode(text)
    except Exception as e:
        raise HTTPException(status_code=500,
                              detail=f"decode failed: {e}") from e
    mit = derive_mitigations(decode_result)
    return {
        "ok":         True,
        "mitigation": mit,
    }
