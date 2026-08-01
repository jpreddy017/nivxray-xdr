"""Learning Engine HTTP surface.

Every consumer that wants to render "Learning Applied" or seed a summary
from analyst corpus calls one of these endpoints. Keeps the engine
callable from both the composer pipeline (in-process) and the frontend
(over HTTP).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user
from nivxforge.learning import fingerprint_cio, learning_context

router = APIRouter(prefix="/learning-engine", tags=["learning-engine"])


class ContextIn(BaseModel):
    cio: Dict[str, Any] = Field(..., description="Full CIO dict to fingerprint")
    surface: str = "summary"
    limit: int = 5


@router.post("/context")
async def context_endpoint(body: ContextIn, user=Depends(get_current_user)):
    """Return the LearningContext for the given CIO."""
    ctx = await learning_context(body.cio, surface=body.surface, limit=body.limit)
    return ctx.to_dict()


class FingerprintIn(BaseModel):
    cio: Dict[str, Any]


@router.post("/fingerprint")
async def fingerprint_endpoint(body: FingerprintIn, user=Depends(get_current_user)):
    """Return the deterministic fingerprint for the given CIO."""
    fp = fingerprint_cio(body.cio)
    return fp.to_dict()
