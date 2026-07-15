"""Learning router — /api/learning/*.

Endpoints
---------
POST /api/learning/boost      body {raw}                  → boost decision + transparency
POST /api/learning/feedback   body {chain[], up:bool}     → record thumbs vote
GET  /api/learning/stats                                  → per-user feedback + auto counters
POST /api/learning/correction body {input, engine_*, corrected_*}
                                                          → analyst correction event
GET  /api/learning/corrections/recent?limit=50            → last N corrections
GET  /api/learning/corrections/summary                    → aggregate stats
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import get_current_user, db
from learning.booster import boost
from learning.feedback import record_vote, get_stats
from reasoning import learning as reasoning_learning

router = APIRouter()


class BoostIn(BaseModel):
    raw: str = Field(..., description="Raw / obfuscated command line")


class FeedbackIn(BaseModel):
    chain: List[str]
    up: bool = True


class CorrectionIn(BaseModel):
    input: str = Field(..., description="Original obfuscated input")
    engine_output: str = Field(..., description="What NivXRay produced")
    engine_chain: List[Dict[str, Any]] = Field(default_factory=list)
    engine_confidence: Optional[float] = None
    engine_reasoning: Optional[Dict[str, Any]] = None
    corrected_output: str = Field(..., description="Analyst's corrected plaintext")
    corrected_chain: Optional[List[Dict[str, Any]]] = None
    corrected_confidence: Optional[float] = None
    notes: Optional[str] = None


@router.post("/learning/boost", tags=["learning"])
async def boost_endpoint(body: BoostIn, user=Depends(get_current_user)):
    return await boost(body.raw, user["email"])


@router.post("/learning/feedback", tags=["learning"])
async def feedback_endpoint(body: FeedbackIn, user=Depends(get_current_user)):
    return await record_vote(user["email"], body.chain, up=bool(body.up))


@router.get("/learning/stats", tags=["learning"])
async def stats_endpoint(user=Depends(get_current_user)):
    return await get_stats(user["email"])


# ── Analyst-correction feedback loop (Feb-2026 learning framework) ────
@router.post("/learning/correction", tags=["learning"])
async def correction_endpoint(body: CorrectionIn, user=Depends(get_current_user)):
    """Record an analyst correction — engine got it wrong, this is the truth.

    Stored in the `learning_events` MongoDB collection with the input's
    characterization profile so we can tune reasoning heuristics later.
    """
    event = await reasoning_learning.record_correction(
        db,
        input_text=body.input,
        engine_output=body.engine_output,
        engine_chain=body.engine_chain,
        engine_confidence=body.engine_confidence,
        engine_reasoning=body.engine_reasoning,
        corrected_output=body.corrected_output,
        corrected_chain=body.corrected_chain,
        corrected_confidence=body.corrected_confidence,
        analyst_id=user.get("email"),
        notes=body.notes,
    )
    return {"ok": True, "event": event}


@router.get("/learning/corrections/recent", tags=["learning"])
async def corrections_recent(
    limit: int = 50, user=Depends(get_current_user),
):
    limit = max(1, min(limit, 200))
    events = await reasoning_learning.list_recent(db, limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/learning/corrections/summary", tags=["learning"])
async def corrections_summary(user=Depends(get_current_user)):
    return await reasoning_learning.summary(db)
