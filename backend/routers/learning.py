"""Learning router — /api/learning/*.

Endpoints
---------
POST /api/learning/boost      body {raw}                  → boost decision + transparency
POST /api/learning/feedback   body {chain[], up:bool}     → record thumbs vote
GET  /api/learning/stats                                  → per-user feedback + auto counters
"""
from __future__ import annotations
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import get_current_user
from learning.booster import boost
from learning.feedback import record_vote, get_stats

router = APIRouter()


class BoostIn(BaseModel):
    raw: str = Field(..., description="Raw / obfuscated command line")


class FeedbackIn(BaseModel):
    chain: List[str]
    up: bool = True


@router.post("/learning/boost", tags=["learning"])
async def boost_endpoint(body: BoostIn, user=Depends(get_current_user)):
    return await boost(body.raw, user["email"])


@router.post("/learning/feedback", tags=["learning"])
async def feedback_endpoint(body: FeedbackIn, user=Depends(get_current_user)):
    return await record_vote(user["email"], body.chain, up=bool(body.up))


@router.get("/learning/stats", tags=["learning"])
async def stats_endpoint(user=Depends(get_current_user)):
    return await get_stats(user["email"])
