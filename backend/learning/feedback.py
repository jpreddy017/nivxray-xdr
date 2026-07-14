"""Feedback recorder — persist thumbs-up-down + auto-record success signals.

Storage: single MongoDB doc per user in `learning_feedback` collection.

Shape:
    {
      "_id": "<user_email>",
      "up_votes":   { "<chain-key>": <count>, ... },
      "down_votes": { "<chain-key>": <count>, ... },
      "auto_success": { "<chain-key>": <count>, ... },     # bumped when a boosted chain wins
      "auto_failure": { "<chain-key>": <count>, ... },     # bumped when a boosted chain misses
      "last_updated": "<iso ts>"
    }
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional

from deps import db


def _chain_key(chain: List[str]) -> str:
    return " → ".join(chain or [])


async def record_vote(user_email: str, chain: List[str], up: bool = True) -> dict:
    key = _chain_key(chain)
    if not key:
        return {"updated": False, "reason": "empty chain"}
    field = "up_votes" if up else "down_votes"
    now = datetime.now(timezone.utc).isoformat()
    await db.learning_feedback.update_one(
        {"_id": user_email},
        {"$inc": {f"{field}.{key}": 1},
         "$set": {"last_updated": now}},
        upsert=True,
    )
    doc = await db.learning_feedback.find_one({"_id": user_email}) or {}
    return {
        "updated": True,
        "chain": chain,
        "current_up":   int((doc.get("up_votes")   or {}).get(key, 0)),
        "current_down": int((doc.get("down_votes") or {}).get(key, 0)),
    }


async def record_auto(user_email: str, chain: List[str], success: bool = True) -> None:
    """Fire-and-forget — bump the auto success/failure counter for the boosted chain."""
    key = _chain_key(chain)
    if not key:
        return
    field = "auto_success" if success else "auto_failure"
    try:
        await db.learning_feedback.update_one(
            {"_id": user_email},
            {"$inc": {f"{field}.{key}": 1}},
            upsert=True,
        )
    except Exception:
        pass   # never block a decode


async def get_stats(user_email: str) -> dict:
    doc = await db.learning_feedback.find_one({"_id": user_email}) or {}
    return {
        "user_email":  user_email,
        "up_votes":    doc.get("up_votes") or {},
        "down_votes":  doc.get("down_votes") or {},
        "auto_success": doc.get("auto_success") or {},
        "auto_failure": doc.get("auto_failure") or {},
        "last_updated": doc.get("last_updated"),
    }
