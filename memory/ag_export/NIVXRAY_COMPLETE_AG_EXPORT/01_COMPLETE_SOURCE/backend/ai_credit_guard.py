"""
NivXRay — Credit-burn protection (v1.5.9)

Four defense layers against user-driven credit exhaustion:

 1. Per-user rate limits (10/hour, 50/day) on any AI endpoint.
 2. Global monthly budget cap — once tripped, AI endpoints return a
    graceful 429 with a clear message; deterministic buttons keep working.
 3. SHA1 response cache — same input → same output → 0 credits.
 4. Emergent-side spend cap — user configures in Profile → Universal Key.

Import `guard_ai_endpoint(user, endpoint_name, payload)` at the top of any
AI route. It raises HTTPException on limit, else awaits internal admission.
"""
from __future__ import annotations
import hashlib
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from fastapi import HTTPException

from deps import db

# ─── Configurable via .env ─────────────────────────────────────────────
RATE_HOURLY  = int(os.environ.get("NIVX_AI_RATE_HOURLY",  "10"))
RATE_DAILY   = int(os.environ.get("NIVX_AI_RATE_DAILY",   "50"))
BUDGET_CAP   = int(os.environ.get("NIVX_AI_BUDGET_CAP_CREDITS", "500"))  # per calendar month
CREDITS_PER  = {  # rough cost estimate per endpoint (credits × 100 = 0.01c precision)
    "ai_decode":         20,   # 0.2 credits
    "ai_describe":       40,   # 0.4
    "predict_tree":      30,   # 0.3
    "auto_investigate":  50,   # 0.5
    "learner_analyze":   30,
    "default":           20,
}


def _payload_sha1(payload: str) -> str:
    return hashlib.sha1((payload or "").encode("utf-8", errors="replace")).hexdigest()


def _month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


async def _rate_check(user_id: str) -> None:
    now = datetime.now(timezone.utc)
    hr_cutoff  = now - timedelta(hours=1)
    day_cutoff = now - timedelta(days=1)
    n_hr  = await db.ai_call_log.count_documents({"user": user_id, "at": {"$gte": hr_cutoff}})
    n_day = await db.ai_call_log.count_documents({"user": user_id, "at": {"$gte": day_cutoff}})
    if n_hr >= RATE_HOURLY:
        raise HTTPException(status_code=429,
            detail=f"Rate limit — {RATE_HOURLY} AI calls/hour reached. Retry after ~{60 - now.minute} min. "
                    "Deterministic decoders (SMART / MAGIC) remain available.")
    if n_day >= RATE_DAILY:
        raise HTTPException(status_code=429,
            detail=f"Daily limit — {RATE_DAILY} AI calls/day reached. Resets at 00:00 UTC. "
                    "Deterministic decoders remain available.")


async def _budget_check() -> None:
    doc = await db.ai_budget.find_one({"_id": _month_key()})
    used = int((doc or {}).get("credits", 0))
    if used >= BUDGET_CAP:
        raise HTTPException(status_code=429,
            detail=f"Monthly AI budget cap reached ({BUDGET_CAP} credits). "
                    "AI endpoints paused until next month. Deterministic decoders remain available. "
                    "Admin can raise NIVX_AI_BUDGET_CAP_CREDITS.")


async def _cache_get(endpoint: str, payload_sha1: str) -> Optional[Dict[str, Any]]:
    doc = await db.ai_response_cache.find_one({"_id": f"{endpoint}:{payload_sha1}"})
    return (doc or {}).get("response")


async def _cache_put(endpoint: str, payload_sha1: str, response: Dict[str, Any]) -> None:
    await db.ai_response_cache.update_one(
        {"_id": f"{endpoint}:{payload_sha1}"},
        {"$set": {"response": response, "cached_at": datetime.now(timezone.utc)}},
        upsert=True,
    )


async def guard_ai_endpoint(user: Any, endpoint: str, payload: str) -> Optional[Dict[str, Any]]:
    """Call at the START of any AI-consuming endpoint.

    Returns a cached response dict if hit (caller should return it directly).
    Returns None if the request should proceed → then MUST call
    `record_ai_spend(user, endpoint, payload, response)` on success.

    Raises HTTPException 429 on rate-limit / budget cap.
    """
    user_id = (user or {}).get("email") or "anonymous"

    # 1. Rate limit
    await _rate_check(user_id)

    # 2. Budget cap
    await _budget_check()

    # 3. Cache hit (also count-free)
    sha1 = _payload_sha1(payload)
    hit = await _cache_get(endpoint, sha1)
    if hit is not None:
        hit["cache_hit"] = True
        return hit

    return None


async def record_ai_spend(user: Any, endpoint: str, payload: str,
                           response: Dict[str, Any]) -> None:
    """Call after a successful AI call so the ledger + cache stay honest."""
    user_id = (user or {}).get("email") or "anonymous"
    sha1 = _payload_sha1(payload)
    cost = CREDITS_PER.get(endpoint, CREDITS_PER["default"])

    now = datetime.now(timezone.utc)
    await db.ai_call_log.insert_one(
        {"user": user_id, "endpoint": endpoint, "sha1": sha1, "cost_units": cost, "at": now}
    )
    await db.ai_budget.update_one(
        {"_id": _month_key()},
        {"$inc": {"credits": cost / 100.0, "call_count": 1},
          "$setOnInsert": {"month": _month_key(), "first_call_at": now}},
        upsert=True,
    )
    await _cache_put(endpoint, sha1, response)


async def budget_status() -> Dict[str, Any]:
    """For admin dashboard / /api/admin/ai-budget."""
    doc = await db.ai_budget.find_one({"_id": _month_key()})
    used = float((doc or {}).get("credits", 0))
    return {
        "month":          _month_key(),
        "used_credits":   round(used, 2),
        "cap_credits":    BUDGET_CAP,
        "call_count":     int((doc or {}).get("call_count", 0)),
        "utilisation":    round(used * 100 / max(BUDGET_CAP, 1), 1),
        "rate_hourly":    RATE_HOURLY,
        "rate_daily":     RATE_DAILY,
    }
