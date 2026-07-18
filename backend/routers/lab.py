"""Analyst Practice Lab — Feb 2026 v1.3.0

Turns NivXRay from a tool into a teaching platform. Analysts pick a
challenge (random payload from the NXGEC gold corpus), guess the MITRE
T-IDs / LOLBins / severity, and see how they scored. Streaks + XP make
it stick.

Endpoints (all under /api):
    GET  /lab/challenge?difficulty=easy|medium|hard   → 1 random challenge (answer hidden)
    POST /lab/attempt                                  → grade user's guesses + persist
    GET  /lab/me                                       → my streak/score/history
    GET  /lab/leaderboard                              → top 20 analysts by score
    GET  /lab/reveal/{challenge_id}                    → full expected answer (post-attempt)
"""
from __future__ import annotations

import json
import os
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from pymongo import MongoClient

from deps import get_current_user

router = APIRouter()

_client = MongoClient(os.environ.get("MONGO_URL"))
_db     = _client[os.environ.get("DB_NAME")]
_attempts = _db.lab_attempts
_stats    = _db.lab_stats

_NXGEC_PATH = "/app/backend/tests/fixtures/nxgec.jsonl"

# ─── Challenge bank (lazy-loaded from NXGEC fixture) ────────────────────
def _load_challenges() -> List[Dict[str, Any]]:
    if not os.path.exists(_NXGEC_PATH):
        return []
    out = []
    with open(_NXGEC_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def _difficulty(case: Dict[str, Any]) -> str:
    """Assign difficulty based on payload characteristics."""
    inp = case.get("input", "")
    mitre_count = len(case.get("expected_mitre_ids") or [])
    if len(inp) < 60 and mitre_count <= 1:
        return "easy"
    if mitre_count >= 3 or len(inp) > 400:
        return "hard"
    return "medium"


def _grade(guess_mitre: List[str], guess_lolbins: List[str], guess_severity: str,
           case: Dict[str, Any]) -> Dict[str, Any]:
    """Compare user's guess to expected answer. Prefix-match on T-IDs."""
    exp_mitre    = set((case.get("expected_mitre_ids") or []))
    exp_lolbins  = set(l.lower() for l in (case.get("expected_lolbins") or []))
    exp_severity = (case.get("expected_severity") or "").lower()

    got_mitre    = set(guess_mitre)
    got_lolbins  = set(l.lower() for l in guess_lolbins)
    got_severity = (guess_severity or "").lower()

    def _covers(exp: set, got: set) -> bool:
        for e in exp:
            base = e.split(".")[0]
            if e in got or any(g == e or g == base or g.startswith(base + ".") for g in got):
                continue
            return False
        return True

    mitre_pass    = _covers(exp_mitre, got_mitre) if exp_mitre else True
    lolbin_pass   = exp_lolbins.issubset(got_lolbins) if exp_lolbins else True
    severity_pass = (not exp_severity) or (got_severity == exp_severity)

    # Score
    total = (10 if mitre_pass else 0) + (5 if lolbin_pass else 0) + (5 if severity_pass else 0)
    perfect = mitre_pass and lolbin_pass and severity_pass

    return {
        "mitre_pass":    mitre_pass,
        "lolbin_pass":   lolbin_pass,
        "severity_pass": severity_pass,
        "score":         total,
        "max_score":     20,
        "perfect":       perfect,
        "expected": {
            "mitre":    sorted(exp_mitre),
            "lolbins":  sorted(exp_lolbins),
            "severity": exp_severity,
        },
        "got": {
            "mitre":    sorted(got_mitre),
            "lolbins":  sorted(got_lolbins),
            "severity": got_severity,
        },
    }


def _email(user):
    return getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)


def _redact_answer(case: Dict[str, Any], difficulty: str) -> Dict[str, Any]:
    """Return the challenge WITHOUT the answer (client sees only input)."""
    return {
        "challenge_id": case.get("id"),
        "title":        case.get("title"),
        "volume":       case.get("volume"),
        "category":     case.get("category"),
        "input":        case.get("input"),
        "difficulty":   difficulty,
        "hint":         "Identify MITRE T-IDs, LOLBins, and severity level.",
    }


# ─── Models ─────────────────────────────────────────────────────────────
class AttemptIn(BaseModel):
    challenge_id:    str
    guess_mitre:     List[str] = Field(default_factory=list)
    guess_lolbins:   List[str] = Field(default_factory=list)
    guess_severity:  Optional[str] = ""


# ─── Endpoints ──────────────────────────────────────────────────────────
@router.get("/lab/challenge")
async def lab_challenge(difficulty: Optional[str] = None, user=Depends(get_current_user)):
    cases = _load_challenges()
    if not cases:
        raise HTTPException(503, "gold corpus missing")

    if difficulty in ("easy", "medium", "hard"):
        pool = [c for c in cases if _difficulty(c) == difficulty]
        if not pool:
            pool = cases
    else:
        pool = cases
    case = random.choice(pool)
    return _redact_answer(case, _difficulty(case))


# ═══════════════════════════════════════════════════════════════════════
# Feb 2026 v1.3.0 · PUBLIC DEMO endpoints (no auth) for attention play
# IP-throttled to 30 requests/hour to prevent abuse. No persistence.
# ═══════════════════════════════════════════════════════════════════════
_public_rate: Dict[str, List[float]] = {}
_PUBLIC_LIMIT = 30
_PUBLIC_WINDOW = 3600


def _check_public_rate(ip: str) -> bool:
    import time
    now = time.time()
    hist = [t for t in _public_rate.get(ip, []) if now - t < _PUBLIC_WINDOW]
    if len(hist) >= _PUBLIC_LIMIT:
        return False
    hist.append(now)
    _public_rate[ip] = hist
    return True


class PublicAttemptIn(BaseModel):
    challenge_id:    str
    guess_mitre:     List[str] = Field(default_factory=list)
    guess_lolbins:   List[str] = Field(default_factory=list)
    guess_severity:  Optional[str] = ""


@router.get("/lab/public/challenge")
async def lab_public_challenge(request: Request, difficulty: Optional[str] = None):
    """PUBLIC · no auth. IP-throttled. For nivxray.nivxforge.com/lab landing page."""
    ip = request.client.host if request.client else "unknown"
    if not _check_public_rate(ip):
        raise HTTPException(429, f"Public demo limited to {_PUBLIC_LIMIT} requests/hour. Sign up for unlimited access.")
    cases = _load_challenges()
    if not cases:
        raise HTTPException(503, "gold corpus missing")
    if difficulty in ("easy", "medium", "hard"):
        pool = [c for c in cases if _difficulty(c) == difficulty]
        if not pool:
            pool = cases
    else:
        pool = cases
    case = random.choice(pool)
    out = _redact_answer(case, _difficulty(case))
    out["public"] = True
    out["daily_limit_remaining"] = _PUBLIC_LIMIT - len(_public_rate.get(ip, []))
    return out


@router.post("/lab/public/attempt")
async def lab_public_attempt(body: PublicAttemptIn, request: Request):
    """PUBLIC · no auth · no persistence. Grade only."""
    ip = request.client.host if request.client else "unknown"
    if not _check_public_rate(ip):
        raise HTTPException(429, "Public demo rate-limited. Sign up for unlimited access.")
    cases = _load_challenges()
    case = next((c for c in cases if c.get("id") == body.challenge_id), None)
    if not case:
        raise HTTPException(404, "challenge not found")
    result = _grade(body.guess_mitre, body.guess_lolbins, body.guess_severity or "", case)
    result["public"] = True
    result["cta"] = "Sign up free to track your streak, unlock all 55 challenges, and access the full decoder."
    return result


@router.post("/lab/attempt")
async def lab_attempt(body: AttemptIn, user=Depends(get_current_user)):
    cases = _load_challenges()
    case  = next((c for c in cases if c.get("id") == body.challenge_id), None)
    if not case:
        raise HTTPException(404, "challenge not found")

    result = _grade(body.guess_mitre, body.guess_lolbins, body.guess_severity or "", case)
    email  = _email(user)
    now    = datetime.now(timezone.utc)

    # Persist attempt
    _attempts.insert_one({
        "user_email":   email,
        "challenge_id": body.challenge_id,
        "guess_mitre":  body.guess_mitre,
        "guess_lolbins": body.guess_lolbins,
        "guess_severity": body.guess_severity,
        "score":        result["score"],
        "perfect":      result["perfect"],
        "created_at":   now.isoformat(),
    })

    # Update user stats (streak logic)
    prev = _stats.find_one({"user_email": email}) or {}
    streak = (prev.get("streak", 0) + 1) if result["perfect"] else 0
    _stats.update_one(
        {"user_email": email},
        {"$set": {
            "user_email":   email,
            "last_active":  now.isoformat(),
            "streak":       streak,
            "best_streak":  max(streak, prev.get("best_streak", 0)),
        },
        "$inc": {
            "total_attempts": 1,
            "total_score":    result["score"],
            "total_perfect":  1 if result["perfect"] else 0,
        }},
        upsert=True,
    )
    return {**result, "streak": streak}


@router.get("/lab/me")
async def lab_me(user=Depends(get_current_user)):
    email = _email(user)
    stats = _stats.find_one({"user_email": email}, {"_id": 0}) or {
        "user_email": email, "streak": 0, "best_streak": 0,
        "total_attempts": 0, "total_score": 0, "total_perfect": 0,
    }
    # Recent attempts (last 10)
    recent = list(_attempts.find({"user_email": email}, {"_id": 0}).sort("created_at", -1).limit(10))
    return {"stats": stats, "recent": recent}


@router.get("/lab/leaderboard")
async def lab_leaderboard(user=Depends(get_current_user)):
    top = list(_stats.find({}, {"_id": 0}).sort([("total_score", -1)]).limit(20))
    return {"leaderboard": top}


@router.get("/lab/reveal/{challenge_id}")
async def lab_reveal(challenge_id: str, user=Depends(get_current_user)):
    """Full expected answer — call this AFTER submitting an attempt."""
    cases = _load_challenges()
    case  = next((c for c in cases if c.get("id") == challenge_id), None)
    if not case:
        raise HTTPException(404, "challenge not found")
    return {
        "challenge_id":    challenge_id,
        "expected_mitre":  case.get("expected_mitre_ids"),
        "expected_lolbins": case.get("expected_lolbins"),
        "expected_severity": case.get("expected_severity"),
        "full_expected":   case.get("expected"),
    }
