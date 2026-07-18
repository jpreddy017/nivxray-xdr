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
try:
    from operations import MITRE_HEURISTICS  # type: ignore
except Exception:
    MITRE_HEURISTICS = []

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


# ─── MITRE lookup (for reveal + AI grading context) ─────────────────────
_MITRE_INDEX_CACHE: Dict[str, Dict[str, str]] = {}


def _mitre_index() -> Dict[str, Dict[str, str]]:
    """Build {T-ID → {name, tactic}} from operations.MITRE_HEURISTICS (once).

    MITRE_HEURISTICS is a list of tuples: (regex, (T-ID, name, tactic))
    """
    global _MITRE_INDEX_CACHE
    if _MITRE_INDEX_CACHE:
        return _MITRE_INDEX_CACHE
    idx: Dict[str, Dict[str, str]] = {}
    for h in MITRE_HEURISTICS or []:
        try:
            meta = h[1] if isinstance(h, tuple) and len(h) >= 2 else h.get("mitre")
        except Exception:
            continue
        # meta may be a tuple (id, name, tactic) or a list of dicts
        if isinstance(meta, tuple) and len(meta) >= 3:
            tid, name, tactic = meta[0], meta[1], meta[2]
            if tid and tid not in idx:
                idx[tid] = {"id": tid, "name": name or "", "tactic": tactic or ""}
        elif isinstance(meta, list):
            for m in meta:
                if not isinstance(m, dict):
                    continue
                tid = m.get("id")
                if tid and tid not in idx:
                    idx[tid] = {"id": tid, "name": m.get("name", "") or "",
                                "tactic": m.get("tactic", "") or ""}
    _MITRE_INDEX_CACHE = idx
    return idx


def _mitre_enrich(ids: List[str]) -> List[Dict[str, str]]:
    """Enrich raw T-IDs with human-readable name + tactic."""
    idx = _mitre_index()
    out = []
    for tid in ids or []:
        base = tid.split(".")[0]
        info = idx.get(tid) or idx.get(base) or {"id": tid, "name": "", "tactic": ""}
        out.append({"id": tid, "name": info.get("name", ""), "tactic": info.get("tactic", "")})
    return out


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


class NarrativeAttemptIn(BaseModel):
    """Free-form analyst write-up — graded by Claude vs the expected answer."""
    challenge_id:    str
    understanding:   str = ""   # what does the command/chain do?
    impact:          str = ""   # what damage / risk if executed?
    recommendations: str = ""   # detections, blocks, containment steps


async def _grade_narrative_with_ai(case: Dict[str, Any],
                                    understanding: str, impact: str,
                                    recommendations: str) -> Dict[str, Any]:
    """Grade a free-form narrative via Claude. Returns
    {score, max_score, perfect, understanding_score, impact_score,
     recommendations_score, feedback, strengths, gaps, reference_summary}.

    Falls back to a keyword-overlap heuristic if the LLM key is missing.
    """
    exp_mitre    = list(case.get("expected_mitre_ids") or [])
    exp_lolbins  = list(case.get("expected_lolbins") or [])
    exp_severity = case.get("expected_severity") or ""
    _exp_raw     = case.get("expected") or case.get("summary") or ""
    exp_summary  = _exp_raw if isinstance(_exp_raw, str) else json.dumps(_exp_raw, ensure_ascii=False)
    payload      = case.get("input") or ""

    key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not key:
        # Heuristic fallback — reward length + coverage of expected tokens.
        def _cover(text: str, tokens: List[str]) -> float:
            if not tokens:
                return 1.0
            t = (text or "").lower()
            hits = sum(1 for tk in tokens if tk.lower() in t)
            return hits / max(1, len(tokens))

        exp_tokens = [l for l in exp_lolbins] + [
            "credential" if "cred" in " ".join(exp_mitre).lower() else "",
            "persistence" if any(m.startswith("T1053") or m.startswith("T1547") or m.startswith("T1543") for m in exp_mitre) else "",
            "download"   if any(m in ("T1105",) for m in exp_mitre) else "",
        ]
        exp_tokens = [t for t in exp_tokens if t]
        u = min(1.0, (len(understanding.split()) / 25) * (0.5 + 0.5 * _cover(understanding, exp_tokens)))
        i = min(1.0, (len(impact.split()) / 15) * (0.5 + 0.5 * (1.0 if exp_severity.lower() in impact.lower() else 0.6)))
        r = min(1.0, len(recommendations.split()) / 15)
        u_s, i_s, r_s = round(u * 40), round(i * 30), round(r * 30)
        total = u_s + i_s + r_s
        return {
            "provider": "static",
            "score":                  total,
            "max_score":              100,
            "perfect":                total >= 85,
            "understanding_score":    u_s,
            "impact_score":           i_s,
            "recommendations_score":  r_s,
            "feedback":               "AI grader unavailable — using length + coverage heuristic. Add EMERGENT_LLM_KEY for full grading.",
            "strengths":              [],
            "gaps":                   [],
            "reference_summary":      exp_summary,
        }

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        system = (
            "You are a senior SOC lead grading a junior analyst's write-up of a suspicious "
            "command line. Be strict but fair. Return STRICT JSON only (no prose, no code "
            "fences). Rubric:\n"
            "  • understanding_score  (0-40) — did they correctly explain what each part of "
            "the command does and identify the tradecraft?\n"
            "  • impact_score         (0-30) — did they name the risk (execution, credential "
            "access, persistence, exfil, impact) and the correct severity level?\n"
            "  • recommendations_score(0-30) — did they suggest concrete detections "
            "(EDR/SIEM rules, LOLBin blocks, hunting queries) and containment steps?\n"
            "Also output 2-4 SHORT strengths and 2-4 SHORT gaps (things missed or wrong). "
            "Keep feedback ≤ 60 words, plain English, actionable. Never invent MITRE IDs "
            "the analyst did not mention."
        )
        prompt = (
            f"PAYLOAD:\n```\n{payload[:1200]}\n```\n\n"
            f"EXPECTED ATT&CK IDs: {', '.join(exp_mitre) or '—'}\n"
            f"EXPECTED LOLBins:    {', '.join(exp_lolbins) or '—'}\n"
            f"EXPECTED SEVERITY:   {exp_severity or '—'}\n"
            f"REFERENCE ANSWER:    {exp_summary[:600] or '—'}\n\n"
            f"ANALYST WRITE-UP:\n"
            f"  1. What does it do?\n     {understanding.strip() or '(empty)'}\n"
            f"  2. Impact / risk:\n     {impact.strip() or '(empty)'}\n"
            f"  3. Recommendations:\n     {recommendations.strip() or '(empty)'}\n\n"
            "Return JSON with keys: understanding_score, impact_score, recommendations_score, "
            "feedback, strengths (array of strings), gaps (array of strings)."
        )
        session_id = f"lab-narrative-{case.get('id')}-{int(datetime.now(timezone.utc).timestamp())}"
        chat = (
            LlmChat(api_key=key, session_id=session_id,
                    system_message=system)
            .with_model("anthropic", "claude-sonnet-4-5-20250929")
            .with_params(max_tokens=700)
        )
        reply = (await chat.send_message(UserMessage(text=prompt))) or ""
        # Extract JSON (Claude sometimes wraps in ```json)
        s = reply.strip()
        if s.startswith("```"):
            s = s.strip("`")
            s = s.split("\n", 1)[1] if "\n" in s else s
            s = s.rsplit("```", 1)[0] if s.endswith("```") else s
        # Find first { and last }
        i0, i1 = s.find("{"), s.rfind("}")
        if i0 >= 0 and i1 > i0:
            s = s[i0:i1 + 1]
        parsed = json.loads(s)
        u_s = max(0, min(40, int(parsed.get("understanding_score",   0) or 0)))
        i_s = max(0, min(30, int(parsed.get("impact_score",          0) or 0)))
        r_s = max(0, min(30, int(parsed.get("recommendations_score", 0) or 0)))
        total = u_s + i_s + r_s
        return {
            "provider":               "emergent-claude",
            "score":                  total,
            "max_score":              100,
            "perfect":                total >= 85,
            "understanding_score":    u_s,
            "impact_score":           i_s,
            "recommendations_score":  r_s,
            "feedback":               (parsed.get("feedback") or "").strip(),
            "strengths":              parsed.get("strengths") or [],
            "gaps":                   parsed.get("gaps") or [],
            "reference_summary":      exp_summary,
        }
    except Exception as e:
        return {
            "provider":               "error",
            "score":                  0,
            "max_score":              100,
            "perfect":                False,
            "understanding_score":    0,
            "impact_score":           0,
            "recommendations_score":  0,
            "feedback":               f"Grader error: {str(e)[:120]}",
            "strengths":              [],
            "gaps":                   [],
            "reference_summary":      exp_summary,
        }


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
    exp_ids = case.get("expected_mitre_ids") or []
    return {
        "challenge_id":       challenge_id,
        "expected_mitre":     exp_ids,
        "expected_mitre_enriched": _mitre_enrich(exp_ids),
        "expected_lolbins":   case.get("expected_lolbins"),
        "expected_severity":  case.get("expected_severity"),
        "full_expected":      case.get("expected"),
    }


@router.post("/lab/attempt/narrative")
async def lab_attempt_narrative(body: NarrativeAttemptIn, user=Depends(get_current_user)):
    """Free-form analyst write-up graded by Claude vs the expected answer.

    Returns score/feedback + the expected MITRE (with human-readable names)
    so the analyst LEARNS the tradecraft instead of memorising T-codes.
    """
    cases = _load_challenges()
    case  = next((c for c in cases if c.get("id") == body.challenge_id), None)
    if not case:
        raise HTTPException(404, "challenge not found")

    grade = await _grade_narrative_with_ai(
        case, body.understanding, body.impact, body.recommendations,
    )

    email = _email(user)
    now   = datetime.now(timezone.utc)

    _attempts.insert_one({
        "user_email":     email,
        "challenge_id":   body.challenge_id,
        "mode":           "narrative",
        "understanding":  body.understanding,
        "impact":         body.impact,
        "recommendations": body.recommendations,
        "score":          grade["score"],
        "max_score":      grade["max_score"],
        "perfect":        grade["perfect"],
        "provider":       grade.get("provider"),
        "created_at":     now.isoformat(),
    })

    # Streak logic — mirrors classic /lab/attempt
    prev = _stats.find_one({"user_email": email}) or {}
    streak = (prev.get("streak", 0) + 1) if grade["perfect"] else 0
    _stats.update_one(
        {"user_email": email},
        {"$set": {
            "user_email":  email,
            "last_active": now.isoformat(),
            "streak":      streak,
            "best_streak": max(streak, prev.get("best_streak", 0)),
        },
        "$inc": {
            "total_attempts": 1,
            "total_score":    grade["score"],
            "total_perfect":  1 if grade["perfect"] else 0,
        }},
        upsert=True,
    )

    exp_ids = case.get("expected_mitre_ids") or []
    return {
        **grade,
        "streak":                  streak,
        "expected_mitre":          exp_ids,
        "expected_mitre_enriched": _mitre_enrich(exp_ids),
        "expected_lolbins":        case.get("expected_lolbins") or [],
        "expected_severity":       case.get("expected_severity") or "",
    }
