"""Decode Feedback router  (v1.4.2 · Feb 2026)

Analyst-facing "report bad decode / undecoded" flow.

The analyst hits the button on Workspace when they see garbled / partial
output. We persist the raw_input, observed_output, and analyst's expected
output, then call Claude Sonnet 4.5 (via emergentintegrations) to explain
WHY the decoder likely failed and HOW to fix it — actionable next-op,
recipe patch, or heuristic gap.

Endpoints
    POST /api/decode/feedback           — submit a bad-decode report
    GET  /api/decode/feedback           — list recent (analyst's own)
    GET  /api/decode/feedback/{id}      — full record incl. AI diagnosis
    GET  /api/decode/feedback/admin/all — admin: cross-user inbox
"""
from __future__ import annotations
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin

log = logging.getLogger("nivxray.feedback")
router = APIRouter(prefix="/decode/feedback", tags=["decode-feedback"])

COLL = "decode_feedback"


# ── Schema ────────────────────────────────────────────────────────────
class FeedbackIn(BaseModel):
    raw_input:       str = Field(..., max_length=200_000)
    observed_output: Optional[str] = Field("", max_length=200_000)
    observed_chain:  Optional[List[str]] = None
    expected_output: Optional[str] = Field("", max_length=200_000)
    reason:          Optional[str] = Field("", max_length=2000)
    kind:            Optional[str] = "wrong_output"    # or "undecoded" / "partial"


class FeedbackOut(BaseModel):
    id:              str
    submitted_at:    str
    diagnosis:       Dict[str, Any]
    record:          Dict[str, Any]


# ── AI diagnosis via Claude Sonnet 4.5 ────────────────────────────────
async def _diagnose(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Run Claude Sonnet 4.5 to explain the decoder gap and recommend a fix.

    Best-effort — if the LLM key or import is unavailable we return a
    deterministic-only diagnosis so the endpoint never fails.
    """
    raw = rec.get("raw_input") or ""
    got = rec.get("observed_output") or ""
    want = rec.get("expected_output") or ""
    chain = rec.get("observed_chain") or []
    kind = rec.get("kind") or "wrong_output"
    reason = rec.get("reason") or ""

    # ── Cheap deterministic hints first (visible even w/o LLM) ─────────
    hints: List[str] = []
    if not chain:
        hints.append("Decoder chain empty — deterministic engine detected no known encoding. "
                     "Likely a novel wrapper or a charset the smart_decoder heuristics don't yet recognise.")
    if got.strip() == raw.strip():
        hints.append("Output is identical to input — pipeline treated the payload as plaintext passthrough.")
    if re.search(r"[\x00-\x08\x0b\x0e-\x1f]", got or ""):
        hints.append("Output contains non-printable control bytes — likely stopped mid-decode "
                     "at a binary layer (compression / shellcode). Consider adding a hex-view step.")
    if raw.strip().endswith("=") and "reverse" not in chain:
        hints.append("Input ends with `=` (base64 padding) — potential reversed base64 tradecraft. "
                     "Try `reverse-string → base64-decode` chain manually.")
    if "==" in raw or "eyJ" in raw:
        hints.append("Payload contains JWT-shape markers (`eyJ...`) — try `jwt-decode` op.")
    if any(w in raw.lower() for w in ("h4siaaaa", "h4siabqm")):
        hints.append("Contains raw GZIP base64 magic (`H4sIA...`). Ensure `base64-decode → gzip-decompress` is applied.")

    diagnosis: Dict[str, Any] = {
        "heuristic_hints": hints,
        "ai_explanation":  None,
        "suggested_ops":   [],
        "provider":        "deterministic-only",
    }

    # ── LLM diagnosis (Claude Sonnet 4.5) ──────────────────────────────
    key = os.environ.get("EMERGENT_LLM_KEY")
    if not key:
        return diagnosis

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
    except Exception as e:
        diagnosis["ai_explanation"] = f"emergentintegrations import failed: {e}"
        return diagnosis

    system = (
        "You are NivXRay's decoder-diagnostic engine. An analyst has reported a bad "
        "or incomplete decode. Your job is to explain WHY the deterministic decoder "
        "likely failed and RECOMMEND concrete next steps. Respond in strict JSON "
        "with keys: root_cause (str), why (str, 2-4 sentences), fix_steps (array of "
        "{op, args_hint, note}), suggested_recipe (array of op strings), missing_heuristic "
        "(str · what smart_decoder should learn), confidence (0-1)."
    )
    user_msg = (
        f"KIND: {kind}\n"
        f"REASON FROM ANALYST: {reason}\n\n"
        f"RAW INPUT (first 4000 chars):\n{raw[:4000]}\n\n"
        f"OBSERVED OUTPUT (first 2000 chars):\n{got[:2000]}\n\n"
        f"EXPECTED OUTPUT / GROUND TRUTH (first 2000 chars):\n{want[:2000]}\n\n"
        f"OBSERVED DECODE CHAIN: {chain}\n\n"
        "Diagnose and recommend fix now. Output STRICT JSON only, no prose."
    )

    try:
        chat = (
            LlmChat(api_key=key, session_id=f"feedback-{rec.get('id') or 'x'}",
                    system_message=system)
            .with_model("anthropic", "claude-sonnet-4-5")
            .with_params(max_tokens=1500)
        )
        resp = await chat.send_message(UserMessage(text=user_msg))
    except Exception as e:
        diagnosis["ai_explanation"] = f"LLM error: {e}"
        return diagnosis

    text = resp if isinstance(resp, str) else str(resp)
    # Extract JSON safely
    import json as _json
    parsed: Dict[str, Any] = {}
    try:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            parsed = _json.loads(m.group(0))
    except Exception:
        parsed = {"raw": text[:2000]}

    diagnosis["ai_explanation"] = parsed.get("why") or parsed.get("root_cause") or text[:1500]
    diagnosis["root_cause"] = parsed.get("root_cause")
    diagnosis["fix_steps"] = parsed.get("fix_steps") or []
    diagnosis["suggested_recipe"] = parsed.get("suggested_recipe") or []
    diagnosis["missing_heuristic"] = parsed.get("missing_heuristic")
    diagnosis["confidence"] = parsed.get("confidence")
    diagnosis["provider"] = "claude-sonnet-4-5"
    return diagnosis


# ── Endpoints ─────────────────────────────────────────────────────────
@router.post("")
async def submit_feedback(body: FeedbackIn, user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    rid = str(uuid.uuid4())
    rec = {
        "id":              rid,
        "user":            user["email"],
        "kind":            body.kind or "wrong_output",
        "raw_input":       body.raw_input,
        "observed_output": body.observed_output or "",
        "observed_chain":  body.observed_chain or [],
        "expected_output": body.expected_output or "",
        "reason":          body.reason or "",
        "submitted_at":    now,
        "status":          "open",
    }
    t0 = time.time()
    diagnosis = await _diagnose(rec)
    rec["diagnosis"]     = diagnosis
    rec["diagnosis_ms"]  = int((time.time() - t0) * 1000)
    await db[COLL].insert_one(rec)
    rec.pop("_id", None)
    rec["submitted_at"] = rec["submitted_at"].isoformat()
    return {"id": rid, "submitted_at": rec["submitted_at"],
            "diagnosis": diagnosis, "record": rec}


@router.get("")
async def list_my_feedback(limit: int = 25, user=Depends(get_current_user)):
    cur = db[COLL].find({"user": user["email"]}).sort("submitted_at", -1).limit(min(int(limit), 100))
    out: List[Dict[str, Any]] = []
    async for doc in cur:
        doc.pop("_id", None)
        if isinstance(doc.get("submitted_at"), datetime):
            doc["submitted_at"] = doc["submitted_at"].isoformat()
        out.append(doc)
    return {"count": len(out), "items": out}


@router.get("/admin/all")
async def list_all_feedback(limit: int = 100, user=Depends(require_admin)):
    cur = db[COLL].find({}).sort("submitted_at", -1).limit(min(int(limit), 500))
    out: List[Dict[str, Any]] = []
    async for doc in cur:
        doc.pop("_id", None)
        if isinstance(doc.get("submitted_at"), datetime):
            doc["submitted_at"] = doc["submitted_at"].isoformat()
        out.append(doc)
    return {"count": len(out), "items": out}


@router.get("/{fid}")
async def get_feedback(fid: str, user=Depends(get_current_user)):
    q = {"id": fid, "user": user["email"]}
    if user.get("role") == "admin":
        q = {"id": fid}
    doc = await db[COLL].find_one(q)
    if not doc:
        raise HTTPException(404, "not found")
    doc.pop("_id", None)
    if isinstance(doc.get("submitted_at"), datetime):
        doc["submitted_at"] = doc["submitted_at"].isoformat()
    return doc
