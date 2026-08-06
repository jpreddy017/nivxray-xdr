"""
UIL · HTTP router (2026-03-02)
───────────────────────────────
Analyst-facing Universal Input endpoint.

    POST /api/uil/classify        text or file    → {kind, label, ready, ...}
    POST /api/uil/split           text            → {fragments: [...]}
    POST /api/uil/investigate     text OR upload  → { session: {...} }

`/investigate` is the new smart front door: it classifies, normalises,
optionally splits mixed input, and delegates to the existing Session
pipeline — NO changes to IDA / DIE / ICE / IOC.
"""
from __future__ import annotations
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from services.uil import classify, normalize, split_mixed, KIND_LABEL, InputKind
from services.session import build_session
from services.die.investigation_results import render as _render_ssot
from routers.sessions import _persist_session

router = APIRouter(prefix="/uil", tags=["uil"])


class TextBody(BaseModel):
    text: str


@router.post("/classify")
async def uil_classify(text:  Optional[str] = Form(default=None),
                         file:  Optional[UploadFile] = File(default=None)) -> Dict[str, Any]:
    payload, filename = await _read_input(text, file)
    if payload is None:
        raise HTTPException(400, "Provide `text` or `file`.")
    kind = classify(payload, filename=filename)
    norm = normalize(payload, kind, filename=filename)
    return {
        "kind":       kind.value,
        "kind_label": KIND_LABEL.get(kind, kind.value),
        "ready":      norm.ready,
        "reason":     norm.reason,
        "metadata":   norm.metadata,
        "text_preview": (norm.text[:400] + "…") if len(norm.text) > 400 else norm.text,
    }


@router.post("/split")
async def uil_split(body: TextBody) -> Dict[str, Any]:
    fragments = split_mixed(body.text or "")
    return {
        "count":     len(fragments),
        "fragments": [f.to_dict() for f in fragments],
    }


@router.post("/investigate")
async def uil_investigate(
    text:  Optional[str]        = Form(default=None),
    file:  Optional[UploadFile] = File(default=None),
) -> Dict[str, Any]:
    """Smart front door: classify → normalize → hand off to Session."""
    payload, filename = await _read_input(text, file)
    if payload is None:
        raise HTTPException(400, "Provide `text` or `file`.")

    kind = classify(payload, filename=filename)
    norm = normalize(payload, kind, filename=filename)

    # Binary formats without a preprocessor yet — return an honest
    # pending envelope instead of pretending we investigated them.
    if not norm.ready:
        return {
            "session": None,
            "uil": {
                "kind":       kind.value,
                "kind_label": KIND_LABEL.get(kind, kind.value),
                "ready":      False,
                "reason":     norm.reason,
                "metadata":   norm.metadata,
            },
        }

    # For MIXED input we could fan out; for the MVP we let the
    # existing pipeline handle the whole paste (it already splits
    # commands / IOCs / URLs internally via IDA-1).  We ALSO surface
    # the fragment breakdown so the frontend can show what UIL saw.
    fragments = split_mixed(norm.text) if kind is InputKind.MIXED else []

    rendered = _render_ssot(norm.text)
    ssot     = rendered.get("object") or {}
    import uuid
    sid      = f"ses_{uuid.uuid4().hex[:12]}"
    session  = build_session(norm.text, ssot, session_id=sid)

    # Enrich the envelope with UIL provenance so the Workspace/Session
    # UI can render "Classified as: PowerShell script (single-line)".
    session["uil"] = {
        "kind":       kind.value,
        "kind_label": KIND_LABEL.get(kind, kind.value),
        "ready":      True,
        "metadata":   norm.metadata,
        "fragments":  [f.to_dict() for f in fragments],
    }
    await _persist_session(session)
    return {"session": session}


# ── helpers ───────────────────────────────────────────────────────
async def _read_input(text: Optional[str], file: Optional[UploadFile]):
    if file is not None:
        data = await file.read()
        return data, (file.filename or None)
    if text is not None:
        return text, None
    return None, None
