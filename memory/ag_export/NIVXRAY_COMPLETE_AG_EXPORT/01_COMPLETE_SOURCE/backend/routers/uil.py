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

ADR-005 · Phase 5.1 (2026-08-10)
────────────────────────────────
When env `NIVX_CANONICAL_UIL_INVESTIGATE=on`, `/investigate` is served
by the direct canonical lifecycle (`services.uil.canonical_entry`).
The legacy code path below is preserved BYTE-IDENTICAL when the flag
is off (default). Rollback = flip the env variable to `off` + restart.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from routers.sessions import _persist_session
from services.die.investigation_results import render as _render_ssot
from services.session import build_session
from services.uil import KIND_LABEL, InputKind, classify, normalize, split_mixed
from services.uil.canonical_entry import (
    canonical_flag_enabled,
    investigate_canonical,
)

router = APIRouter(prefix="/uil", tags=["uil"])


class TextBody(BaseModel):
    text: str


@router.post("/classify")
async def uil_classify(text:  str | None = Form(default=None),
                         file:  UploadFile | None = File(default=None)) -> dict[str, Any]:
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
async def uil_split(body: TextBody) -> dict[str, Any]:
    fragments = split_mixed(body.text or "")
    return {
        "count":     len(fragments),
        "fragments": [f.to_dict() for f in fragments],
    }


@router.post("/investigate")
async def uil_investigate(
    text:  str | None        = Form(default=None),
    file:  UploadFile | None = File(default=None),
) -> dict[str, Any]:
    """Smart front door: classify → normalize → hand off to Session.

    Phase 5.1 (2026-08-10): when `NIVX_CANONICAL_UIL_INVESTIGATE=on`,
    the canonical lifecycle path is used (services.uil.canonical_entry).
    Otherwise, the legacy path below runs unchanged.
    """
    payload, filename = await _read_input(text, file)
    if payload is None:
        raise HTTPException(400, "Provide `text` or `file`.")

    # ── Phase 5.1 · Canonical branch (opt-in via env flag) ────────────
    if canonical_flag_enabled():
        correlation_id = f"uil-{uuid.uuid4().hex[:12]}"
        result = investigate_canonical(
            payload=payload if isinstance(payload, (bytes, bytearray))
                    else str(payload).encode("utf-8", "replace"),
            filename=filename,
            text_input=text,
            correlation_id=correlation_id,
        )
        session = result.get("session")
        if session is not None:
            await _persist_session(session)
        return result

    # ── Legacy path (byte-identical to Phase 3.y exit) ────────────────
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
async def _read_input(text: str | None, file: UploadFile | None):
    if file is not None:
        data = await file.read()
        return data, (file.filename or None)
    if text is not None:
        return text, None
    return None, None
