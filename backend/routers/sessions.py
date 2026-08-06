"""
Sessions · HTTP router (Rule R22 · 2026-03-02)
──────────────────────────────────────────────
Investigation Session endpoints.  A "session" is the L4 analyst
workspace envelope: it wraps the Canonical Investigation Object
(SSOT) into a structure the frontend consumes directly.

Endpoints
─────────
POST   /api/session/investigate      Mint a NEW session from raw input.
                                      Runs the SSOT pipeline, wraps in
                                      Session shape, persists to Mongo,
                                      returns the full session object.

POST   /api/session/from-investigation
                                      Mint a session from an ALREADY-
                                      computed investigation object
                                      (workspace-side re-use — avoids
                                      re-running the pipeline when the
                                      workspace has already fetched the
                                      SSOT via /api/die/investigation).

GET    /api/session/{session_id}     Fetch the persisted session.
GET    /api/session/{session_id}/input/{input_id}
                                      Fetch a single Investigation Input
                                      (child investigation drill-down).
"""
from __future__ import annotations
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from services.session import build_session, render_markdown, render_pdf
from services.die.investigation_results import render as _render_ssot
from deps import db

router = APIRouter(prefix="/session", tags=["session"])
log = logging.getLogger("nivxray.session")


# ── DB helpers ────────────────────────────────────────────────────
_COLLECTION = "investigation_sessions"


def _mongo_safe(obj: Any) -> Any:
    """Strip Mongo-hostile bytes so Motor can persist without errors.

    Recursively clones dicts/lists.  Bytes are hex-encoded (they only
    appear for archive artifacts which we keep as metadata anyway)."""
    if isinstance(obj, dict):
        return {k: _mongo_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mongo_safe(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", "replace")
        except Exception:
            return obj.hex()
    return obj


async def _persist_session(session: Dict[str, Any]) -> None:
    """Best-effort persistence.  A failure here MUST NOT block the
    response — the session envelope itself is still returned so the
    frontend has the full data; only durable read-by-id would be
    unavailable until the next mint."""
    try:
        doc = _mongo_safe({**session, "_id": session["session_id"]})
        await db[_COLLECTION].replace_one(
            {"_id": session["session_id"]}, doc, upsert=True,
        )
    except Exception as e:                       # pragma: no cover
        log.warning("session.persist_failed: %s", e)


async def _load_session(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        doc = await db[_COLLECTION].find_one({"_id": session_id})
        if not doc:
            return None
        doc.pop("_id", None)
        return doc
    except Exception as e:                       # pragma: no cover
        log.warning("session.load_failed: %s", e)
        return None


# ── Request models ────────────────────────────────────────────────
class InvestigateBody(BaseModel):
    input: str = Field(..., description="Raw analyst paste (URL, command, report, …).")


class FromInvestigationBody(BaseModel):
    input:         Optional[str]           = Field(None, description="Original input string (optional).")
    investigation: Dict[str, Any]          = Field(..., description="Canonical Investigation Object.")


# ── Endpoints ─────────────────────────────────────────────────────
@router.post("/investigate")
async def session_investigate(body: InvestigateBody) -> Dict[str, Any]:
    """Run the full SSOT pipeline and mint an Investigation Session.

    Delegates every heavy step (IUE · IDA · DIE · ICE) to the existing
    `investigation_results.render()` — this router is the Session
    Adapter layer described by Rule R22.  Backend mints the
    session_id (uuid4 → short prefix) so URLs are stable and
    shareable.
    """
    src = body.input or ""
    rendered = _render_ssot(src)
    ssot     = rendered.get("object") or {}
    sid      = f"ses_{uuid.uuid4().hex[:12]}"
    session  = build_session(src, ssot, session_id=sid)
    await _persist_session(session)
    return {"session": session}


@router.post("/from-investigation")
async def session_from_investigation(body: FromInvestigationBody) -> Dict[str, Any]:
    """Mint a session from an ALREADY-computed investigation object.

    Used by the Workspace gateway: the workspace has already fetched
    the SSOT via `/api/die/investigation`; we wrap it here rather
    than paying the pipeline cost twice.
    """
    sid     = f"ses_{uuid.uuid4().hex[:12]}"
    session = build_session(body.input or "", body.investigation or {}, session_id=sid)
    await _persist_session(session)
    return {"session": session}


@router.get("/{session_id}")
async def session_get(session_id: str) -> Dict[str, Any]:
    session = await _load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session": session}


@router.get("/{session_id}/input/{input_id}")
async def session_input_get(session_id: str, input_id: str) -> Dict[str, Any]:
    """Return a single Investigation Input (child investigation).

    Used by the Investigation Input Detail page — same UI as the
    manual paste flow, deep-linked via a stable id.
    """
    session = await _load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    for inp in session.get("investigation_inputs", []):
        if inp.get("id") == input_id:
            return {"session_id": session_id, "input": inp}
    raise HTTPException(status_code=404, detail="Investigation Input not found")


# ── NIST Incident Report exports ──────────────────────────────────
@router.get("/{session_id}/nist.md", response_class=PlainTextResponse)
async def session_nist_md(session_id: str) -> PlainTextResponse:
    session = await _load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    md = render_markdown(session)
    return PlainTextResponse(
        md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition":
                    f'attachment; filename="{session_id}.nist.md"'},
    )


@router.get("/{session_id}/nist.pdf")
async def session_nist_pdf(session_id: str) -> Response:
    session = await _load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        pdf = render_pdf(session)
    except Exception as e:                             # pragma: no cover
        log.exception("session.pdf_render_failed")
        raise HTTPException(status_code=500,
                              detail=f"PDF render failed: {e}") from e
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition":
                    f'attachment; filename="{session_id}.nist.pdf"'},
    )


# ── Ad-hoc render (body-driven · no persistence required) ─────────
# Lets the frontend render a PDF / MD even when the session lives
# only in the client cache (ses_local_… fallbacks or shared
# investigations that were never persisted server-side).
class RenderBody(BaseModel):
    session:       Optional[Dict[str, Any]] = None
    investigation: Optional[Dict[str, Any]] = None
    input:         Optional[str]            = None


def _coerce_session(body: RenderBody) -> Dict[str, Any]:
    if body.session and body.session.get("session_id"):
        return body.session
    if body.investigation:
        return build_session(body.input or "", body.investigation or {})
    raise HTTPException(status_code=400,
                          detail="Provide either `session` or `investigation`.")


@router.post("/render/nist.pdf")
async def session_render_pdf(body: RenderBody) -> Response:
    session = _coerce_session(body)
    try:
        pdf = render_pdf(session)
    except Exception as e:                             # pragma: no cover
        log.exception("session.render_pdf_failed")
        raise HTTPException(status_code=500,
                              detail=f"PDF render failed: {e}") from e
    fname = f"{session.get('session_id') or 'nivxray'}.nist.pdf"
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.post("/render/nist.md", response_class=PlainTextResponse)
async def session_render_md(body: RenderBody) -> PlainTextResponse:
    session = _coerce_session(body)
    md = render_markdown(session)
    fname = f"{session.get('session_id') or 'nivxray'}.nist.md"
    return PlainTextResponse(
        md, media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
