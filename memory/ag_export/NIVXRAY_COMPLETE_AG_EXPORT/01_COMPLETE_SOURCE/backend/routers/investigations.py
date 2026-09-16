"""Investigations & Timeline router — /api/investigations/*.

Investigation IDs are deterministic: `sha256(input_text)[:16]`. So any
POST body carrying `input` groups its event under the same investigation
without an explicit create call.

Feb-2026 SEC-003 fix: every read and every delete is now scoped to the
calling user's ``email`` — one analyst can no longer read or delete
another analyst's investigations. Admins get the same scope by default
(the audit explicitly warned against blanket admin bypass); if a shared
"team view" is ever needed it should be a separate opt-in endpoint.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user
from timeline import (
    investigation_id_for, record as _record,
    list_events, list_recent, list_investigations, clear,
)


router = APIRouter()


class NoteIn(BaseModel):
    note: str = Field(..., min_length=1)


class InvestigationLookupIn(BaseModel):
    input: str


@router.get("/investigations", tags=["investigations"])
async def list_all(limit: int = 50, user=Depends(get_current_user)):
    items = await list_investigations(db, limit=limit, actor_filter=user["email"])
    return {"investigations": items, "count": len(items)}


@router.get("/investigations/recent", tags=["investigations"])
async def recent(limit: int = 100, user=Depends(get_current_user)):
    """Owner-scoped recent-events feed (Feb-2026 SEC-003)."""
    events = await list_recent(db, limit=limit, actor_filter=user["email"])
    return {"events": events, "count": len(events)}


@router.post("/investigations/lookup", tags=["investigations"])
async def lookup(body: InvestigationLookupIn, user=Depends(get_current_user)):
    """Return the deterministic investigation_id for a given input.

    The returned events are scoped to the calling user — looking up an iid
    the user does not own returns an empty list (no leakage that the iid
    exists for someone else).
    """
    iid = investigation_id_for(body.input)
    events = await list_events(db, investigation_id=iid, limit=200,
                               actor_filter=user["email"])
    return {"investigation_id": iid, "input": body.input,
            "events": events, "count": len(events)}


@router.get("/investigations/{iid}/timeline", tags=["investigations"])
async def timeline(iid: str, limit: int = 200, user=Depends(get_current_user)):
    events = await list_events(db, investigation_id=iid, limit=limit,
                               actor_filter=user["email"])
    if not events:
        # Either the iid doesn't exist or the caller doesn't own it —
        # respond 404 either way so we don't leak existence.
        raise HTTPException(status_code=404, detail="investigation_not_found")
    return {"investigation_id": iid, "events": events, "count": len(events)}


@router.post("/investigations/{iid}/note", tags=["investigations"])
async def post_note(iid: str, body: NoteIn, user=Depends(get_current_user)):
    # Confirm caller owns this investigation before recording a note against
    # it — otherwise anyone with a guessable iid could pollute another
    # analyst's timeline.
    owned = await list_events(db, investigation_id=iid, limit=1,
                              actor_filter=user["email"])
    if not owned:
        raise HTTPException(status_code=404, detail="investigation_not_found")
    ev = await _record(
        db, kind="note", title=body.note[:200],
        investigation_id=iid, actor=user["email"],
        summary=body.note, severity="info",
    )
    return {"ok": True, "event": ev}


@router.delete("/investigations/{iid}", tags=["investigations"])
async def clear_investigation(iid: str, user=Depends(get_current_user)):
    """Remove every event for an investigation. Only events authored by
    the caller are removed (Feb-2026 SEC-003)."""
    n = await clear(db, iid, actor_filter=user["email"])
    if n == 0:
        raise HTTPException(status_code=404, detail="investigation_not_found")
    return {"ok": True, "removed": n}
