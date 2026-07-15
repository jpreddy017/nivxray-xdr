"""Investigations & Timeline router — /api/investigations/*.

Investigation IDs are deterministic: `sha256(input_text)[:16]`. So any
POST body carrying `input` groups its event under the same investigation
without an explicit create call.
"""
from __future__ import annotations
from typing import Optional

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
    items = await list_investigations(db, limit=limit)
    return {"investigations": items, "count": len(items)}


@router.get("/investigations/recent", tags=["investigations"])
async def recent(limit: int = 100, user=Depends(get_current_user)):
    """Global recent-events feed across every investigation."""
    events = await list_recent(db, limit=limit)
    return {"events": events, "count": len(events)}


@router.post("/investigations/lookup", tags=["investigations"])
async def lookup(body: InvestigationLookupIn, user=Depends(get_current_user)):
    """Return the deterministic investigation_id for a given input."""
    iid = investigation_id_for(body.input)
    events = await list_events(db, investigation_id=iid, limit=200)
    return {"investigation_id": iid, "input": body.input,
            "events": events, "count": len(events)}


@router.get("/investigations/{iid}/timeline", tags=["investigations"])
async def timeline(iid: str, limit: int = 200, user=Depends(get_current_user)):
    events = await list_events(db, investigation_id=iid, limit=limit)
    return {"investigation_id": iid, "events": events, "count": len(events)}


@router.post("/investigations/{iid}/note", tags=["investigations"])
async def post_note(iid: str, body: NoteIn, user=Depends(get_current_user)):
    ev = await _record(
        db, kind="note", title=body.note[:200],
        investigation_id=iid, actor=user.get("email"),
        summary=body.note, severity="info",
    )
    return {"ok": True, "event": ev}


@router.delete("/investigations/{iid}", tags=["investigations"])
async def clear_investigation(iid: str, user=Depends(get_current_user)):
    """Remove every event for an investigation (analyst-only cleanup)."""
    n = await clear(db, iid)
    return {"ok": True, "removed": n}
