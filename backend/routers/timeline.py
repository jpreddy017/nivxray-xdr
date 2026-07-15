"""Investigation Timeline router — /api/timeline/*.

Endpoints
    GET  /api/timeline/events?investigation_id=X&limit=N
    POST /api/timeline/events               body {kind, title, ...}
    GET  /api/timeline/recent?limit=N       global feed
    DELETE /api/timeline/events/{investigation_id}    (admin)
"""
from __future__ import annotations
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin
from timeline import record, list_events, list_recent, clear


router = APIRouter()


class EventIn(BaseModel):
    kind: str = Field(..., description="decode|correction|corpus-promote|benchmark|gate-block|taxii-push|threat-intel|sample-library-promote|error|note")
    title: str
    investigation_id: str = "adhoc"
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"


@router.get("/timeline/events", tags=["timeline"])
async def get_events(
    investigation_id: str = "adhoc", limit: int = 100,
    user=Depends(get_current_user),
):
    events = await list_events(db, investigation_id=investigation_id, limit=limit)
    return {"events": events, "count": len(events), "investigation_id": investigation_id}


@router.post("/timeline/events", tags=["timeline"])
async def create_event(body: EventIn, user=Depends(get_current_user)):
    doc = await record(
        db,
        kind=body.kind,
        title=body.title,
        investigation_id=body.investigation_id,
        actor=user.get("email"),
        summary=body.summary,
        metadata=body.metadata,
        severity=body.severity,
    )
    return {"ok": True, "event": doc}


@router.get("/timeline/recent", tags=["timeline"])
async def recent(limit: int = 100, user=Depends(get_current_user)):
    events = await list_recent(db, limit=limit)
    return {"events": events, "count": len(events)}


@router.delete("/timeline/events/{investigation_id}", tags=["timeline"])
async def clear_events(investigation_id: str, user=Depends(require_admin)):
    n = await clear(db, investigation_id)
    return {"ok": True, "deleted": n}
