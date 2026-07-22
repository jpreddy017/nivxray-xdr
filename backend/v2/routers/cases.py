"""/api/v2/cases · Case CRUD (Phase 3).

Behind `NIVX_FLAG_CASE_ENGINE`. Every endpoint returns 503 when the
flag is disabled — no v2 state is ever created or read while the
flag is off. Reuses admin auth from the existing `deps` module —
the ONLY cross-namespace import allowed (a stable, versioned utility
per the Round-6 conditions).

No RC5 storage is ever touched. Reads/writes go exclusively to the
`v2_cases` collection defined in `v2/case_engine/schema.py`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from deps import require_admin, db as _db     # stable versioned utility (auth + Mongo)
from v2.case_engine.schema import COLLECTIONS
from v2.flags import get as get_flag

router = APIRouter(prefix="/v2/cases", tags=["v2-cases"])


def _guard():
    if not get_flag("CASE_ENGINE").observable():
        raise HTTPException(status_code=503, detail="v2 case engine disabled")


class CaseCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    tags: list[str] = Field(default_factory=list)


class CaseOut(BaseModel):
    id: str
    name: str
    tags: list[str]
    status: str
    created_at: str
    created_by: str
    event_count: int = 0
    entity_count: int = 0


def _to_out(doc: dict[str, Any]) -> CaseOut:
    return CaseOut(
        id=doc["_id"],
        name=doc.get("name", ""),
        tags=doc.get("tags", []),
        status=doc.get("status", "open"),
        created_at=doc.get("created_at").isoformat() if isinstance(doc.get("created_at"), datetime) else str(doc.get("created_at")),
        created_by=doc.get("created_by", ""),
        event_count=doc.get("event_count", 0),
        entity_count=doc.get("entity_count", 0),
    )


@router.post("", response_model=CaseOut)
async def create_case(body: CaseCreate, user=Depends(require_admin)) -> Any:
    _guard()
    coll = _db[COLLECTIONS["cases"]]
    doc = {
        "_id": f"case_{uuid.uuid4().hex}",
        "name": body.name,
        "tags": list(body.tags),
        "status": "open",
        "created_at": datetime.now(timezone.utc),
        "created_by": user.get("email") if isinstance(user, dict) else "admin",
        "event_count": 0,
        "entity_count": 0,
    }
    await coll.insert_one(doc)
    return _to_out(doc)


@router.get("")
async def list_cases(limit: int = 50, _: dict = Depends(require_admin)) -> list[CaseOut]:
    _guard()
    coll = _db[COLLECTIONS["cases"]]
    cursor = coll.find({}, sort=[("created_at", -1)]).limit(max(1, min(limit, 200)))
    return [_to_out(d) async for d in cursor]


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(case_id: str, _: dict = Depends(require_admin)) -> Any:
    _guard()
    coll = _db[COLLECTIONS["cases"]]
    doc = await coll.find_one({"_id": case_id})
    if not doc:
        raise HTTPException(status_code=404, detail="case not found")
    return _to_out(doc)


@router.delete("/{case_id}")
async def delete_case(case_id: str, _: dict = Depends(require_admin)) -> dict[str, Any]:
    """Soft-delete: mark case as `deleted`. Never dropped from storage."""
    _guard()
    coll = _db[COLLECTIONS["cases"]]
    res = await coll.update_one({"_id": case_id}, {"$set": {"status": "deleted"}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="case not found")
    return {"ok": True, "case_id": case_id, "status": "deleted"}
