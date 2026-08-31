"""Phase 2 · Bulk operations + Saved Views.

Two owner-locked capabilities on top of the Investigation-Aware
Incident Queue:

  1. Bulk assign · bulk state-transition (assignee + state only).
     Every mutation records an audit row into ``xdr_audit_log`` and
     NEVER touches canonical evidence.

  2. Per-user Saved Views (name + filters + sort + column set + lens).
     Full CRUD; shareable via saved-view id.

Both endpoints treat the queue as a read model on top of canonical
evidence.  No investigation engine is ever invoked here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user_optional, sync_collection

router = APIRouter(prefix="/xdr", tags=["xdr-queue-ops"])

_incidents  = sync_collection("workspace_cases")
_audit      = sync_collection("xdr_audit_log")
_saved      = sync_collection("xdr_saved_views")

# Lifecycle states allowed for bulk transitions — mirrors
# `LIFECYCLE_TRANSITIONS` in incidents.py.  Kept explicit here so a
# future policy change does not silently widen bulk scope.
_BULK_STATES = {"new", "in_progress", "on_hold", "resolved", "closed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════
# BULK · assignee
# ═══════════════════════════════════════════════════════════════════
class BulkAssignBody(BaseModel):
    incident_ids: List[str] = Field(..., min_length=1, max_length=200)
    assignee:     Optional[str] = None       # None = unassign
    reason:       Optional[str] = Field(None, max_length=200)


@router.post("/incidents/bulk/assign")
async def bulk_assign(body: BulkAssignBody,
                        user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    actor = (user or {}).get("email") or "anonymous"
    now = _now()
    new_assignee = (body.assignee or "").strip() or None

    updated_ids: List[str] = []
    skipped: List[Dict[str, Any]] = []
    audit_rows: List[Dict[str, Any]] = []

    for iid in body.incident_ids:
        doc = _incidents.find_one({"id": iid},
                                     {"_id": 0, "id": 1, "incident_assignee": 1})
        if not doc:
            skipped.append({"id": iid, "reason": "not_found"})
            continue
        before = doc.get("incident_assignee")
        if before == new_assignee:
            skipped.append({"id": iid, "reason": "no_change"})
            continue
        _incidents.update_one(
            {"id": iid},
            {"$set": {"incident_assignee": new_assignee, "updated_at": now}},
        )
        updated_ids.append(iid)
        audit_rows.append({
            "id":          str(uuid.uuid4()),
            "at":          now,
            "actor":       actor,
            "action":      "bulk_assign",
            "incident_id": iid,
            "before":      {"assignee": before},
            "after":       {"assignee": new_assignee},
            "reason":      body.reason,
            "canonical_evidence_touched": False,
        })
    if audit_rows:
        _audit.insert_many(audit_rows)

    return {
        "generated_at":  now,
        "actor":         actor,
        "action":        "bulk_assign",
        "updated_count": len(updated_ids),
        "updated_ids":   updated_ids,
        "skipped":       skipped,
        "audit_written": len(audit_rows),
    }


# ═══════════════════════════════════════════════════════════════════
# BULK · state
# ═══════════════════════════════════════════════════════════════════
class BulkStateBody(BaseModel):
    incident_ids: List[str] = Field(..., min_length=1, max_length=200)
    target_state: str
    note:         Optional[str] = Field(None, max_length=200)


@router.post("/incidents/bulk/state")
async def bulk_state(body: BulkStateBody,
                        user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    actor = (user or {}).get("email") or "anonymous"
    now = _now()
    if body.target_state not in _BULK_STATES:
        raise HTTPException(status_code=400,
                              detail={"error": "invalid_state",
                                        "state": body.target_state,
                                        "allowed": sorted(_BULK_STATES)})

    updated_ids: List[str] = []
    skipped: List[Dict[str, Any]] = []
    audit_rows: List[Dict[str, Any]] = []

    for iid in body.incident_ids:
        doc = _incidents.find_one({"id": iid},
                                     {"_id": 0, "id": 1, "incident_state": 1,
                                        "incident_state_history": 1})
        if not doc:
            skipped.append({"id": iid, "reason": "not_found"})
            continue
        before = doc.get("incident_state") or "new"
        if before == body.target_state:
            skipped.append({"id": iid, "reason": "no_change"})
            continue
        history = list(doc.get("incident_state_history") or [])
        history.append({"at": now, "actor": actor,
                          "from_state": before, "to_state": body.target_state,
                          "note": body.note})
        _incidents.update_one(
            {"id": iid},
            {"$set": {"incident_state": body.target_state,
                        "incident_state_history": history,
                        "updated_at": now}},
        )
        updated_ids.append(iid)
        audit_rows.append({
            "id":          str(uuid.uuid4()),
            "at":          now,
            "actor":       actor,
            "action":      "bulk_state",
            "incident_id": iid,
            "before":      {"state": before},
            "after":       {"state": body.target_state},
            "reason":      body.note,
            "canonical_evidence_touched": False,
        })
    if audit_rows:
        _audit.insert_many(audit_rows)

    return {
        "generated_at":  now,
        "actor":         actor,
        "action":        "bulk_state",
        "target_state":  body.target_state,
        "updated_count": len(updated_ids),
        "updated_ids":   updated_ids,
        "skipped":       skipped,
        "audit_written": len(audit_rows),
    }


# ═══════════════════════════════════════════════════════════════════
# SAVED VIEWS · full CRUD
# ═══════════════════════════════════════════════════════════════════
class SavedViewBody(BaseModel):
    name:            str = Field(..., min_length=1, max_length=80)
    filters:         Dict[str, Any] = Field(default_factory=dict)
    sort:            Optional[str] = "updated_at"
    order:           Optional[str] = "desc"
    lens:            Optional[str] = None
    visible_columns: List[str] = Field(default_factory=list)


def _view_row(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: d.get(k) for k in ("id", "name", "filters", "sort", "order",
                                          "lens", "visible_columns",
                                          "owner", "created_at", "updated_at")}


@router.get("/saved-views")
async def list_saved_views(user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    owner = (user or {}).get("email")
    q = {"owner": owner} if owner else {"owner": None}
    rows = [_view_row(d) for d in _saved.find(q, {"_id": 0})
                                         .sort("updated_at", -1)]
    return {"views": rows, "count": len(rows), "owner": owner}


@router.get("/saved-views/{view_id}")
async def get_saved_view(view_id: str,
                            user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    owner = (user or {}).get("email")
    d = _saved.find_one({"id": view_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404,
                              detail={"error": "saved_view_not_found"})
    if d.get("owner") != owner:
        raise HTTPException(status_code=403,
                              detail={"error": "forbidden_saved_view"})
    return _view_row(d)


@router.post("/saved-views")
async def create_saved_view(body: SavedViewBody,
                                user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    owner = (user or {}).get("email")
    now = _now()
    doc = {
        "id":              str(uuid.uuid4()),
        "name":            body.name.strip(),
        "filters":         body.filters,
        "sort":            body.sort or "updated_at",
        "order":           body.order or "desc",
        "lens":            body.lens,
        "visible_columns": body.visible_columns,
        "owner":           owner,
        "created_at":      now,
        "updated_at":      now,
    }
    _saved.insert_one(doc)
    doc.pop("_id", None)
    return _view_row(doc)


@router.put("/saved-views/{view_id}")
async def update_saved_view(view_id: str, body: SavedViewBody,
                                user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    owner = (user or {}).get("email")
    d = _saved.find_one({"id": view_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404,
                              detail={"error": "saved_view_not_found"})
    if d.get("owner") != owner:
        raise HTTPException(status_code=403,
                              detail={"error": "forbidden_saved_view"})
    updates = {
        "name":            body.name.strip(),
        "filters":         body.filters,
        "sort":            body.sort or "updated_at",
        "order":           body.order or "desc",
        "lens":            body.lens,
        "visible_columns": body.visible_columns,
        "updated_at":      _now(),
    }
    _saved.update_one({"id": view_id}, {"$set": updates})
    d = _saved.find_one({"id": view_id}, {"_id": 0})
    return _view_row(d)


@router.delete("/saved-views/{view_id}")
async def delete_saved_view(view_id: str,
                                user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    owner = (user or {}).get("email")
    d = _saved.find_one({"id": view_id}, {"_id": 0})
    if not d:
        raise HTTPException(status_code=404,
                              detail={"error": "saved_view_not_found"})
    if d.get("owner") != owner:
        raise HTTPException(status_code=403,
                              detail={"error": "forbidden_saved_view"})
    _saved.delete_one({"id": view_id})
    return {"deleted": view_id}
