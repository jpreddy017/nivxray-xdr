"""GATE 11 · saved investigation views.

A saved view stores the QUERY, never the results. Opening one re-queries
the current evidence the operator is authorised for, so a view can never
become a stale private copy of someone else's data.

Sharing is a `view_id` in the URL and nothing else: no filters, no
tokens, no evidence. Tenant authorisation is applied on every read, so a
shared link handed to someone outside the tenant resolves to a refusal,
not to data.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from deps import db as _db, get_current_user
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter(prefix="/edr/saved-views",
                   tags=["nivxforge-edr-saved-views"])

VIEWS = "edr_saved_views"
SURFACES = ("events", "audit")

#: Only query state may be persisted. Anything else — an event id, a
#: payload, a token — would turn a view into a copy of evidence.
ALLOWED_FILTERS = ("endpoint_id", "hostname", "activity", "detection",
                   "payload_sha256", "q", "source_kind", "trust_state",
                   "telemetry_quality", "category", "actor", "action")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


def _who(user: dict) -> str:
    return (user or {}).get("email") or "unknown"


async def ensure_indexes(db: Any) -> None:
    await db[VIEWS].create_index([("tenant_id", 1), ("view_id", 1)],
                                 unique=True, name="uniq_tenant_view")
    await db[VIEWS].create_index([("tenant_id", 1), ("surface", 1)],
                                 name="tenant_surface")


class TimeSemantics(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: RELATIVE re-anchors to now on every open — which is what an
    #: operator means by "last 24 hours". ABSOLUTE pins a window, which
    #: is what they mean when handing over an incident.
    mode: str = Field(default="RELATIVE", pattern="^(RELATIVE|ABSOLUTE)$")
    hours: Optional[int] = Field(default=24, ge=1, le=24 * 365)
    since: Optional[str] = None
    until: Optional[str] = None


class SavedViewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    surface: str = Field(default="events")
    filters: Dict[str, Any] = Field(default_factory=dict)
    sort: str = Field(default="desc", pattern="^(asc|desc)$")
    columns: List[str] = Field(default_factory=list)
    time: TimeSemantics = Field(default_factory=TimeSemantics)
    shared: bool = False
    description: Optional[str] = Field(default=None, max_length=500)


def _clean_filters(filters: Dict[str, Any]) -> Dict[str, Any]:
    rejected = [k for k in filters if k not in ALLOWED_FILTERS]
    if rejected:
        raise HTTPException(422, detail={
            "code": "FILTER_NOT_PERSISTABLE", "rejected": rejected,
            "allowed": list(ALLOWED_FILTERS),
            "reason": ("a saved view stores query state only; anything else "
                       "would make it a copy of evidence rather than a "
                       "question about it")})
    return {k: v for k, v in filters.items() if v not in (None, "", [])}


def _public(doc: Dict[str, Any], user: dict) -> Dict[str, Any]:
    return {**doc, "is_owner": doc.get("owner") == _who(user),
            "deep_link": f"/edr/{doc.get('surface')}?view={doc.get('view_id')}"}


@router.get("")
async def list_views(surface: Optional[str] = Query(None),
                     user: dict = Depends(get_current_user),
                     tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Views this operator may open: their own, plus shared ones."""
    tenant = _scoped(tenant_id, user)
    me = _who(user)
    q: Dict[str, Any] = {"tenant_id": tenant,
                         "$or": [{"owner": me}, {"shared": True}]}
    if surface:
        q["surface"] = surface
    rows = [_public(v, user) async for v in _db[VIEWS].find(
        q, {"_id": 0}).sort("updated_at", -1).limit(200)]
    return {"tenant_id": tenant, "views": rows, "count": len(rows),
            "surfaces": list(SURFACES),
            "contract": ("a saved view stores the query, never the results. "
                         "Opening it re-queries the evidence you are "
                         "currently authorised for.")}


@router.post("")
async def create_view(body: SavedViewBody,
                      user: dict = Depends(get_current_user),
                      tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    if body.surface not in SURFACES:
        raise HTTPException(422, detail={"code": "SURFACE_INVALID",
                                         "allowed": list(SURFACES)})
    doc = {"view_id": "vw_" + secrets.token_hex(8), "tenant_id": tenant,
           "name": body.name, "surface": body.surface,
           "filters": _clean_filters(body.filters), "sort": body.sort,
           "columns": list(body.columns), "time": body.time.model_dump(),
           "shared": body.shared, "description": body.description,
           "owner": _who(user), "created_at": _now(), "updated_at": _now()}
    await _db[VIEWS].insert_one(dict(doc))
    doc.pop("_id", None)
    return _public(doc, user)


@router.get("/{view_id}")
async def get_view(view_id: str, user: dict = Depends(get_current_user),
                   tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Resolve a shared deep link.

    The tenant predicate is applied here, which is why a shared URL can
    never bypass authorisation: a view in another tenant simply does not
    resolve.
    """
    tenant = _scoped(tenant_id, user)
    doc = await _db[VIEWS].find_one({"tenant_id": tenant, "view_id": view_id},
                                    {"_id": 0})
    if doc is None:
        raise HTTPException(404, detail={
            "code": "VIEW_NOT_FOUND",
            "reason": ("no such view in the customer you are authorised for. "
                       "A shared link carries only a view id and never "
                       "grants access to another customer's evidence")})
    if not doc.get("shared") and doc.get("owner") != _who(user):
        raise HTTPException(403, detail={
            "code": "VIEW_NOT_SHARED",
            "reason": "this view is private to its owner"})
    return _public(doc, user)


@router.patch("/{view_id}")
async def update_view(view_id: str, body: SavedViewBody,
                      user: dict = Depends(get_current_user),
                      tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    doc = await _db[VIEWS].find_one({"tenant_id": tenant, "view_id": view_id},
                                    {"_id": 0})
    if doc is None:
        raise HTTPException(404, detail={"code": "VIEW_NOT_FOUND"})
    if doc.get("owner") != _who(user):
        raise HTTPException(403, detail={
            "code": "NOT_VIEW_OWNER",
            "reason": "only the operator who saved a view may change it"})
    update = {"name": body.name, "filters": _clean_filters(body.filters),
              "sort": body.sort, "columns": list(body.columns),
              "time": body.time.model_dump(), "shared": body.shared,
              "description": body.description, "updated_at": _now()}
    await _db[VIEWS].update_one({"tenant_id": tenant, "view_id": view_id},
                                {"$set": update})
    return _public({**doc, **update}, user)


@router.delete("/{view_id}")
async def delete_view(view_id: str, user: dict = Depends(get_current_user),
                      tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    doc = await _db[VIEWS].find_one({"tenant_id": tenant, "view_id": view_id},
                                    {"_id": 0, "owner": 1})
    if doc is None:
        raise HTTPException(404, detail={"code": "VIEW_NOT_FOUND"})
    if doc.get("owner") != _who(user):
        raise HTTPException(403, detail={"code": "NOT_VIEW_OWNER"})
    await _db[VIEWS].delete_one({"tenant_id": tenant, "view_id": view_id})
    return {"view_id": view_id, "deleted": True,
            "note": ("only the query was deleted; no evidence is affected "
                     "because a view never held any")}
