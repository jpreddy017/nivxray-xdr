"""Lane H · Event Explorer — the authoritative, source-agnostic event API.

Reads canonical evidence only. No fixtures, no synthesised rows, and no
Windows-specific schema: the same contract serves every source whose DSM
produces canonical evidence.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from routers.xdr_rbac import require_permission
from services import event_search

router = APIRouter(prefix="/api/xdr/events", tags=["xdr-events"])

READ = Depends(require_permission("evidence.read"))


def _tenant(req: Request) -> str:
    from routers.xdr_rbac import resolve_principal
    tenant, _, _ = resolve_principal(req)
    return tenant


def _adb():
    from deps import db
    return db


@router.get("/search", dependencies=[READ])
async def search_events(
        request: Request,
        q: str | None = Query(None, description="free text over canonical fields"),
        host: str | None = Query(None),
        channel: str | None = Query(None),
        source: str | None = Query(None),
        event_id: str | None = Query(None, description="source event id"),
        user: str | None = Query(None),
        process: str | None = Query(None),
        level: str | None = Query(None),
        dsm_id: str | None = Query(None),
        time_from: str | None = Query(None),
        time_to: str | None = Query(None),
        has_detection: bool | None = Query(None),
        limit: int = Query(100, ge=1, le=event_search.MAX_LIMIT),
        offset: int = Query(0, ge=0)):
    data = await event_search.search(
        _adb(), tenant_id=_tenant(request), limit=limit, offset=offset,
        q=q, host=host, channel=channel, source=source, event_id=event_id,
        user=user, process=process, level=level, dsm_id=dsm_id,
        time_from=time_from, time_to=time_to, has_detection=has_detection)
    return {"ok": True, "data": data}


@router.get("/facets", dependencies=[READ])
async def event_facets(request: Request):
    data = await event_search.facets(_adb(), _tenant(request))
    return {"ok": True, "data": data}


@router.get("/{event_id}", dependencies=[READ])
async def event_detail(event_id: str, request: Request):
    data = await event_search.detail(_adb(), tenant_id=_tenant(request),
                                     event_id=event_id)
    if data is None:
        raise HTTPException(404, detail={"code": "EVENT_NOT_FOUND",
                                         "event_id": event_id})
    return {"ok": True, "data": data}
