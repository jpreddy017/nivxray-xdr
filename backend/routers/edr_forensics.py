"""Forensic snapshot routes · request one, list history, read one job.

Customer scope comes from the server-resolved acting tenant, never from the
body: a job id is not a capability, so reading one from another customer is a
404 in that customer's own words rather than a cross-tenant read.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from routers.edr_analyzer import router as analyzer_router
from pydantic import BaseModel, ConfigDict

from deps import db as _db, get_current_user
from edr_plane import authority as authz
from edr_plane import response as resp
from routers.edr_tenancy import edr_scope, edr_tenant
from services.edr import forensic_snapshots as svc
from services.edr import live_query as lq

router = APIRouter(prefix="/edr/forensics", tags=["nivxforge-edr-forensics"])

board_router = APIRouter(prefix="/edr/dashboard", tags=["nivxforge-edr-dashboard"])


@board_router.get("/fleet")
async def dashboard_fleet(user: dict = Depends(get_current_user),
                          tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    from services.edr import dashboard as board_svc
    return {"ok": True, "tenant_id": tenant_id,
            "fleet": board_svc.fleet_status(tenant_id)}


@board_router.get("/board")
async def dashboard_board(start: str, end: str, sha256: str | None = None,
                          path_contains: str | None = None,
                          activity: str | None = None, limit: int = 100,
                          user: dict = Depends(get_current_user),
                          tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    from services.edr import dashboard as board_svc
    return board_svc.board(tenant_id, start=start, end=end, sha256=sha256,
                           path_contains=path_contains, activity=activity,
                           limit=limit)


class SnapshotBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str
    reason: str = ""


@router.post("/snapshots")
async def request_snapshot(body: SnapshotBody,
                           user: dict = Depends(get_current_user),
                           tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    requester = str(user.get("email") or user.get("sub") or "user")
    try:
        decision = await authz.authorize(
            verb=svc.ACTION, tenant_id=tenant_id,
            endpoint_id=body.endpoint_id, requester=requester,
            session_role=user.get("role"), db=_db)
    except authz.AuthorityError as e:
        raise HTTPException(status_code=e.http, detail=e.as_detail()) from None
    try:
        return await svc.request(_db, tenant_id=tenant_id,
                                 endpoint_id=body.endpoint_id,
                                 requested_by=requester, reason=body.reason,
                                 authority=decision)
    except resp.ResponseError as e:
        raise HTTPException(status_code=e.http,
                            detail={"error": e.code,
                                    "reason": e.reason}) from None


@router.get("/snapshots")
async def list_snapshots(endpoint_id: str | None = None, limit: int = 50,
                         user: dict = Depends(get_current_user),
                         tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    return await svc.list_jobs(_db, tenant_id=tenant_id,
                               endpoint_id=endpoint_id, limit=limit)


@router.get("/snapshots/{job_id}")
async def get_snapshot(job_id: str, user: dict = Depends(get_current_user),
                       tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    job = await svc.get_job(_db, tenant_id=tenant_id, job_id=job_id)
    if not job:
        raise HTTPException(
            status_code=404,
            detail={"error": "SNAPSHOT_NOT_FOUND",
                    "reason": f"no forensic snapshot {job_id} exists in "
                              f"{tenant_id}. A job id is not a capability: a "
                              f"job belonging to another customer is not "
                              f"readable here."})
    return job


# ── Live Query ──────────────────────────────────────────────────────────────
# One read-only question, answered by the endpoint. It shares the response
# plane with snapshots, so a query id is a command id and the same customer
# binding applies: a query id is not a capability.
live = APIRouter(prefix="/edr/live-query", tags=["nivxforge-edr-live-query"])


class QueryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str
    process_name: str


@live.post("/queries")
async def run_query(body: QueryBody, user: dict = Depends(get_current_user),
                    tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    requester = str(user.get("email") or user.get("sub") or "user")
    try:
        decision = await authz.authorize(
            verb=lq.ACTION, tenant_id=tenant_id, endpoint_id=body.endpoint_id,
            requester=requester, session_role=user.get("role"), db=_db)
    except authz.AuthorityError as e:
        raise HTTPException(status_code=e.http, detail=e.as_detail()) from None
    try:
        return await lq.run(_db, tenant_id=tenant_id,
                            endpoint_id=body.endpoint_id,
                            process_name=body.process_name,
                            requested_by=requester, authority=decision)
    except lq.QueryError as e:
        raise HTTPException(status_code=e.http,
                            detail={"error": e.code,
                                    "reason": e.reason}) from None
    except resp.ResponseError as e:
        raise HTTPException(status_code=e.http,
                            detail={"error": e.code,
                                    "reason": e.reason}) from None


@live.get("/queries")
async def list_queries(endpoint_id: str | None = None, limit: int = 50,
                       user: dict = Depends(get_current_user),
                       tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    return await lq.list_queries(_db, tenant_id=tenant_id,
                                 endpoint_id=endpoint_id, limit=limit)


@live.get("/queries/{query_id}")
async def get_query(query_id: str, user: dict = Depends(get_current_user),
                    tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    q = await lq.get_query(_db, tenant_id=tenant_id, query_id=query_id)
    if not q:
        raise HTTPException(
            status_code=404,
            detail={"error": "QUERY_NOT_FOUND",
                    "reason": f"no live query {query_id} exists in "
                              f"{tenant_id}. A query id is not a capability: "
                              f"a query belonging to another customer is not "
                              f"readable here."})
    return q


router.include_router(analyzer_router)
