"""Forensic snapshot routes · request one, list history, read one job.

Customer scope comes from the server-resolved acting tenant, never from the
body: a job id is not a capability, so reading one from another customer is a
404 in that customer's own words rather than a cross-tenant read.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from deps import db as _db, get_current_user
from edr_plane import authority as authz
from edr_plane import response as resp
from routers.edr_tenancy import edr_scope, edr_tenant
from services.edr import forensic_snapshots as svc

router = APIRouter(prefix="/edr/forensics", tags=["nivxforge-edr-forensics"])


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
