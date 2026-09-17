"""Authoritative tenancy control plane — organizations and tenants.

The ONLY way tenancy comes into existence. Gated by the `tenants.manage` /
`tenants.read` permissions that the RBAC vocabulary already reserved
(`xdr_rbac._PERMISSIONS`) and that previously had no route behind them.

Nothing here is seeded at startup and nothing is created as a side effect of a
deployment: code deployment and production bootstrap stay separate auditable
operations.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission
from services import tenant_registry as reg

organizations_router = APIRouter(prefix="/api/xdr/organizations",
                                 tags=["xdr-tenancy"])
tenants_router = APIRouter(prefix="/api/xdr/tenants", tags=["xdr-tenancy"])


def _actor(request: Request) -> str:
    """Attribution for the audit record.

    Machine principals are stamped on `request.state` by
    `authenticate_api_key()`. For a human principal the identity is read from
    the VERIFIED bearer token (same secret/algorithm as `deps.get_current_user`
    — a client-supplied `X-Principal-Id` header is deliberately not trusted
    here, which is also the direction B3 will take for the ingest path).
    """
    pid = getattr(request.state, "principal_id", None)
    if pid:
        return str(pid)
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        try:
            import jwt as _jwt
            from deps import JWT_ALG, JWT_SECRET
            claims = _jwt.decode(auth.split(None, 1)[1], JWT_SECRET,
                                 algorithms=[JWT_ALG])
            if claims.get("sub"):
                return str(claims["sub"])
        except Exception:                                  # noqa: BLE001
            pass
    return "unknown"


def _fail(e: reg.TenantRegistryError):
    raise HTTPException(status_code=e.http, detail=e.detail())


class CreateOrganizationBody(BaseModel):
    slug: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    kind: str = Field(description=f"one of {list(reg.ORG_KINDS)}")


class CreateTenantBody(BaseModel):
    organization_id: str = Field(min_length=1, max_length=64)
    slug: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    kind: str = Field(description=f"one of {list(reg.TENANT_KINDS)}")
    products: list[str] = Field(default_factory=list)


class StateBody(BaseModel):
    state: str = Field(description=f"one of {list(reg.STATES)}")


@organizations_router.post(
    "", dependencies=[Depends(require_permission("tenants.manage"))])
def create_organization(body: CreateOrganizationBody, request: Request):
    try:
        doc = reg.create_organization(slug=body.slug,
                                      display_name=body.display_name,
                                      kind=body.kind,
                                      created_by=_actor(request))
    except reg.TenantRegistryError as e:
        _fail(e)
    audit = emit_audit(tenant_id=doc["id"], principal_id=_actor(request),
                       principal_kind="user", action="ORGANIZATION_CREATED",
                       resource_kind="organization", resource_id=doc["id"],
                       after={"slug": doc["slug"], "kind": doc["kind"]})
    return {"ok": True, "data": doc, "audit_ref": audit["id"]}


@organizations_router.get(
    "", dependencies=[Depends(require_permission("tenants.read"))])
def list_organizations(limit: int = Query(200, ge=1, le=1000)):
    rows = reg.list_organizations(limit)
    return {"ok": True, "data": {"organizations": rows, "count": len(rows)}}


@organizations_router.put(
    "/{org_id}/state",
    dependencies=[Depends(require_permission("tenants.manage"))])
def set_organization_state(org_id: str, body: StateBody, request: Request):
    try:
        doc = reg.set_state("organization", org_id, body.state)
    except reg.TenantRegistryError as e:
        _fail(e)
    emit_audit(tenant_id=org_id, principal_id=_actor(request),
               principal_kind="user", action="ORGANIZATION_STATE_CHANGED",
               resource_kind="organization", resource_id=org_id,
               after={"state": body.state})
    return {"ok": True, "data": doc}


@tenants_router.post(
    "", dependencies=[Depends(require_permission("tenants.manage"))])
def create_tenant(body: CreateTenantBody, request: Request):
    try:
        doc = reg.create_tenant(organization_id=body.organization_id,
                                slug=body.slug,
                                display_name=body.display_name,
                                kind=body.kind, products=body.products,
                                created_by=_actor(request))
    except reg.TenantRegistryError as e:
        _fail(e)
    audit = emit_audit(tenant_id=doc["id"], principal_id=_actor(request),
                       principal_kind="user", action="TENANT_CREATED",
                       resource_kind="tenant", resource_id=doc["id"],
                       after={"organization_id": doc["organization_id"],
                              "slug": doc["slug"], "kind": doc["kind"],
                              "products": doc["products"]})
    return {"ok": True, "data": doc, "audit_ref": audit["id"]}


@tenants_router.get(
    "", dependencies=[Depends(require_permission("tenants.read"))])
def list_tenants(organization_id: str | None = Query(None),
                 limit: int = Query(500, ge=1, le=1000)):
    rows = reg.list_tenants(organization_id, limit)
    return {"ok": True, "data": {"tenants": rows, "count": len(rows),
                                 "enforcing": reg.enforcing()}}


@tenants_router.get(
    "/{tenant_id}", dependencies=[Depends(require_permission("tenants.read"))])
def get_tenant(tenant_id: str):
    doc = reg.get_tenant(tenant_id)
    if doc is None:
        raise HTTPException(status_code=404, detail={
            "code": "TENANT_NOT_FOUND", "tenant_id": tenant_id})
    return {"ok": True, "data": doc}


@tenants_router.put(
    "/{tenant_id}/state",
    dependencies=[Depends(require_permission("tenants.manage"))])
def set_tenant_state(tenant_id: str, body: StateBody, request: Request):
    try:
        doc = reg.set_state("tenant", tenant_id, body.state)
    except reg.TenantRegistryError as e:
        _fail(e)
    emit_audit(tenant_id=tenant_id, principal_id=_actor(request),
               principal_kind="user", action="TENANT_STATE_CHANGED",
               resource_kind="tenant", resource_id=tenant_id,
               after={"state": body.state})
    return {"ok": True, "data": doc}
