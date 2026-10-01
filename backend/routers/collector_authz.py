"""Collector Auth P0 · the ONE fail-closed guard for `/api/xdr/collector/*`.

The ladder, in this order, with no step skippable:

    AUTHENTICATION  ->  PERMISSION  ->  TENANT AUTHORITY  ->  CAPABILITY

Refusals:
    undeclared route                 -> 403 COLLECTOR_ROUTE_UNCLASSIFIED
    no credential                    -> 403 ACCESS_DENIED / unauthenticated
    authenticated, wrong role        -> 403 ACCESS_DENIED
    missing tenant (HUMAN_CONTROL)   -> 403 TENANT_REQUIRED
    unknown tenant                   -> 403 TENANT_NOT_FOUND
    non-ACTIVE tenant                -> 403 TENANT_NOT_ACTIVE
    TEST_PLANE without the flag      -> 403 TEST_PLANE_DISABLED

A valid `ten_*` is an identifier, not a credential — `GET /api/xdr/tenants`
returns them — so a tenant can never satisfy the authentication step. The
accepted tenant contract is untouched; authentication is added IN FRONT of it.

No new authority is introduced. `routers.xdr_rbac.require_permission` is the
existing dual-principal (JWT / `X-XDR-API-Key`) gate, `collectors` is already
an RBAC resource with the needed actions, and
`services.tenant_registry.authoritative` is already this plane's tenant
authority. The webhook keeps its per-connector HMAC and never sees a JWT.
"""
from __future__ import annotations

import os

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from framework.route_classification import (HUMAN_CONTROL, MACHINE,  # noqa: E402
                                            PRODUCT_METADATA, TEST_PLANE,
                                            classify, relative_path)
from routers.xdr_rbac import require_permission
from services import tenant_registry

TENANT_HEADER = "X-Tenant-Id"

#: Deployment flag that must be explicitly set for the TEST_PLANE injection
#: route to be callable at all. Absent (production) => refused.
TEST_PLANE_FLAG = "NIVX_COLLECTOR_TEST_PLANE"

_bearer_optional = HTTPBearer(auto_error=False)


def _mount_prefix(request: Request) -> str:
    return getattr(request.app.state, "collector_mount_prefix", "") or ""


async def collector_guard(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer_optional),
) -> str:
    """Attached at `include_router` time to every collector router."""
    route = request.scope.get("route")
    full_path = getattr(route, "path", "") or request.url.path
    rel = relative_path(full_path, _mount_prefix(request))
    declared = classify(request.method, rel)

    if declared is None:
        # A route nobody classified is refused rather than served. This is the
        # clause that makes "somebody adds /collector/new-feature" safe.
        raise HTTPException(status_code=403, detail={
            "code": "COLLECTOR_ROUTE_UNCLASSIFIED",
            "reason": ("this collector operation is not declared in "
                       "framework.route_classification."
                       "COLLECTOR_ROUTE_CLASSIFICATION; the collector plane "
                       "fails closed for undeclared routes"),
            "operation": f"{request.method} {rel}"})

    route_class, permission = declared

    # The vendor webhook owns its own machine credential (per-connector HMAC).
    if route_class == MACHINE:
        return MACHINE

    # 1 · AUTHENTICATION + 2 · PERMISSION (existing dual-principal gate).
    await require_permission(permission)(request, creds)

    # 3 · TENANT AUTHORITY — only for operations that act on tenant data.
    if route_class == HUMAN_CONTROL:
        raw = (request.headers.get(TENANT_HEADER) or "").strip()
        try:
            tenant_registry.authoritative(raw, purpose="xdr.collector")
        except tenant_registry.TenantRegistryError as e:
            raise HTTPException(status_code=e.http, detail=e.detail()) from None

    if route_class == TEST_PLANE:
        if os.environ.get(TEST_PLANE_FLAG) != "1":
            raise HTTPException(status_code=403, detail={
                "code": "TEST_PLANE_DISABLED",
                "reason": ("synthetic injection is not enabled on this "
                           f"deployment ({TEST_PLANE_FLAG} is not set); "
                           "fabricated evidence cannot enter the canonical "
                           "pipeline")})

    return route_class
