"""Authorization shim · resolves the collector guard for BOTH mounts.

Landed inside the NivXRay backend the real guard
(`routers.collector_authz.collector_guard`) is importable and enforces
AUTHENTICATION -> PERMISSION -> TENANT AUTHORITY -> CAPABILITY.

Standalone management requires the existing backend-to-collector service
credential and an explicit backend-authenticated tenant. Without that configured
credential it fails closed. Shared handlers enforce resource ownership for both
mounts; a service credential does not grant access to a different request tenant.
Webhooks keep their separate payload authentication boundary.
"""
from __future__ import annotations

import hmac
import os
from fastapi import HTTPException, Request
from framework.tenant_scope import bind_scope

from framework.route_classification import MACHINE, TEST_PLANE, classify, relative_path

try:  # landed inside the NivXRay backend
    from routers.collector_authz import collector_guard  # noqa: F401
    STANDALONE_FAIL_CLOSED = False
except ImportError:  # standalone deployment
    STANDALONE_FAIL_CLOSED = True

    async def collector_guard(request: Request) -> str:  # type: ignore[misc]
        route = request.scope.get("route")
        full_path = getattr(route, "path", "") or request.url.path
        prefix = getattr(request.app.state, "collector_mount_prefix", "") or ""
        declared = classify(request.method, relative_path(full_path, prefix))
        if declared and declared[0] == MACHINE:
            return MACHINE
        expected = os.environ.get('COLLECTOR_CONTROL_SERVICE_CREDENTIAL', '')
        if expected and declared:
            scheme, _, supplied = request.headers.get('Authorization', '').partition(' ')
            if scheme.lower() != 'bearer' or not supplied or not hmac.compare_digest(
                    expected.encode(), supplied.encode()):
                raise HTTPException(401, detail={'code': 'INVALID_SERVICE_CREDENTIAL'})
            tenant = request.headers.get('X-Authenticated-Tenant', '').strip()
            if not tenant:
                raise HTTPException(403, detail={'code': 'AUTHENTICATED_TENANT_REQUIRED'})
            await bind_scope(request, tenant)
            if declared[0] == TEST_PLANE and os.environ.get('NIVX_COLLECTOR_TEST_PLANE') != '1':
                raise HTTPException(403, detail={'code': 'TEST_PLANE_DISABLED'})
            request.state.authenticated_service = 'authoritative-backend'
            return declared[0]
        raise HTTPException(status_code=403, detail={
            "code": "COLLECTOR_AUTH_UNAVAILABLE",
            "reason": ("this collector is running standalone, where no "
                       "authentication authority, RBAC store or tenant "
                       "registry exists; the control plane fails closed. "
                       "Mount the collector inside the NivXRay backend, or "
                       "front it with an authenticating proxy.")})
