"""Authorization shim · resolves the collector guard for BOTH mounts.

Landed inside the NivXRay backend the real guard
(`routers.collector_authz.collector_guard`) is importable and enforces
AUTHENTICATION -> PERMISSION -> TENANT AUTHORITY -> CAPABILITY.

In a STANDALONE deployment the backend's identity, RBAC and tenant registry do
not exist, so there is nothing to authenticate against. The shim therefore
FAILS CLOSED: every operation except the HMAC-authenticated webhook is refused.
It does not fall back to "no authentication required" — that fallback is the
defect this closure exists to remove. A standalone operator who needs the
control plane runs it behind the landed backend (or an authenticating proxy),
not open.
"""
from __future__ import annotations

from fastapi import HTTPException, Request

from framework.route_classification import MACHINE, classify, relative_path

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
        raise HTTPException(status_code=403, detail={
            "code": "COLLECTOR_AUTH_UNAVAILABLE",
            "reason": ("this collector is running standalone, where no "
                       "authentication authority, RBAC store or tenant "
                       "registry exists; the control plane fails closed. "
                       "Mount the collector inside the NivXRay backend, or "
                       "front it with an authenticating proxy.")})
