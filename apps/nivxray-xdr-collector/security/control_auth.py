"""Fail-closed authentication for the Collector management plane.

Only the authoritative backend service may manage collectors.  The backend sends
an authenticated tenant context after validating the user.  Public webhook
receivers are excluded here because they authenticate each payload with HMAC.
"""
from __future__ import annotations

import hmac
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


def _dev_bypass() -> bool:
    env = os.environ.get("XDR_COLLECTOR_ENV", "production").lower()
    flag = os.environ.get("XDR_COLLECTOR_ALLOW_UNAUTHENTICATED_DEV", "0").lower()
    return env in {"development", "test"} and flag in {"1", "true", "yes"}


class CollectorControlAuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/xdr/") or path.startswith("/api/xdr/webhooks/"):
            return await call_next(request)
        if _dev_bypass():
            return await call_next(request)

        expected = os.environ.get("COLLECTOR_CONTROL_SERVICE_CREDENTIAL", "")
        if not expected:
            return JSONResponse(503, content={"detail": {
                "error": "collector_control_auth_not_configured"
            }})
        header = request.headers.get("Authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not supplied or not hmac.compare_digest(
            supplied.encode(), expected.encode()
        ):
            return JSONResponse(
                401, headers={"WWW-Authenticate": "Bearer"},
                content={"detail": {"error": "invalid_service_credential"}},
            )

        tenant = request.headers.get("X-Authenticated-Tenant", "").strip()
        if not tenant:
            return JSONResponse(403, content={"detail": {
                "error": "authenticated_tenant_required"
            }})

        # Replace any untrusted X-Tenant-Id with the backend-authenticated tenant.
        filtered = [(k, v) for k, v in request.scope["headers"]
                    if k.lower() != b"x-tenant-id"]
        filtered.append((b"x-tenant-id", tenant.encode("utf-8")))
        request.scope["headers"] = filtered
        request.state.tenant_id = tenant
        request.state.authenticated_service = "authoritative-backend"
        return await call_next(request)
