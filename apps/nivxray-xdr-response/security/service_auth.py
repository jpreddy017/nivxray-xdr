"""Fail-closed service authentication for the Response Engine.

The Response Engine is not a browser/user trust boundary.  Only the
authoritative backend may call /api/respond/*, using a distinct deployment
secret.  A bypass exists solely when XDR_RESPOND_ALLOW_UNAUTHENTICATED_DEV=1
and XDR_RESPOND_ENV is explicitly "development" or "test".
"""
from __future__ import annotations

import hmac
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


def _dev_bypass() -> bool:
    env = os.environ.get("XDR_RESPOND_ENV", "production").lower()
    flag = os.environ.get("XDR_RESPOND_ALLOW_UNAUTHENTICATED_DEV", "0").lower()
    return env in {"development", "test"} and flag in {"1", "true", "yes"}


class ServiceAuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/respond/"):
            return await call_next(request)
        if _dev_bypass():
            request.state.authenticated_service = "explicit-dev-bypass"
            return await call_next(request)

        expected = os.environ.get("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "")
        if not expected:
            return JSONResponse(status_code=503, content={
                "detail": {
                    "error": "service_auth_not_configured",
                    "reason": "Response Engine is not ready for trusted dispatch",
                }
            })

        header = request.headers.get("Authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not supplied or not hmac.compare_digest(
            supplied.encode("utf-8"), expected.encode("utf-8")
        ):
            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
                content={"detail": {"error": "invalid_service_credential"}},
            )

        request.state.authenticated_service = "authoritative-backend"
        request.state.correlation_id = request.headers.get("X-Correlation-ID")
        return await call_next(request)
