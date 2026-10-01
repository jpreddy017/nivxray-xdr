"""The pluggable transport/auth boundary.

This is the ONLY module in NivXForge EDR that knows a bearer token exists.
Directive §3 requires that mTLS can replace it later without touching
endpoint identity, the telemetry envelope, the ingestion contracts or any
investigation/response contract — so the seam is drawn here, deliberately
narrow: every authenticator is a callable that returns
`AuthenticatedEndpoint` and nothing else.

`authenticate_mtls` is present as an explicit NOT-IMPLEMENTED stub rather
than absent, because an absent seam is a seam nobody will honour. It
raises `TRANSPORT_NOT_REGISTERED` — the same honest shape the response
plane uses for a missing driver.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request

from .identity import AuthenticatedEndpoint
from .rejection import record_rejection
from .security import PREFIX_SESSION, has_prefix, redact
from .store import EnrollmentError, resolve_session


def _client_ip(request: Request) -> Optional[str]:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _presented(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


async def authenticate_bearer(db: Any, request: Request
                              ) -> AuthenticatedEndpoint:
    """Authenticate a telemetry request from a session token.

    On EVERY failure path this records a rejection security signal before
    raising. Directive §10 / owner decision 4C: an unauthorised sensor
    attempting ingest is itself a signal, and it must never be silently
    dropped.
    """
    token = _presented(request)
    ip = _client_ip(request)

    async def refuse(code: str, status: int, reason: str):
        await record_rejection(
            db, tenant_id=None, presented_secret=token, source_ip=ip,
            code=code, reason=reason, request_id=request.headers.get(
                "x-request-id"), path=str(request.url.path))
        raise HTTPException(status_code=status, detail={
            "code": code, "reason": reason,
            "presented": redact(token),
            "security_signal_recorded": True,
            "honesty_note": (
                "This payload was REFUSED at the trust boundary. It is "
                "retained as a security signal and is NOT endpoint "
                "evidence — it will never enter the EDR evidence, "
                "detection or response pipelines."),
        })

    if not token:
        await refuse("SENSOR_UNAUTHENTICATED", 401,
                     "no bearer session token was presented")
    if not has_prefix(token, PREFIX_SESSION):
        await refuse("SENSOR_UNAUTHENTICATED", 401,
                     "the presented credential is not an endpoint session "
                     "token")
    try:
        resolved = await resolve_session(db, presented=token)
    except EnrollmentError as e:
        await refuse(e.code, e.status, e.reason or e.code)

    session, cred, endpoint = (resolved["session"], resolved["credential"],
                               resolved["endpoint"])
    return AuthenticatedEndpoint(
        tenant_id=session["tenant_id"], endpoint_id=session["endpoint_id"],
        credential_id=cred["credential_id"], session_id=session["session_id"],
        auth_method="bearer_session",
        device_iid=endpoint.get("device_iid"),
        authenticated_at=datetime.now(timezone.utc).isoformat())


async def authenticate_mtls(db: Any, request: Request
                            ) -> AuthenticatedEndpoint:
    """Reserved. Not registered — and says so rather than falling back.

    A silent fallback to bearer here would mean an operator could believe
    mTLS was enforced when it was not, which is worse than no mTLS.
    """
    raise HTTPException(status_code=501, detail={
        "code": "TRANSPORT_NOT_REGISTERED",
        "transport": "mtls",
        "reason": ("mTLS endpoint authentication is not registered. It is a "
                   "planned transport; the identity, envelope and ingestion "
                   "contracts already accommodate it without change."),
    })


#: The active authenticator. Swapping this line is the whole migration.
ACTIVE_TRANSPORT = "bearer_session"

_AUTHENTICATORS = {
    "bearer_session": authenticate_bearer,
    "mtls": authenticate_mtls,
}


async def get_authenticated_endpoint(request: Request
                                     ) -> AuthenticatedEndpoint:
    """FastAPI dependency for any authenticated endpoint-agent route."""
    from deps import db
    return await _AUTHENTICATORS[ACTIVE_TRANSPORT](db, request)


def transport_status() -> dict:
    return {
        "active": ACTIVE_TRANSPORT,
        "registered": [k for k, v in _AUTHENTICATORS.items()
                       if k == ACTIVE_TRANSPORT],
        "reserved": [k for k in _AUTHENTICATORS if k != ACTIVE_TRANSPORT],
        "boundary": ("Endpoint Identity != Authentication Mechanism != "
                     "Transport != Telemetry Envelope. Changing the "
                     "authenticator does not change any of the other three."),
    }
