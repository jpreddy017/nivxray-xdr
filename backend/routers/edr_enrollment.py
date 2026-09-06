"""P0-A.2 routes · enrolment control plane + authenticated agent surface.

Two audiences, deliberately separated:

  * `/api/edr/enrollment/*` — ADMIN. Requires a platform user. Mints
    tokens, lists endpoints, rotates and revokes.
  * `/api/edr/agent/*` — the ENDPOINT AGENT. Never a platform user. Uses
    the one-time token, then its durable credential, then its session
    token.

The telemetry route is the payoff of the whole slice: it is authenticated,
and it stamps `AuthenticatedEndpoint.provenance()` onto the immutable raw
event, so the question *"which authenticated endpoint produced this exact
evidence?"* has a recorded answer for every event in the store.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from deps import db as _db, get_current_user
from edr_plane import raw_events as raw
from edr_plane.canonical_bridge import bridge
from edr_plane.contracts.identity import EndpointIdentity
from edr_plane.enrollment import store
from edr_plane.enrollment.identity import AuthenticatedEndpoint
from edr_plane.enrollment import rejection
from edr_plane.enrollment.store import EnrollmentError
from edr_plane.enrollment.transport import (get_authenticated_endpoint,
                                            transport_status)

admin = APIRouter(prefix="/edr/enrollment", tags=["nivxforge-edr-enrollment"])
agent = APIRouter(prefix="/edr/agent", tags=["nivxforge-edr-agent"])


def _tenant(user: dict) -> str:
    return (user or {}).get("customer") or "default"


def _fail(e: EnrollmentError):
    raise HTTPException(status_code=e.status,
                        detail={"code": e.code, "reason": e.reason})


# ── admin control plane ───────────────────────────────────────────

class MintTokenBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Optional[str] = Field(
        default=None, description="Operator note, e.g. 'lab linux box 3'.")
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=86400)


@admin.post("/tokens")
async def mint_token(body: MintTokenBody,
                     user: dict = Depends(get_current_user)) -> dict:
    """Mint a one-time, short-TTL enrolment token.

    The plaintext appears in THIS response and nowhere else — not in
    Mongo, not in a log, and not in any later GET.
    """
    return await store.mint_enrollment_token(
        _db, tenant_id=_tenant(user),
        issued_by=(user or {}).get("email") or "unknown",
        label=body.label, ttl_seconds=body.ttl_seconds)


@admin.get("/tokens")
async def list_tokens(user: dict = Depends(get_current_user)) -> dict:
    rows = await store.list_tokens(_db, tenant_id=_tenant(user))
    return {"tokens": rows, "count": len(rows),
            "note": ("Metadata only. No route returns a token's plaintext "
                     "or its stored digest.")}


@admin.get("/endpoints")
async def list_enrolled(user: dict = Depends(get_current_user)) -> dict:
    rows = await store.list_endpoints(_db, tenant_id=_tenant(user))
    return {
        "endpoints": rows, "count": len(rows),
        "transport": transport_status(),
        "note": ("enrollment_state, credential_state and sensor_state are "
                 "three INDEPENDENT dimensions. An ENROLLED endpoint with "
                 "an ACTIVE credential and sensor_state "
                 "ENROLLED_NEVER_REPORTED has sent nothing — enrolment is "
                 "not evidence of visibility."),
    }


@admin.post("/endpoints/{endpoint_id}/rotate")
async def rotate(endpoint_id: str,
                 user: dict = Depends(get_current_user)) -> dict:
    try:
        return await store.rotate_credential(
            _db, tenant_id=_tenant(user), endpoint_id=endpoint_id,
            rotated_by=(user or {}).get("email") or "unknown")
    except EnrollmentError as e:
        _fail(e)


class RevokeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3,
                        description="Recorded verbatim in the audit record.")


@admin.post("/endpoints/{endpoint_id}/revoke")
async def revoke(endpoint_id: str, body: RevokeBody,
                 user: dict = Depends(get_current_user)) -> dict:
    try:
        return await store.revoke_endpoint(
            _db, tenant_id=_tenant(user), endpoint_id=endpoint_id,
            revoked_by=(user or {}).get("email") or "unknown",
            reason=body.reason)
    except EnrollmentError as e:
        _fail(e)


@admin.get("/rejections")
async def rejections(limit: int = Query(100, le=500),
                     code: Optional[str] = Query(None),
                     user: dict = Depends(get_current_user)) -> dict:
    """The Rejected Sensor Alarm feed.

    Every refused ingest attempt, retained as a security signal an analyst
    can investigate. Never silently dropped, and never eligible to become
    endpoint evidence.
    """
    rows = await rejection.list_rejections(_db, limit=limit, code=code)
    return {"rejections": rows, "count": len(rows),
            "summary": await rejection.rejection_summary(_db)}


# ── agent surface ─────────────────────────────────────────────────

class EnrollBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    enrollment_token: str
    hostname: Optional[str] = None
    platform: Optional[str] = None
    sensor_version: Optional[str] = None
    processor_id: Optional[str] = None
    machine_guid: Optional[str] = None
    device_iid: Optional[str] = None


@agent.post("/enroll")
async def enroll(body: EnrollBody, request: Request) -> dict:
    """Enrol with a one-time token and receive the durable credential.

    `endpoint_id` is MINTED BY THE PLATFORM from durable machine
    attributes (hardware id > machine guid > device_iid > hostname), never
    accepted from the agent. An agent that could name its own endpoint_id
    could impersonate another endpoint's identity — and hostname is last
    in that precedence because it is the only attribute an attacker can
    trivially change.
    """
    try:
        endpoint_id = EndpointIdentity.mint(
            tenant_id=body.tenant_id, processor_id=body.processor_id,
            machine_guid=body.machine_guid, device_iid=body.device_iid,
            hostname=body.hostname)
    except ValueError as e:
        raise HTTPException(status_code=422, detail={
            "code": "NO_DURABLE_IDENTITY", "reason": str(e),
            "required_one_of": ["processor_id", "machine_guid", "device_iid",
                                "hostname"]})
    try:
        return await store.enroll(
            _db, tenant_id=body.tenant_id,
            presented_token=body.enrollment_token, endpoint_id=endpoint_id,
            hostname=body.hostname, platform=body.platform,
            sensor_version=body.sensor_version, device_iid=body.device_iid)
    except EnrollmentError as e:
        await rejection.record_rejection(
            _db, tenant_id=body.tenant_id,
            presented_secret=body.enrollment_token,
            source_ip=(request.client.host if request.client else None),
            code=e.code, reason=e.reason or e.code, path="/api/edr/agent/enroll",
            endpoint_id=endpoint_id)
        _fail(e)


class SessionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    agent_credential: str


@agent.post("/session")
async def open_session(body: SessionBody, request: Request) -> dict:
    """Exchange the durable credential for a short-lived scoped session."""
    try:
        return await store.open_session(
            _db, tenant_id=body.tenant_id,
            agent_credential=body.agent_credential)
    except EnrollmentError as e:
        await rejection.record_rejection(
            _db, tenant_id=body.tenant_id,
            presented_secret=body.agent_credential,
            source_ip=(request.client.host if request.client else None),
            code=e.code, reason=e.reason or e.code,
            path="/api/edr/agent/session")
        _fail(e)


class TelemetryBody(BaseModel):
    """The envelope. Note what is NOT here: no tenant_id and no
    endpoint_id. Both come from the authenticated identity, so an agent
    cannot attribute its telemetry to anyone else."""
    model_config = ConfigDict(extra="forbid")
    payload: str = Field(description="Verbatim sensor payload, preserved "
                                     "byte-for-byte.")
    event_time: Optional[str] = None
    source_kind: str = "sensor"
    sensor_version: Optional[str] = None


@agent.post("/telemetry")
async def ingest(body: TelemetryBody, request: Request,
                 who: AuthenticatedEndpoint = Depends(
                     get_authenticated_endpoint)) -> dict:
    """Authenticated telemetry → immutable raw event.

    This is the live `edr_raw_events` write path. The event is stamped
    AUTHENTICATED with the endpoint, credential and session that produced
    it, which is what makes every downstream trajectory, story and
    response authorisation attributable rather than assumed.
    """
    ev = raw.RawEndpointEvent.build(
        tenant_id=who.tenant_id, source=who.endpoint_id,
        source_kind=body.source_kind, sensor_version=body.sensor_version,
        endpoint_ref=who.endpoint_id, payload=body.payload,
        event_time=body.event_time,
        received_from_ip=(request.client.host if request.client else None),
        trust_state="AUTHENTICATED")
    ev.authentication = who.provenance()
    result = await raw.append(_db, ev)
    await store.mark_reported(_db, tenant_id=who.tenant_id,
                              endpoint_id=who.endpoint_id,
                              at=ev.ingest_time)

    # P0-D · canonical bridge. Only for a NEW event: re-canonicalising a
    # byte-identical duplicate would double-count the same activity.
    canonical = {"canonicalized": False, "reason": "duplicate payload; the "
                 "original event was already canonicalised"}
    if result.get("stored"):
        ep = await store.get_endpoint(_db, tenant_id=who.tenant_id,
                                      endpoint_id=who.endpoint_id) or {}
        canonical = await bridge(
            _db, raw_id=ev.raw_id, tenant_id=who.tenant_id,
            payload=body.payload, endpoint_id=who.endpoint_id,
            hostname=ep.get("hostname"), authentication=who.provenance())

    return {
        **result,
        "endpoint_id": who.endpoint_id,
        "authenticated": True,
        "auth_method": who.auth_method,
        "canonical": canonical,
        "note": ("Raw bytes preserved immutably. The parse outcome is "
                 "APPENDED as a derivation and never overwrites the "
                 "original — a parser failure leaves a retained, replayable "
                 "event."),
    }


@agent.get("/whoami")
async def whoami(who: AuthenticatedEndpoint = Depends(
        get_authenticated_endpoint)) -> dict:
    """Lets an agent (and a test) confirm exactly who the platform
    believes it is, without sending telemetry."""
    ep = await store.get_endpoint(_db, tenant_id=who.tenant_id,
                                  endpoint_id=who.endpoint_id)
    return {"identity": who.model_dump(), "endpoint": ep,
            "transport": transport_status()}
