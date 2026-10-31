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

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from deps import db as _db, get_current_user
from edr_plane import delivery_counters as counters
from edr_plane import acquisition_integrity as acq_integrity
from edr_plane import raw_events as raw
from edr_plane import processing_queue
from edr_plane.canonical_bridge import bridge
from edr_plane.contracts.identity import EndpointIdentity
from edr_plane.enrollment import store
from edr_plane.enrollment import audit as enrollment_audit
from edr_plane.enrollment.identity import AuthenticatedEndpoint
from edr_plane.enrollment import rejection
from edr_plane.enrollment.security import digest as _digest
from edr_plane.enrollment.store import EnrollmentError
from edr_plane.enrollment.transport import (get_authenticated_endpoint,
                                            transport_status)
from routers.edr_tenancy import edr_tenant
from services import tenant_registry

log = logging.getLogger(__name__)

admin = APIRouter(prefix="/edr/enrollment", tags=["nivxforge-edr-enrollment"])
agent = APIRouter(prefix="/edr/agent", tags=["nivxforge-edr-agent"])


#: P0-FIX-1B · the duplicate registry-only resolver that used to live here
#: (`_tenant(user, req)`) is GONE. It validated the registry but never
#: authorised the principal, so these seven TENANT_SCOPED admin operations
#: were a second, weaker tenant-authorization path. They now consume the ONE
#: canonical authority, `routers.edr_tenancy.edr_tenant`, as a dependency.
#: The SENSOR plane below is unaffected: `_agent_tenant()` derives the tenant
#: from an already-authenticated enrolment/agent credential and reads no
#: caller-supplied header.
def _agent_tenant(tenant_id: str, *, oracle: str) -> str:
    """Tenant presented by a sensor. The one-time token / credential is
    tenant-scoped, so a wrong value already fails to match; the registry adds
    "and it must be a registered, ACTIVE tenant". Enrolment never creates
    tenancy.

    ERROR-ORACLE RULE (P0-A.2): this surface is UNAUTHENTICATED, so the
    registry's own `TENANT_NOT_FOUND` / inactive refusals may not reach
    it — an attacker could otherwise enumerate which tenant ids exist by
    watching 403 against 401, before presenting any credential at all.
    An unregistered tenant is therefore indistinguishable from an
    unknown, expired, reused or foreign token: the caller gets the one
    generic 401. The admin surfaces keep the specific refusal, because
    there the caller has already proven who they are.
    """
    try:
        return tenant_registry.authoritative_required(tenant_id,
                                                      purpose="edr.agent")
    except tenant_registry.TenantRegistryError:
        raise EnrollmentError(oracle, 401, store.GENERIC_TOKEN_FAILURE
                              if oracle == "ENROLLMENT_TOKEN_INVALID"
                              else "agent credential is not valid") from None


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
async def mint_token(body: MintTokenBody, request: Request,
                     user: dict = Depends(get_current_user),
                     tenant_id: str = Depends(edr_tenant)) -> dict:
    """Mint a one-time, short-TTL enrolment token.

    The plaintext appears in THIS response and nowhere else — not in
    Mongo, not in a log, and not in any later GET.
    """
    return await store.mint_enrollment_token(
        _db, tenant_id=tenant_id,
        issued_by=(user or {}).get("email") or "unknown",
        label=body.label, ttl_seconds=body.ttl_seconds)


@admin.get("/tokens")
async def list_tokens(request: Request,
                      user: dict = Depends(get_current_user),
                      tenant_id: str = Depends(edr_tenant)) -> dict:
    rows = await store.list_tokens(_db, tenant_id=tenant_id)
    return {"tokens": rows, "count": len(rows),
            "note": ("Metadata only. No route returns a token's plaintext "
                     "or its stored digest.")}


class RevokeTokenBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3,
                        description="Recorded verbatim in the audit record.")


@admin.post("/tokens/{token_id}/revoke")
async def revoke_token(token_id: str, body: RevokeTokenBody, request: Request,
                       user: dict = Depends(get_current_user),
                       tenant_id: str = Depends(edr_tenant)) -> dict:
    """Revoke an UNUSED enrolment token.

    Deliberately distinct from endpoint revocation: this closes a
    bootstrap authority that has not been spent yet and never retracts an
    identity that was already issued.
    """
    try:
        return await store.revoke_enrollment_token(
            _db, tenant_id=tenant_id, token_id=token_id,
            revoked_by=(user or {}).get("email") or "unknown",
            reason=body.reason)
    except EnrollmentError as e:
        _fail(e)


@admin.get("/endpoints")
async def list_enrolled(request: Request,
                        user: dict = Depends(get_current_user),
                        tenant_id: str = Depends(edr_tenant)) -> dict:
    rows = await store.list_endpoints(_db, tenant_id=tenant_id)
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
async def rotate(endpoint_id: str, request: Request,
                 user: dict = Depends(get_current_user),
                 tenant_id: str = Depends(edr_tenant)) -> dict:
    try:
        return await store.rotate_credential(
            _db, tenant_id=tenant_id, endpoint_id=endpoint_id,
            rotated_by=(user or {}).get("email") or "unknown")
    except EnrollmentError as e:
        _fail(e)


class RevokeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3,
                        description="Recorded verbatim in the audit record.")


@admin.post("/endpoints/{endpoint_id}/revoke")
async def revoke(endpoint_id: str, body: RevokeBody, request: Request,
                 user: dict = Depends(get_current_user),
                 tenant_id: str = Depends(edr_tenant)) -> dict:
    try:
        return await store.revoke_endpoint(
            _db, tenant_id=tenant_id, endpoint_id=endpoint_id,
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


@admin.get("/acquisition-integrity")
async def read_acquisition_integrity(
        endpoint_id: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        user: dict = Depends(get_current_user),
        tenant_id: str = Depends(edr_tenant)) -> dict:
    """The platform-side read. Lets an operator answer "was this interval
    trustworthy for this channel?" before drawing an absence-based
    conclusion — which is what E3's negative controls will require."""
    del user
    return {
        "tenant_id": tenant_id,
        "contract": acq_integrity.CONTRACT,
        "contract_version": acq_integrity.CONTRACT_VERSION,
        "channels": await acq_integrity.list_reports(
            _db, tenant_id=tenant_id, endpoint_id=endpoint_id, limit=limit),
        "acquisition_gaps": await acq_integrity.list_gaps(
            _db, tenant_id=tenant_id, endpoint_id=endpoint_id, limit=limit),
        "semantics": acq_integrity.SEMANTICS,
    }


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
        _agent_tenant(body.tenant_id, oracle="ENROLLMENT_TOKEN_INVALID")
    except EnrollmentError as e:
        await rejection.record_rejection(
            _db, tenant_id=body.tenant_id,
            presented_secret=body.enrollment_token,
            source_ip=(request.client.host if request.client else None),
            code="TENANT_NOT_AUTHORITATIVE",
            reason=("the presented tenant is not a registered, active "
                    "tenant; the caller is told only that the token is "
                    "not valid"),
            path="/api/edr/agent/enroll", endpoint_id=None)
        await enrollment_audit.record_safe(
            _db, tenant_id=body.tenant_id,
            event=enrollment_audit.ENROLLMENT_REJECTED,
            actor="unknown-endpoint", outcome="REJECTED",
            reason_code="TENANT_NOT_AUTHORITATIVE",
            presented_secret=body.enrollment_token,
            source_ip=(request.client.host if request.client else None))
        _fail(e)
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
        enrolled = await store.enroll(
            _db, tenant_id=body.tenant_id,
            presented_token=body.enrollment_token, endpoint_id=endpoint_id,
            hostname=body.hostname, platform=body.platform,
            sensor_version=body.sensor_version, device_iid=body.device_iid)
        # Onboarding V1 · a newly enrolled computer lands in the default
        # group and policy instead of nowhere. Existing placements are never
        # overwritten, so a reinstall cannot move a computer out of its group.
        # Connector productization: when the enrolment credential was minted
        # by a Management -> Downloads DEPLOYMENT, the chosen group travels
        # with the credential, so the computer registers into the group the
        # administrator selected without the artifact carrying anything.
        from routers.edr_onboarding import (assign_default_placement,
                                            assign_deployment_placement)
        tok = await _db[store.TOKENS].find_one(
            {"tenant_id": body.tenant_id,
             "token_hash": _digest(body.enrollment_token)},
            {"_id": 0, "group_id": 1, "deployment_id": 1})
        if tok and tok.get("group_id"):
            placement = await assign_deployment_placement(
                body.tenant_id, endpoint_id, tok["group_id"],
                tok.get("deployment_id"))
            basis = "CONNECTOR_DEPLOYMENT"
        else:
            placement = await assign_default_placement(body.tenant_id,
                                                       endpoint_id)
            basis = "DEFAULT_AT_ENROLMENT"
        return {**enrolled, **placement, "placement_basis": basis}
    except EnrollmentError as e:
        await rejection.record_rejection(
            _db, tenant_id=body.tenant_id,
            presented_secret=body.enrollment_token,
            source_ip=(request.client.host if request.client else None),
            code=e.code, reason=e.reason or e.code, path="/api/edr/agent/enroll",
            endpoint_id=endpoint_id)
        await enrollment_audit.record_safe(
            _db, tenant_id=body.tenant_id,
            event=enrollment_audit.ENROLLMENT_REJECTED,
            actor=endpoint_id, outcome="REJECTED", reason_code=e.code,
            endpoint_id=endpoint_id,
            presented_secret=body.enrollment_token,
            source_ip=(request.client.host if request.client else None))
        _fail(e)


class SessionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    agent_credential: str


@agent.post("/session")
async def open_session(body: SessionBody, request: Request) -> dict:
    """Exchange the durable credential for a short-lived scoped session."""
    try:
        _agent_tenant(body.tenant_id, oracle="AGENT_CREDENTIAL_INVALID")
    except EnrollmentError as e:
        await rejection.record_rejection(
            _db, tenant_id=body.tenant_id,
            presented_secret=body.agent_credential,
            source_ip=(request.client.host if request.client else None),
            code="TENANT_NOT_AUTHORITATIVE",
            reason=("the presented tenant is not a registered, active "
                    "tenant; the caller is told only that the credential "
                    "is not valid"),
            path="/api/edr/agent/session", endpoint_id=None)
        _fail(e)
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
    report_interval_seconds: Optional[float] = Field(
        default=None, gt=0,
        description="The sensor's OWN configured collect/flush cadence. "
                    "P0-3 derives this endpoint's staleness thresholds from "
                    "it, so the console never invents a timeout.")


class HeartbeatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_interval_seconds: Optional[float] = Field(default=None, gt=0)
    sensor_version: Optional[str] = None
    queue_depth: Optional[int] = Field(
        default=None, ge=0,
        description="Unsent events in the sensor's local outbox. Lets the "
                    "platform distinguish a BACKLOG from a silence: a "
                    "sensor that is alive and behind has not stopped.")
    counter_epoch: Optional[str] = Field(
        default=None, max_length=64,
        description="The sensor's counter epoch. Sensor counters restart "
                    "with the sensor process, so a new epoch is recorded "
                    "as an epoch CHANGE and the previous snapshot is "
                    "retained — never added to or subtracted from the new "
                    "one.")
    delivery_counters: Optional[dict] = Field(
        default=None,
        description="The ENDPOINT's own monotonic delivery counters "
                    "(observed / read / attempted / sent / failed / "
                    "suppressed / queue depth). Metadata only: no event "
                    "content, no path, no command line. Stored as a "
                    "SENSOR CLAIM and never as a server measurement, and "
                    "never as an evidence authority.")


@agent.post("/heartbeat")
async def heartbeat(body: HeartbeatBody,
                    who: AuthenticatedEndpoint = Depends(
                        get_authenticated_endpoint)) -> dict:
    """Sensor LIVENESS · P0-3.

    Without this route the platform could not tell a sensor that died
    from a sensor that is alive and has observed nothing new — both look
    identical in `last_telemetry_at`. A heartbeat is deliberately NOT
    telemetry: it creates no raw event, does not move
    `last_telemetry_at` and does not count as an event, so it can never
    make a silent endpoint look like a delivering one.
    """
    beat = await store.mark_heartbeat(
        _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
        at=datetime.now(timezone.utc).isoformat(),
        report_interval_seconds=body.report_interval_seconds,
        sensor_version=body.sensor_version,
        queue_depth=body.queue_depth)
    if body.delivery_counters is not None:
        try:
            beat = {**beat, "delivery_counters": (
                await counters.record_sensor_reported(
                    _db, tenant_id=who.tenant_id,
                    endpoint_id=who.endpoint_id,
                    counter_epoch=body.counter_epoch or "",
                    counters=body.delivery_counters,
                    sensor_version=body.sensor_version))}
        except ValueError as ex:
            raise HTTPException(
                status_code=422,
                detail={"code": "SENSOR_COUNTER_REFUSED",
                        "reason": str(ex)[:200]}) from None
    return beat


#: GATE B · batch ingest bounds. A batch exists to amortise connection,
#: TLS and ingress cost, not to become an unbounded upload: a 100-event
#: batch at the measured ~86 ms in-connection cost already turns ~11.6
#: events/sec into ~1,000+, which is two orders of magnitude above the
#: ~20 events/sec the endpoint produces.
MAX_BATCH_EVENTS = 100
MAX_BATCH_BYTES = 4 * 1024 * 1024


class TelemetryEventItem(BaseModel):
    """One event inside a batch. Same bytes, same guarantees, same
    idempotency as the single-event route."""
    model_config = ConfigDict(extra="forbid")
    payload: str = Field(description="Verbatim sensor payload, preserved "
                                     "byte-for-byte.")
    event_time: Optional[str] = None


class TelemetryBatchBody(BaseModel):
    """ADDITIVE. The single-event `TelemetryBody` is untouched, so a sensor
    running the previous build keeps working unchanged."""
    model_config = ConfigDict(extra="forbid")
    events: list[TelemetryEventItem] = Field(
        min_length=1, max_length=MAX_BATCH_EVENTS)
    source_kind: str = "sensor"
    sensor_version: Optional[str] = None
    report_interval_seconds: Optional[float] = Field(default=None, gt=0)
    batch_id: Optional[str] = Field(
        default=None, max_length=128,
        description="The sensor's own batch identifier, echoed back. It is "
                    "a correlation aid only: acceptance is decided PER "
                    "EVENT, so a retried batch is never accepted or "
                    "rejected wholesale.")


async def _ingest_one(*, payload: str, event_time: Optional[str],
                      source_kind: str, sensor_version: Optional[str],
                      report_interval_seconds: Optional[float],
                      who: AuthenticatedEndpoint, request: Request,
                      report: bool = True) -> dict:
    """THE ingest path. Both the single-event and the batch route call this,
    so batching cannot become a second set of semantics."""
    ev = raw.RawEndpointEvent.build(
        tenant_id=who.tenant_id, source=who.endpoint_id,
        source_kind=source_kind, sensor_version=sensor_version,
        endpoint_ref=who.endpoint_id, payload=payload,
        event_time=event_time,
        received_from_ip=(request.client.host if request.client else None),
        trust_state="AUTHENTICATED",
        # PROVENANCE, NOT A TIMESTAMP. This event is created by the
        # durable-ACK path, so it declares that a processing obligation is
        # expected to exist for it. Reconciliation acts on this declaration
        # alone, which is what makes a rolling deployment safe: an event
        # served by an older pod simply never carries the marker.
        processing_contract=processing_queue.PROCESSING_CONTRACT)
    ev.authentication = who.provenance()
    result = await raw.append(_db, ev)
    # DELIVERY FIDELITY · the event is RECEIVED the moment the
    # authenticated handler holds it. Every received event increments
    # exactly one terminal outcome below, so an event can never vanish
    # into an uncounted gap.
    channel = counters.channel_of(payload)

    async def _count(outcomes, reason_code=None) -> None:
        try:
            await counters.record(
                _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
                channel=channel, outcomes=outcomes, reason_code=reason_code)
        except Exception as ex:  # noqa: BLE001
            log.warning("[delivery-counters] %s", str(ex)[:200])

    # DURABLE ACK BOUNDARY
    # The endpoint may release its local evidence only after the backend
    # durably owns BOTH the immutable raw event and its downstream
    # processing obligation.  Enqueue is intentionally attempted for
    # duplicates too: a redelivery repairs the crash window where the raw
    # write succeeded but the processing-job write did not.
    processing_created = await processing_queue.enqueue(
        _db, tenant_id=who.tenant_id, raw_id=result["raw_id"])

    # Liveness is advanced only after the complete durable ACK boundary
    # succeeds. If queue persistence fails, the endpoint receives no ACK
    # and is not falsely recorded as having successfully reported.
    if report:
        await store.mark_reported(_db, tenant_id=who.tenant_id,
                                  endpoint_id=who.endpoint_id,
                                  at=ev.ingest_time,
                                  report_interval_seconds=(
                                      report_interval_seconds))

    # Count RECEIVED only once the request has crossed every durable/
    # liveness prerequisite required to reach its terminal delivery outcome.
    # A failed enqueue or mark_reported therefore cannot leave a permanent
    # unaccounted_received gap.
    await _count([counters.RECEIVED])

    if result.get("stored"):
        await _count([counters.ACCEPTED])
    else:
        await _count([counters.DEDUPLICATED, "deduplicated_payload"])

    canonical = {
        "canonicalized": False,
        "reason": "durably queued for asynchronous processing",
    }
    processing = {
        "durable": True,
        # Report what enqueue() actually decided. `processing_created` is the
        # enqueue RESULT DICT, which is always truthy — reporting the dict
        # itself told every duplicate redelivery that it had created a new
        # obligation when it had not.
        "created": bool(processing_created.get("created")),
    }

    return {
        **result,
        "endpoint_id": who.endpoint_id,
        "authenticated": True,
        "auth_method": who.auth_method,
        "canonical": canonical,
        "processing": processing,
        "note": ("Raw bytes preserved immutably. The parse outcome is "
                 "APPENDED as a derivation and never overwrites the "
                 "original — a parser failure leaves a retained, replayable "
                 "event."),
    }


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
    return await _ingest_one(
        payload=body.payload, event_time=body.event_time,
        source_kind=body.source_kind, sensor_version=body.sensor_version,
        report_interval_seconds=body.report_interval_seconds,
        who=who, request=request)


@agent.post("/telemetry/batch")
async def ingest_batch(body: TelemetryBatchBody, request: Request,
                       who: AuthenticatedEndpoint = Depends(
                           get_authenticated_endpoint)) -> dict:
    """GATE B · many events, ONE request. Acceptance stays PER EVENT.

    The whole point of B5-GAP-1's delivery gate is that a sensor may only
    release evidence it has been told was accepted. So this route returns
    an ordered per-event verdict and NEVER an all-or-nothing batch verdict:
    one event that fails to persist leaves that one event owned by the
    endpoint, and the other 99 are released.

    Idempotency is inherited, not invented: `raw.append` dedupes on
    `(tenant_id, dedup_key)`, so a batch retried after a lost response
    re-reports `stored=False, duplicate=True` per event and cannot create
    a second copy of anything.
    """
    total_bytes = sum(len(item.payload.encode("utf-8"))
                      for item in body.events)
    if total_bytes > MAX_BATCH_BYTES:
        # Refused as a whole, deliberately: nothing was ingested, so the
        # endpoint still owns every event and can re-send smaller batches.
        raise HTTPException(
            status_code=413,
            detail={"error": "BATCH_TOO_LARGE",
                    "bytes": total_bytes, "max_bytes": MAX_BATCH_BYTES,
                    "events": len(body.events),
                    "note": "no event in this batch was ingested; the "
                            "endpoint retains all of them"})

    results: list[dict] = []
    accepted = 0
    for index, item in enumerate(body.events):
        try:
            outcome = await _ingest_one(
                payload=item.payload, event_time=item.event_time,
                source_kind=body.source_kind,
                sensor_version=body.sensor_version,
                report_interval_seconds=body.report_interval_seconds,
                who=who, request=request,
                # Endpoint-level liveness is recorded ONCE per batch, below.
                report=False)
            results.append({"index": index, "accepted": True,
                            "stored": bool(outcome.get("stored")),
                            "duplicate": bool(outcome.get("duplicate")),
                            "raw_id": outcome.get("raw_id"),
                            "canonicalized": bool(
                                (outcome.get("canonical") or {}
                                 ).get("canonicalized"))})
            accepted += 1
        except Exception as ex:                                # noqa: BLE001
            # NOT accepted. The endpoint keeps this event and retries it.
            log.warning("[telemetry-batch] event %d refused: %s",
                        index, str(ex)[:200])
            results.append({"index": index, "accepted": False,
                            "error": type(ex).__name__,
                            "detail": str(ex)[:200]})

    if accepted:
        await store.mark_reported(
            _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
            at=datetime.now(timezone.utc).isoformat(),
            report_interval_seconds=body.report_interval_seconds)

    return {"batch_id": body.batch_id, "count": len(body.events),
            "accepted": accepted, "refused": len(body.events) - accepted,
            "bytes": total_bytes,
            "endpoint_id": who.endpoint_id, "authenticated": True,
            "auth_method": who.auth_method,
            "results": results,
            "note": ("Acceptance is per event and in request order. An "
                     "event without accepted=true was NOT accepted and is "
                     "still owned by the endpoint.")}


class AcquisitionIntegrityBody(BaseModel):
    """GATE C · the endpoint's own statement about its ACQUISITION.

    A separate, versioned contract rather than new fields on the heartbeat:
    `HeartbeatBody` is `extra="forbid"`, so adding to it would 422 every
    sensor still running the previous build.
    """
    model_config = ConfigDict(extra="forbid")
    at: Optional[str] = Field(default=None, max_length=64)
    contract_version: int = Field(default=1, ge=1, le=1)
    sensor_version: Optional[str] = None
    channels: dict = Field(
        default_factory=dict,
        description="Per-channel acquisition facts: cursors, records read "
                    "and journaled, query failures, lag, source head/tail.")
    acquisition_gaps: list[dict] = Field(
        default_factory=list, max_length=200,
        description="Declared source RecordID discontinuities. The server "
                    "recomputes the missing count and asserts the "
                    "classification and cause itself.")
    acquisition_gap_count: Optional[int] = Field(default=None, ge=0)
    journal_depth: Optional[int] = Field(default=None, ge=0)
    journal_bytes: Optional[int] = Field(default=None, ge=0)
    journal_live_bytes: Optional[int] = Field(default=None, ge=0)
    delivery_backlog: Optional[int] = Field(default=None, ge=0)
    health_states: list[str] = Field(default_factory=list, max_length=32)


@agent.post("/acquisition-integrity")
async def acquisition_integrity(body: AcquisitionIntegrityBody,
                                who: AuthenticatedEndpoint = Depends(
                                    get_authenticated_endpoint)) -> dict:
    """Receive acquisition integrity so it stops being trapped on the host.

    Stored as a SENSOR CLAIM about its own collection — never as a server
    measurement and never as an evidence authority. A declared gap is
    recorded as `SOURCE_RECORD_DISCONTINUITY` with `cause = NOT_PROVEN`,
    asserted server-side; it is never turned into a detection and never
    treated as benign.
    """
    return await acq_integrity.record(
        _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
        sensor_version=body.sensor_version,
        report=body.model_dump())


@agent.get("/whoami")
async def whoami(who: AuthenticatedEndpoint = Depends(
        get_authenticated_endpoint)) -> dict:
    """Lets an agent (and a test) confirm exactly who the platform
    believes it is, without sending telemetry."""
    ep = await store.get_endpoint(_db, tenant_id=who.tenant_id,
                                  endpoint_id=who.endpoint_id)
    return {"identity": who.model_dump(), "endpoint": ep,
            "transport": transport_status()}
