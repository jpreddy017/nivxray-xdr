"""P0-F.5/F.6 · endpoint response surfaces.

Analyst side authenticates as a user; sensor side authenticates as the
enrolled endpoint. Neither side may assert its own identity — the sensor's
endpoint_id comes from its session, never from the request body.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from deps import db as _db, get_current_user
from edr_plane import isolation_policy
from edr_plane import response as resp
from edr_plane.enrollment.identity import AuthenticatedEndpoint
from routers.edr_enrollment import get_authenticated_endpoint
from routers.edr_tenancy import edr_scope, edr_tenant, sensor_tenant
from services.edr import device_identity as dir_svc
from services.edr import endpoint_query as eq

router = APIRouter(prefix="/edr/response", tags=["nivxforge-edr-response"])
agent = APIRouter(prefix="/edr/agent", tags=["nivxforge-edr-agent"])


def _fail(e: resp.ResponseError):
    raise HTTPException(status_code=e.http,
                        detail={"error": e.code, "reason": e.reason})


class ActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str
    action: str
    target: Dict[str, Any] = {}
    reason: str = ""


class ResultBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str
    outcome: str
    detail: str = ""
    evidence: Dict[str, Any] = {}


class VerifyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str
    probe: Dict[str, Any]


@router.post("/actions")
async def request_action(body: ActionBody,
                         user: dict = Depends(get_current_user),
                         tenant_id: str = Depends(edr_tenant)) -> dict:
    """P0-2C · the command plane accepts the same aliases the read plane
    does.

    P1 · B5/B7 · the tenant is the explicit, registry-resolved
    `X-Tenant-Id` — previously `user["tenant_id"] or "default"`, which keyed
    every containment action to a tenant that does not exist in the registry.
    Only the tenant resolution changed: approval, permission, dispatch,
    idempotency, audit and independent verification are untouched, and
    ACCEPTED != EXECUTED != CONTAINED != VERIFIED still holds.

    The command store and the enrolment registry key on the
    platform-minted `endpoint_id`, but the console pivots on the
    `device_iid`. Without resolution here, requesting an action from a
    trajectory URL returned `404 ENDPOINT_NOT_ENROLLED` — a false
    statement about enrolment for an endpoint that IS enrolled. The
    enrolment record stays the authority; only the identifier is widened,
    and it is widened under the CALLER'S scope.
    """
    endpoint_id = await _canonical_endpoint_id(
        body.endpoint_id, tenant_id, edr_scope(tenant_id, user))
    try:
        return await resp.request_action(
            _db, tenant_id=tenant_id,
            endpoint_id=endpoint_id, action=body.action,
            target=body.target, reason=body.reason,
            requested_by=str(user.get("sub") or user.get("email") or "user"))
    except resp.ResponseError as e:
        _fail(e)


async def _canonical_endpoint_id(supplied: str, tenant_id: str,
                                 scope) -> str:
    """The enrolled `endpoint_id` this reference addresses.

    An identifier that is already an enrolment key in this tenant is
    returned untouched — the enrolment registry remains the authority
    and no resolution is attempted. Only a non-enrolment identifier is
    passed through the authoritative resolver, and only its aliases that
    are themselves enrolled in THIS tenant are accepted.
    """
    if await _db["edr_endpoints"].find_one(
            {"tenant_id": tenant_id, "endpoint_id": supplied},
            {"_id": 1}):
        return supplied
    res = eq.resolve_endpoint(supplied, scope)
    if not res:
        return supplied            # caller sees the honest enrolment error
    for ref in res.refs:
        if ref == supplied:
            continue
        if await _db["edr_endpoints"].find_one(
                {"tenant_id": tenant_id, "endpoint_id": ref}, {"_id": 1}):
            return ref
    return supplied


@router.get("/actions")
async def list_actions(endpoint_id: Optional[str] = None,
                       user: dict = Depends(get_current_user),
                       tenant_id: str = Depends(edr_tenant)) -> dict:
    """P0-W.F-1 (third occurrence) · resolve the endpoint reference.

    The command store keys on the platform-minted `endpoint_id`, but the
    EDR console navigates and pivots on the `device_iid`. Without alias
    resolution this surface reported "0 of 0" for an endpoint that has
    real command records — the same false-empty class as the process
    tree and endpoint detections. It reuses the SAME authoritative
    resolver; it widens the identifiers, never the authorization.
    """
    refs = None
    if endpoint_id:
        scope = edr_scope(tenant_id, user)
        res = eq.resolve_endpoint(endpoint_id, scope)
        if not res:
            return {**eq.unresolved_envelope(endpoint_id),
                    "commands": [], "count": 0,
                    "total_count": 0, "truncated": False, "by_state": {},
                    "verified_count": 0, "integrity_alarms": 0}
        refs = res.refs
    out = await resp.list_commands(
        _db, tenant_id=tenant_id,
        endpoint_id=endpoint_id, endpoint_refs=refs)
    if refs:
        out["identity"] = {"resolved": True, "addressed_by": refs}
    return out


@router.get("/actions/{command_id}")
async def get_action(command_id: str,
                     user: dict = Depends(get_current_user),
                     tenant_id: str = Depends(edr_tenant)) -> dict:
    """The full action record for one command — the audit surface the
    console renders. Read-only; this route never mutates state."""
    try:
        return await resp.get_command(
            _db, tenant_id=tenant_id, command_id=command_id)
    except resp.ResponseError as e:
        _fail(e)


class PolicyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allow_list: Optional[list] = None
    allow_dns: Optional[bool] = None
    extra_control_hosts: Optional[list] = None
    verification_target: Optional[Dict[str, Any]] = None
    auto_release_seconds: Optional[int] = None


@router.get("/isolation-policy")
async def read_isolation_policy(
        user: dict = Depends(get_current_user),
        tenant_id: str = Depends(edr_tenant)) -> dict:
    return await isolation_policy.get_policy(_db, tenant_id=tenant_id)


@router.put("/isolation-policy")
async def write_isolation_policy(
        body: PolicyBody, user: dict = Depends(get_current_user),
        tenant_id: str = Depends(edr_tenant)) -> dict:
    try:
        return await isolation_policy.put_policy(
            _db, tenant_id=tenant_id,
            updated_by=str(user.get("sub") or user.get("email") or "user"),
            allow_list=body.allow_list, allow_dns=body.allow_dns,
            extra_control_hosts=body.extra_control_hosts,
            verification_target=body.verification_target,
            auto_release_seconds=body.auto_release_seconds)
    except ValueError as e:
        raise HTTPException(status_code=400,
                            detail={"error": "INVALID_POLICY",
                                    "reason": str(e)}) from None


@agent.get("/commands")
async def poll_commands(who: AuthenticatedEndpoint = Depends(
        get_authenticated_endpoint)) -> dict:
    """The sensor claims only ITS OWN commands, scoped by its session.

    SENSOR_SCOPED · the tenant comes from the authenticated endpoint session
    and is validated against the registry. No request header is read.
    """
    cmds = await resp.claim_pending(_db,
                                   tenant_id=sensor_tenant(who.tenant_id),
                                   endpoint_id=who.endpoint_id)
    return {"endpoint_id": who.endpoint_id, "commands": cmds,
            "count": len(cmds)}


@agent.post("/command-result")
async def command_result(body: ResultBody,
                         who: AuthenticatedEndpoint = Depends(
                             get_authenticated_endpoint)) -> dict:
    try:
        return await resp.record_result(
            _db, tenant_id=sensor_tenant(who.tenant_id),
            endpoint_id=who.endpoint_id,
            command_id=body.command_id, outcome=body.outcome,
            detail=body.detail, evidence=body.evidence)
    except resp.ResponseError as e:
        _fail(e)


@agent.post("/command-verification")
async def command_verification(body: VerifyBody,
                               who: AuthenticatedEndpoint = Depends(
                                   get_authenticated_endpoint)) -> dict:
    """Post-action evidence. This is the only path to VERIFIED."""
    try:
        return await resp.verify(_db,
                                 tenant_id=sensor_tenant(who.tenant_id),
                                 endpoint_id=who.endpoint_id,
                                 command_id=body.command_id, probe=body.probe)
    except resp.ResponseError as e:
        _fail(e)
