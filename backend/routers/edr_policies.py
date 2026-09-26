"""GATE 5 · Policy Authority & Enforcement — admin + connector surfaces.

Two audiences, one authority:

    /api/edr/policies/*      ADMIN. Authors policies, versions, groups and
                             assignments. Can never mark an endpoint
                             APPLIED.
    /api/edr/agent/policy    the CONNECTOR. Fetching is DELIVERY.
    /api/edr/agent/policy-ack the CONNECTOR. Acknowledging is the ONLY
                             route to ACKNOWLEDGED / APPLIED / VERIFIED.

The nine-state lifecycle and the invariant
`ASSIGNED != DELIVERED != APPLIED != VERIFIED` live in
`edr_plane.policy.contracts`, which is the one place that derives state.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from deps import db as _db, get_current_user
from edr_plane.connector import catalog
from edr_plane.enrollment import store as enrollment_store
from edr_plane.enrollment.identity import AuthenticatedEndpoint
from edr_plane.enrollment.transport import get_authenticated_endpoint
from edr_plane.exclusions import store as exclusion_store
from edr_plane.policy import store as policy_store
from edr_plane.policy.contracts import (LIFECYCLE_CONTRACT, PolicyConfig,
                                        PolicyState, ScopeType,
                                        unsupported_settings)
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter(prefix="/edr/policies", tags=["nivxforge-edr-policies"])
groups_router = APIRouter(prefix="/edr/groups", tags=["nivxforge-edr-policies"])
agent = APIRouter(prefix="/edr/agent", tags=["nivxforge-edr-agent"])


def _who(user: dict) -> str:
    return (user or {}).get("email") or "unknown"


def _fail(e: policy_store.PolicyError):
    raise HTTPException(status_code=e.status,
                        detail={"code": e.code, "reason": e.reason})


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


# ── admin · policies ─────────────────────────────────────────────────
class CreatePolicyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    os: str = Field(default="WINDOWS", pattern="^(WINDOWS|LINUX|MACOS)$")
    description: Optional[str] = Field(default=None, max_length=2000)
    config: PolicyConfig = Field(default_factory=PolicyConfig)


class CreateVersionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config: PolicyConfig
    notes: Optional[str] = Field(default=None, max_length=2000)


class AssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_type: ScopeType
    scope_id: str = Field(min_length=3)


@router.get("")
async def list_policies(user: dict = Depends(get_current_user),
                        tenant_id: str = Depends(edr_tenant)
                        ) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    rows = await policy_store.list_policies(_db, tenant_id=tenant)
    _rows, counts = await policy_store.deployment_matrix(_db,
                                                         tenant_id=tenant)
    return {"tenant_id": tenant, "policies": rows, "count": len(rows),
            "state_distribution": counts,
            "lifecycle": [s.value for s in PolicyState],
            "lifecycle_contract": LIFECYCLE_CONTRACT}


@router.post("")
async def create_policy(body: CreatePolicyBody,
                        user: dict = Depends(get_current_user),
                        tenant_id: str = Depends(edr_tenant)
                        ) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        created = await policy_store.create_policy(
            _db, tenant_id=tenant, name=body.name, os_family=body.os,
            description=body.description, config=body.config,
            by=_who(user))
    except policy_store.PolicyError as e:
        _fail(e)
    await exclusion_store.bind_to_policy_version(
        _db, tenant_id=tenant, set_ids=body.config.exclusion_set_ids,
        policy_id=created["policy"]["id"], version=1)
    return {**created,
            "not_enforced": unsupported_settings(
                body.config, catalog.capabilities(
                    "nvf-connector-windows-0.1.0-x64")),
            "state": PolicyState.CREATED.value,
            "note": ("CREATED only. A policy affects nothing until it is "
                     "assigned, delivered and acknowledged.")}


@router.get("/deployment")
async def deployment(policy_id: Optional[str] = None,
                     user: dict = Depends(get_current_user),
                     tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Per-endpoint delivery truth — the Policies console's core table."""
    tenant = _scoped(tenant_id, user)
    rows, counts = await policy_store.deployment_matrix(
        _db, tenant_id=tenant, policy_id=policy_id)
    confirmed = sum(1 for r in rows if r.get("confirmed_by_endpoint"))
    return {"tenant_id": tenant, "endpoints": rows, "count": len(rows),
            "state_distribution": counts,
            "confirmed_by_endpoint": confirmed,
            "not_confirmed": len(rows) - confirmed,
            "lifecycle_contract": LIFECYCLE_CONTRACT}


@router.get("/audit")
async def audit(limit: int = 200, user: dict = Depends(get_current_user),
                tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    rows = [r async for r in _db[policy_store.AUDIT].find(
        {"tenant_id": tenant}, {"_id": 0}).sort("at", -1).limit(
            max(1, min(limit, 1000)))]
    return {"tenant_id": tenant, "audit": rows, "count": len(rows)}


@router.get("/{policy_id}")
async def get_policy(policy_id: str, user: dict = Depends(get_current_user),
                     tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        detail = await policy_store.get_policy(_db, tenant_id=tenant,
                                               policy_id=policy_id)
    except policy_store.PolicyError as e:
        _fail(e)
    rows, counts = await policy_store.deployment_matrix(
        _db, tenant_id=tenant, policy_id=policy_id)
    caps = catalog.capabilities("nvf-connector-windows-0.1.0-x64")
    current = next((v for v in detail["versions"]
                    if v["version"] == detail["policy"].get(
                        "current_version")), None)
    return {**detail, "tenant_id": tenant, "endpoints": rows,
            "state_distribution": counts,
            "not_enforced": (unsupported_settings(
                PolicyConfig(**current["config"]), caps) if current else []),
            "lifecycle_contract": LIFECYCLE_CONTRACT}


@router.post("/{policy_id}/versions")
async def create_version(policy_id: str, body: CreateVersionBody,
                         user: dict = Depends(get_current_user),
                         tenant_id: str = Depends(edr_tenant)
                         ) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        version = await policy_store.create_version(
            _db, tenant_id=tenant, policy_id=policy_id, config=body.config,
            by=_who(user), notes=body.notes)
    except policy_store.PolicyError as e:
        _fail(e)
    await exclusion_store.bind_to_policy_version(
        _db, tenant_id=tenant, set_ids=body.config.exclusion_set_ids,
        policy_id=policy_id, version=version["version"])
    return {"version": version,
            "not_enforced": unsupported_settings(
                body.config, catalog.capabilities(
                    "nvf-connector-windows-0.1.0-x64")),
            "note": ("a new version supersedes the assigned version, so "
                     "every endpoint holding the previous one becomes "
                     "OUT_OF_SYNC until it acknowledges this one")}


@router.post("/{policy_id}/assign")
async def assign(policy_id: str, body: AssignBody,
                 user: dict = Depends(get_current_user),
                 tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        return await policy_store.assign(
            _db, tenant_id=tenant, policy_id=policy_id,
            scope_type=body.scope_type.value if hasattr(
                body.scope_type, "value") else str(body.scope_type),
            scope_id=body.scope_id, by=_who(user))
    except policy_store.PolicyError as e:
        _fail(e)


# ── admin · groups ───────────────────────────────────────────────────
class CreateGroupBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    policy_id: Optional[str] = None


@groups_router.get("")
async def list_groups(user: dict = Depends(get_current_user),
                      tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    rows = await policy_store.list_groups(_db, tenant_id=tenant)
    return {"tenant_id": tenant, "groups": rows, "count": len(rows)}


@groups_router.post("")
async def create_group(body: CreateGroupBody,
                       user: dict = Depends(get_current_user),
                       tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    try:
        return await policy_store.create_group(
            _db, tenant_id=tenant, name=body.name,
            description=body.description, policy_id=body.policy_id,
            by=_who(user))
    except policy_store.PolicyError as e:
        _fail(e)


# ── connector surface ────────────────────────────────────────────────
async def _endpoint_record(tenant_id: str, endpoint_id: str) -> Dict[str, Any]:
    rec = await _db[enrollment_store.ENDPOINTS].find_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id}, {"_id": 0})
    if rec is None:
        raise HTTPException(404, detail={"code": "ENDPOINT_NOT_FOUND"})
    return rec


@agent.get("/policy")
async def fetch_policy(who: AuthenticatedEndpoint = Depends(
        get_authenticated_endpoint)) -> Dict[str, Any]:
    """The connector fetches its assigned policy. This IS delivery.

    Fetching records DELIVERED and nothing more. The connector must call
    `/policy-ack` for the platform to believe anything about what it is
    running.
    """
    rec = await _endpoint_record(who.tenant_id, who.endpoint_id)
    assigned = await policy_store.resolve_assignment(
        _db, tenant_id=who.tenant_id, endpoint=rec)
    if not assigned:
        return {"policy": None, "state": "POLICY_UNASSIGNED",
                "reason": ("no policy resolves to this endpoint; the "
                           "connector must not invent a configuration")}
    delivered_at = await policy_store.record_delivery(
        _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
        assigned=assigned, connector_version=rec.get("sensor_version"))
    set_ids = (assigned["config"].get("exclusion_set_ids") or [])
    exclusions = await exclusion_store.enforceable_for_endpoint(
        _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
        group_id=rec.get("group_id"), set_ids=set_ids or None)
    return {
        "policy": {"policy_id": assigned["policy_id"],
                   "policy_name": assigned["policy_name"],
                   "version": assigned["version"],
                   "config_digest": assigned["config_digest"],
                   "config": assigned["config"]},
        "exclusions": [{"exclusion_id": e["exclusion_id"],
                        "type": e["type"], "match": e["match"],
                        "value": e["value"]} for e in exclusions],
        "state": PolicyState.DELIVERED.value,
        "delivered_at": delivered_at,
        "ack_required": True,
        "ack_contract": ("acknowledge policy_id, version and config_digest "
                         "EXACTLY as delivered. An acknowledgement naming "
                         "anything else is recorded as OUT_OF_SYNC and can "
                         "never produce APPLIED."),
    }


class PolicyAckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str
    version: int = Field(ge=1)
    config_digest: str = Field(min_length=8)
    applied: bool
    running_config_digest: Optional[str] = None
    failure_reason: Optional[str] = Field(default=None, max_length=2000)
    connector_version: Optional[str] = None
    exclusions_applied: Optional[int] = Field(default=None, ge=0)


@agent.post("/policy-ack")
async def policy_ack(body: PolicyAckBody,
                     who: AuthenticatedEndpoint = Depends(
                         get_authenticated_endpoint)) -> Dict[str, Any]:
    """The endpoint's own statement about what it received and applied.

    This is the only surface in the product that can move an endpoint to
    ACKNOWLEDGED, APPLIED or VERIFIED.
    """
    rec = await _endpoint_record(who.tenant_id, who.endpoint_id)
    assigned = await policy_store.resolve_assignment(
        _db, tenant_id=who.tenant_id, endpoint=rec)
    result = await policy_store.record_ack(
        _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
        assigned=assigned, policy_id=body.policy_id, version=body.version,
        config_digest=body.config_digest, applied=body.applied,
        running_config_digest=body.running_config_digest,
        failure_reason=body.failure_reason,
        connector_version=body.connector_version or rec.get("sensor_version"))
    rec = await _endpoint_record(who.tenant_id, who.endpoint_id)
    state = await policy_store.endpoint_policy_state(
        _db, tenant_id=who.tenant_id, endpoint=rec)
    return {**result, "effective": state,
            "lifecycle_contract": LIFECYCLE_CONTRACT}
