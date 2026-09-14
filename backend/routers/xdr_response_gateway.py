"""Option-3 Response gateway: the authoritative backend is the user trust boundary.

Browser assertions about tenant, actor, role, permissions, or approval are never
used as authority.  The authenticated backend user is resolved first; tenant and
permissions are then derived from authoritative stores before a service-authenticated
request can reach the standalone Response Engine.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import get_current_user, sync_collection
from routers.xdr_rbac import check_access

router = APIRouter(prefix="/xdr/response", tags=["xdr-response-gateway"])

_cases = sync_collection("workspace_cases")
_xdr_users = sync_collection("xdr_users")
_requests = sync_collection("xdr_response_requests")
_approvals = sync_collection("xdr_response_approvals")
_dispatches = sync_collection("xdr_response_dispatches")

_APPROVAL_ROLES = {"admin", "platform_admin", "tenant_admin", "soc_manager"}
_EXECUTE_ROLES = _APPROVAL_ROLES | {"responder", "l3_investigator"}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(action: dict[str, Any], target: dict[str, Any]) -> str:
    raw = json.dumps({"action": action, "target": target}, sort_keys=True,
                     separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def _tenant_for_user(user: dict[str, Any]) -> str:
    """Derive one tenant from authoritative records; never from request headers."""
    direct = user.get("tenant_id") or user.get("organization_id")
    if direct:
        return str(direct)
    email = str(user.get("email") or "").lower()
    matches = list(_xdr_users.find(
        {"email": email, "enabled": {"$ne": False}},
        {"_id": 0, "tenant_id": 1},
    ).limit(2))
    tenants = {str(row.get("tenant_id")) for row in matches if row.get("tenant_id")}
    if len(tenants) != 1:
        raise HTTPException(403, detail={
            "error": "tenant_context_unavailable",
            "reason": "authenticated user must resolve to exactly one authoritative tenant",
        })
    return next(iter(tenants))


def _role(user: dict[str, Any], tenant_id: str) -> str:
    email = str(user.get("email") or "").lower()
    row = _xdr_users.find_one({"tenant_id": tenant_id, "email": email},
                              {"_id": 0, "role": 1, "roles": 1})
    if row:
        if row.get("role"):
            return str(row["role"])
        roles = row.get("roles") or []
        if roles:
            return str(roles[0])
    return str(user.get("role") or "user")


def _authorize(user: dict[str, Any], tenant_id: str, permission: str,
               allowed_roles: set[str]) -> tuple[str, str]:
    email = str(user.get("email") or "").lower()
    role = _role(user, tenant_id)
    if role in allowed_roles or role == "admin":
        return email, role
    result = check_access(tenant_id, email, permission)
    if not result.get("allow"):
        raise HTTPException(403, detail={
            "error": "access_denied", "permission": permission,
            "reason": result.get("reason"),
        })
    return email, str(result.get("matched_role") or role)


def _assert_optional_claim(value: str | None, authoritative: str, field: str) -> None:
    if value is not None and not hmac.compare_digest(str(value), authoritative):
        raise HTTPException(403, detail={
            "error": "forged_security_context", "field": field,
        })


def _case_for_tenant(case_id: str, tenant_id: str) -> dict[str, Any]:
    case = _cases.find_one({"id": case_id}, {"_id": 0})
    if not case:
        raise HTTPException(404, detail={"error": "response_target_not_found"})
    resource_tenant = case.get("tenant_id") or case.get("organization_id")
    if not resource_tenant:
        raise HTTPException(409, detail={
            "error": "response_target_tenant_unattributed",
            "case_id": case_id,
        })
    if not hmac.compare_digest(str(resource_tenant), tenant_id):
        # Deliberately 404 to avoid confirming cross-tenant object existence.
        raise HTTPException(404, detail={"error": "response_target_not_found"})
    return case


class ResponseRequestIn(BaseModel):
    case_id: str
    action: dict[str, Any]
    target: dict[str, Any]
    reason: str = Field(min_length=1, max_length=2000)
    tenant_id: str | None = None
    invoker: str | None = None
    approved_by: str | None = None
    authorization: dict[str, Any] | None = None
    dry_run: bool = False


class ApprovalIn(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=1, max_length=2000)


@router.post("/requests")
def create_response_request(body: ResponseRequestIn,
                            user=Depends(get_current_user)):
    tenant = _tenant_for_user(user)
    principal, role = _authorize(user, tenant, "response.execute", _EXECUTE_ROLES)
    _assert_optional_claim(body.tenant_id, tenant, "tenant_id")
    _assert_optional_claim(body.invoker, principal, "invoker")
    # approved_by / authorization are accepted only for compatibility and ignored.
    _case_for_tenant(body.case_id, tenant)
    now = _iso()
    request_id = "rr-" + uuid.uuid4().hex
    approval_required = not body.dry_run
    doc = {
        "response_request_id": request_id,
        "tenant_id": tenant,
        "case_id": body.case_id,
        "principal_id": principal,
        "principal_role": role,
        "action": body.action,
        "target": body.target,
        "binding_digest": _digest(body.action, body.target),
        "reason": body.reason,
        "dry_run": body.dry_run,
        "approval_required": approval_required,
        "approval_status": "pending" if approval_required else "not_required",
        "state": "REQUESTED",
        "created_at": now,
    }
    _requests.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "binding_digest"}


@router.post("/requests/{response_request_id}/approval")
def decide_response_request(response_request_id: str, body: ApprovalIn,
                            user=Depends(get_current_user)):
    tenant = _tenant_for_user(user)
    principal, role = _authorize(user, tenant, "response.approve", _APPROVAL_ROLES)
    req = _requests.find_one({
        "response_request_id": response_request_id,
        "tenant_id": tenant,
    }, {"_id": 0})
    if not req:
        raise HTTPException(404, detail={"error": "response_request_not_found"})
    if req.get("state") != "REQUESTED" or req.get("approval_status") != "pending":
        raise HTTPException(409, detail={"error": "approval_not_pending"})
    now = _iso()
    approval_id = "approval-" + uuid.uuid4().hex
    approval = {
        "approval_id": approval_id,
        "response_request_id": response_request_id,
        "tenant_id": tenant,
        "approver_id": principal,
        "approver_role": role,
        "decision": body.decision,
        "action": req["action"],
        "target": req["target"],
        "binding_digest": req["binding_digest"],
        "reason": body.reason,
        "created_at": now,
    }
    _approvals.insert_one(approval)
    status = "approved" if body.decision == "approve" else "rejected"
    state = "APPROVED" if status == "approved" else "REJECTED"
    _requests.update_one(
        {"response_request_id": response_request_id, "tenant_id": tenant,
         "state": "REQUESTED", "approval_status": "pending"},
        {"$set": {"approval_id": approval_id, "approval_status": status,
                  "state": state, "decided_at": now}},
    )
    return {
        "approval_id": approval_id, "response_request_id": response_request_id,
        "tenant_id": tenant, "decision": body.decision,
        "approver_id": principal, "state": state, "created_at": now,
    }


@router.post("/requests/{response_request_id}/dispatch")
async def dispatch_response_request(response_request_id: str,
                                    request: Request,
                                    user=Depends(get_current_user)):
    tenant = _tenant_for_user(user)
    principal, role = _authorize(user, tenant, "response.execute", _EXECUTE_ROLES)
    req = _requests.find_one({
        "response_request_id": response_request_id,
        "tenant_id": tenant,
    }, {"_id": 0})
    if not req:
        raise HTTPException(404, detail={"error": "response_request_not_found"})
    _case_for_tenant(req["case_id"], tenant)

    if req.get("approval_required"):
        approval = _approvals.find_one({
            "approval_id": req.get("approval_id"),
            "response_request_id": response_request_id,
            "tenant_id": tenant,
            "decision": "approve",
        }, {"_id": 0})
        if not approval:
            raise HTTPException(403, detail={"error": "valid_approval_required"})
        current = _digest(req["action"], req["target"])
        if not hmac.compare_digest(current, str(approval.get("binding_digest") or "")):
            raise HTTPException(403, detail={"error": "approval_binding_mismatch"})
        if approval.get("action") != req["action"] or approval.get("target") != req["target"]:
            raise HTTPException(403, detail={"error": "approval_binding_mismatch"})
    elif req.get("state") != "REQUESTED":
        raise HTTPException(409, detail={"error": "invalid_dispatch_state"})

    prior = _dispatches.find_one({
        "response_request_id": response_request_id, "tenant_id": tenant,
    }, {"_id": 0})
    if prior:
        return {**prior, "idempotent_replay": True}

    url = os.environ.get("RESPONSE_ENGINE_URL", "").rstrip("/")
    credential = os.environ.get("RESPONSE_ENGINE_SERVICE_CREDENTIAL", "")
    if not url or not credential:
        raise HTTPException(503, detail={
            "error": "response_engine_not_ready",
            "url_configured": bool(url), "credential_configured": bool(credential),
        })

    correlation_id = request.headers.get("X-Request-ID") or "corr-" + uuid.uuid4().hex
    execution_id = "exec-" + uuid.uuid4().hex
    created_at = _iso()
    dispatch = {
        "execution_id": execution_id,
        "response_request_id": response_request_id,
        "tenant_id": tenant,
        "invoker": {
            "kind": "authenticated_user",
            "id": principal,
            "context": {
                "case_id": req["case_id"],
                "incident_id": req["case_id"],
                "principal_role": role,
                "correlation_id": correlation_id,
                "created_at": created_at,
            },
        },
        "action": {**req["action"], "parameters": req["target"]},
        "authorization": {
            "scopes": ["response.execute"],
            "approval_ref": req.get("approval_id"),
            "approved_by": (
                approval.get("approver_id") if req.get("approval_required") else None
            ),
            "reason": req["reason"],
        },
        "constraints": {"dry_run": bool(req.get("dry_run"))},
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{url}/api/respond/execute",
                json=dispatch,
                headers={
                    "Authorization": f"Bearer {credential}",
                    "X-Correlation-ID": correlation_id,
                    "Content-Type": "application/json",
                },
            )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        raise HTTPException(502, detail={
            "error": "response_engine_unreachable",
            "reason": type(exc).__name__,
        }) from exc
    if response.status_code >= 400:
        raise HTTPException(502, detail={
            "error": "response_engine_rejected_dispatch",
            "upstream_status": response.status_code,
        })

    upstream = response.json()
    # HTTP acceptance is not execution, containment, or verification.
    record = {
        "dispatch_id": "dispatch-" + uuid.uuid4().hex,
        "correlation_id": correlation_id,
        "execution_id": execution_id,
        "response_request_id": response_request_id,
        "tenant_id": tenant,
        "dispatched_by": principal,
        "state": "ACCEPTED",
        "engine_state": upstream.get("state"),
        "accepted_at": _iso(),
        "executed": False,
        "verified": False,
        "contained": False,
    }
    _dispatches.insert_one(record)
    _requests.update_one(
        {"response_request_id": response_request_id, "tenant_id": tenant},
        {"$set": {"state": "ACCEPTED", "dispatch_id": record["dispatch_id"],
                  "correlation_id": correlation_id, "execution_id": execution_id}},
    )
    return record
