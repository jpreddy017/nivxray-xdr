"""P0-1 · XDR ⇄ Response Engine SERVICE BOUNDARY.

The response plane is an independently deployed service
(`apps/nivxray-xdr-response`, supervisor program `xdr_response`). Only
ports 8001/3000 traverse the ingress, so the console cannot address it
directly; this router is the boundary the base backend exposes on its
behalf.

It is a BOUNDARY, not a second response implementation:

  · it holds no response state, no registry, no approval logic and no
    execution logic — the service owns all of it;
  · it forwards the acting analyst's bearer so the source product
    performs tenant scoping, and it re-derives no authorization;
  · it FAILS CLOSED. If the service is unreachable, misconfigured or
    slow, the caller receives an explicit unavailable state. A response
    action is NEVER reported as accepted, dispatched or successful
    because the boundary could not reach the engine.

Everything under `/api/xdr/respond/*` requires an authenticated
principal — this plane moves control out, so it has no anonymous
surface.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from deps import get_current_user

router = APIRouter(prefix="/xdr/respond", tags=["xdr-respond-boundary"])


def _service_url() -> Optional[str]:
    return (os.environ.get("XDR_RESPONSE_SERVICE_URL") or "").rstrip("/") or None


def _timeout() -> float:
    return float(os.environ.get("XDR_RESPONSE_SERVICE_TIMEOUT", "45"))


def _unavailable(reason: str, detail: Any = None):
    """Fail closed — an unreachable engine is never a successful action."""
    raise HTTPException(
        status_code=503,
        detail={"error": "response_engine_unavailable",
                "response_lifecycle": {"lifecycle": "dispatch_failed",
                                       "facts": {"dispatched": False,
                                                 "executing": False,
                                                 "executed": False,
                                                 "verified": False}},
                "reason": reason,
                "engine_detail": detail,
                "honesty_note": ("the response engine could not be reached, so "
                                 "NOTHING was requested, approved, dispatched or "
                                 "executed. This is not a partial success.")})


def _bearer(request: Request) -> Optional[str]:
    raw = request.headers.get("authorization") or ""
    return raw.split(" ", 1)[1].strip() if raw.lower().startswith("bearer ") else None


# ── authorization: DERIVED from the existing XDR RBAC, never invented ──
# The response engine speaks `role:scope` (e.g. `responder:endpoint:isolate`);
# NivXRay XDR speaks `resource.action` (e.g. `response.execute`). This
# boundary translates between the two EXISTING models and grants nothing
# of its own: if the principal does not hold `response.execute`, no scope
# is issued and the engine refuses the action on its own authority.
#
# `session_role` is the coarse fact the live product actually issues; the
# granular `xdr_user_roles` store is authoritative wherever it holds an
# assignment. The basis used is disclosed on every request.
_SESSION_ROLE_ALIAS = {"admin": "platform_admin", "superadmin": "platform_admin"}

RESPONSE_EXECUTE = "response.execute"
RESPONSE_APPROVE = "response.approve"


def _permissions_of(user: dict) -> tuple[set, str]:
    """(effective permission set, basis) for the acting principal."""
    from routers.xdr_rbac import (_BUILTIN_ROLE_BY_NAME, _expand_wildcard,
                                  _resolve_user_permissions)
    tenant = user.get("tenant_id") or "default"
    email = str(user.get("email") or user.get("sub") or "")
    try:
        granular, assignments = _resolve_user_permissions(tenant, email)
    except Exception:                                           # noqa: BLE001
        granular, assignments = set(), []
    if granular:
        return granular, "xdr_user_roles_assignment"
    role = str(user.get("role") or "").lower()
    role = _SESSION_ROLE_ALIAS.get(role, role)
    spec = _BUILTIN_ROLE_BY_NAME.get(role)
    if not spec:
        return set(), f"no_role_definition:{role or 'none'}"
    perms: set = set()
    for p in spec.get("permissions", []):
        perms |= _expand_wildcard(p)
    return perms, f"builtin_role:{role}"


def _scopes_for(action_id: str, user: dict, request: Request) -> tuple[list, str, set]:
    """Engine scopes the principal may exercise for ONE action."""
    perms, basis = _permissions_of(user)
    if RESPONSE_EXECUTE not in perms:
        return [], basis, perms
    reg = getattr(request.app.state, "_respond_catalogue", None) or {}
    spec = reg.get(action_id) or {}
    scopes: list = []
    for p in spec.get("required_permissions") or []:
        scopes.append(f"{p['role']}:{p['scope']}")
        scopes.append(p["scope"])
    return sorted(set(scopes)), basis, perms


async def _catalogue(request: Request) -> Dict[str, Any]:
    """Cache the engine's own action catalogue — the engine owns it."""
    cached = getattr(request.app.state, "_respond_catalogue", None)
    if cached:
        return cached
    body = await _call("GET", "/api/respond/actions", request=request)
    reg = {a["action_id"]: a for a in (body or {}).get("actions") or []}
    request.app.state._respond_catalogue = reg
    return reg


async def _call(method: str, path: str, *, request: Request,
                json_body: Optional[Dict[str, Any]] = None,
                params: Optional[Dict[str, Any]] = None) -> Any:
    url = _service_url()
    if not url:
        _unavailable("XDR_RESPONSE_SERVICE_URL is not configured")
    async with httpx.AsyncClient(timeout=_timeout()) as cx:
        try:
            r = await cx.request(method, f"{url}{path}",
                                 json=json_body, params=params)
        except httpx.TimeoutException:
            _unavailable("the response engine did not answer in time")
        except Exception as exc:                                # noqa: BLE001
            _unavailable(f"transport failure: {type(exc).__name__}")
    body: Any
    try:
        body = r.json()
    except Exception:                                           # noqa: BLE001
        body = {"raw": r.text[:400]}
    if r.status_code >= 500:
        _unavailable(f"the response engine returned {r.status_code}", body)
    if r.status_code >= 400:
        # A 4xx is the ENGINE'S authoritative refusal — surfaced verbatim.
        raise HTTPException(status_code=r.status_code,
                            detail=body.get("detail", body)
                            if isinstance(body, dict) else body)
    return body


@router.get("/health")
async def engine_health(request: Request,
                        user: dict = Depends(get_current_user)):
    """Readiness of the response plane, from the engine itself."""
    url = _service_url()
    if not url:
        return {"configured": False, "state": "NOT_CONFIGURED",
                "reachable": False,
                "honesty_note": ("no response engine is configured; every "
                                 "response action is unavailable")}
    body = await _call("GET", "/health", request=request)
    return {"configured": True, "state": "REAL_RUNTIME_VERIFIED",
            "reachable": True, "service_url": url, "engine": body}


@router.get("/actions")
async def catalogue(request: Request, user: dict = Depends(get_current_user)):
    return await _call("GET", "/api/respond/actions", request=request)


@router.get("/executions/{execution_id}")
async def execution(execution_id: str, request: Request,
                    user: dict = Depends(get_current_user)):
    """One execution, addressed by the FULL idempotency key.

    The tenant and invoker come from the session, so the engine's strict
    tenant isolation is used rather than a bare execution-id lookup.
    """
    return await _call("GET", f"/api/respond/executions/{execution_id}",
                       request=request,
                       params={"tenant_id": user.get("tenant_id") or "default",
                               "invoker_kind": "analyst",
                               "invoker_id": str(user.get("email")
                                                 or user.get("sub") or "user")})


@router.get("/pending-approvals")
async def pending_approvals(request: Request,
                            user: dict = Depends(get_current_user)):
    """Only ever this principal's own tenant — the boundary supplies the
    tenant from the session, never from a query parameter."""
    return await _call("GET", "/api/respond/pending-approvals",
                       request=request,
                       params={"tenant_id": user.get("tenant_id") or "default"})


@router.post("/execute")
async def execute(body: Dict[str, Any], request: Request,
                  user: dict = Depends(get_current_user)):
    """Submit a response request.

    The tenant and the invoker are taken from the SESSION and overwrite
    anything the client sent, so a caller cannot request an action in
    another customer's name. The acting bearer is forwarded so the
    source product enforces its own scoping.
    """
    payload = dict(body or {})
    payload["tenant_id"] = user.get("tenant_id") or "default"
    payload["invoker"] = {
        "kind": "analyst",
        "id": str(user.get("email") or user.get("sub") or "user"),
        "context": {**((body or {}).get("invoker") or {}).get("context", {}),
                    "product": "NIVXRAY_XDR"},
    }
    action_id = ((body or {}).get("action") or {}).get("action_id") or ""
    await _catalogue(request)
    scopes, basis, perms = _scopes_for(action_id, user, request)
    if not scopes:
        # Separation of duties: an analyst who may only recommend a
        # response cannot execute one. The refusal names the missing
        # permission instead of failing opaquely.
        raise HTTPException(
            status_code=403,
            detail={"error": "response_execute_not_authorized",
                    "required_permission": RESPONSE_EXECUTE,
                    "authorization_basis": basis,
                    "holds_response_permissions": sorted(
                        p for p in perms if p.startswith("response.")),
                    "response_lifecycle": {"lifecycle": "rejected",
                                           "facts": {"dispatched": False,
                                                     "executing": False,
                                                     "executed": False,
                                                     "verified": False}},
                    "honesty_note": ("no response action was requested, "
                                     "approved, dispatched or executed")})
    authz = dict(payload.get("authorization") or {})
    authz["bearer"] = _bearer(request)
    authz["scopes"] = scopes
    authz["authorization_basis"] = basis
    payload["authorization"] = authz
    return await _call("POST", "/api/respond/execute",
                       request=request, json_body=payload)


@router.post("/approve/{execution_id}")
async def approve(execution_id: str, body: Dict[str, Any], request: Request,
                  user: dict = Depends(get_current_user)):
    """Approve — the approver is the SESSION principal, never the body.

    This is what makes the approval audit trustworthy: a client cannot
    nominate who approved an action.
    """
    payload = dict(body or {})
    payload["approved_by"] = str(user.get("email") or user.get("sub") or "user")
    perms, basis = _permissions_of(user)
    if RESPONSE_APPROVE not in perms:
        raise HTTPException(
            status_code=403,
            detail={"error": "response_approve_not_authorized",
                    "required_permission": RESPONSE_APPROVE,
                    "authorization_basis": basis,
                    "holds_response_permissions": sorted(
                        p for p in perms if p.startswith("response.")),
                    "honesty_note": ("the execution remains awaiting approval; "
                                     "nothing was dispatched")})
    return await _call("POST", f"/api/respond/approve/{execution_id}",
                       request=request, json_body=payload)


@router.post("/reject/{execution_id}")
async def reject(execution_id: str, body: Dict[str, Any], request: Request,
                 user: dict = Depends(get_current_user)):
    payload = dict(body or {})
    payload["rejected_by"] = str(user.get("email") or user.get("sub") or "user")
    return await _call("POST", f"/api/respond/reject/{execution_id}",
                       request=request, json_body=payload)
