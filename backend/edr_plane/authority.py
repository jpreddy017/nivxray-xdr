"""P0-A · the EDR response AUTHORITY GATE.

NivXForge EDR is an approval **consumer and enforcer**, never an approval
issuer. There is exactly ONE approval authority in the product:

    user / EDR console
      → authoritative backend identity + RBAC   (`routers/xdr_rbac.py`)
      → response-engine approval authority       (`/api/respond/*`)
      → validated exact-action approval          (this module)
      → NivXForge EDR                            (`edr_plane/response.py`)
      → endpoint → execution result → independent verification

This module therefore:

  * resolves the acting principal's permissions through the EXISTING
    authoritative resolver — it defines no roles and mints no permissions;
  * asks the authoritative action catalogue (owned by the response
    engine) whether an action requires approval — it never decides that
    locally;
  * VALIDATES an approval artifact that the authority already issued,
    binding it to the exact `{tenant, endpoint, action, requester}`;
  * fails CLOSED. An authority that cannot be reached is a 503, never an
    authorization. "Could not validate" is never converted into "allowed".

The artifact EDR validates is the response engine's execution record. It
exists, is `approved`, and names its approver BEFORE the engine dispatches
into EDR, so validating it introduces no circular dependency on the
dispatch it authorises: EDR reads a stable prior authorization, not the
outcome of its own execution.

`RELEASE_ISOLATION` is permission-gated and never second-person gated —
being unable to release a contained host is itself a safety failure. It
is still authenticated, tenant-bound, permission-checked, audited,
idempotent and independently verified.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

PERMISSION_EXECUTE = "response.execute"
PERMISSION_APPROVE = "response.approve"

#: EDR verb → the authoritative action id in the response-engine catalogue.
VERB_ACTION_ID: Dict[str, str] = {
    "KILL_PROCESS": "endpoint.kill_process",
    "ISOLATE_ENDPOINT": "endpoint.isolate",
}

#: Restorative verbs: permission-gated, never approval-gated.
PERMISSION_ONLY_VERBS: Tuple[str, ...] = ("RELEASE_ISOLATION",)

#: The authority's artifact carries `approved_at` but no expiry. EDR
#: enforces a bounded freshness window of its own so an old approval
#: cannot be replayed weeks later. This is an EDR-side control and is
#: disclosed as such on every decision.
APPROVAL_MAX_AGE_SECONDS = int(
    os.environ.get("EDR_APPROVAL_MAX_AGE_SECONDS", "900"))

_SESSION_ROLE_ALIAS = {"admin": "platform_admin",
                       "superadmin": "platform_admin"}

_CATALOGUE_TTL_S = 60.0
_catalogue_cache: Dict[str, Any] = {"at": 0.0, "actions": None}

WORKFLOW_HINT = ("request the action through the authoritative response "
                 "workflow (POST /api/xdr/respond/execute) and have a "
                 "second operator holding response.approve approve it "
                 "(POST /api/xdr/respond/approve/{execution_id}); the "
                 "approval is then dispatched into NivXForge EDR")


class AuthorityError(Exception):
    def __init__(self, code: str, reason: str, http: int = 403,
                 **detail: Any):
        self.code, self.reason, self.http = code, reason, http
        self.detail = detail
        super().__init__(reason)

    def as_detail(self) -> Dict[str, Any]:
        return {"error": self.code, "reason": self.reason, **self.detail,
                "honesty_note": ("no command was recorded, authorised, "
                                 "dispatched or executed")}


def _is_loopback(url: str) -> bool:
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") \
        or host.startswith("127.")


def _service_url() -> Optional[str]:
    """The response authority, or None when there is none.

    PRODUCTION RULE (P0-PROD-SYNC): under
    `NIVX_DEPLOYMENT_ENV=production` a loopback address is treated as NOT
    CONFIGURED. A production backend cannot legitimately reach a response
    authority on its own localhost, so such a value is a leftover preview
    setting rather than an authority — and honouring it would mean
    dialling whatever happens to own that port. `None` here yields
    `RESPONSE_AUTHORITY_NOT_CONFIGURED` (503), which is the correct state
    until P0-PROD-4 closes. It also means the fail-closed guarantee does
    not depend on an operator being able to blank a key that the
    deployment UI refuses to save empty.
    """
    raw = (os.environ.get("XDR_RESPONSE_SERVICE_URL") or "").rstrip("/")
    if not raw:
        return None
    from security.secret_policy import is_production
    if is_production() and _is_loopback(raw):
        return None
    return raw


def _timeout() -> float:
    return float(os.environ.get("XDR_RESPONSE_SERVICE_TIMEOUT", "10"))


async def _platform_role(email: str, db: Any = None) -> Optional[str]:
    if db is None:
        from deps import db as _default
        db = _default
    doc = await db["users"].find_one({"email": email}, {"_id": 0, "role": 1})
    return (doc or {}).get("role")


async def permissions_for(tenant_id: str, email: str,
                          session_role: Optional[str] = None,
                          db: Any = None) -> Tuple[set, str]:
    """Effective permissions of ONE principal, and the basis used.

    Resolution order is the platform's existing one: a granular
    `xdr_user_roles` assignment is authoritative wherever it exists;
    otherwise the principal's built-in role is expanded. Nothing is
    granted here.
    """
    from routers.xdr_rbac import (_BUILTIN_ROLE_BY_NAME, _expand_wildcard,
                                  _resolve_user_permissions)
    try:
        granular, _ = _resolve_user_permissions(tenant_id, email)
    except Exception:                                           # noqa: BLE001
        granular = set()
    if granular:
        return set(granular), "xdr_user_roles_assignment"
    role = str(session_role or await _platform_role(email, db)
                or "").lower()
    role = _SESSION_ROLE_ALIAS.get(role, role)
    spec = _BUILTIN_ROLE_BY_NAME.get(role)
    if not spec:
        return set(), f"no_role_definition:{role or 'none'}"
    perms: set = set()
    for p in spec.get("permissions") or []:
        perms |= _expand_wildcard(p)
    return perms, f"builtin_role:{role}"


async def action_spec(action_id: str) -> Dict[str, Any]:
    """The AUTHORITATIVE spec for one action, from the engine catalogue.

    Cached briefly. Unreachable authority or an unknown action is a
    refusal, never a permissive default.
    """
    now = time.monotonic()
    actions = _catalogue_cache.get("actions")
    if not actions or (now - float(_catalogue_cache["at"])) > _CATALOGUE_TTL_S:
        url = _service_url()
        if not url:
            raise AuthorityError(
                "RESPONSE_AUTHORITY_NOT_CONFIGURED",
                "no response authority is configured, so no destructive "
                "action can be authorised", 503)
        try:
            async with httpx.AsyncClient(timeout=_timeout()) as cx:
                r = await cx.get(f"{url}/api/respond/actions")
            if r.status_code >= 400:
                raise RuntimeError(f"catalogue http {r.status_code}")
            actions = {a["action_id"]: a
                       for a in (r.json() or {}).get("actions") or []}
        except Exception as exc:                                # noqa: BLE001
            raise AuthorityError(
                "RESPONSE_AUTHORITY_UNAVAILABLE",
                f"the response authority could not be reached "
                f"({type(exc).__name__}), so the approval requirement for "
                f"{action_id} could not be established; failing closed",
                503) from None
        _catalogue_cache.update({"at": now, "actions": actions})
    spec = (actions or {}).get(action_id)
    if not spec:
        raise AuthorityError(
            "ACTION_NOT_IN_AUTHORITATIVE_CATALOGUE",
            f"{action_id} is not declared by the response authority; EDR "
            f"will not invent an authorisation rule for it", 503)
    return spec


async def fetch_approval(approval_ref: str) -> Optional[Dict[str, Any]]:
    """The authority's own execution record — read, never written."""
    url = _service_url()
    if not url:
        raise AuthorityError("RESPONSE_AUTHORITY_NOT_CONFIGURED",
                             "no response authority is configured", 503)
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as cx:
            r = await cx.get(f"{url}/api/respond/executions/{approval_ref}")
    except Exception as exc:                                    # noqa: BLE001
        raise AuthorityError(
            "RESPONSE_AUTHORITY_UNAVAILABLE",
            f"the response authority could not be reached "
            f"({type(exc).__name__}); the approval could not be validated "
            f"and nothing was authorised", 503) from None
    if r.status_code == 404:
        return None
    if r.status_code >= 400:
        raise AuthorityError(
            "RESPONSE_AUTHORITY_UNAVAILABLE",
            f"the response authority answered {r.status_code} for this "
            f"approval; it could not be validated", 503)
    try:
        return r.json()
    except Exception:                                           # noqa: BLE001
        raise AuthorityError("RESPONSE_AUTHORITY_UNAVAILABLE",
                             "the response authority returned an "
                             "unreadable approval record", 503) from None


def _approved_endpoint(record: Dict[str, Any]) -> Optional[str]:
    """The endpoint the approval was granted FOR, from the artifact only."""
    for src in (record.get("parameters") or {},
                record.get("canonical_target") or {},
                record.get("canonical") or {}):
        for key in ("host_id", "endpoint_id", "device_id"):
            val = src.get(key)
            if val:
                return str(val)
    return None


def _age_seconds(approved_at: Optional[str]) -> Optional[float]:
    if not approved_at:
        return None
    try:
        at = datetime.fromisoformat(str(approved_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - at).total_seconds()


async def validate_approval(*, approval_ref: Optional[str], action_id: str,
                            verb: str, tenant_id: str, endpoint_id: str,
                            requester: str, db: Any = None
                            ) -> Dict[str, Any]:
    """Bind an authority-issued approval to THIS exact request.

    An approval for another action, endpoint, tenant or requester
    authorises nothing.
    """
    if not approval_ref:
        raise AuthorityError(
            "APPROVAL_REQUIRED",
            f"{verb} is declared destructive and approval-required by the "
            f"response authority; NivXForge EDR does not issue approvals",
            403, required_action_id=action_id, workflow=WORKFLOW_HINT)
    record = await fetch_approval(approval_ref)
    if not record:
        raise AuthorityError(
            "APPROVAL_NOT_FOUND",
            f"the response authority holds no approval {approval_ref}",
            403, approval_ref=approval_ref)
    approval = record.get("approval") or {}
    status = str(approval.get("status") or "").lower()
    if status != "approved":
        raise AuthorityError(
            "APPROVAL_NOT_APPROVED",
            f"approval {approval_ref} is '{status or 'absent'}', not "
            f"approved", 403,
            approval_ref=approval_ref, approval_status=status or None,
            authority_state=record.get("state"))
    if str(record.get("action_id")) != action_id:
        raise AuthorityError(
            "APPROVAL_ACTION_MISMATCH",
            f"approval {approval_ref} was granted for "
            f"{record.get('action_id')}, not {action_id}", 403)
    if str(record.get("tenant_id")) != str(tenant_id):
        raise AuthorityError(
            "APPROVAL_TENANT_MISMATCH",
            f"approval {approval_ref} belongs to another tenant", 403)
    approved_endpoint = _approved_endpoint(record)
    if not approved_endpoint:
        raise AuthorityError(
            "APPROVAL_TARGET_NOT_DISCLOSED",
            f"approval {approval_ref} does not disclose the endpoint it was "
            f"granted for, so it cannot be bound to this request", 403)
    if approved_endpoint != str(endpoint_id):
        raise AuthorityError(
            "APPROVAL_ENDPOINT_MISMATCH",
            f"approval {approval_ref} was granted for endpoint "
            f"{approved_endpoint}, not {endpoint_id}", 403)
    invoker_id = str((record.get("invoker") or {}).get("id") or "")
    if invoker_id != str(requester):
        raise AuthorityError(
            "APPROVAL_REQUESTER_MISMATCH",
            f"approval {approval_ref} was requested by {invoker_id or 'nobody'}"
            f", not by {requester}", 403)
    approver = str(approval.get("approved_by") or "")
    if not approver:
        raise AuthorityError(
            "APPROVER_NOT_RECORDED",
            f"approval {approval_ref} names no approver", 403)
    if approver == str(requester):
        raise AuthorityError(
            "SELF_APPROVAL_REFUSED",
            f"{requester} both requested and approved {approval_ref}; "
            f"separation of duties is not satisfied", 403)
    approver_perms, approver_basis = await permissions_for(
        tenant_id, approver, db=db)
    if PERMISSION_APPROVE not in approver_perms:
        raise AuthorityError(
            "APPROVER_NOT_AUTHORIZED",
            f"{approver} does not hold {PERMISSION_APPROVE}, so the "
            f"approval is not authoritative", 403,
            approver=approver, approver_authorization_basis=approver_basis)
    age = _age_seconds(approval.get("approved_at"))
    if age is None:
        raise AuthorityError(
            "APPROVAL_AGE_UNKNOWN",
            f"approval {approval_ref} carries no usable approval time, so "
            f"its freshness cannot be established", 403)
    if age > APPROVAL_MAX_AGE_SECONDS:
        raise AuthorityError(
            "APPROVAL_EXPIRED",
            f"approval {approval_ref} was granted {int(age)}s ago; EDR "
            f"honours an approval for at most {APPROVAL_MAX_AGE_SECONDS}s",
            403, approved_at=approval.get("approved_at"))
    return {
        "approval_ref": approval_ref,
        "approval_status": status,
        "approved_by": approver,
        "approved_at": approval.get("approved_at"),
        "approval_age_seconds": int(age),
        "approval_max_age_seconds": APPROVAL_MAX_AGE_SECONDS,
        "approver_authorization_basis": approver_basis,
        "authority_action_id": action_id,
        "authority_state": record.get("state"),
        "authority_execution_id": record.get("execution_id"),
        "bound_endpoint_id": approved_endpoint,
        "requested_by_on_authority": invoker_id,
    }


async def authorize(*, verb: str, tenant_id: str, endpoint_id: str,
                    requester: str, session_role: Optional[str],
                    approval_ref: Optional[str] = None,
                    db: Any = None) -> Dict[str, Any]:
    """The full gate: permission → authoritative requirement → approval.

    Returns the authority record stamped onto the command. Raises
    `AuthorityError` — and records nothing — on any failure.
    """
    perms, basis = await permissions_for(tenant_id, requester,
                                         session_role, db=db)
    if PERMISSION_EXECUTE not in perms:
        raise AuthorityError(
            "RESPONSE_EXECUTE_NOT_AUTHORIZED",
            f"{requester} does not hold {PERMISSION_EXECUTE}", 403,
            required_permission=PERMISSION_EXECUTE,
            authorization_basis=basis,
            holds_response_permissions=sorted(
                p for p in perms if p.startswith("response.")))

    decision: Dict[str, Any] = {
        "decision": "AUTHORIZED",
        "principal": requester,
        "required_permission": PERMISSION_EXECUTE,
        "authorization_basis": basis,
        "authority": "nivxray::response_engine_approval_authority",
        "authority_service_url": _service_url(),
        "verb": verb,
        "tenant_id": tenant_id,
        "endpoint_id": endpoint_id,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    if verb in PERMISSION_ONLY_VERBS:
        return {**decision, "approval_required": False,
                "approval_requirement_basis":
                    "RESTORATIVE_ACTION_PERMISSION_ONLY",
                "approval_requirement_note":
                    ("releasing containment is never blocked behind a "
                     "second approval: an operator who cannot release a "
                     "contained host is itself a safety failure. The "
                     "action remains authenticated, tenant-bound, "
                     "permission-checked, idempotent, audited and "
                     "independently verified.")}

    action_id = VERB_ACTION_ID.get(verb)
    if not action_id:
        raise AuthorityError(
            "VERB_NOT_MAPPED_TO_AUTHORITY",
            f"{verb} has no authoritative action id, so its approval "
            f"requirement cannot be established", 503)
    spec = await action_spec(action_id)
    approval_required = bool(spec.get("approval_required")
                             or spec.get("destructive"))
    decision.update({
        "authority_action_id": action_id,
        "approval_required": approval_required,
        "destructive": bool(spec.get("destructive")),
        "approval_requirement_basis":
            "RESPONSE_AUTHORITY_ACTION_CATALOGUE",
    })
    if not approval_required:
        return decision
    approval = await validate_approval(
        approval_ref=approval_ref, action_id=action_id, verb=verb,
        tenant_id=tenant_id, endpoint_id=endpoint_id, requester=requester,
        db=db)
    return {**decision, **approval, "approval_validated": True}
