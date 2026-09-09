"""
XDR RBAC — P0-3 of the Admin Control-Plane Spec.

Enterprise-grade, backend-enforced role-based access control.

Model
=====
    USER
     │
     ├── GROUPS  (team membership · authoritative for shared perms)
     │
     └── ROLE ASSIGNMENTS  (many-to-many, per user, per scope)
          │
          └── ROLE  (built-in or custom)
                │
                └── PERMISSION[]  (resource × action, e.g. `users.create`)
                       │
                       └── SCOPE
                              ├── tenant_id       (default: current tenant)
                              ├── resource_ids    (optional: specific rows)
                              └── environment     (optional: prod/stage/etc.)

Enforcement
===========
Any protected FastAPI route may write:

    from routers.xdr_rbac import require_permission
    @router.post("/xxx", dependencies=[Depends(require_permission("secrets.create"))])
    def create_xxx(...): ...

`require_permission` performs:

    principal → user → role assignments → permission set → scope check
       → deny/allow → audit ACCESS_DENIED on deny (SUCCESS-audited by the
       calling route on allow).

Audit
=====
Every RBAC mutation writes to the tamper-evident Audit Log (P0-1) via
`emit_audit`.  Every access-denied returns a deterministic reason.

Backwards compatibility
=======================
Existing routes NOT using `require_permission` behave exactly as before.
Enforcement is *opt-in per route* to prevent an accidental global lockout
during rollout.  We retrofit critical routers (starting with Secrets)
in this same slice.

Follow-up items (in queue after this slice):
- Session revocation surface (requires session middleware, not yet in
  the platform).
- SSO / SAML / OIDC integration surfaces.
- Access review scheduling.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from pymongo import ASCENDING, MongoClient

from deps import get_current_user as _deps_current_user
from routers.xdr_audit_log import emit_audit

router = APIRouter(prefix="/api/xdr/rbac", tags=["xdr-rbac"])

# ── Mongo binding ─────────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    if _client is None:
        return None
    return _client[_DB_NAME]


def _c_users():         return _db()["xdr_users"]        if _db() is not None else None
def _c_api_keys():      return _db()["xdr_api_keys"]     if _db() is not None else None
def _c_roles():         return _db()["xdr_roles"]        if _db() is not None else None
def _c_groups():        return _db()["xdr_groups"]       if _db() is not None else None
def _c_assignments():   return _db()["xdr_user_roles"]   if _db() is not None else None


# ── Canonical Permission Registry ────────────────────────────────
# Format: "resource.action"  →  human_label
# Actions are drawn from a fixed vocabulary so UIs can render matrices
# consistently.  Adding a new permission is a one-line change here.
_ACTIONS = ["read", "write", "create", "update", "delete", "enable", "disable",
                    "execute", "approve", "publish", "rollback", "test",
                    "export", "sync", "rotate", "reveal", "revoke",
                    "install", "assign", "merge", "split", "annotate",
                    "ack", "recommend", "enroll", "configure", "manage",
                    "admin"]

# Each resource enumerates the SUBSET of _ACTIONS meaningful for it.
_RESOURCES: dict[str, dict[str, Any]] = {
    "users":         {"actions": ["read", "create", "update", "delete",
                                                   "enable", "disable"], "group": "Identity"},
    "roles":         {"actions": ["read", "create", "update", "delete",
                                                   "enable", "disable", "publish"],
                              "group": "Identity"},
    "groups":        {"actions": ["read", "create", "update", "delete"],
                              "group": "Identity"},
    "permissions":   {"actions": ["read"], "group": "Identity"},
    "sessions":      {"actions": ["read", "revoke"], "group": "Identity"},
    "api_keys":      {"actions": ["read", "create", "rotate", "revoke",
                                                   "delete"], "group": "Integrations"},
    "webhooks":      {"actions": ["read", "create", "update", "delete",
                                                   "test", "enable", "disable", "rotate"],
                              "group": "Integrations"},
    "secrets":       {"actions": ["read", "create", "update", "rotate",
                                                   "reveal", "delete"], "group": "Governance"},
    "audit":         {"actions": ["read", "write"], "group": "Governance"},
    "tenants":       {"actions": ["read", "manage"], "group": "Platform"},
    "platform":      {"actions": ["read", "admin"], "group": "Platform"},
    "engines":       {"actions": ["read", "admin"], "group": "Platform"},
    "extensions":    {"actions": ["read", "install", "enable", "disable"],
                              "group": "Integrations"},
    "data_sources":  {"actions": ["read", "create", "update", "delete",
                                                   "enable", "disable", "test", "rotate"],
                              "group": "Data & Collection"},
    "collectors":    {"actions": ["read", "create", "update", "delete",
                                                   "enroll", "revoke", "test",
                                                   "enable", "disable", "rotate"],
                              "group": "Data & Collection"},
    "parsers":       {"actions": ["read", "create", "update", "delete",
                                                   "test"], "group": "Data & Collection"},
    "normalization": {"actions": ["read", "update", "test"],
                              "group": "Data & Collection"},
    "detections":    {"actions": ["read", "create", "update", "delete",
                                                   "publish", "test", "rollback"],
                              "group": "Detection"},
    "correlation":   {"actions": ["read", "create", "update", "delete",
                                                   "publish", "test", "rollback"],
                              "group": "Detection"},
    "lolbas":        {"actions": ["read", "sync", "rollback", "disable"],
                              "group": "Intelligence"},
    "gtfobins":      {"actions": ["read", "sync", "rollback", "disable"],
                              "group": "Intelligence"},
    "sigma":         {"actions": ["read", "sync"], "group": "Intelligence"},
    "intel":         {"actions": ["read", "configure", "test", "rotate"],
                              "group": "Intelligence"},
    "osint_providers": {"actions": ["read", "create", "update", "delete",
                                                       "enable", "disable", "test", "rotate"],
                                "group": "Intelligence"},
    "alerts":        {"actions": ["read", "update", "ack", "assign"],
                              "group": "Detection"},
    "incidents":     {"actions": ["read", "update", "assign", "merge",
                                                   "split"], "group": "Investigation"},
    "investigations": {"actions": ["read", "update", "annotate"],
                                "group": "Investigation"},
    "evidence":      {"actions": ["read", "export"], "group": "Investigation"},
    "threat_hunting": {"actions": ["read", "execute"],
                                "group": "Investigation"},
    "playbooks":     {"actions": ["read", "create", "update", "delete",
                                                   "execute", "approve"],
                              "group": "Response"},
    "response":      {"actions": ["read", "execute", "recommend",
                                                   "approve"], "group": "Response"},
    "reports":       {"actions": ["read", "create", "export"],
                              "group": "Governance"},
    "intelligence_policy": {
        "actions": ["read", "update", "override"],
        "group":   "Intelligence",
    },
}


def _all_permissions() -> list[str]:
    return [f"{r}.{a}" for r, meta in _RESOURCES.items()
                 for a in meta["actions"]]


def _valid_permission(p: str) -> bool:
    if p == "*.*": return True
    try:
        r, a = p.split(".", 1)
    except ValueError:
        return False
    if a == "*":
        return r in _RESOURCES or r == "*"
    if r == "*":
        return a in _ACTIONS
    meta = _RESOURCES.get(r)
    return bool(meta and a in meta["actions"])


# ── Built-in starter roles ────────────────────────────────────────
_BUILTIN_ROLES: list[dict] = [
    {"id": "role_builtin_platform_admin",
     "name": "platform_admin", "display_name": "Platform Admin",
     "tier": "PLATFORM", "type": "SYSTEM",
     "description": "Platform-wide authority.  Manages tenants, engines, "
                            "extensions, RBAC, secrets and audit configuration.",
     "permissions": ["*.*"]},
    {"id": "role_builtin_tenant_admin",
     "name": "tenant_admin", "display_name": "Tenant Admin",
     "tier": "MANAGEMENT", "type": "TENANT",
     "description": "Tenant-level control-plane operator.",
     "permissions": ["users.*", "roles.*", "groups.*", "sessions.*",
                             "api_keys.*", "webhooks.*", "secrets.*",
                             "data_sources.*", "collectors.*", "parsers.*",
                             "normalization.*", "detections.*", "correlation.*",
                             "lolbas.*", "gtfobins.*", "sigma.*", "intel.*",
                             "osint_providers.*", "extensions.*", "alerts.*",
                             "incidents.*", "investigations.*", "evidence.*",
                             "threat_hunting.*", "playbooks.*", "response.*",
                             "reports.*", "intelligence_policy.*",
                             "audit.read", "engines.read"]},
    {"id": "role_builtin_soc_manager",
     "name": "soc_manager", "display_name": "SOC Manager",
     "tier": "MANAGEMENT", "type": "SYSTEM",
     "description": "SOC operations manager · assign, review, approve.",
     "permissions": ["alerts.read", "alerts.update", "alerts.assign",
                             "incidents.*", "investigations.*",
                             "evidence.read", "reports.read", "reports.create",
                             "response.approve", "response.recommend",
                             "playbooks.read", "playbooks.approve",
                             "intelligence_policy.read",
                             "intelligence_policy.update",
                             "intelligence_policy.override",
                             "audit.read", "users.read", "roles.read"]},
    {"id": "role_builtin_l3_investigator",
     "name": "l3_investigator", "display_name": "L3 / T3 Investigator",
     "tier": "L3", "type": "SYSTEM",
     "description": "Senior investigator · advanced hunting, complex "
                            "investigation, detection tuning, incident merging.",
     "permissions": ["alerts.read", "alerts.update", "alerts.ack",
                             "incidents.read", "incidents.update",
                             "incidents.merge", "incidents.split",
                             "investigations.*", "evidence.*",
                             "threat_hunting.*", "detections.read",
                             "detections.create", "detections.update",
                             "detections.test", "correlation.read",
                             "correlation.create", "correlation.update",
                             "correlation.test", "intel.read",
                             "playbooks.read", "playbooks.execute",
                             "response.recommend", "response.execute",
                             "lolbas.read", "sigma.read"]},
    {"id": "role_builtin_l2_investigator",
     "name": "l2_investigator", "display_name": "L2 / T2 Investigator",
     "tier": "L2", "type": "SYSTEM",
     "description": "Investigator · deep investigation and threat hunting.",
     "permissions": ["alerts.read", "alerts.update", "alerts.ack",
                             "incidents.read", "incidents.update",
                             "investigations.*", "evidence.read",
                             "evidence.export", "threat_hunting.read",
                             "threat_hunting.execute",
                             "detections.read", "correlation.read",
                             "intel.read", "playbooks.read",
                             "response.recommend", "lolbas.read"]},
    {"id": "role_builtin_l1_analyst",
     "name": "l1_analyst", "display_name": "L1 / T1 Analyst",
     "tier": "L1", "type": "SYSTEM",
     "description": "First-line triage · read + acknowledge + assign.",
     "permissions": ["alerts.read", "alerts.ack", "alerts.assign",
                             "incidents.read", "investigations.read",
                             "investigations.annotate", "evidence.read",
                             "intel.read", "detections.read",
                             "correlation.read", "lolbas.read"]},
    {"id": "role_builtin_threat_hunter",
     "name": "threat_hunter", "display_name": "Threat Hunter",
     "tier": "SPECIALIST", "type": "SYSTEM",
     "description": "Proactive hunting authority.",
     "permissions": ["alerts.read", "incidents.read",
                             "investigations.read", "investigations.annotate",
                             "evidence.read", "evidence.export",
                             "threat_hunting.*", "detections.read",
                             "detections.create", "correlation.read",
                             "correlation.create", "intel.read",
                             "lolbas.read", "sigma.read"]},
    {"id": "role_builtin_detection_sme",
     "name": "detection_sme", "display_name": "Detection Engineering SME",
     "tier": "SPECIALIST", "type": "SYSTEM",
     "description": "Owns detection & correlation content.",
     "permissions": ["detections.*", "correlation.*",
                             "sigma.*", "lolbas.*", "gtfobins.*",
                             "alerts.read", "incidents.read",
                             "investigations.read", "evidence.read",
                             "reports.read", "reports.create"]},
    {"id": "role_builtin_responder",
     "name": "responder", "display_name": "Responder",
     "tier": "SPECIALIST", "type": "SYSTEM",
     "description": "Playbook operator with response-execute authority.",
     "permissions": ["alerts.read", "incidents.read",
                             "investigations.read", "evidence.read",
                             "playbooks.read", "playbooks.execute",
                             "response.execute", "response.recommend",
                             "intel.read"]},
    {"id": "role_builtin_auditor",
     "name": "auditor", "display_name": "Auditor",
     "tier": "AUDIT", "type": "SYSTEM",
     "description": "Read-only + audit visibility.",
     "permissions": ["audit.read", "users.read", "roles.read",
                             "groups.read", "sessions.read",
                             "detections.read", "correlation.read",
                             "alerts.read", "incidents.read",
                             "investigations.read", "evidence.read",
                             "reports.read", "reports.export",
                             "lolbas.read", "sigma.read", "intel.read",
                             "data_sources.read", "collectors.read"]},
    {"id": "role_builtin_read_only",
     "name": "read_only", "display_name": "Read Only",
     "tier": "AUDIT", "type": "SYSTEM",
     "description": "Read-only viewer (no audit access).",
     "permissions": ["alerts.read", "incidents.read",
                             "investigations.read", "evidence.read",
                             "detections.read", "correlation.read",
                             "intel.read", "lolbas.read"]},
]

_BUILTIN_ROLE_BY_ID   = {r["id"]:   r for r in _BUILTIN_ROLES}
_BUILTIN_ROLE_BY_NAME = {r["name"]: r for r in _BUILTIN_ROLES}


# ── Principal extraction ──────────────────────────────────────────
def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


# ── Permission resolution ─────────────────────────────────────────
def _expand_wildcard(perm: str) -> set[str]:
    """Expand `*.*`, `resource.*`, `*.action` to concrete permissions."""
    if perm == "*.*":
        return set(_all_permissions())
    try:
        r, a = perm.split(".", 1)
    except ValueError:
        return set()
    if r == "*":
        return {f"{res}.{a}" for res, meta in _RESOURCES.items()
                    if a in meta["actions"]}
    if a == "*":
        meta = _RESOURCES.get(r)
        return {f"{r}.{ac}" for ac in (meta["actions"] if meta else [])}
    return {perm}


def _role_by_id(role_id: str) -> dict | None:
    if role_id in _BUILTIN_ROLE_BY_ID:
        return _BUILTIN_ROLE_BY_ID[role_id]
    if _c_roles() is None:
        return None
    return _c_roles().find_one({"id": role_id}, {"_id": 0})


def _user_by_id(tenant_id: str, user_id: str) -> dict | None:
    if _c_users() is None:
        return None
    return _c_users().find_one({"tenant_id": tenant_id, "id": user_id},
                                             {"_id": 0})


def _user_by_email(tenant_id: str, email: str) -> dict | None:
    if _c_users() is None:
        return None
    return _c_users().find_one({"tenant_id": tenant_id, "email": email},
                                             {"_id": 0})


def _resolve_user_permissions(tenant_id: str, user_id: str
                                                ) -> tuple[set[str], list[dict]]:
    """Return (effective_permission_set, matched_assignments)."""
    if _c_assignments() is None:
        return set(), []
    assignments = list(_c_assignments().find(
        {"tenant_id": tenant_id, "user_id": user_id},
        {"_id": 0},
    ))
    perms: set[str] = set()
    for a in assignments:
        role = _role_by_id(a.get("role_id", ""))
        if role and role.get("enabled", True):
            for p in role.get("permissions", []):
                perms |= _expand_wildcard(p)
    return perms, assignments


def check_access(tenant_id: str, principal_id: str, permission: str,
                          resource_id: str | None = None) -> dict:
    """Deterministic access check.

    Returns:
        {allow: bool, reason: str, matched_role: str|None,
         matched_permission: str|None, effective_permissions: [..],
         scope_ok: bool}
    """
    if not _valid_permission(permission):
        return {"allow": False, "reason": "unknown-permission",
                     "matched_role": None, "matched_permission": None,
                     "effective_permissions": [], "scope_ok": False}
    if _c_users() is None:
        return {"allow": False, "reason": "storage-unavailable",
                     "matched_role": None, "matched_permission": None,
                     "effective_permissions": [], "scope_ok": False}

    user = _user_by_email(tenant_id, principal_id) or \
              _user_by_id(tenant_id, principal_id)
    if not user:
        return {"allow": False, "reason": "user-not-provisioned",
                     "matched_role": None, "matched_permission": None,
                     "effective_permissions": [], "scope_ok": False}
    if not user.get("enabled", True):
        return {"allow": False, "reason": "user-disabled",
                     "matched_role": None, "matched_permission": None,
                     "effective_permissions": [], "scope_ok": False}

    perms, assignments = _resolve_user_permissions(tenant_id, user["id"])

    # Match permission (concrete first, then any wildcard hit already
    # expanded into `perms`).
    if permission not in perms:
        return {"allow": False, "reason": "permission-not-granted",
                     "matched_role": None, "matched_permission": None,
                     "effective_permissions": sorted(perms),
                     "scope_ok": False,
                     "user_id": user["id"]}

    # Scope check — first matching assignment whose role provides this
    # permission and whose scope allows the resource.
    for a in assignments:
        role = _role_by_id(a.get("role_id", ""))
        if not role or not role.get("enabled", True):
            continue
        role_expanded = set()
        for p in role.get("permissions", []):
            role_expanded |= _expand_wildcard(p)
        if permission not in role_expanded:
            continue
        # Scope filter.
        scope = a.get("scope") or {}
        allowed_ids = scope.get("resource_ids") or []
        if allowed_ids and resource_id and resource_id not in allowed_ids:
            continue
        return {"allow": True, "reason": "role-permission-match",
                     "matched_role": role.get("name"),
                     "matched_permission": permission,
                     "effective_permissions": sorted(perms),
                     "scope_ok": True,
                     "user_id": user["id"]}

    return {"allow": False, "reason": "scope-denied",
                 "matched_role": None, "matched_permission": permission,
                 "effective_permissions": sorted(perms),
                 "scope_ok": False,
                 "user_id": user["id"]}


# ── Machine principals · XDR collector API keys ───────────────────
# A telemetry collector is not a user: it holds no JWT and has no row in
# `xdr_users`.  It authenticates with a scoped API key minted by
# `routers.xdr_api_keys`, which persists ONLY the SHA-256 digest of the
# plaintext (there is no plaintext column and therefore no plaintext
# comparison path anywhere in this file).
#
# Every one of the following is a DENY — the machine path is as
# fail-closed as the JWT path:
#     missing key · malformed key · unknown digest · disabled · revoked
#     · expired · malformed expiry · tenant mismatch · scope mismatch
#     · authorization store unavailable (503)
_API_KEY_HEADER = "X-XDR-API-Key"
_API_KEY_RE     = re.compile(r"^nvx_[0-9a-f]{48}$")
_TENANT_RE      = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _machine_denied(permission: str, reason: str, *, status: int = 401):
    return HTTPException(status_code=status, detail={
        "code": "ACCESS_DENIED", "permission": permission,
        "principal_kind": "api_key", "reason": reason})


def _key_effective_permissions(doc: dict) -> set[str]:
    perms: set[str] = set()
    for s in doc.get("scopes") or []:
        if isinstance(s, str) and _valid_permission(s):
            perms |= _expand_wildcard(s)
    return perms


def _audit_machine_denial(tenant: str | None, key_id: str | None,
                                          permission: str, reason: str) -> None:
    try:
        emit_audit(tenant_id=tenant or "unknown",
                          principal_id=f"apikey:{key_id or 'unknown'}",
                          principal_kind="api_key",
                          action="ACCESS_DENIED", resource_kind="permission",
                          resource_id=permission, outcome="FAILURE",
                          metadata={"reason": reason})
    except Exception:  # noqa: BLE001,S110
        pass


def authenticate_api_key(request: Request, raw_key: str,
                                          permission: str) -> dict:
    """Authenticate a collector API key and authorize `permission`.

    Returns the matched (hash-stripped) key document.  Raises on every
    failure — there is no permissive branch.
    """
    tenant_hdr = request.headers.get("X-Tenant-Id")
    if not _API_KEY_RE.fullmatch(raw_key or ""):
        _audit_machine_denial(tenant_hdr, None, permission, "malformed-api-key")
        raise _machine_denied(permission, "malformed-api-key")
    if not tenant_hdr or not _TENANT_RE.fullmatch(tenant_hdr):
        _audit_machine_denial(tenant_hdr, None, permission, "missing-tenant-header")
        raise _machine_denied(permission, "missing-tenant-header")
    if not _valid_permission(permission):
        raise _machine_denied(permission, "unknown-permission", status=403)
    if _c_api_keys() is None:
        raise HTTPException(status_code=503, detail={
            "code": "AUTHZ_UNAVAILABLE", "permission": permission,
            "reason": "authorization store unavailable"})

    digest = hashlib.sha256(raw_key.encode("ascii")).hexdigest()
    doc = _c_api_keys().find_one({"hash": digest})
    if (not doc or not isinstance(doc.get("hash"), str)
            or not hmac.compare_digest(doc["hash"], digest)):
        _audit_machine_denial(tenant_hdr, None, permission, "unknown-api-key")
        raise _machine_denied(permission, "unknown-api-key")

    kid = doc.get("id")
    if doc.get("revoked_at") is not None:
        _audit_machine_denial(tenant_hdr, kid, permission, "api-key-revoked")
        raise _machine_denied(permission, "api-key-revoked", status=403)
    if doc.get("enabled") is not True:
        _audit_machine_denial(tenant_hdr, kid, permission, "api-key-disabled")
        raise _machine_denied(permission, "api-key-disabled", status=403)
    exp = doc.get("expires_at")
    if exp is not None:
        try:
            expires = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            # A malformed expiry is never treated as never-expiring.
            _audit_machine_denial(tenant_hdr, kid, permission, "api-key-expiry-malformed")
            raise _machine_denied(permission, "api-key-expiry-malformed", status=403)
        if datetime.now(timezone.utc) >= expires:
            _audit_machine_denial(tenant_hdr, kid, permission, "api-key-expired")
            raise _machine_denied(permission, "api-key-expired", status=403)
    if doc.get("tenant_id") != tenant_hdr:
        _audit_machine_denial(tenant_hdr, kid, permission, "api-key-tenant-mismatch")
        raise _machine_denied(permission, "api-key-tenant-mismatch", status=403)
    if permission not in _key_effective_permissions(doc):
        _audit_machine_denial(tenant_hdr, kid, permission, "scope-not-granted")
        raise _machine_denied(permission, "scope-not-granted", status=403)

    now = datetime.now(timezone.utc).isoformat()
    src_ip = request.client.host if request.client else None
    try:
        _c_api_keys().update_one({"_id": doc["_id"]}, {
            "$set": {"last_used_at": now, "last_used_ip": src_ip},
            "$inc": {"use_count": 1}})
    except Exception:  # noqa: BLE001,S110
        # Usage telemetry is best-effort; it must not gate a valid request.
        pass
    # Downstream routers read the principal for audit purposes.
    request.state.tenant_id      = doc["tenant_id"]
    request.state.principal_id   = f"apikey:{kid}"
    request.state.principal_kind = "api_key"
    return {k: v for k, v in doc.items() if k not in ("hash", "_id")}


# ── Enforcement dependency ────────────────────────────────────────
_bearer_optional = HTTPBearer(auto_error=False)


def require_permission(permission: str, *, resource_id_header: str | None = None):
    """FastAPI dependency factory.  Use like:

        @router.post("/x", dependencies=[Depends(require_permission("secrets.create"))])

    Two mutually exclusive principals are accepted:
      · USER    — a verified JWT (`deps.get_current_user`), resolved
                  through role assignments in `xdr_users` / `xdr_user_roles`.
      · MACHINE — an `X-XDR-API-Key` + `X-Tenant-Id` pair validated
                  against the SHA-256 digests in `xdr_api_keys`.
    Presenting both is ambiguous and rejected.
    """
    async def _dep(request: Request,
                            creds: HTTPAuthorizationCredentials | None =
                                Depends(_bearer_optional)):
        # Machine principal — collector API key.  Evaluated before the JWT
        # path only when no bearer token is present, so a bad JWT can never
        # fall through to key auth.
        raw_key = request.headers.get(_API_KEY_HEADER)
        if raw_key is not None and creds is not None:
            raise _machine_denied(permission, "ambiguous-credentials")
        if raw_key is not None:
            authenticate_api_key(request, raw_key, permission)
            return True
        # No credential at all => fail closed (same 403 HTTPBearer produced
        # before this dual-principal path existed).
        if creds is None:
            raise HTTPException(status_code=403, detail={
                "code": "ACCESS_DENIED", "permission": permission,
                "reason": "unauthenticated"})
        # User principal — identity comes ONLY from the verified JWT.
        user = await _deps_current_user(creds)
        # P0-SEC (2026-09-09) · FAIL CLOSED.
        #
        # The previous implementation resolved the principal from the
        # client-supplied `X-Tenant-Id` / `X-Principal-Id` headers and then
        # returned True whenever `users` had no document for that tenant.
        # `_principal()` defaults an anonymous caller to tenant "default" /
        # `system@ingest`, and `seed_admin()` writes admins with no
        # `tenant_id`, so that count was permanently 0 — every RBAC-gated
        # route was open to unauthenticated callers in production.
        #
        # Identity now comes ONLY from the verified JWT (`get_current_user`,
        # which raises 403 without a bearer token and 401 on an invalid or
        # expired one, before any body validation or datastore lookup).
        # Client headers can no longer establish identity, `system@ingest`
        # is not reachable from an external request, and the tenant-empty
        # bootstrap bypass is gone: the first admin is created by
        # `deps.seed_admin()` at startup, which never traverses RBAC, so no
        # chicken-and-egg lockout exists.
        email = (user or {}).get("email")
        role = (user or {}).get("role")
        if not email:
            raise HTTPException(status_code=403, detail={
                "code": "ACCESS_DENIED", "permission": permission,
                "reason": "unauthenticated"})
        rid = request.headers.get(resource_id_header) if resource_id_header else None
        # Cross-tenant platform administrator — the same role gate
        # `deps.require_admin` enforces elsewhere.
        if role == "admin":
            return True
        # Tenant-scoped principal: the tenant is read from the AUTHENTICATED
        # user record, never from a request header.
        ten = (user or {}).get("tenant_id")
        if not ten:
            raise HTTPException(status_code=403, detail={
                "code": "ACCESS_DENIED", "permission": permission,
                "reason": "principal has no tenant scope"})
        # Datastore unavailable => fail closed, never open.
        if _c_users() is None:
            raise HTTPException(status_code=503, detail={
                "code": "AUTHZ_UNAVAILABLE", "permission": permission,
                "reason": "authorization store unavailable"})
        pid, pkd = email, "user"
        result = check_access(ten, pid, permission, resource_id=rid)
        if not result["allow"]:
            # Audit access denials (never fabricate; never spam on user-not-provisioned).
            try:
                emit_audit(
                    tenant_id=ten, principal_id=pid, principal_kind=pkd,
                    action="ACCESS_DENIED", resource_kind="permission",
                    resource_id=permission, outcome="FAILURE",
                    metadata={"reason": result["reason"],
                                    "resource_target": rid},
                )
            except Exception:  # noqa: BLE001,S110
                pass
            raise HTTPException(status_code=403, detail={
                "code": "ACCESS_DENIED", "permission": permission,
                "reason": result["reason"]})
        return True
    return _dep


# ── Pydantic bodies ───────────────────────────────────────────────
class ScopeSpec(BaseModel):
    tenant_ids:   list[str] = Field(default_factory=list)
    resource_ids: list[str] = Field(default_factory=list)
    environment:  str | None = None


class CreateRoleBody(BaseModel):
    name: str = Field(min_length=1, max_length=64,
                                pattern=r"^[a-z0-9_.:-]+$")
    display_name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    tier: str | None = None
    type: str = "CUSTOM"
    permissions: list[str] = Field(default_factory=list)


class UpdateRoleBody(BaseModel):
    display_name: str | None = None
    description: str | None = None
    tier: str | None = None
    permissions: list[str] | None = None
    enabled: bool | None = None


class CreateUserBody(BaseModel):
    email: str = Field(min_length=3, max_length=180)
    display_name: str | None = None
    groups: list[str] = Field(default_factory=list)
    initial_roles: list[str] = Field(default_factory=list,
                                                        description="role names or ids")


class UpdateUserBody(BaseModel):
    display_name: str | None = None
    groups: list[str] | None = None
    enabled: bool | None = None


class AssignRoleBody(BaseModel):
    role_id: str
    scope: ScopeSpec = Field(default_factory=ScopeSpec)


class CreateGroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=80,
                                pattern=r"^[a-zA-Z0-9_.:-]+$")
    description: str | None = None


class SimulateBody(BaseModel):
    user_id_or_email: str
    permission: str
    resource_id: str | None = None


# ── Endpoints · permissions catalog ──────────────────────────────
@router.get("/permissions",
                     dependencies=[Depends(require_permission("permissions.read"))])
def list_permissions():
    groups: dict[str, list[dict]] = {}
    for r, meta in _RESOURCES.items():
        groups.setdefault(meta["group"], []).append(
            {"resource": r,
              "permissions": [{"key": f"{r}.{a}", "action": a} for a in meta["actions"]]})
    return {"ok": True, "data": {"actions": _ACTIONS,
                                                    "resources": _RESOURCES,
                                                    "groups": groups,
                                                    "all": _all_permissions()}}


# ── Endpoints · roles ─────────────────────────────────────────────
def _list_all_roles():
    custom = list(_c_roles().find({}, {"_id": 0})) if _c_roles() is not None else []
    return _BUILTIN_ROLES + custom


@router.get("/roles",
                     dependencies=[Depends(require_permission("roles.read"))])
def list_roles():
    rows = _list_all_roles()
    return {"ok": True, "data": {"roles": rows, "count": len(rows)}}


@router.get("/roles/{role_id}",
                     dependencies=[Depends(require_permission("roles.read"))])
def get_role(role_id: str):
    role = _role_by_id(role_id)
    if not role:
        raise HTTPException(status_code=404, detail="role not found")
    expanded = set()
    for p in role.get("permissions", []):
        expanded |= _expand_wildcard(p)
    return {"ok": True, "data": {**role,
                                                    "effective_permissions": sorted(expanded)}}


@router.post("/roles",
                     dependencies=[Depends(require_permission("roles.create"))])
def create_role(body: CreateRoleBody, request: Request):
    if _c_roles() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    for p in body.permissions:
        if not _valid_permission(p):
            raise HTTPException(status_code=400,
                detail=f"invalid permission: {p}")
    if body.name in _BUILTIN_ROLE_BY_NAME:
        raise HTTPException(status_code=409,
            detail="role name collides with a built-in role")
    if _c_roles().find_one({"name": body.name}):
        raise HTTPException(status_code=409, detail="role name already exists")
    now = datetime.now(timezone.utc).isoformat()
    rid = f"role_{uuid.uuid4().hex[:20]}"
    doc = {"id": rid, "name": body.name,
              "display_name": body.display_name,
              "description": body.description,
              "tier": body.tier, "type": body.type or "CUSTOM",
              "permissions": list(body.permissions), "enabled": True,
              "created_at": now, "updated_at": now, "created_by": pid}
    _c_roles().insert_one(dict(doc))
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="ROLE_CREATED", resource_kind="role",
                                resource_id=rid,
                                after={"name": body.name,
                                            "permissions_count": len(body.permissions)})
    return {"ok": True, "data": doc, "audit_ref": audit["id"]}


@router.put("/roles/{role_id}",
                    dependencies=[Depends(require_permission("roles.update"))])
def update_role(role_id: str, body: UpdateRoleBody, request: Request):
    if _c_roles() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    if role_id in _BUILTIN_ROLE_BY_ID:
        raise HTTPException(status_code=409, detail="cannot modify built-in role")
    ten, pid, pkd = _principal(request)
    doc = _c_roles().find_one({"id": role_id})
    if not doc:
        raise HTTPException(status_code=404, detail="role not found")
    patch: dict[str, Any] = {}
    if body.display_name is not None: patch["display_name"] = body.display_name
    if body.description is not None:  patch["description"]  = body.description
    if body.tier is not None:         patch["tier"]         = body.tier
    if body.enabled is not None:      patch["enabled"]      = body.enabled
    if body.permissions is not None:
        for p in body.permissions:
            if not _valid_permission(p):
                raise HTTPException(status_code=400,
                    detail=f"invalid permission: {p}")
        patch["permissions"] = list(body.permissions)
    if not patch:
        raise HTTPException(status_code=400, detail="no updatable fields")
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    _c_roles().update_one({"_id": doc["_id"]}, {"$set": patch})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="ROLE_UPDATED", resource_kind="role",
                                resource_id=role_id,
                                before={k: doc.get(k) for k in patch if k != "updated_at"},
                                after={k: v for k, v in patch.items() if k != "updated_at"})
    return {"ok": True, "data": _c_roles().find_one({"id": role_id}, {"_id": 0}),
                 "audit_ref": audit["id"]}


@router.post("/roles/{role_id}/clone",
                       dependencies=[Depends(require_permission("roles.create"))])
def clone_role(role_id: str, request: Request):
    src = _role_by_id(role_id)
    if not src:
        raise HTTPException(status_code=404, detail="role not found")
    ten, pid, pkd = _principal(request)
    now = datetime.now(timezone.utc).isoformat()
    new_id = f"role_{uuid.uuid4().hex[:20]}"
    base_name = src["name"] + "_copy"
    n, name = 0, base_name
    while _c_roles().find_one({"name": name}) or name in _BUILTIN_ROLE_BY_NAME:
        n += 1
        name = f"{base_name}_{n}"
    doc = {"id": new_id, "name": name,
              "display_name": src["display_name"] + " (Copy)",
              "description": src.get("description"),
              "tier": src.get("tier"), "type": "CUSTOM",
              "permissions": list(src.get("permissions") or []),
              "enabled": True, "created_at": now, "updated_at": now,
              "created_by": pid, "cloned_from": role_id}
    _c_roles().insert_one(dict(doc))
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="ROLE_CLONED", resource_kind="role",
                                resource_id=new_id,
                                after={"cloned_from": role_id, "name": name})
    return {"ok": True, "data": doc, "audit_ref": audit["id"]}


@router.delete("/roles/{role_id}",
                          dependencies=[Depends(require_permission("roles.delete"))])
def delete_role(role_id: str, request: Request):
    if role_id in _BUILTIN_ROLE_BY_ID:
        raise HTTPException(status_code=409, detail="cannot delete built-in role")
    doc = _c_roles().find_one({"id": role_id})
    if not doc:
        raise HTTPException(status_code=404, detail="role not found")
    # Deny if any assignments reference this role.
    if _c_assignments().count_documents({"role_id": role_id}) > 0:
        raise HTTPException(status_code=409,
            detail="role still has active user assignments · remove them first")
    ten, pid, pkd = _principal(request)
    _c_roles().delete_one({"_id": doc["_id"]})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="ROLE_DELETED", resource_kind="role",
                                resource_id=role_id,
                                before={"name": doc.get("name")})
    return {"ok": True, "data": {"id": role_id, "deleted": True},
                 "audit_ref": audit["id"]}


# ── Endpoints · users ─────────────────────────────────────────────
@router.get("/users",
                     dependencies=[Depends(require_permission("users.read"))])
def list_users(request: Request):
    if _c_users() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    rows = list(_c_users().find({"tenant_id": ten}, {"_id": 0}).sort(
        "email", ASCENDING))
    # Attach role summaries.
    for r in rows:
        assigns = list(_c_assignments().find(
            {"tenant_id": ten, "user_id": r["id"]}, {"_id": 0}))
        r["assignments"] = assigns
        r["role_names"]  = sorted({(_role_by_id(a["role_id"]) or {}).get("name")
                                                  for a in assigns} - {None})
    return {"ok": True, "data": {"users": rows, "count": len(rows)}}


@router.post("/users",
                     dependencies=[Depends(require_permission("users.create"))])
def create_user(body: CreateUserBody, request: Request):
    if _c_users() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    if _c_users().find_one({"tenant_id": ten, "email": body.email}):
        raise HTTPException(status_code=409,
            detail=f"user '{body.email}' already exists for tenant")
    now = datetime.now(timezone.utc).isoformat()
    uid = f"usr_{uuid.uuid4().hex[:20]}"
    doc = {"id": uid, "tenant_id": ten, "email": body.email,
              "display_name": body.display_name or body.email,
              "groups": list(body.groups or []),
              "enabled": True, "created_at": now, "updated_at": now,
              "last_login": None, "created_by": pid}
    _c_users().insert_one(dict(doc))

    initial_assignments: list[dict] = []
    for role_ref in body.initial_roles or []:
        role = _role_by_id(role_ref) or _BUILTIN_ROLE_BY_NAME.get(role_ref)
        if role is None and _c_roles() is not None:
            role = _c_roles().find_one({"name": role_ref}, {"_id": 0})
        if not role:
            continue
        aid = f"asg_{uuid.uuid4().hex[:20]}"
        _c_assignments().insert_one({"id": aid, "tenant_id": ten,
                                                        "user_id": uid,
                                                        "role_id": role["id"],
                                                        "scope": {}, "created_at": now,
                                                        "created_by": pid})
        initial_assignments.append({"id": aid, "role_id": role["id"],
                                                     "role_name": role["name"]})

    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="USER_CREATED", resource_kind="user",
                                resource_id=uid,
                                after={"email": body.email,
                                            "initial_roles": [a["role_name"]
                                                                        for a in initial_assignments]})
    return {"ok": True, "data": {**doc, "assignments": initial_assignments},
                 "audit_ref": audit["id"]}


@router.put("/users/{user_id}",
                    dependencies=[Depends(require_permission("users.update"))])
def update_user(user_id: str, body: UpdateUserBody, request: Request):
    if _c_users() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _c_users().find_one({"tenant_id": ten, "id": user_id})
    if not doc:
        raise HTTPException(status_code=404, detail="user not found")
    patch: dict[str, Any] = {}
    if body.display_name is not None: patch["display_name"] = body.display_name
    if body.groups is not None:       patch["groups"]       = list(body.groups)
    if body.enabled is not None:      patch["enabled"]      = body.enabled
    if not patch:
        raise HTTPException(status_code=400, detail="no updatable fields")
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    _c_users().update_one({"_id": doc["_id"]}, {"$set": patch})
    action = ("USER_ENABLED" if body.enabled is True
                    else "USER_DISABLED" if body.enabled is False
                    else "USER_UPDATED")
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action=action, resource_kind="user",
                                resource_id=user_id,
                                before={k: doc.get(k) for k in patch if k != "updated_at"},
                                after={k: v for k, v in patch.items() if k != "updated_at"})
    return {"ok": True, "data": _c_users().find_one({"id": user_id}, {"_id": 0}),
                 "audit_ref": audit["id"]}


@router.delete("/users/{user_id}",
                          dependencies=[Depends(require_permission("users.delete"))])
def delete_user(user_id: str, request: Request):
    if _c_users() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _c_users().find_one({"tenant_id": ten, "id": user_id})
    if not doc:
        raise HTTPException(status_code=404, detail="user not found")
    _c_users().delete_one({"_id": doc["_id"]})
    _c_assignments().delete_many({"tenant_id": ten, "user_id": user_id})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="USER_DELETED", resource_kind="user",
                                resource_id=user_id,
                                before={"email": doc.get("email")})
    return {"ok": True, "data": {"id": user_id, "deleted": True},
                 "audit_ref": audit["id"]}


@router.post("/users/{user_id}/roles",
                       dependencies=[Depends(require_permission("roles.publish"))])
def assign_role(user_id: str, body: AssignRoleBody, request: Request):
    if _c_users() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    if not _user_by_id(ten, user_id):
        raise HTTPException(status_code=404, detail="user not found")
    role = _role_by_id(body.role_id)
    if not role:
        raise HTTPException(status_code=404, detail="role not found")
    # Idempotent: if the same role is already assigned with equal scope,
    # return the existing assignment.
    scope = body.scope.model_dump()
    existing = _c_assignments().find_one(
        {"tenant_id": ten, "user_id": user_id, "role_id": body.role_id,
         "scope": scope},
    )
    if existing:
        return {"ok": True, "data": {**existing, "_id": None,
                                                    "idempotent": True}}
    aid = f"asg_{uuid.uuid4().hex[:20]}"
    doc = {"id": aid, "tenant_id": ten, "user_id": user_id,
              "role_id": body.role_id, "role_name": role.get("name"),
              "scope": scope,
              "created_at": datetime.now(timezone.utc).isoformat(),
              "created_by": pid}
    _c_assignments().insert_one(dict(doc))
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="ROLE_ASSIGNED", resource_kind="user_role",
                                resource_id=aid,
                                after={"user_id": user_id,
                                            "role_name": role.get("name"),
                                            "scope": scope})
    doc.pop("_id", None)
    return {"ok": True, "data": doc, "audit_ref": audit["id"]}


@router.delete("/users/{user_id}/roles/{assignment_id}",
                          dependencies=[Depends(require_permission("roles.publish"))])
def revoke_role(user_id: str, assignment_id: str, request: Request):
    if _c_users() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    a = _c_assignments().find_one({"tenant_id": ten,
                                                        "user_id": user_id,
                                                        "id": assignment_id})
    if not a:
        raise HTTPException(status_code=404, detail="assignment not found")
    _c_assignments().delete_one({"_id": a["_id"]})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="ROLE_REMOVED", resource_kind="user_role",
                                resource_id=assignment_id,
                                before={"user_id": user_id,
                                              "role_name": a.get("role_name")})
    return {"ok": True, "data": {"id": assignment_id, "removed": True},
                 "audit_ref": audit["id"]}


@router.get("/users/{user_id}/effective",
                     dependencies=[Depends(require_permission("users.read"))])
def effective_permissions(user_id: str, request: Request):
    """Return the resolved permission set for a user (union of assigned roles)."""
    ten, _, _ = _principal(request)
    u = _user_by_id(ten, user_id) or _user_by_email(ten, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    perms, assigns = _resolve_user_permissions(ten, u["id"])
    return {"ok": True, "data": {
        "user":        {"id": u["id"], "email": u["email"],
                                "enabled": u.get("enabled", True)},
        "roles":       [_role_by_id(a["role_id"]) for a in assigns
                              if _role_by_id(a["role_id"])],
        "assignments": assigns,
        "permissions": sorted(perms),
        "count":       len(perms),
    }}


# ── Endpoints · groups ────────────────────────────────────────────
@router.get("/groups",
                     dependencies=[Depends(require_permission("groups.read"))])
def list_groups(request: Request):
    if _c_groups() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    rows = list(_c_groups().find({"tenant_id": ten}, {"_id": 0}))
    return {"ok": True, "data": {"groups": rows, "count": len(rows)}}


@router.post("/groups",
                     dependencies=[Depends(require_permission("groups.create"))])
def create_group(body: CreateGroupBody, request: Request):
    if _c_groups() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    if _c_groups().find_one({"tenant_id": ten, "name": body.name}):
        raise HTTPException(status_code=409, detail="group name already exists")
    gid = f"grp_{uuid.uuid4().hex[:20]}"
    doc = {"id": gid, "tenant_id": ten, "name": body.name,
              "description": body.description,
              "created_at": datetime.now(timezone.utc).isoformat(),
              "created_by": pid}
    _c_groups().insert_one(dict(doc))
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="GROUP_CREATED", resource_kind="group",
                                resource_id=gid,
                                after={"name": body.name})
    doc.pop("_id", None)
    return {"ok": True, "data": doc, "audit_ref": audit["id"]}


@router.delete("/groups/{group_id}",
                          dependencies=[Depends(require_permission("groups.delete"))])
def delete_group(group_id: str, request: Request):
    if _c_groups() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _c_groups().find_one({"tenant_id": ten, "id": group_id})
    if not doc:
        raise HTTPException(status_code=404, detail="group not found")
    _c_groups().delete_one({"_id": doc["_id"]})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="GROUP_DELETED", resource_kind="group",
                                resource_id=group_id,
                                before={"name": doc.get("name")})
    return {"ok": True, "data": {"id": group_id, "deleted": True},
                 "audit_ref": audit["id"]}


# ── Access simulation ─────────────────────────────────────────────
@router.post("/simulate",
                       dependencies=[Depends(require_permission("permissions.read"))])
def simulate(body: SimulateBody, request: Request):
    """Test whether a user WOULD be allowed a specific permission.
    Never mutates state.  Emits an audit ACCESS_SIMULATED event."""
    ten, pid, pkd = _principal(request)
    target = _user_by_email(ten, body.user_id_or_email) or \
                    _user_by_id(ten, body.user_id_or_email)
    if not target:
        return {"ok": True, "data": {"decision": "DENY",
                                                        "reason": "user-not-provisioned",
                                                        "target": body.user_id_or_email,
                                                        "permission": body.permission}}
    result = check_access(ten, target["email"], body.permission,
                                       resource_id=body.resource_id)
    try:
        emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                          action="ACCESS_SIMULATED", resource_kind="rbac_check",
                          resource_id=target["id"],
                          metadata={"permission": body.permission,
                                          "decision": "ALLOW" if result["allow"] else "DENY",
                                          "reason": result["reason"]})
    except Exception:  # noqa: BLE001,S110
        pass
    return {"ok": True, "data": {
        "decision":  "ALLOW" if result["allow"] else "DENY",
        "reason":    result["reason"],
        "target":    {"id": target["id"], "email": target["email"]},
        "permission": body.permission,
        "matched_role":       result.get("matched_role"),
        "matched_permission": result.get("matched_permission"),
        "effective_permissions_count": len(result.get("effective_permissions") or []),
        "scope_ok":  result.get("scope_ok"),
    }}


# ── Endpoint · session context (shell customer pill) ──────────────
# The XDR shell top bar previously printed the analyst's e-mail where the
# customer belongs. Tenant identity is an authorisation fact, so it is
# resolved here from the persisted principal and the real case corpus.
@router.get("/session-context")
def rbac_session_context(user=Depends(_deps_current_user)):
    from services.session_context import tenant_context
    return {"ok": True, "data": tenant_context((user or {}).get("email"))}
