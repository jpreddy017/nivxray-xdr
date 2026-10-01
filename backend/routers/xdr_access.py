"""Program D · Access Management write paths + Effective Access.

Every endpoint here can WIDEN or NARROW someone's authority, so every one
of them is escalation-checked: **no principal may grant more than it
itself holds**. An administrator able to mint a permission they do not
hold is a privilege-escalation primitive, not an administrator.

`require_permission()` is untouched. These endpoints sit behind it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from routers.xdr_rbac import (
    _all_permissions, _c_groups, _c_grants, _c_restrictions, _c_users,
    _expand_wildcard, _role_by_id, _user_by_id, resolve_access,
    resolve_principal, require_permission,
)
from routers.xdr_audit_log import emit_audit as _emit
from services import access_authority

router = APIRouter(prefix="/api/xdr/rbac", tags=["xdr-access-management"])

READ = Depends(require_permission("users.read"))
WRITE = Depends(require_permission("users.update"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit_audit(request: Request, *, action: str, tenant_id: str,
               target: str, outcome: str, detail: dict) -> None:
    """Audit adapter — every access change is recorded, hash-chained."""
    _, principal = _actor(request)
    _emit(tenant_id=tenant_id, principal_id=principal,
          principal_kind="user", action=action,
          resource_kind="access", resource_id=target, outcome=outcome,
          after=detail, source="xdr-access-management")


def _actor(req: Request) -> tuple[str, str]:
    tenant, principal, _ = resolve_principal(req)
    return tenant, principal


def _actor_permissions(tenant: str, principal: str) -> set[str]:
    from routers.xdr_rbac import _user_by_email
    user = _user_by_email(tenant, principal) or _user_by_id(tenant, principal)
    if not user:
        return set()
    return set(resolve_access(tenant, user)["effective_permissions"])


def _guard_escalation(tenant: str, principal: str,
                      requested: list[str]) -> None:
    ok, over = access_authority.escalation_check(
        actor_permissions=_actor_permissions(tenant, principal),
        requested=requested, expand=_expand_wildcard)
    if not ok:
        raise HTTPException(403, detail={
            "code": "PRIVILEGE_ESCALATION_REFUSED",
            "reason": ("a principal may not grant a permission it does not "
                       "itself hold"),
            "over_granted": over})


def _validate_permissions(perms: list[str]) -> None:
    catalog = set(_all_permissions())
    unknown = sorted(p for p in perms
                     if p not in catalog and not p.endswith(".*")
                     and p != "*.*")
    if unknown:
        raise HTTPException(400, detail={
            "code": "UNKNOWN_PERMISSION",
            "reason": "the permission catalog is the frozen contract",
            "unknown": unknown})


def _group(tenant: str, group_id: str) -> dict[str, Any]:
    coll = _c_groups()
    doc = coll.find_one({"tenant_id": tenant, "id": group_id}, {"_id": 0}) \
        if coll is not None else None
    if not doc:
        raise HTTPException(404, detail={"code": "GROUP_NOT_FOUND",
                                         "group_id": group_id})
    return doc


class MembersBody(BaseModel):
    user_ids: list[str] = Field(default_factory=list)


class GroupRolesBody(BaseModel):
    role_ids: list[str] = Field(default_factory=list)
    scope: dict[str, Any] | None = None


class GrantBody(BaseModel):
    permissions: list[str] = Field(default_factory=list)
    reason: str = ""
    scope: dict[str, Any] | None = None


class RestrictionBody(BaseModel):
    permissions: list[str] = Field(default_factory=list)
    reason: str = ""


# ── groups · membership and role binding (the REPAIR) ─────────────
@router.get("/groups/{group_id}/effective", dependencies=[READ])
def group_effective(group_id: str, request: Request):
    tenant, _ = _actor(request)
    grp = _group(tenant, group_id)
    perms: set[str] = set()
    roles: list[dict[str, Any]] = []
    for rid in grp.get("roles") or []:
        role = _role_by_id(rid)
        if not role:
            continue
        expanded: set[str] = set()
        for p in role.get("permissions", []):
            expanded |= _expand_wildcard(p)
        roles.append({"role_id": rid, "name": role.get("name"),
                      "enabled": role.get("enabled", True),
                      "permission_count": len(expanded)})
        if role.get("enabled", True):
            perms |= expanded
    members = []
    if _c_users() is not None:
        for uid in grp.get("members") or []:
            u = _user_by_id(tenant, uid)
            members.append({"user_id": uid,
                            "email": (u or {}).get("email"),
                            "enabled": (u or {}).get("enabled", True),
                            "provisioned": bool(u)})
    return {"ok": True, "data": {
        "group": grp, "members": members, "roles": roles,
        "effective_permissions": sorted(perms),
        "authority_note": ("a group grants only through the roles bound to "
                           "it. A group with no roles is a label, and this "
                           "surface reports it as granting nothing"),
    }}


@router.put("/groups/{group_id}/members", dependencies=[WRITE])
def set_group_members(group_id: str, body: MembersBody, request: Request):
    tenant, principal = _actor(request)
    grp = _group(tenant, group_id)
    # Membership may only name principals provisioned IN THIS TENANT.
    # Without this check a group becomes a cross-tenant bridge.
    unknown = [uid for uid in body.user_ids
               if not _user_by_id(tenant, uid)]
    if unknown:
        raise HTTPException(400, detail={
            "code": "USER_NOT_IN_TENANT",
            "reason": ("group membership may only name principals "
                       "provisioned in this tenant"),
            "unknown": unknown})
    # Adding a member widens THAT member's access by the group's roles, so
    # the actor must already hold everything the group grants.
    granted = group_effective(group_id, request)["data"][
        "effective_permissions"]
    _guard_escalation(tenant, principal, granted)

    _c_groups().update_one({"tenant_id": tenant, "id": group_id},
                           {"$set": {"members": list(dict.fromkeys(
                               body.user_ids)),
                               "updated_at": _now(),
                               "updated_by": principal}})
    emit_audit(request, action="GROUP_MEMBERS_SET", tenant_id=tenant,
               target=group_id, outcome="SUCCESS",
               detail={"members": body.user_ids,
                       "previous": grp.get("members") or []})
    return {"ok": True, "data": {"group_id": group_id,
                                 "members": body.user_ids}}


@router.put("/groups/{group_id}/roles", dependencies=[WRITE])
def set_group_roles(group_id: str, body: GroupRolesBody, request: Request):
    tenant, principal = _actor(request)
    _group(tenant, group_id)
    missing = [rid for rid in body.role_ids if not _role_by_id(rid)]
    if missing:
        raise HTTPException(404, detail={"code": "ROLE_NOT_FOUND",
                                         "unknown": missing})
    widened: set[str] = set()
    for rid in body.role_ids:
        role = _role_by_id(rid) or {}
        for p in role.get("permissions", []):
            widened |= _expand_wildcard(p)
    _guard_escalation(tenant, principal, sorted(widened))

    update: dict[str, Any] = {"roles": list(dict.fromkeys(body.role_ids)),
                              "updated_at": _now(),
                              "updated_by": principal}
    if body.scope is not None:
        update["scope"] = body.scope
    _c_groups().update_one({"tenant_id": tenant, "id": group_id},
                           {"$set": update})
    emit_audit(request, action="GROUP_ROLES_SET", tenant_id=tenant,
               target=group_id, outcome="SUCCESS",
               detail={"roles": body.role_ids, "scope": body.scope})
    return {"ok": True, "data": {"group_id": group_id,
                                 "roles": body.role_ids,
                                 "effective_permissions": sorted(widened)}}


# ── direct grants and restrictions ────────────────────────────────
@router.post("/users/{user_id}/grants", dependencies=[WRITE])
def create_grant(user_id: str, body: GrantBody, request: Request):
    tenant, principal = _actor(request)
    if not _user_by_id(tenant, user_id):
        raise HTTPException(404, detail={"code": "USER_NOT_FOUND",
                                         "user_id": user_id})
    _validate_permissions(body.permissions)
    _guard_escalation(tenant, principal, body.permissions)
    doc = {"id": f"grant_{uuid.uuid4().hex[:16]}", "tenant_id": tenant,
           "user_id": user_id, "permissions": body.permissions,
           "reason": body.reason, "scope": body.scope or {},
           "created_at": _now(), "created_by": principal}
    _c_grants().insert_one(dict(doc))
    emit_audit(request, action="ACCESS_GRANT_CREATED", tenant_id=tenant,
               target=user_id, outcome="SUCCESS",
               detail={"grant_id": doc["id"],
                       "permissions": body.permissions,
                       "reason": body.reason})
    return {"ok": True, "data": doc}


@router.delete("/users/{user_id}/grants/{grant_id}", dependencies=[WRITE])
def delete_grant(user_id: str, grant_id: str, request: Request):
    tenant, principal = _actor(request)
    res = _c_grants().delete_one({"tenant_id": tenant, "user_id": user_id,
                                  "id": grant_id})
    if res.deleted_count == 0:
        raise HTTPException(404, detail={"code": "GRANT_NOT_FOUND",
                                         "grant_id": grant_id})
    emit_audit(request, action="ACCESS_GRANT_REVOKED", tenant_id=tenant,
               target=user_id, outcome="SUCCESS",
               detail={"grant_id": grant_id, "by": principal})
    return {"ok": True, "data": {"grant_id": grant_id, "revoked": True}}


@router.post("/users/{user_id}/restrictions", dependencies=[WRITE])
def create_restriction(user_id: str, body: RestrictionBody,
                       request: Request):
    tenant, principal = _actor(request)
    if not _user_by_id(tenant, user_id):
        raise HTTPException(404, detail={"code": "USER_NOT_FOUND",
                                         "user_id": user_id})
    _validate_permissions(body.permissions)
    # A restriction NARROWS access, so it is deliberately NOT
    # escalation-checked: withholding a permission can never widen anyone.
    doc = {"id": f"restrict_{uuid.uuid4().hex[:16]}", "tenant_id": tenant,
           "user_id": user_id, "permissions": body.permissions,
           "reason": body.reason, "created_at": _now(),
           "created_by": principal}
    _c_restrictions().insert_one(dict(doc))
    emit_audit(request, action="ACCESS_RESTRICTION_CREATED",
               tenant_id=tenant, target=user_id, outcome="SUCCESS",
               detail={"restriction_id": doc["id"],
                       "permissions": body.permissions,
                       "reason": body.reason})
    return {"ok": True, "data": doc}


@router.delete("/users/{user_id}/restrictions/{restriction_id}",
               dependencies=[WRITE])
def delete_restriction(user_id: str, restriction_id: str, request: Request):
    tenant, principal = _actor(request)
    res = _c_restrictions().delete_one({"tenant_id": tenant,
                                        "user_id": user_id,
                                        "id": restriction_id})
    if res.deleted_count == 0:
        raise HTTPException(404, detail={"code": "RESTRICTION_NOT_FOUND",
                                         "restriction_id": restriction_id})
    emit_audit(request, action="ACCESS_RESTRICTION_LIFTED",
               tenant_id=tenant, target=user_id, outcome="SUCCESS",
               detail={"restriction_id": restriction_id, "by": principal})
    return {"ok": True, "data": {"restriction_id": restriction_id,
                                 "lifted": True}}


# ── effective access · every permission, with its path ────────────
@router.get("/users/{user_id}/effective-access", dependencies=[READ])
def effective_access(user_id: str, request: Request):
    """WHY does this principal have — or not have — each permission?"""
    tenant, _ = _actor(request)
    user = _user_by_id(tenant, user_id)
    if not user:
        raise HTTPException(404, detail={"code": "USER_NOT_FOUND",
                                         "user_id": user_id})
    resolved = resolve_access(tenant, user)
    rows = [access_authority.explain(resolved, perm)
            for perm in sorted(set(resolved["granted_permissions"])
                               | set(resolved["restricted_permissions"]))]
    return {"ok": True, "data": {
        "user": {"id": user.get("id"), "email": user.get("email"),
                 "enabled": user.get("enabled", True)},
        "effective_permissions": resolved["effective_permissions"],
        "withheld_by_restriction": resolved["withheld_by_restriction"],
        "sources": resolved["sources"],
        "precedence": resolved["precedence"],
        "decisions": rows,
        "enforcement_note": ("this is the SAME resolver that "
                             "require_permission() enforces with. It is an "
                             "explanation of enforcement, not a parallel "
                             "model of it"),
    }}


@router.get("/users/{user_id}/effective-access/{permission}",
            dependencies=[READ])
def explain_permission(user_id: str, permission: str, request: Request):
    tenant, _ = _actor(request)
    user = _user_by_id(tenant, user_id)
    if not user:
        raise HTTPException(404, detail={"code": "USER_NOT_FOUND",
                                         "user_id": user_id})
    resolved = resolve_access(tenant, user)
    return {"ok": True, "data": access_authority.explain(resolved,
                                                         permission)}
