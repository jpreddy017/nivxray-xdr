"""Program D · the access AUTHORITY — one resolver, every decision cited.

Repairs the verified defect recorded in
`memory/RBAC-0_ACCESS_MANAGEMENT_DISCOVERY.md` (row "Groups", verdict
REPAIR): an `xdr_groups` document had no members field and no roles field,
and `_resolve_user_permissions()` read the assignments collection only. A
group therefore **could not contain anyone and could not grant anything** —
it was a label that looked like authority. This module makes the group a
real grant path, and adds the two concepts that were entirely absent:
direct grants, and explicit restrictions (the only way to express DENY).

FROZEN PRECEDENCE — evaluated in this order, and this order only:

    0. tenant resolution            (happens BEFORE this module is called)
    1. explicit RESTRICTION    → DENY   · always wins, even over admin
    2. direct GRANT            → ALLOW
    3. GROUP → role → permission → ALLOW
    4. direct ROLE assignment  → ALLOW
    5. otherwise               → DENY   `no-applicable-grant`

Every decision returns the path that produced it. **A decision without a
path is a bug, not a default** — `explain()` therefore never returns an
empty path, not even for a denial.

WHAT THIS MODULE DOES NOT DO
  * It does not authenticate. The principal arrives already authenticated
    and already tenant-resolved.
  * It does not widen `require_permission()`. It is a resolver: the gate
    still decides, still fails closed, and now fails closed for one more
    reason (an explicit restriction).
  * It does not read UI state. UI visibility is not authority.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable

# ── decision sources, in precedence order ─────────────────────────
SOURCE_RESTRICTION = "RESTRICTION"
SOURCE_DIRECT_GRANT = "DIRECT_GRANT"
SOURCE_GROUP_ROLE = "GROUP_ROLE"
SOURCE_DIRECT_ROLE = "DIRECT_ROLE"
SOURCE_NONE = "NO_APPLICABLE_GRANT"

PRECEDENCE = (SOURCE_RESTRICTION, SOURCE_DIRECT_GRANT, SOURCE_GROUP_ROLE,
              SOURCE_DIRECT_ROLE)

REASON_RESTRICTED = "explicit-restriction"
REASON_GRANTED_DIRECT = "direct-grant"
REASON_GRANTED_GROUP = "group-role-permission-match"
REASON_GRANTED_ROLE = "role-permission-match"
REASON_NO_GRANT = "no-applicable-grant"


def resolve(*, tenant_id: str, user: dict[str, Any],
            role_by_id: Callable[[str], dict | None],
            expand: Callable[[str], Iterable[str]],
            assignments: list[dict[str, Any]],
            groups: list[dict[str, Any]],
            grants: list[dict[str, Any]],
            restrictions: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the full effective-access picture for ONE principal.

    `assignments` are direct user→role rows. `groups` are every group in
    the tenant (membership is filtered here, so a caller cannot forget to).
    """
    user_id = user.get("id") or ""
    paths: dict[str, list[dict[str, Any]]] = {}
    allowed: set[str] = set()
    restricted: set[str] = set()

    def add(perm: str, entry: dict[str, Any]) -> None:
        paths.setdefault(perm, []).append(entry)

    # ── 1 · restrictions. Collected FIRST so nothing below can be read
    #        without knowing a DENY exists.
    for r in restrictions:
        if r.get("user_id") != user_id:
            continue
        for perm in _expand_all(r.get("permissions") or [], expand):
            restricted.add(perm)
            add(perm, {
                "source": SOURCE_RESTRICTION,
                "decision": "DENY",
                "restriction_id": r.get("id"),
                "reason": r.get("reason") or "",
                "granted_by": r.get("created_by"),
                "granted_at": r.get("created_at"),
                "note": ("an explicit restriction withholds this permission "
                         "and outranks every grant, including a role held "
                         "by an administrator"),
            })

    # ── 2 · direct grants
    for g in grants:
        if g.get("user_id") != user_id:
            continue
        for perm in _expand_all(g.get("permissions") or [], expand):
            allowed.add(perm)
            add(perm, {
                "source": SOURCE_DIRECT_GRANT,
                "decision": "ALLOW",
                "grant_id": g.get("id"),
                "reason": g.get("reason") or "",
                "granted_by": g.get("created_by"),
                "granted_at": g.get("created_at"),
                "scope": g.get("scope") or {},
            })

    # ── 3 · group → role → permission
    group_assignments: list[dict[str, Any]] = []
    member_groups: list[dict[str, Any]] = []
    for grp in groups:
        if user_id not in (grp.get("members") or []):
            continue
        if not grp.get("enabled", True):
            continue
        member_groups.append(grp)
        for role_id in (grp.get("roles") or []):
            role = role_by_id(role_id)
            if not role or not role.get("enabled", True):
                continue
            # A group role binding carries the GROUP's scope. When the
            # group declares none, the binding is tenant-wide for that
            # role — stated here because an unstated scope default is how
            # authorization accidents happen.
            group_assignments.append({
                "assignment_id": f"group:{grp.get('id')}:{role_id}",
                "role_id": role_id,
                "scope": grp.get("scope") or {},
                "via_group": grp.get("id"),
                "via_group_name": grp.get("name"),
            })
            for p in role.get("permissions", []):
                for perm in expand(p):
                    allowed.add(perm)
                    add(perm, {
                        "source": SOURCE_GROUP_ROLE,
                        "decision": "ALLOW",
                        "group_id": grp.get("id"),
                        "group_name": grp.get("name"),
                        "role_id": role_id,
                        "role_name": role.get("name"),
                        "permission_declared": p,
                        "scope": grp.get("scope") or {},
                    })

    # ── 4 · direct role assignments
    for a in assignments:
        role = role_by_id(a.get("role_id", ""))
        if not role or not role.get("enabled", True):
            continue
        for p in role.get("permissions", []):
            for perm in expand(p):
                allowed.add(perm)
                add(perm, {
                    "source": SOURCE_DIRECT_ROLE,
                    "decision": "ALLOW",
                    "assignment_id": a.get("id"),
                    "role_id": a.get("role_id"),
                    "role_name": role.get("name"),
                    "permission_declared": p,
                    "scope": a.get("scope") or {},
                })

    effective = allowed - restricted

    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "effective_permissions": sorted(effective),
        "granted_permissions": sorted(allowed),
        "restricted_permissions": sorted(restricted),
        "withheld_by_restriction": sorted(allowed & restricted),
        "paths": paths,
        "assignments": list(assignments) + group_assignments,
        "sources": {
            "groups": [{"id": g.get("id"), "name": g.get("name"),
                        "roles": g.get("roles") or []}
                       for g in member_groups],
            "direct_roles": [a.get("role_id") for a in assignments],
            "grants": [g.get("id") for g in grants
                       if g.get("user_id") == user_id],
            "restrictions": [r.get("id") for r in restrictions
                             if r.get("user_id") == user_id],
        },
        "precedence": list(PRECEDENCE) + [SOURCE_NONE],
    }


def _expand_all(perms: Iterable[str],
                expand: Callable[[str], Iterable[str]]) -> set[str]:
    out: set[str] = set()
    for p in perms:
        out |= set(expand(p))
    return out


def explain(resolved: dict[str, Any], permission: str) -> dict[str, Any]:
    """WHY does this principal have — or not have — this permission?

    Returns the winning path and every other path that was considered, so
    an auditor can see that a DENY outranked an ALLOW rather than having to
    trust that it did.
    """
    considered = resolved["paths"].get(permission, [])
    deny = [p for p in considered if p["decision"] == "DENY"]
    allow = [p for p in considered if p["decision"] == "ALLOW"]

    if deny:
        winning = deny[0]
        return {
            "permission": permission, "allow": False,
            "reason": REASON_RESTRICTED,
            "winning_path": winning,
            "overridden_paths": allow,
            "explanation": _sentence(False, winning),
            "considered": considered,
        }
    for source, reason in ((SOURCE_DIRECT_GRANT, REASON_GRANTED_DIRECT),
                           (SOURCE_GROUP_ROLE, REASON_GRANTED_GROUP),
                           (SOURCE_DIRECT_ROLE, REASON_GRANTED_ROLE)):
        match = next((p for p in allow if p["source"] == source), None)
        if match:
            return {
                "permission": permission, "allow": True, "reason": reason,
                "winning_path": match,
                "overridden_paths": [p for p in allow if p is not match],
                "explanation": _sentence(True, match),
                "considered": considered,
            }
    return {
        "permission": permission, "allow": False, "reason": REASON_NO_GRANT,
        "winning_path": {"source": SOURCE_NONE, "decision": "DENY",
                         "note": ("no group, grant or role assignment "
                                  "provides this permission to this "
                                  "principal in this tenant")},
        "overridden_paths": [],
        "explanation": (f"DENIED ↳ no applicable grant ↳ {permission}"),
        "considered": considered,
    }


def _sentence(allow: bool, path: dict[str, Any]) -> str:
    """The four-sentence explanation shape frozen in RBAC-0 §2."""
    head = "ALLOWED" if allow else "DENIED"
    src = path.get("source")
    if src == SOURCE_GROUP_ROLE:
        return (f"{head} ↳ {path.get('group_name')} (group) ↳ "
                f"{path.get('role_name')} ↳ "
                f"{path.get('permission_declared')}")
    if src == SOURCE_DIRECT_ROLE:
        return (f"{head} ↳ {path.get('role_name')} (role) ↳ "
                f"{path.get('permission_declared')}")
    if src == SOURCE_DIRECT_GRANT:
        return (f"{head} ↳ direct grant ↳ granted by "
                f"{path.get('granted_by') or 'unknown'} on "
                f"{path.get('granted_at') or 'unknown date'}")
    if src == SOURCE_RESTRICTION:
        return (f"{head} ↳ explicit restriction ↳ withheld"
                + (f" · {path['reason']}" if path.get("reason") else ""))
    return f"{head} ↳ no applicable grant"


def escalation_check(*, actor_permissions: set[str],
                     requested: Iterable[str],
                     expand: Callable[[str], Iterable[str]]
                     ) -> tuple[bool, list[str]]:
    """No principal may grant more than it itself holds.

    Returns `(ok, over_grant)`. This is checked on every write path that
    can widen someone's access — group role binding, direct grant, role
    assignment — because an administrator who can mint a permission they
    do not hold is a privilege-escalation primitive, not an administrator.
    """
    wanted = _expand_all(requested, expand)
    over = sorted(wanted - set(actor_permissions))
    return (not over), over
