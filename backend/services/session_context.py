"""Authoritative session / customer context.

One implementation, two consumers: the XDR shell's customer pill and the
NivXForge EDR entry-context endpoint. Nothing here trusts the browser —
the principal comes from the bearer token, the tenant authorisation from
``resolve_tenant_scope`` and the customer list from the real case corpus
via the single authoritative queue predicate ``dashboard_lenses._scope``.

Entry context (owner-locked 2026-09-07):

    DIRECT_EDR  — the analyst authenticated into the EDR plane; tenant
                  context is whatever the principal is authorised for.
    XDR_PIVOT   — the analyst arrived from an XDR incident; the tenant is
                  INHERITED from that incident and may not be switched
                  while the investigation context is held.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from deps import sync_collection
from services.dashboard_lenses import _scope, resolve_tenant_scope

_cases = sync_collection("workspace_cases")

#: Stated, not implied. Ownership is resolved server-side from the
#: enrolment record and cross-checked against each observation.
EDR_TENANT_BOUNDARY = (
    "Endpoint ownership is resolved from the authenticated enrolment "
    "record (edr_endpoints.tenant_id) cross-checked against each "
    "observation's tenant_id via the connector_id the sensor "
    "authenticated with. A customer-scoped principal is shown its own "
    "endpoints or nothing — never another customer's. Observations that "
    "carry no owner stay UNATTRIBUTED_LEGACY_OBSERVATION and are "
    "released to cross-tenant roles only; they are never assigned to a "
    "customer by inference."
)


def list_customers(email: Optional[str], limit: int = 25) -> List[Dict[str, Any]]:
    """Real customers the principal is authorised to see.

    Same predicate as the incident queue and the MSS panels, so the
    customer list can never drift from the queue it links to.
    """
    q = _scope({}, email)
    pipeline = [
        {"$match": q},
        {"$group": {
            "_id": {"$ifNull": ["$tenant_id",
                                {"$ifNull": ["$user_email", "default"]}]},
            "open": {"$sum": {"$cond": [
                {"$not": [{"$in": ["$incident_state",
                                   ["resolved", "closed"]]}]}, 1, 0]}},
            "total": {"$sum": 1},
        }},
        {"$sort": {"open": -1, "_id": 1}},
        {"$limit": int(limit)},
    ]
    return [{"customer": r["_id"], "open_incidents": int(r["open"]),
             "incidents": int(r["total"]),
             "queue_href": f"/xdr/incidents?customer={r['_id']}"}
            for r in _cases.aggregate(pipeline)]


def tenant_context(email: Optional[str],
                   inherited_tenant: Optional[str] = None,
                   explicit_tenant: Optional[str] = None) -> Dict[str, Any]:
    """Principal + tenant authorisation + the resolved active customer.

    ``inherited_tenant`` is only ever passed by the server after it has
    itself read the tenant off an authorised incident document.

    P3 · B5/B7 · ``explicit_tenant`` is the registry-resolved
    ``X-Tenant-Id`` the caller named. It NARROWS the reported scope and the
    customer list to that one tenant, so a cross-tenant principal asking
    about a tenant is not answered with the whole estate.
    """
    scope = resolve_tenant_scope(email)
    customers = list_customers(email) if scope.get("authorized") else []
    if explicit_tenant:
        customers = [c for c in customers
                     if c.get("customer") == explicit_tenant]

    if explicit_tenant:
        active, basis = explicit_tenant, "EXPLICIT_REQUEST_TENANT"
    elif inherited_tenant:
        active, basis = inherited_tenant, "INHERITED_FROM_INCIDENT"
    elif not scope.get("authorized"):
        active, basis = None, "NOT_AUTHORIZED"
    elif not scope.get("all_tenants") and len(scope.get("tenant_ids") or []) == 1:
        active, basis = scope["tenant_ids"][0], "SINGLE_AUTHORIZED_TENANT"
    elif scope.get("all_tenants"):
        active, basis = None, "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
    else:
        active, basis = None, "MULTIPLE_AUTHORIZED_TENANTS"

    return {
        "principal": {"email": email, "role": scope.get("role")},
        "tenant_scope": {
            "authorized": bool(scope.get("authorized")),
            "all_tenants": False if explicit_tenant
                           else bool(scope.get("all_tenants")),
            "tenant_ids": ([explicit_tenant] if explicit_tenant
                           else scope.get("tenant_ids") or []),
            "explicit_tenant": explicit_tenant,
        },
        "customers": customers,
        "active_customer": {"value": active, "basis": basis},
        "edr_tenant_boundary": EDR_TENANT_BOUNDARY,
    }


# ── A0.5 · authoritative scope contract ───────────────────────────
# ScopeSelection is CLIENT INTENT. EffectiveScope is SERVER TRUTH.
#
#     EffectiveScope = RequestedScope ∩ AuthorizedScope
#
# Nothing below introduces a second resolver: every authorization fact is
# read from ``resolve_tenant_scope`` (the tenant authority), the customer
# list from ``list_customers`` (the case corpus) and the resolution reason
# from the same six bases ``tenant_context`` already publishes.

#: The six authoritative resolution bases. The Scope Navigator's state
#: machine is THIS set — a presentation layer may relabel them, never
#: replace them.
SCOPE_BASES = (
    "EXPLICIT_REQUEST_TENANT",
    "INHERITED_FROM_INCIDENT",
    "SINGLE_AUTHORIZED_TENANT",
    "MULTIPLE_AUTHORIZED_TENANTS",
    "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER",
    "NOT_AUTHORIZED",
)

#: Analyst-facing wording for each basis. Presentation metadata only — the
#: basis remains the authoritative reason and is always returned alongside.
SCOPE_BASIS_LABELS = {
    "EXPLICIT_REQUEST_TENANT":   "Selected tenant",
    "INHERITED_FROM_INCIDENT":   "Scope locked to incident customer",
    "SINGLE_AUTHORIZED_TENANT":  "Only authorized tenant",
    "MULTIPLE_AUTHORIZED_TENANTS": "Multiple tenants available",
    "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER": "Cross-tenant scope",
    "NOT_AUTHORIZED":            "Not authorized",
}

#: Tenant Groups · CONTRACT SHAPE ONLY (owner decision, A0.5-6).
#: There is no persistent tenant-group model in this backend. Groups are
#: NEVER derived from the case corpus and presented as administratively
#: configured groups, and group membership NEVER confers tenant access.
TENANT_GROUP_STATE = "DEFERRED_NOT_YET_AUTHORITATIVE"
TENANT_GROUP_CONTRACT = {
    "state": TENANT_GROUP_STATE,
    "reason": ("no persistent tenant-group model is approved or implemented; "
               "groups organize scope and never grant authority"),
    "fields": ["group_id", "name", "description", "tenant_ids",
               "authorized_tenant_ids", "denied_tenant_ids",
               "requested_count", "effective_count",
               "provenance", "version"],
}


class ScopeDenied(Exception):
    """Fail-closed scope resolution failure.

    Raised whenever a tenant/scope cannot be established. There is no
    implicit ``"default"`` tenant: an unresolved tenant is a DENIAL, never
    a substitution.
    """

    def __init__(self, code: str, reason: str, basis: str = "NOT_AUTHORIZED",
                 requested: Optional[str] = None, http: int = 403):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.basis = basis
        self.requested = requested
        self.http = http

    def detail(self) -> Dict[str, Any]:
        return {"code": self.code, "reason": self.reason,
                "basis": self.basis, "requested_tenant": self.requested,
                "fail_closed": True}


def authorize_requested_tenant(email: Optional[str],
                               requested: Optional[str] = None
                               ) -> tuple[str, str]:
    """Resolve the ONE tenant a control-plane operation acts in.

    ``requested`` is whatever the caller named (``X-Tenant-Id``). It is an
    INPUT to authorization, never a result of it.

    Returns ``(tenant_id, basis)``; raises :class:`ScopeDenied` when no
    tenant can be authoritatively established. **Never returns a fallback
    tenant** — that was T-RISK-1.
    """
    if not email:
        raise ScopeDenied("ACCESS_DENIED",
                          "no verified principal; identity cannot be "
                          "established from a client header",
                          "NOT_AUTHORIZED", requested)
    scope = resolve_tenant_scope(email)
    if not scope.get("authorized"):
        raise ScopeDenied("ACCESS_DENIED",
                          "principal is not authorized for any tenant",
                          "NOT_AUTHORIZED", requested)
    all_tenants = bool(scope.get("all_tenants"))
    authorized = [t for t in (scope.get("tenant_ids") or []) if t]

    if requested:
        if all_tenants or requested in authorized:
            return requested, "EXPLICIT_REQUEST_TENANT"
        raise ScopeDenied("TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL",
                          "principal is not authorized for the requested "
                          "tenant; naming a tenant never authorizes one",
                          "NOT_AUTHORIZED", requested)
    if all_tenants:
        raise ScopeDenied("TENANT_REQUIRED",
                          "cross-tenant principal must name the tenant it is "
                          "operating in; there is no default tenant",
                          "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER", requested)
    if len(authorized) == 1:
        return authorized[0], "SINGLE_AUTHORIZED_TENANT"
    if len(authorized) > 1:
        raise ScopeDenied("TENANT_REQUIRED",
                          "principal is authorized for several tenants and "
                          "named none; there is no default tenant",
                          "MULTIPLE_AUTHORIZED_TENANTS", requested)
    raise ScopeDenied("TENANT_NOT_RESOLVED",
                      "principal holds no tenant scope; no tenant can be "
                      "established, so the request fails closed",
                      "NOT_AUTHORIZED", requested)


def effective_scope(email: Optional[str],
                    kind: str = "all_authorized",
                    tenant_id: Optional[str] = None,
                    group_tenant_ids: Optional[List[str]] = None,
                    incident_id: Optional[str] = None) -> Dict[str, Any]:
    """Resolve a ``ScopeSelection`` into the authoritative EffectiveScope.

    The browser REQUESTS a scope; this function DETERMINES it. The result
    is always an intersection with the authorized set — never a union,
    never the requested set, never a group's membership list.
    """
    requested = {"kind": kind, "tenant_id": tenant_id,
                 "group_tenant_ids": list(group_tenant_ids or [])}
    scope = resolve_tenant_scope(email)
    authorized = [t for t in (scope.get("tenant_ids") or []) if t]
    all_tenants = bool(scope.get("all_tenants"))
    customers = [c.get("customer") for c in
                 (list_customers(email) if scope.get("authorized") else [])]
    # For a cross-tenant principal the authorized universe is the real
    # customer corpus it may see — never a tenant table, never invented.
    universe = customers if all_tenants else authorized

    def _deny(basis: str, reason: str) -> Dict[str, Any]:
        return {"tenant_ids": [], "requested": requested,
                "authorized_count": len(universe),
                "basis": basis, "basis_label": SCOPE_BASIS_LABELS[basis],
                "denied_tenant_ids": [t for t in
                                      ([tenant_id] if tenant_id else
                                       list(group_tenant_ids or []))],
                "cross_tenant": False, "locked": False,
                "lock_reason": None, "authority": "server",
                "authorized": False, "reason": reason,
                "tenant_groups": TENANT_GROUP_CONTRACT}

    if not email or not scope.get("authorized"):
        return _deny("NOT_AUTHORIZED",
                     "principal is not authorized for any tenant")

    # Incident-bound scope is a SECURITY property, not a UX preference.
    if incident_id:
        bound = authorised_incident(incident_id, email)
        if bound["state"] != "AUTHORIZED":
            return _deny("NOT_AUTHORIZED", bound["state"])
        locked_tenant = bound["tenant"]
        if tenant_id and tenant_id != locked_tenant:
            out = _deny("INHERITED_FROM_INCIDENT",
                        "SCOPE_LOCKED_TO_INCIDENT · this incident belongs to "
                        "another tenant; leave the incident context to change "
                        "tenant")
            out["locked"] = True
            out["lock_reason"] = ("scope is locked to the incident's "
                                  "authoritative customer")
            return out
        return {"tenant_ids": [locked_tenant], "requested": requested,
                "authorized_count": len(universe),
                "basis": "INHERITED_FROM_INCIDENT",
                "basis_label": SCOPE_BASIS_LABELS["INHERITED_FROM_INCIDENT"],
                "denied_tenant_ids": [], "cross_tenant": False,
                "locked": True,
                "lock_reason": ("this incident belongs to " + str(locked_tenant)
                                + "; investigation and response are "
                                "restricted to this tenant"),
                "authority": "server", "authorized": True,
                "resource": {"kind": "incident", "id": incident_id},
                "tenant_groups": TENANT_GROUP_CONTRACT}

    if kind == "tenant":
        if not tenant_id:
            return _deny("NOT_AUTHORIZED",
                         "scope kind 'tenant' requires a tenant_id")
        if all_tenants or tenant_id in authorized:
            return {"tenant_ids": [tenant_id], "requested": requested,
                    "authorized_count": len(universe),
                    "basis": "EXPLICIT_REQUEST_TENANT",
                    "basis_label": SCOPE_BASIS_LABELS["EXPLICIT_REQUEST_TENANT"],
                    "denied_tenant_ids": [], "cross_tenant": False,
                    "locked": False, "lock_reason": None,
                    "authority": "server", "authorized": True,
                    "tenant_groups": TENANT_GROUP_CONTRACT}
        return _deny("NOT_AUTHORIZED",
                     "principal is not authorized for the requested tenant")

    if kind == "group":
        members = [t for t in (group_tenant_ids or []) if t]
        if not members:
            return _deny("NOT_AUTHORIZED",
                         "scope kind 'group' requires the group's tenant_ids; "
                         "tenant groups are not authoritative in this build")
        granted = ([m for m in members] if all_tenants
                   else [m for m in members if m in authorized])
        denied = [m for m in members if m not in granted]
        if not granted:
            out = _deny("NOT_AUTHORIZED",
                        "no tenant in the requested group is within your "
                        "authorization; group membership never grants access")
            out["denied_tenant_ids"] = denied
            return out
        return {"tenant_ids": granted, "requested": requested,
                "authorized_count": len(universe),
                "basis": ("SINGLE_AUTHORIZED_TENANT" if len(granted) == 1
                          else "MULTIPLE_AUTHORIZED_TENANTS"),
                "basis_label": SCOPE_BASIS_LABELS[
                    "SINGLE_AUTHORIZED_TENANT" if len(granted) == 1
                    else "MULTIPLE_AUTHORIZED_TENANTS"],
                "denied_tenant_ids": denied,
                "requested_count": len(members),
                "effective_count": len(granted),
                "cross_tenant": len(granted) > 1,
                "locked": False, "lock_reason": None,
                "authority": "server", "authorized": True,
                "tenant_groups": TENANT_GROUP_CONTRACT}

    # kind == "all_authorized"
    if all_tenants:
        return {"tenant_ids": list(universe), "requested": requested,
                "authorized_count": len(universe),
                "basis": "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER",
                "basis_label": SCOPE_BASIS_LABELS[
                    "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"],
                "denied_tenant_ids": [], "cross_tenant": True,
                "locked": False, "lock_reason": None,
                "authority": "server", "authorized": True,
                "tenant_groups": TENANT_GROUP_CONTRACT}
    if len(authorized) == 1:
        basis = "SINGLE_AUTHORIZED_TENANT"
    elif len(authorized) > 1:
        basis = "MULTIPLE_AUTHORIZED_TENANTS"
    else:
        return _deny("NOT_AUTHORIZED",
                     "principal holds no tenant scope")
    return {"tenant_ids": list(authorized), "requested": requested,
            "authorized_count": len(universe),
            "basis": basis, "basis_label": SCOPE_BASIS_LABELS[basis],
            "denied_tenant_ids": [], "cross_tenant": len(authorized) > 1,
            "locked": False, "lock_reason": None,
            "authority": "server", "authorized": True,
            "tenant_groups": TENANT_GROUP_CONTRACT}


def authorised_incident(incident_id: str,
                        email: Optional[str]) -> Dict[str, Any]:
    """Read an incident ONLY if the principal's tenant scope allows it.

    Returns ``{"state": ..., "doc": ...}``. The browser may name an
    incident; it may never assert that it is allowed to see it.
    """
    doc = _cases.find_one({"id": incident_id}, {"_id": 0}) or {}
    if not doc:
        return {"state": "INCIDENT_NOT_FOUND", "doc": None}
    scope = resolve_tenant_scope(email)
    if not scope.get("authorized"):
        return {"state": "NOT_AUTHORIZED", "doc": None}
    tenant = doc.get("tenant_id") or doc.get("user_email") or "default"
    if not scope.get("all_tenants") and tenant not in (scope.get("tenant_ids") or []):
        return {"state": "INCIDENT_TENANT_OUT_OF_SCOPE", "doc": None}
    return {"state": "AUTHORIZED", "doc": doc, "tenant": tenant}
