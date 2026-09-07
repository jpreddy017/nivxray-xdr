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
                   inherited_tenant: Optional[str] = None) -> Dict[str, Any]:
    """Principal + tenant authorisation + the resolved active customer.

    ``inherited_tenant`` is only ever passed by the server after it has
    itself read the tenant off an authorised incident document.
    """
    scope = resolve_tenant_scope(email)
    customers = list_customers(email) if scope.get("authorized") else []

    if inherited_tenant:
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
            "all_tenants": bool(scope.get("all_tenants")),
            "tenant_ids": scope.get("tenant_ids") or [],
        },
        "customers": customers,
        "active_customer": {"value": active, "basis": basis},
        "edr_tenant_boundary": EDR_TENANT_BOUNDARY,
    }


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
