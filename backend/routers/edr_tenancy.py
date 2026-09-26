"""P0 · the ONE fail-closed tenant authority for the NivXForge EDR planes.

Gate H (production, publish 100 / build 8833215) proved that B5 convergence
had been applied to `routers/edr_enrollment.py` only. `GET /api/edr/endpoints`
accepted an authenticated request with no tenant at all and silently IGNORED a
supplied `X-Tenant-Id`, so `NIVX_TENANT_REGISTRY_ENFORCE=true` could not reach
it — `tenant_registry.authoritative()` was never called.

Two distinct questions had been conflated:

    resolve_tenant_scope(email)        = which tenants is this PRINCIPAL
                                         authorised for?      (authorisation)
    tenant_registry.authoritative(id)  = which single registered ACTIVE tenant
                                         is this REQUEST acting in? (authority)

Both are required, in that order, and the second may only ever NARROW the
first. This module introduces no new authority: it reuses
`services.tenant_registry` exactly as `edr_enrollment._tenant()` already does.

Three route classes, because the sensor plane is not the analyst plane:

  TENANT_SCOPED     explicit `X-Tenant-Id`, resolved through the registry.
  SENSOR_SCOPED     tenant comes from the AUTHENTICATED ENDPOINT SESSION and
                    is validated against the registry. A caller-supplied
                    header is never read here.
  PRODUCT_METADATA  product truth, identical for every tenant, carries no
                    tenant data. Authentication still required; explicit
                    tenant not required.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

from services import tenant_registry
from services.dashboard_lenses import resolve_tenant_scope

TENANT_HEADER = "X-Tenant-Id"

TENANT_SCOPED = "TENANT_SCOPED"
SENSOR_SCOPED = "SENSOR_SCOPED"
PRODUCT_METADATA = "PRODUCT_METADATA"

#: Every `/api/edr/*` operation, classified. The R4 regression gate walks the
#: live route table and FAILS when an operation is missing from this map, so a
#: new EDR route is failed-closed by default until it is classified here.
ROUTE_CLASSIFICATION: Dict[tuple, str] = {
    # ── routers/edr.py · evidence reads (14) ──────────────────────────
    ("GET", "/api/edr/detections"): TENANT_SCOPED,
    ("GET", "/api/edr/endpoint-detections"): TENANT_SCOPED,
    ("GET", "/api/edr/process-tree"): TENANT_SCOPED,
    ("GET", "/api/edr/campaign-story"): TENANT_SCOPED,
    ("GET", "/api/edr/observation-narrative"): TENANT_SCOPED,
    ("GET", "/api/edr/file-trajectory"): TENANT_SCOPED,
    ("GET", "/api/edr/fleet-spread-index"): TENANT_SCOPED,
    ("GET", "/api/edr/telemetry/freshness"): TENANT_SCOPED,
    ("GET", "/api/edr/endpoints"): TENANT_SCOPED,
    ("GET", "/api/edr/endpoints/{endpoint_id}/trajectory"): TENANT_SCOPED,
    ("GET", "/api/edr/device-trajectory"): TENANT_SCOPED,
    ("GET", "/api/edr/context"): TENANT_SCOPED,
    ("GET", "/api/edr/endpoints/{endpoint_id}/linked-incidents"): TENANT_SCOPED,
    ("GET", "/api/edr/endpoints/{endpoint_id}/trajectory/focus"): TENANT_SCOPED,
    # ── routers/edr.py · observed endpoint command evidence (1) ───────
    #: Command Intelligence. Tenant-scoped through the SAME resolver the
    #: other evidence reads use; it is NOT the response plane.
    ("GET", "/api/edr/endpoint-commands"): TENANT_SCOPED,
    # ── routers/edr_onboarding.py · management surfaces (4) ───────────
    #: The sensor build catalog describes artifacts on disk and carries no
    #: customer evidence, so it is product metadata, not tenant data.
    ("GET", "/api/edr/onboarding/packages"): PRODUCT_METADATA,
    ("GET", "/api/edr/onboarding/packages/{package_id}/file/{name}"):
        PRODUCT_METADATA,
    ("GET", "/api/edr/onboarding/computers"): TENANT_SCOPED,
    ("GET", "/api/edr/onboarding/computers/{endpoint_id}"): TENANT_SCOPED,
    # ── routers/edr_response.py · analyst response plane (5) ──────────
    ("POST", "/api/edr/response/actions"): TENANT_SCOPED,
    ("GET", "/api/edr/response/actions"): TENANT_SCOPED,
    ("GET", "/api/edr/response/actions/{command_id}"): TENANT_SCOPED,
    ("GET", "/api/edr/response/isolation-policy"): TENANT_SCOPED,
    ("PUT", "/api/edr/response/isolation-policy"): TENANT_SCOPED,
    # ── routers/edr_wave0.py · tenant raw-event reads (2) ─────────────
    ("GET", "/api/edr/wave0/raw-events/stats"): TENANT_SCOPED,
    ("GET", "/api/edr/wave0/raw-events/replay-candidates"): TENANT_SCOPED,
    # ── routers/edr_enrollment.py · admin control plane (6) ───────────
    ("POST", "/api/edr/enrollment/tokens"): TENANT_SCOPED,
    ("GET", "/api/edr/enrollment/tokens"): TENANT_SCOPED,
    ("GET", "/api/edr/enrollment/endpoints"): TENANT_SCOPED,
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/rotate"): TENANT_SCOPED,
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/revoke"): TENANT_SCOPED,
    ("GET", "/api/edr/enrollment/rejections"): PRODUCT_METADATA,
    # ── sensor / agent surface · tenant from the authenticated session ─
    ("POST", "/api/edr/agent/enroll"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/session"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/heartbeat"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/telemetry"): SENSOR_SCOPED,
    ("GET", "/api/edr/agent/whoami"): SENSOR_SCOPED,
    ("GET", "/api/edr/agent/commands"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/command-result"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/command-verification"): SENSOR_SCOPED,
    # ── routers/edr_wave0.py · product truth, tenant-independent (8) ──
    ("GET", "/api/edr/wave0/capabilities"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/capabilities/summary"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/capabilities/{capability_id}"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/sensors"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/contracts"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/contracts/{name}/schema"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/filter-taxonomy"): PRODUCT_METADATA,
    ("GET", "/api/edr/wave0/detection-rule-bindings"): PRODUCT_METADATA,
    # ── routers/edr_policies.py · GATE 5 policy authority (8) ─────────
    ("GET", "/api/edr/policies"): TENANT_SCOPED,
    ("POST", "/api/edr/policies"): TENANT_SCOPED,
    ("GET", "/api/edr/policies/deployment"): TENANT_SCOPED,
    ("GET", "/api/edr/policies/audit"): TENANT_SCOPED,
    ("GET", "/api/edr/policies/{policy_id}"): TENANT_SCOPED,
    ("POST", "/api/edr/policies/{policy_id}/versions"): TENANT_SCOPED,
    ("POST", "/api/edr/policies/{policy_id}/assign"): TENANT_SCOPED,
    ("GET", "/api/edr/groups"): TENANT_SCOPED,
    ("POST", "/api/edr/groups"): TENANT_SCOPED,
    #: The connector's own policy surface. Tenant comes from the
    #: authenticated endpoint session; fetching is DELIVERY and the ACK is
    #: the only route to APPLIED.
    ("GET", "/api/edr/agent/policy"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/policy-ack"): SENSOR_SCOPED,
    # ── routers/edr_exclusions.py · GATE 7 (7) ────────────────────────
    ("GET", "/api/edr/exclusions/taxonomy"): PRODUCT_METADATA,
    ("GET", "/api/edr/exclusions/sets"): TENANT_SCOPED,
    ("POST", "/api/edr/exclusions/sets"): TENANT_SCOPED,
    ("GET", "/api/edr/exclusions"): TENANT_SCOPED,
    ("POST", "/api/edr/exclusions"): TENANT_SCOPED,
    ("POST", "/api/edr/exclusions/{exclusion_id}/approval"): TENANT_SCOPED,
    ("POST", "/api/edr/exclusions/{exclusion_id}/revoke"): TENANT_SCOPED,
    ("GET", "/api/edr/exclusions/enforcement-proof"): TENANT_SCOPED,
    # ── routers/edr_events.py · GATE 11 estate-wide events (3) ────────
    ("GET", "/api/edr/events"): TENANT_SCOPED,
    ("GET", "/api/edr/events/facets"): TENANT_SCOPED,
    ("GET", "/api/edr/events/{raw_id}"): TENANT_SCOPED,
    # ── routers/edr_connector.py · release catalog + deployments (5) ──
    #: A connector RELEASE is product truth: the same artifact, the same
    #: identity, for every tenant. Deployment context is tenant data.
    ("GET", "/api/edr/connector/releases"): PRODUCT_METADATA,
    ("GET", "/api/edr/connector/releases/{release_id}"): PRODUCT_METADATA,
    ("GET", "/api/edr/connector/releases/{release_id}/artifact/{name}"):
        PRODUCT_METADATA,
    ("POST", "/api/edr/connector/deployments"): TENANT_SCOPED,
    ("GET", "/api/edr/connector/deployments"): TENANT_SCOPED,
}


def _refuse(e: tenant_registry.TenantRegistryError) -> None:
    raise HTTPException(status_code=e.http, detail=e.detail()) from None


async def edr_tenant(request: Request) -> str:
    """FastAPI dependency · the registered ACTIVE tenant this request acts in.

    No header            -> 403 TENANT_REQUIRED   (B7 Option A: there is no
                                                   default tenant)
    unregistered tenant  -> 403 TENANT_NOT_FOUND
    non-ACTIVE tenant    -> 403 TENANT_NOT_ACTIVE
    """
    raw = (request.headers.get(TENANT_HEADER) or "").strip()
    try:
        return tenant_registry.authoritative(raw, purpose="edr.control_plane")
    except tenant_registry.TenantRegistryError as e:
        _refuse(e)


def sensor_tenant(tenant_id: Optional[str]) -> str:
    """The tenant a SENSOR is acting in, taken from its authenticated session.

    The endpoint's credential is already tenant-bound, so a wrong value cannot
    match; the registry adds "and it must be a registered, ACTIVE tenant".
    No request header is consulted, because a sensor does not get to name its
    own tenancy and an analyst does not get to name a sensor's.
    """
    try:
        return tenant_registry.authoritative(tenant_id or "",
                                             purpose="edr.sensor_session")
    except tenant_registry.TenantRegistryError as e:
        _refuse(e)


def edr_scope(tenant_id: str, user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Intersect the resolved tenant with what the PRINCIPAL may see.

    Authority narrows; it never widens. A cross-tenant principal that names
    `ten_X` is scoped to `ten_X` and nothing else — which is what makes the
    supplied header impossible to silently ignore. A tenant-scoped principal
    that names a tenant it does not hold is refused outright rather than
    quietly downgraded to its own tenant.

    The returned shape is the SAME scope object every EDR read already
    consumes (`device_identity._norm_scope`, `endpoint_query.resolve_endpoint`,
    `telemetry_freshness.fleet_freshness`), so the narrowing propagates through
    the existing query sites without a second filter being invented. Because
    `all_tenants` is always False, `device_identity.list_devices` already drops
    `UNATTRIBUTED_LEGACY_OBSERVATION` and both `*_FAILED_CLOSED` rows: an
    explicit tenant request can never be answered with unowned evidence.
    """
    scope = resolve_tenant_scope((user or {}).get("email"))
    if not scope.get("authorized"):
        raise HTTPException(status_code=403, detail={
            "code": "ACCESS_DENIED", "reason": "principal not authorized",
            "requested_tenant": tenant_id})
    if not scope.get("all_tenants") and \
            tenant_id not in (scope.get("tenant_ids") or []):
        raise HTTPException(status_code=403, detail={
            "code": "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL",
            "reason": ("a request may name a tenant but never authorise one; "
                       "this principal does not hold the named tenant"),
            "requested_tenant": tenant_id})
    return {"authorized": True, "all_tenants": False,
            "tenant_ids": [tenant_id], "explicit_tenant": tenant_id,
            "role": scope.get("role")}
