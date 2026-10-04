"""P0 · the ONE fail-closed tenant authority for the NivXForge EDR planes.

Gate H (production, publish 100 / build 8833215) proved that B5 convergence
had been applied to `routers/edr_enrollment.py` only. `GET /api/edr/endpoints`
accepted an authenticated request with no tenant at all and silently IGNORED a
supplied `X-Tenant-Id`, so `NIVX_TENANT_REGISTRY_ENFORCE=true` could not reach
it — the registry authority was never called.

Two distinct questions had been conflated:

    resolve_tenant_scope(email)        = which tenants is this PRINCIPAL
                                         authorised for?      (authorisation)
    tenant_registry.authoritative_required(id)
                                       = which single registered ACTIVE tenant
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

import logging
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request

from deps import get_current_user
from services import tenant_registry
from services.dashboard_lenses import resolve_tenant_scope
from services.session_context import ScopeDenied, authorize_requested_tenant

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
    # ── routers/edr_enrollment.py · admin control plane (7) ───────────
    ("POST", "/api/edr/enrollment/tokens"): TENANT_SCOPED,
    ("GET", "/api/edr/enrollment/tokens"): TENANT_SCOPED,
    # P0-FIX-3A · this live operation was never classified, so the R4
    # matrix never probed it. It already consumed `edr_tenant`, so this is
    # a coverage entry, not an authorization change.
    ("POST", "/api/edr/enrollment/tokens/{token_id}/revoke"): TENANT_SCOPED,
    ("GET", "/api/edr/enrollment/endpoints"): TENANT_SCOPED,
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/rotate"): TENANT_SCOPED,
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/revoke"): TENANT_SCOPED,
    ("GET", "/api/edr/enrollment/rejections"): PRODUCT_METADATA,
    #: GATE C · platform-side read of endpoint acquisition integrity.
    ("GET", "/api/edr/enrollment/acquisition-integrity"): TENANT_SCOPED,
    # ── sensor / agent surface · tenant from the authenticated session ─
    ("POST", "/api/edr/agent/enroll"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/session"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/heartbeat"): SENSOR_SCOPED,
    ("POST", "/api/edr/agent/telemetry"): SENSOR_SCOPED,
    #: GATE B · many events, ONE request. Same tenant authority as the
    #: single-event route: the tenant comes from the authenticated session,
    #: never from the batch body.
    ("POST", "/api/edr/agent/telemetry/batch"): SENSOR_SCOPED,
    #: GATE C · the endpoint's own statement about its ACQUISITION, so the
    #: platform can tell "observed nothing" apart from "failed to observe".
    ("POST", "/api/edr/agent/acquisition-integrity"): SENSOR_SCOPED,
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
    #: GATE 7 · the endpoint's own statement of what its engine enforced.
    ("POST", "/api/edr/agent/exclusion-enforcement"): SENSOR_SCOPED,
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
    # ── routers/edr_audit.py · EDR-native audit aggregator (2) ────────
    ("GET", "/api/edr/audit"): TENANT_SCOPED,
    ("GET", "/api/edr/audit/facets"): TENANT_SCOPED,
    # ── routers/edr_saved_views.py · saved investigation views (5) ────
    #: A saved view is tenant data holding QUERY state only. Tenant
    #: authority is applied on every read, so a shared deep link cannot
    #: reach another customer's evidence.
    ("GET", "/api/edr/saved-views"): TENANT_SCOPED,
    ("POST", "/api/edr/saved-views"): TENANT_SCOPED,
    ("GET", "/api/edr/saved-views/{view_id}"): TENANT_SCOPED,
    ("PATCH", "/api/edr/saved-views/{view_id}"): TENANT_SCOPED,
    ("DELETE", "/api/edr/saved-views/{view_id}"): TENANT_SCOPED,
    # ── routers/edr_findings.py · P0-C durable findings (4) ───────────
    #: The finding TAXONOMY is product truth (which detection sources
    #: exist, which are implemented, what each evaluation state means).
    #: Findings and evaluation state are tenant evidence.
    ("GET", "/api/edr/findings/taxonomy"): PRODUCT_METADATA,
    ("GET", "/api/edr/findings"): TENANT_SCOPED,
    ("GET", "/api/edr/findings/evaluation-state"): TENANT_SCOPED,
    ("GET", "/api/edr/findings/{finding_id}"): TENANT_SCOPED,
}


def _refuse(e: tenant_registry.TenantRegistryError) -> None:
    raise HTTPException(status_code=e.http, detail=e.detail()) from None


# ── P0-FIX-2 · non-disclosing refusal ─────────────────────────────────
#
# A principal without tenant-discovery privilege must not be able to learn
# whether ANOTHER customer's tenant exists, is inactive, or is merely
# unauthorised. Those three facts used to be distinguishable:
#
#   unheld tenant                -> TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL
#   cross-tenant role, unknown   -> TENANT_NOT_FOUND
#   cross-tenant role, archived  -> TENANT_NOT_ACTIVE
#
# so a `soc_manager` / `mssp_operator` (all_tenants, but WITHOUT
# `tenants.read`) could enumerate the registry through the refusal codes.
# All three now collapse into ONE byte-identical refusal for such a
# principal. The precise reason is kept server-side (log + audit).
#
# This normalises DISCLOSURE only. Authorisation is untouched and still
# runs first, so nothing is ever granted by this code path.
TENANT_DISCOVERY_PERMISSION = "tenants.read"
UNAUTHORIZED_TENANT_CODE = "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"
UNAUTHORIZED_TENANT_REASON = (
    "a request may name a tenant but never authorise one; this principal "
    "does not hold the named tenant. Whether that tenant exists, and its "
    "state, are deliberately not disclosed.")
DISCLOSURE_NOTE = "TENANT_EXISTENCE_AND_STATE_NOT_DISCLOSED"

_log = logging.getLogger("nivxray.edr.tenant_authority")


def _may_discover_tenants(user: Optional[Dict[str, Any]],
                          requested: Optional[str]) -> bool:
    """Does this principal hold `tenants.read`?

    Read through the EXISTING RBAC vocabulary (`routers.xdr_rbac`): a
    granular `xdr_user_roles` assignment where one exists, otherwise the
    built-in role on the verified principal. Grants nothing, and a failure
    to resolve means NOT privileged (fail closed towards non-disclosure).
    """
    email = (user or {}).get("email") or (user or {}).get("sub")
    try:
        from routers.xdr_rbac import (_BUILTIN_ROLE_BY_NAME,
                                      _expand_wildcard,
                                      _resolve_user_permissions)
        if requested and email:
            try:
                granular, _ = _resolve_user_permissions(requested, email)
            except Exception:                                   # noqa: BLE001
                granular = set()
            if granular:
                return TENANT_DISCOVERY_PERMISSION in set(granular)
        role = str((user or {}).get("role") or "").strip().lower()
        role = {"admin": "platform_admin",
                "superadmin": "platform_admin"}.get(role, role)
        spec = _BUILTIN_ROLE_BY_NAME.get(role)
        if not spec:
            return False
        perms: set = set()
        for p in spec.get("permissions") or []:
            perms |= _expand_wildcard(p)
        return TENANT_DISCOVERY_PERMISSION in perms
    except Exception:                                           # noqa: BLE001
        return False


def _opaque_refusal(requested: Optional[str], principal: Optional[str],
                    precise_code: str) -> HTTPException:
    """ONE refusal for every unauthorised-tenant outcome.

    The precise reason survives in the server log and the audit record; it
    does not survive into the response.
    """
    _log.warning("[edr.tenant_authority] refusal normalised "
                 "principal=%s requested=%s precise=%s",
                 principal or "unresolved", requested, precise_code)
    try:
        from routers.xdr_rbac import _audit_scope_denial
        _audit_scope_denial(requested, principal, "tenant_scope",
                            f"P0-FIX-2:non_disclosing:{precise_code}")
    except Exception:                                           # noqa: BLE001
        pass
    return HTTPException(status_code=403, detail={
        "code": UNAUTHORIZED_TENANT_CODE,
        "reason": UNAUTHORIZED_TENANT_REASON,
        "basis": "NOT_AUTHORIZED",
        "requested_tenant": requested,
        "authority": "server",
        "fail_closed": True,
        "disclosure": DISCLOSURE_NOTE})


async def edr_tenant(request: Request,
                     user: Dict[str, Any] = Depends(get_current_user)) -> str:
    """FastAPI dependency · the AUTHORIZED, registered, ACTIVE tenant.

    P0-FIX-1. This dependency used to ask ONE question — "is the named
    tenant registered and ACTIVE?" — and left "is this PRINCIPAL
    authorised for it?" to an optional `edr_scope()` call inside each
    route. Eight TENANT_SCOPED operations never made that call, so on
    those routes a client-supplied `X-Tenant-Id` *expanded* authority.

    It now asks BOTH, in the only safe order, reusing the SAME server-side
    machinery the XDR/session-context plane already uses — no second
    authorization model is introduced:

        verified principal
          → authorize_requested_tenant(principal, X-Tenant-Id)   AUTHORISATION
          → tenant_registry.authoritative_required(tenant)       AUTHORITY
          → the tenant this request acts in

    Authorisation runs FIRST, so the registry can only ever NARROW it; a
    tenant the principal does not hold never reaches the registry lookup
    and is never confirmed to exist.

    Outcomes:

    single authorized tenant, no header  -> auto-bound (no header needed)
    header naming a tenant not held      -> 403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL
    cross-tenant principal, no header    -> 403 TENANT_REQUIRED
    zero-tenant principal                -> 403 TENANT_NOT_RESOLVED
    unregistered tenant                  -> 403 TENANT_NOT_FOUND *
    non-ACTIVE tenant                    -> 403 TENANT_NOT_ACTIVE *
    registry unreachable                 -> 503 REGISTRY_UNAVAILABLE *

    P0-FIX-5A · registry validation here is UNCONDITIONAL. It is reached
    through `authoritative_required()`, which reads no environment flag, so
    neither an unset nor a `false` `NIVX_TENANT_REGISTRY_ENFORCE` can turn
    this authority into a pass-through.

    \\* P0-FIX-2 · only for a principal holding `tenants.read`. For anyone
    else a REQUESTED tenant that is unheld, unregistered or inactive yields
    ONE indistinguishable refusal, so tenant existence and state cannot be
    probed. A refusal about the principal's OWN auto-bound tenant keeps its
    precise code: it discloses nothing about another customer.
    """
    requested = (request.headers.get(TENANT_HEADER) or "").strip() or None
    principal = (user or {}).get("email") or (user or {}).get("sub")
    privileged = _may_discover_tenants(user, requested)
    try:
        authorized, basis = authorize_requested_tenant(principal, requested)
    except ScopeDenied as e:
        if requested and not privileged \
                and e.code == UNAUTHORIZED_TENANT_CODE:
            raise _opaque_refusal(requested, principal, e.code) from None
        raise HTTPException(status_code=e.http,
                            detail={**e.detail(),
                                    "authority": "server",
                                    "requested_tenant": requested}) from None
    try:
        resolved = tenant_registry.authoritative_required(
            authorized, purpose="edr.control_plane")
    except tenant_registry.TenantRegistryError as e:
        if requested and not privileged:
            raise _opaque_refusal(requested, principal, e.code) from None
        _refuse(e)
    request.state.effective_tenant_id = resolved
    request.state.tenant_resolution_basis = basis
    return resolved


def sensor_tenant(tenant_id: Optional[str]) -> str:
    """The tenant a SENSOR is acting in, taken from its authenticated session.

    The endpoint's credential is already tenant-bound, so a wrong value cannot
    match; the registry adds "and it must be a registered, ACTIVE tenant".
    No request header is consulted, because a sensor does not get to name its
    own tenancy and an analyst does not get to name a sensor's.
    """
    try:
        return tenant_registry.authoritative_required(
            tenant_id or "", purpose="edr.sensor_session")
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
