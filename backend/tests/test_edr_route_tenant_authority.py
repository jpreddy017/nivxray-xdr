"""P5 · R4 · the EDR route-level tenant-authority regression GATE.

Gate H (production, publish 100 / build 8833215) proved the defect this file
exists to prevent: `GET /api/edr/endpoints` accepted an authenticated request
with **no tenant at all** and silently IGNORED a supplied `X-Tenant-Id`.

Why the pre-existing B5 suite could not catch it:
`tests/test_b4b5_tenant_registry_authority.py` asserts three things about
`routers/edr_enrollment.py`, two of them by calling `_tenant()` **directly as
a function**. That proves the resolver is correct; it cannot prove WHICH
ROUTES CALL IT. A route that never calls it is invisible to that style of
test. This file is therefore table-driven off the LIVE ROUTE TABLE, so a route
that forgets the authority fails here.

The completeness clause is the important one: an `/api/edr/*` operation that is
absent from `routers.edr_tenancy.ROUTE_CLASSIFICATION` FAILS. A new EDR route
is failed-closed by default until somebody classifies it deliberately.

EVIDENCE LABELLING — TEST/SYNTHETIC. Read-only against preview. No POST/PUT
route is ever driven with a valid tenant, so this suite creates no command, no
policy, no token and no endpoint.
"""
from __future__ import annotations

import json
import os

import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

from routers.edr_tenancy import (PRODUCT_METADATA, ROUTE_CLASSIFICATION,  # noqa: E402
                                 SENSOR_SCOPED, TENANT_SCOPED)

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
SCOPED_EMAIL = "analyst@nivx-live.com"
SCOPED_PASSWORD = "NivxLive!Analyst2026"

TENANT_A = "default"                                   # registered · ACTIVE
TENANT_B = "nivx-live"                                 # registered · ACTIVE
TENANT_ARCHIVED = "ten_813aa3160190401f7723ce1c4e"     # registered · ARCHIVED
TENANT_UNKNOWN = "ten_definitely_not_registered_0000"

#: A concrete, parameter-complete request per TENANT_SCOPED operation. Every
#: required query parameter is supplied so the request always reaches the
#: authority check instead of being turned away by schema validation.
#: ``mutating`` routes are driven for the REFUSAL cases only.
SAMPLES: dict[tuple, dict] = {
    ("GET", "/api/edr/detections"): {"url": "/api/edr/detections?incident_id=probe"},
    ("GET", "/api/edr/endpoint-detections"): {"url": "/api/edr/endpoint-detections?endpoint_id=probe"},
    ("GET", "/api/edr/process-tree"): {"url": "/api/edr/process-tree?endpoint_id=probe"},
    ("GET", "/api/edr/campaign-story"): {"url": "/api/edr/campaign-story?incident_id=probe"},
    ("GET", "/api/edr/observation-narrative"): {"url": "/api/edr/observation-narrative?device=probe&event_iid=probe"},
    ("GET", "/api/edr/file-trajectory"): {"url": "/api/edr/file-trajectory?key=probe"},
    ("GET", "/api/edr/fleet-spread-index"): {"url": "/api/edr/fleet-spread-index"},
    ("GET", "/api/edr/telemetry/freshness"): {"url": "/api/edr/telemetry/freshness"},
    ("GET", "/api/edr/endpoints"): {"url": "/api/edr/endpoints"},
    ("GET", "/api/edr/endpoints/{endpoint_id}/trajectory"): {"url": "/api/edr/endpoints/probe/trajectory"},
    ("GET", "/api/edr/device-trajectory"): {"url": "/api/edr/device-trajectory?device=probe"},
    ("GET", "/api/edr/context"): {"url": "/api/edr/context"},
    ("GET", "/api/edr/endpoints/{endpoint_id}/linked-incidents"): {"url": "/api/edr/endpoints/probe/linked-incidents"},
    ("GET", "/api/edr/endpoints/{endpoint_id}/trajectory/focus"): {"url": "/api/edr/endpoints/probe/trajectory/focus"},
    ("GET", "/api/edr/response/actions"): {"url": "/api/edr/response/actions"},
    ("GET", "/api/edr/response/actions/{command_id}"): {"url": "/api/edr/response/actions/probe"},
    ("GET", "/api/edr/response/isolation-policy"): {"url": "/api/edr/response/isolation-policy"},
    ("GET", "/api/edr/wave0/raw-events/stats"): {"url": "/api/edr/wave0/raw-events/stats"},
    ("GET", "/api/edr/wave0/raw-events/replay-candidates"): {"url": "/api/edr/wave0/raw-events/replay-candidates"},
    ("GET", "/api/edr/enrollment/tokens"): {"url": "/api/edr/enrollment/tokens"},
    ("GET", "/api/edr/enrollment/endpoints"): {"url": "/api/edr/enrollment/endpoints"},
    # ── Fleet Operations wave · Computers + Command Intelligence ──────
    ("GET", "/api/edr/onboarding/computers"): {"url": "/api/edr/onboarding/computers"},
    ("GET", "/api/edr/onboarding/computers/{endpoint_id}"): {"url": "/api/edr/onboarding/computers/probe"},
    ("GET", "/api/edr/endpoint-commands"): {"url": "/api/edr/endpoint-commands?endpoint_id=probe"},
    ("POST", "/api/edr/response/actions"): {
        "url": "/api/edr/response/actions", "mutating": True,
        "json": {"endpoint_id": "probe", "action": "isolate",
                 "target": {}, "reason": "route-authority-probe"}},
    ("PUT", "/api/edr/response/isolation-policy"): {
        "url": "/api/edr/response/isolation-policy", "mutating": True,
        "json": {"allow_dns": True}},
    ("POST", "/api/edr/enrollment/tokens"): {
        "url": "/api/edr/enrollment/tokens", "mutating": True,
        "json": {"label": "route-authority-probe"}},
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/rotate"): {
        "url": "/api/edr/enrollment/endpoints/probe/rotate", "mutating": True,
        "json": {}},
    ("POST", "/api/edr/enrollment/endpoints/{endpoint_id}/revoke"): {
        "url": "/api/edr/enrollment/endpoints/probe/revoke", "mutating": True,
        "json": {"reason": "route-authority-probe"}},
    # ── P0-A.1 · probes for the surfaces added in the Policy / Exclusions /
    #    Events / Saved-Views / Audit / Connector-deployment wave. Every
    #    TENANT_SCOPED operation carries a parameter-complete probe so the
    #    request reaches the AUTHORITY check instead of schema validation.
    #    Mutating probes are driven for the REFUSAL cases only, so this
    #    suite still creates no policy, exclusion, view or deployment.
    ("GET", "/api/edr/policies"): {"url": "/api/edr/policies"},
    ("GET", "/api/edr/policies/{policy_id}"): {
        "url": "/api/edr/policies/probe"},
    ("GET", "/api/edr/policies/audit"): {"url": "/api/edr/policies/audit"},
    ("GET", "/api/edr/policies/deployment"): {
        "url": "/api/edr/policies/deployment"},
    ("POST", "/api/edr/policies"): {
        "url": "/api/edr/policies", "mutating": True,
        "json": {"name": "route-authority-probe", "os": "LINUX"}},
    ("POST", "/api/edr/policies/{policy_id}/versions"): {
        "url": "/api/edr/policies/probe/versions", "mutating": True,
        "json": {"config": {}, "notes": "route-authority-probe"}},
    ("POST", "/api/edr/policies/{policy_id}/assign"): {
        "url": "/api/edr/policies/probe/assign", "mutating": True,
        "json": {"scope_type": "ENDPOINT", "scope_id": "probe-endpoint"}},
    ("GET", "/api/edr/groups"): {"url": "/api/edr/groups"},
    ("POST", "/api/edr/groups"): {
        "url": "/api/edr/groups", "mutating": True,
        "json": {"name": "route-authority-probe"}},
    ("GET", "/api/edr/exclusions"): {"url": "/api/edr/exclusions"},
    ("GET", "/api/edr/exclusions/sets"): {"url": "/api/edr/exclusions/sets"},
    ("GET", "/api/edr/exclusions/enforcement-proof"): {
        "url": "/api/edr/exclusions/enforcement-proof?sample=10"},
    ("POST", "/api/edr/exclusions"): {
        "url": "/api/edr/exclusions", "mutating": True,
        "json": {"set_id": "probe-set", "type": "PATH",
                 "value": "/opt/route-authority-probe",
                 "match": "EXACT",
                 "reason": "route authority probe · never approved",
                 "affected_engines": ["endpoint.collection"]}},
    ("POST", "/api/edr/exclusions/sets"): {
        "url": "/api/edr/exclusions/sets", "mutating": True,
        "json": {"name": "route-authority-probe", "os": "LINUX"}},
    ("POST", "/api/edr/exclusions/{exclusion_id}/approval"): {
        "url": "/api/edr/exclusions/probe/approval", "mutating": True,
        "json": {"decision": "REJECTED", "note": "route-authority-probe"}},
    ("POST", "/api/edr/exclusions/{exclusion_id}/revoke"): {
        "url": "/api/edr/exclusions/probe/revoke", "mutating": True,
        "json": {"reason": "route-authority-probe"}},
    ("GET", "/api/edr/events"): {"url": "/api/edr/events?limit=1"},
    ("GET", "/api/edr/events/facets"): {"url": "/api/edr/events/facets"},
    ("GET", "/api/edr/events/{raw_id}"): {"url": "/api/edr/events/probe"},
    ("GET", "/api/edr/saved-views"): {"url": "/api/edr/saved-views"},
    ("GET", "/api/edr/saved-views/{view_id}"): {
        "url": "/api/edr/saved-views/probe"},
    ("POST", "/api/edr/saved-views"): {
        "url": "/api/edr/saved-views", "mutating": True,
        "json": {"name": "route-authority-probe", "surface": "events"}},
    ("PATCH", "/api/edr/saved-views/{view_id}"): {
        "url": "/api/edr/saved-views/probe", "mutating": True,
        "json": {"name": "route-authority-probe", "surface": "events"}},
    ("DELETE", "/api/edr/saved-views/{view_id}"): {
        "url": "/api/edr/saved-views/probe", "mutating": True},
    # P0-C · durable findings. Read-only probes; the id is deliberately one
    # that cannot exist, so a registered tenant is answered by the authority
    # and not by another customer's evidence.
    ("GET", "/api/edr/findings"): {"url": "/api/edr/findings?limit=1"},
    ("GET", "/api/edr/findings/evaluation-state"): {
        "url": "/api/edr/findings/evaluation-state"},
    ("GET", "/api/edr/findings/{finding_id}"): {
        "url": "/api/edr/findings/fnd_probe_does_not_exist"},
    ("GET", "/api/edr/audit"): {"url": "/api/edr/audit?days=1&limit=1"},
    ("GET", "/api/edr/audit/facets"): {"url": "/api/edr/audit/facets?days=1"},
    ("GET", "/api/edr/connector/deployments"): {
        "url": "/api/edr/connector/deployments"},
    ("POST", "/api/edr/connector/deployments"): {
        "url": "/api/edr/connector/deployments", "mutating": True,
        "json": {"release_id": "nvf-connector-linux-0.2.0-x64",
                 "group_id": "probe-group", "ttl_seconds": 300}},
}

_TENANT_SCOPED_OPS = sorted(k for k, v in ROUTE_CLASSIFICATION.items()
                            if v == TENANT_SCOPED)
_READ_OPS = [k for k in _TENANT_SCOPED_OPS
             if not SAMPLES.get(k, {}).get("mutating")]
_METADATA_OPS = sorted(k for k, v in ROUTE_CLASSIFICATION.items()
                       if v == PRODUCT_METADATA)
_SENSOR_OPS = sorted(k for k, v in ROUTE_CLASSIFICATION.items()
                     if v == SENSOR_SCOPED)


def _login(email: str, password: str) -> str:
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": email, "password": password}, timeout=20)
    assert r.status_code == 200, f"login {email}: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin() -> dict:
    return {"Authorization": f"Bearer {_login(ADMIN_EMAIL, ADMIN_PASSWORD)}"}


@pytest.fixture(scope="module")
def scoped() -> dict:
    """A tenant-scoped analyst holding `nivx-live` and nothing else."""
    return {"Authorization": f"Bearer {_login(SCOPED_EMAIL, SCOPED_PASSWORD)}"}


def _call(op: tuple, headers: dict) -> requests.Response:
    method, _path = op
    spec = SAMPLES[op]
    return requests.request(method, f"{BASE_URL}{spec['url']}",
                            headers=headers, json=spec.get("json"), timeout=30)


def _code(r: requests.Response) -> str:
    """The authority code the platform returned, or ''."""
    try:
        detail = r.json().get("detail")
    except (ValueError, AttributeError):
        return ""
    if isinstance(detail, dict):
        return str(detail.get("code") or "")
    return ""


def _body(r: requests.Response) -> str:
    return r.text


# ══════════════════════════════════════════════════════════════════
# CLAUSE 1 · COVERAGE COMPLETENESS  (offline · the gate that matters)
# ══════════════════════════════════════════════════════════════════
def _live_edr_operations() -> set:
    os.environ.setdefault("DB_NAME", "test_database")
    from server import app
    ops = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/edr"):
            continue
        for method in (getattr(route, "methods", None) or set()):
            if method in ("HEAD", "OPTIONS"):
                continue
            ops.add((method, path))
    return ops


def test_every_live_edr_operation_is_explicitly_classified():
    """A new EDR route is FAILED CLOSED until it is classified.

    This is the clause that would have caught Gate H: `/api/edr/endpoints`
    existed for months with no tenant authority and nothing asserted that it
    had to have one.
    """
    live = _live_edr_operations()
    unclassified = sorted(live - set(ROUTE_CLASSIFICATION))
    assert not unclassified, (
        "these live /api/edr operations are not in "
        "routers.edr_tenancy.ROUTE_CLASSIFICATION — classify each one as "
        f"TENANT_SCOPED, SENSOR_SCOPED or PRODUCT_METADATA: {unclassified}")


def test_classification_has_no_entries_for_routes_that_no_longer_exist():
    live = _live_edr_operations()
    stale = sorted(set(ROUTE_CLASSIFICATION) - live)
    assert not stale, f"classified but not mounted: {stale}"


def test_every_tenant_scoped_operation_has_a_concrete_probe():
    missing = sorted(set(_TENANT_SCOPED_OPS) - set(SAMPLES))
    assert not missing, (
        "a TENANT_SCOPED operation with no probe in SAMPLES is untested "
        f"authority: {missing}")


def test_classification_values_are_from_the_closed_set():
    assert set(ROUTE_CLASSIFICATION.values()) <= {
        TENANT_SCOPED, SENSOR_SCOPED, PRODUCT_METADATA}


# ══════════════════════════════════════════════════════════════════
# CLAUSE 2 · THE AUTHORITY CONTRACT, PER TENANT_SCOPED OPERATION
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _TENANT_SCOPED_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_missing_explicit_tenant_is_refused_tenant_required(op, admin):
    """B7 Option A · there is no default tenant."""
    r = _call(op, admin)
    assert r.status_code == 403, f"{op} -> {r.status_code} {_body(r)}"
    assert _code(r) == "TENANT_REQUIRED", f"{op} -> {_body(r)}"


@pytest.mark.parametrize("op", _TENANT_SCOPED_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_unregistered_tenant_is_refused_tenant_not_found(op, admin):
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_UNKNOWN})
    assert r.status_code == 403, f"{op} -> {r.status_code} {_body(r)}"
    assert _code(r) == "TENANT_NOT_FOUND", f"{op} -> {_body(r)}"


@pytest.mark.parametrize("op", _TENANT_SCOPED_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_non_active_tenant_is_refused_tenant_not_active(op, admin):
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_ARCHIVED})
    assert r.status_code == 403, f"{op} -> {r.status_code} {_body(r)}"
    assert _code(r) == "TENANT_NOT_ACTIVE", f"{op} -> {_body(r)}"


@pytest.mark.parametrize("op", _READ_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_registered_active_tenant_proceeds(op, admin):
    """A registered ACTIVE tenant is answered. 404 for a probe id is fine —
    what must never happen is an authority refusal."""
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_A})
    assert r.status_code not in (401, 403), f"{op} -> {r.status_code} {_body(r)}"
    assert _code(r) not in ("TENANT_REQUIRED", "TENANT_NOT_FOUND",
                            "TENANT_NOT_ACTIVE"), f"{op} -> {_body(r)}"


# ══════════════════════════════════════════════════════════════════
# CLAUSE 3 · THE HEADER IS NEVER SILENTLY IGNORED
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _READ_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_supplied_tenant_changes_the_outcome(op, admin):
    """Gate H's actual failure mode: the header was read by nobody, so
    `X-Tenant-Id: <anything>` and no header at all returned the SAME body.
    Three distinct outcomes prove the value is consumed."""
    valid = _call(op, {**admin, "X-Tenant-Id": TENANT_A})
    absent = _call(op, admin)
    garbage = _call(op, {**admin, "X-Tenant-Id": TENANT_UNKNOWN})
    assert _body(valid) != _body(absent), f"{op}: header ignored (absent)"
    assert _body(valid) != _body(garbage), f"{op}: header ignored (unknown)"
    assert _body(absent) != _body(valid), f"{op}: no-header answered as tenant"


def test_endpoints_projection_is_confined_to_the_named_tenant(admin):
    """R2 · unattributed legacy evidence is NOT the requested tenant's.

    On production this route returned `ENG-42` with an EMPTY `tenant_id` and
    `tenant_attribution=UNATTRIBUTED_LEGACY_OBSERVATION` while the caller had
    named `ten_e759…`. That is the mis-attribution this asserts against.
    """
    for tenant in (TENANT_A, TENANT_B):
        r = requests.get(f"{BASE_URL}/api/edr/endpoints",
                         headers={**admin, "X-Tenant-Id": tenant}, timeout=30)
        assert r.status_code == 200, r.text
        for row in r.json().get("endpoints") or []:
            attribution = row.get("tenant_attribution")
            if attribution is not None:
                assert attribution.startswith("ATTRIBUTED"), (
                    f"{tenant}: unowned row released under an explicit "
                    f"tenant: {row.get('host')} {attribution}")
                assert row.get("tenant_id") == tenant, (
                    f"{tenant}: foreign row {row.get('host')} "
                    f"tenant_id={row.get('tenant_id')}")


# ══════════════════════════════════════════════════════════════════
# CLAUSE 4 · CROSS-TENANT AUTHORITY IS NOT AN IMPLICIT TENANT
# ══════════════════════════════════════════════════════════════════
def test_cross_tenant_admin_still_needs_an_explicit_tenant(admin):
    r = requests.get(f"{BASE_URL}/api/edr/endpoints", headers=admin, timeout=30)
    assert r.status_code == 403 and _code(r) == "TENANT_REQUIRED", r.text


def test_cross_tenant_admin_naming_a_tenant_is_narrowed_to_it(admin):
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     headers={**admin, "X-Tenant-Id": TENANT_B}, timeout=30)
    assert r.status_code == 200, r.text
    scope = r.json()["tenant_scope"]
    assert scope["all_tenants"] is False
    assert scope["tenant_ids"] == [TENANT_B]
    assert scope["explicit_tenant"] == TENANT_B


def test_scoped_principal_cannot_name_a_tenant_it_does_not_hold(scoped):
    """A request may NAME a tenant; it may never AUTHORISE one."""
    r = requests.get(f"{BASE_URL}/api/edr/endpoints",
                     headers={**scoped, "X-Tenant-Id": TENANT_A}, timeout=30)
    assert r.status_code == 403, r.text
    assert _code(r) == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL", r.text


def test_scoped_principal_is_answered_for_its_own_tenant(scoped):
    r = requests.get(f"{BASE_URL}/api/edr/endpoints",
                     headers={**scoped, "X-Tenant-Id": TENANT_B}, timeout=30)
    assert r.status_code == 200, r.text


# ══════════════════════════════════════════════════════════════════
# CLAUSE 5 · SENSOR_SCOPED — tenant comes from the SESSION
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _SENSOR_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_sensor_routes_do_not_demand_an_analyst_tenant_header(op):
    """A sensor does not send `X-Tenant-Id` and must not be asked to.

    These routes must refuse for the SENSOR-CREDENTIAL reason, never for a
    missing analyst header — otherwise converging them would have broken every
    enrolled endpoint.
    """
    method, path = op
    url = BASE_URL + path.replace("{endpoint_id}", "probe")
    r = requests.request(method, url, json={}, timeout=30)
    assert _code(r) != "TENANT_REQUIRED", f"{op} -> {_body(r)}"
    assert r.status_code in (401, 403, 422), f"{op} -> {r.status_code} {_body(r)}"


# ══════════════════════════════════════════════════════════════════
# CLAUSE 6 · PRODUCT_METADATA is tenant-independent
# ══════════════════════════════════════════════════════════════════
_METADATA_URLS = {
    ("GET", "/api/edr/wave0/capabilities"): "/api/edr/wave0/capabilities",
    ("GET", "/api/edr/wave0/capabilities/summary"): "/api/edr/wave0/capabilities/summary",
    ("GET", "/api/edr/wave0/capabilities/{capability_id}"): "/api/edr/wave0/capabilities/EDR-CAP-DOES-NOT-EXIST",
    ("GET", "/api/edr/wave0/sensors"): "/api/edr/wave0/sensors",
    ("GET", "/api/edr/wave0/contracts"): "/api/edr/wave0/contracts",
    ("GET", "/api/edr/wave0/contracts/{name}/schema"): "/api/edr/wave0/contracts/does-not-exist/schema",
    ("GET", "/api/edr/wave0/filter-taxonomy"): "/api/edr/wave0/filter-taxonomy",
    ("GET", "/api/edr/wave0/detection-rule-bindings"): "/api/edr/wave0/detection-rule-bindings",
    ("GET", "/api/edr/enrollment/rejections"): "/api/edr/enrollment/rejections",
    # The sensor build catalog describes artifacts on disk, not customers.
    ("GET", "/api/edr/onboarding/packages"): "/api/edr/onboarding/packages",
    ("GET", "/api/edr/onboarding/packages/{package_id}/file/{name}"):
        "/api/edr/onboarding/packages/windows-x64/file/"
        "Install-NivXForgeSensor.ps1",
    # P0-A.1 · the connector RELEASE catalog and the exclusion taxonomy are
    # product metadata: the same released artifact and the same typed
    # vocabulary for every customer. These probes assert exactly that — if
    # either ever differs per tenant it must be reclassified TENANT_SCOPED.
    ("GET", "/api/edr/connector/releases"): "/api/edr/connector/releases",
    ("GET", "/api/edr/connector/releases/{release_id}"):
        "/api/edr/connector/releases/nvf-connector-linux-0.2.0-x64",
    ("GET", "/api/edr/connector/releases/{release_id}/artifact/{name}"):
        "/api/edr/connector/releases/nvf-connector-linux-0.2.0-x64/artifact/"
        "nivxforge_sensor.py",
    ("GET", "/api/edr/exclusions/taxonomy"): "/api/edr/exclusions/taxonomy",
    # P0-C · the finding taxonomy states which detection sources exist and
    # which are implemented. Product truth, identical for every customer.
    ("GET", "/api/edr/findings/taxonomy"): "/api/edr/findings/taxonomy",
}


def test_every_product_metadata_operation_has_a_probe():
    assert not sorted(set(_METADATA_OPS) - set(_METADATA_URLS))


@pytest.mark.parametrize("op", _METADATA_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_product_metadata_needs_no_tenant_and_carries_none(op, admin):
    url = BASE_URL + _METADATA_URLS[op]
    bare = requests.get(url, headers=admin, timeout=30)
    assert _code(bare) != "TENANT_REQUIRED", f"{op} -> {_body(bare)}"
    a = requests.get(url, headers={**admin, "X-Tenant-Id": TENANT_A}, timeout=30)
    b = requests.get(url, headers={**admin, "X-Tenant-Id": TENANT_B}, timeout=30)
    assert a.status_code == b.status_code == bare.status_code
    assert _body(a) == _body(b) == _body(bare), (
        f"{op}: product metadata differs per tenant — it is tenant data and "
        "must be reclassified TENANT_SCOPED")


def test_product_metadata_still_requires_authentication(admin):
    anon = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities", timeout=30)
    assert anon.status_code in (401, 403), anon.text


# ══════════════════════════════════════════════════════════════════
# CLAUSE 7 · R2 unit · list_devices under an explicit tenant
# ══════════════════════════════════════════════════════════════════
def test_list_devices_under_explicit_tenant_never_returns_unowned_evidence():
    from services.edr import device_identity as dir_svc
    scope = {"authorized": True, "all_tenants": False,
             "tenant_ids": [TENANT_A], "explicit_tenant": TENANT_A}
    for row in dir_svc.list_devices(scope):
        assert row["tenant_attribution"].startswith("ATTRIBUTED")
        assert row["tenant_id"] == TENANT_A


def test_cross_tenant_projection_is_unchanged_without_an_explicit_tenant():
    """R2 narrows the ANSWER; it must not destroy or hide the EVIDENCE.

    A cross-tenant role with no explicit tenant still sees at least every
    device an explicitly-scoped read would see, plus whatever carries no
    owner. If this ever inverted, R2 had deleted evidence rather than
    declining to mis-attribute it.
    """
    from services.edr import device_identity as dir_svc
    wide = dir_svc.list_devices({"all_tenants": True, "tenant_ids": []})
    narrow = dir_svc.list_devices(
        {"authorized": True, "all_tenants": False,
         "tenant_ids": [TENANT_A], "explicit_tenant": TENANT_A})
    wide_refs = {r["device_ref"] for r in wide}
    assert {r["device_ref"] for r in narrow} <= wide_refs
    assert len(wide) >= len(narrow)
    # Unowned evidence, where the substrate holds any, is released here and
    # ONLY here — never under an explicit tenant.
    for row in wide:
        assert row["tenant_attribution"] in (
            "ATTRIBUTED_AUTHENTICATED_ENDPOINT", "ATTRIBUTED_TENANT_ONLY",
            "UNATTRIBUTED_LEGACY_OBSERVATION",
            "TENANT_CONFLICT_FAILED_CLOSED", "TENANT_MISMATCH_FAILED_CLOSED")


# ══════════════════════════════════════════════════════════════════
# CLAUSE 8 · no surviving "default" tenancy fallback in the EDR planes
# ══════════════════════════════════════════════════════════════════
def test_no_edr_router_resolves_tenancy_to_the_literal_default():
    import pathlib
    root = pathlib.Path("/app/backend/routers")
    offenders = []
    for name in ("edr.py", "edr_response.py", "edr_wave0.py",
                 "edr_enrollment.py"):
        for i, line in enumerate(
                (root / name).read_text().splitlines(), start=1):
            code = line.split("#", 1)[0]
            if "`" in code:                     # prose inside a docstring
                continue
            if 'or "default"' in code or "or 'default'" in code:
                offenders.append(f"{name}:{i}: {line.strip()}")
    assert not offenders, (
        "a tenancy fallback to the literal 'default' survives — this is the "
        f"B5 defect class: {json.dumps(offenders, indent=1)}")


def test_authorisation_path_no_longer_invents_a_default_tenant():
    """R5 · `resolve_tenant_scope` returned `['default']` for a user holding
    no tenant. A principal with no tenant now holds no tenant."""
    from services.dashboard_lenses import resolve_tenant_scope
    scope = resolve_tenant_scope(ADMIN_EMAIL)
    assert scope["authorized"] is True
    assert scope.get("all_tenants") is True
    assert "default" not in (scope.get("tenant_ids") or [])
