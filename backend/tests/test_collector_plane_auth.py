"""Collector Auth P0 · the collector-plane authentication/RBAC regression GATE.

Production (publish 100 / build `a55ec13`) answered these ANONYMOUSLY with
200: `/collector/collectors`, `/collector/data-sources`, `/collector/outbox`,
`/collector/outbox/health`, `/collector/telemetry-health`,
`/collector/source-types`. Reading the deployed source showed nine anonymously
MUTATING operations on the same plane, including `POST /connectors/{cid}/inject`
(fabricated evidence into the canonical pipeline) and
`POST /connectors/{cid}/stop` (silence a security data source).

Why the tenant suites could not catch it: they assert WHICH TENANT a request
acts in. Nothing asserted that a request had a PRINCIPAL at all. This file is
table-driven off the LIVE ROUTE TABLE and off
`framework.route_classification.COLLECTOR_ROUTE_CLASSIFICATION`, so an
undeclared collector route fails here.

Ladder under test, in order:
    AUTHENTICATION -> PERMISSION -> TENANT AUTHORITY -> CAPABILITY

EVIDENCE LABELLING — TEST/SYNTHETIC, PREVIEW ONLY. Every mutating operation is
driven for its REFUSAL case only, and the connector inventory is asserted
unchanged afterwards, so this suite creates no connector, no envelope, no
telemetry and no key.
"""
from __future__ import annotations

import os
import sys

import pytest
import requests
from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

os.environ.setdefault("DB_NAME", "test_database")

_COLLECTOR_ROOT = "/app/apps/nivxray-xdr-collector"
if _COLLECTOR_ROOT not in sys.path:
    sys.path.insert(0, _COLLECTOR_ROOT)

from framework.route_classification import (COLLECTOR_ROUTE_CLASSIFICATION,  # noqa: E402
                                            CLASSES, HUMAN_CONTROL, MACHINE,
                                            PRODUCT_METADATA, TEST_PLANE,
                                            relative_path)

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
PREFIX = "/api/xdr/collector"

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
UNPRIVILEGED_EMAIL = "analyst@default.com"
UNPRIVILEGED_PASSWORD = "DefaultCo!Analyst2026"

TENANT_OK = "default"                                  # registered · ACTIVE
TENANT_UNKNOWN = "ten_definitely_not_registered_0000"
TENANT_ARCHIVED = "ten_813aa3160190401f7723ce1c4e"     # registered · ARCHIVED

#: A concrete, parameter-complete request per declared operation.
SAMPLES: dict[tuple, dict] = {
    ("GET", "/source-types"): {"url": "/source-types"},
    ("GET", "/connectors"): {"url": "/connectors"},
    ("POST", "/connectors"): {"url": "/connectors", "mutating": True,
                              "json": {"source_type": "webhook",
                                       "label": "collector-auth-probe",
                                       "config": {"secret_id": "auth-probe"}}},
    ("GET", "/connectors/{cid}"): {"url": "/connectors/probe"},
    ("PATCH", "/connectors/{cid}"): {"url": "/connectors/probe",
                                     "mutating": True,
                                     "json": {"label": "collector-auth-probe"}},
    ("DELETE", "/connectors/{cid}"): {"url": "/connectors/probe", "mutating": True},
    ("POST", "/connectors/{cid}/test"): {"url": "/connectors/probe/test",
                                         "mutating": True, "json": {}},
    ("POST", "/connectors/{cid}/start"): {"url": "/connectors/probe/start",
                                          "mutating": True, "json": {}},
    ("POST", "/connectors/{cid}/stop"): {"url": "/connectors/probe/stop",
                                         "mutating": True, "json": {}},
    ("POST", "/connectors/{cid}/inject"): {"url": "/connectors/probe/inject",
                                           "mutating": True,
                                           "json": {"payload": {"probe": True}},
                                           "headers": {"X-Debug-Inject": "1"}},
    ("GET", "/collectors"): {"url": "/collectors"},
    ("GET", "/collectors/{collector_id}"): {"url": "/collectors/self"},
    ("GET", "/outbox/health"): {"url": "/outbox/health"},
    ("GET", "/outbox"): {"url": "/outbox"},
    ("GET", "/outbox/{rid}"): {"url": "/outbox/probe"},
    ("POST", "/outbox/{rid}/replay"): {"url": "/outbox/probe/replay",
                                       "mutating": True, "json": {}},
    ("POST", "/outbox/drain-once"): {"url": "/outbox/drain-once",
                                     "mutating": True, "json": {}},
    ("GET", "/data-sources"): {"url": "/data-sources"},
    ("GET", "/telemetry-health"): {"url": "/telemetry-health"},
    ("POST", "/ingest-preflight"): {"url": "/ingest-preflight",
                                    "mutating": True, "json": {}},
    ("POST", "/webhooks/{secret_id}"): {"url": "/webhooks/no-such-secret-id",
                                        "mutating": True, "json": {}},
    ("GET", "/landing"): {"url": "/landing"},
}

_HUMAN_OPS = sorted(k for k, v in COLLECTOR_ROUTE_CLASSIFICATION.items()
                    if v[0] == HUMAN_CONTROL)
_METADATA_OPS = sorted(k for k, v in COLLECTOR_ROUTE_CLASSIFICATION.items()
                       if v[0] == PRODUCT_METADATA)
_TEST_PLANE_OPS = sorted(k for k, v in COLLECTOR_ROUTE_CLASSIFICATION.items()
                         if v[0] == TEST_PLANE)
_MACHINE_OPS = sorted(k for k, v in COLLECTOR_ROUTE_CLASSIFICATION.items()
                      if v[0] == MACHINE)
_NON_MACHINE_OPS = sorted(set(COLLECTOR_ROUTE_CLASSIFICATION) - set(_MACHINE_OPS))
_READ_OPS = [k for k in _HUMAN_OPS if not SAMPLES[k].get("mutating")]


def _login(email: str, password: str) -> str:
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": email, "password": password}, timeout=20)
    assert r.status_code == 200, f"login {email}: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin() -> dict:
    return {"Authorization": f"Bearer {_login(ADMIN_EMAIL, ADMIN_PASSWORD)}"}


@pytest.fixture(scope="module")
def unprivileged() -> dict:
    """An authenticated principal that does NOT hold `collectors.*`."""
    return {"Authorization":
            f"Bearer {_login(UNPRIVILEGED_EMAIL, UNPRIVILEGED_PASSWORD)}"}


def _call(op: tuple, headers: dict) -> requests.Response:
    method, _path = op
    spec = SAMPLES[op]
    hdrs = dict(headers)
    hdrs.update(spec.get("headers") or {})
    return requests.request(method, f"{BASE_URL}{PREFIX}{spec['url']}",
                            headers=hdrs, json=spec.get("json"), timeout=30)


def _code(r: requests.Response) -> str:
    try:
        detail = r.json().get("detail")
    except (ValueError, AttributeError):
        return ""
    if isinstance(detail, dict):
        return str(detail.get("code") or "")
    return ""


def _connector_count(admin: dict) -> int:
    r = requests.get(f"{BASE_URL}{PREFIX}/connectors",
                     headers={**admin, "X-Tenant-Id": TENANT_OK}, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["count"]


# ══════════════════════════════════════════════════════════════════
# CLAUSE 1 · COVERAGE COMPLETENESS (offline · the gate that matters)
# ══════════════════════════════════════════════════════════════════
def _live_collector_operations() -> set:
    """Read the LIVE route table off the running service's OpenAPI contract.

    Deliberately not `from server import app`: the served contract is the
    thing that must be classified, and a route that exists only in an
    importable module cannot expose anything.
    """
    for candidate in (f"{BASE_URL}/api/openapi.json", f"{BASE_URL}/openapi.json"):
        r = requests.get(candidate, timeout=30)
        if r.status_code == 200:
            spec = r.json()
            break
    else:
        pytest.fail("could not read the live OpenAPI contract")
    ops = set()
    for path, item in spec.get("paths", {}).items():
        # `/api/xdr/collectors*` is a DIFFERENT (core XDR) router — match the
        # landed collector prefix as a path segment, not as a string prefix.
        if not (path == PREFIX or path.startswith(PREFIX + "/")):
            continue
        for method in item:
            if method.upper() in ("HEAD", "OPTIONS", "PARAMETERS"):
                continue
            ops.add((method.upper(), relative_path(path, PREFIX)))
    return ops


def test_every_live_collector_operation_is_explicitly_classified():
    """A new collector route is FAILED CLOSED until it is classified."""
    live = _live_collector_operations()
    unclassified = sorted(live - set(COLLECTOR_ROUTE_CLASSIFICATION))
    assert not unclassified, (
        "these live /api/xdr/collector operations are not declared in "
        "framework.route_classification.COLLECTOR_ROUTE_CLASSIFICATION — "
        "classify each one as HUMAN_CONTROL, MACHINE, TEST_PLANE or "
        f"PRODUCT_METADATA: {unclassified}")


def test_classification_has_no_entries_for_routes_that_no_longer_exist():
    live = _live_collector_operations()
    stale = sorted(set(COLLECTOR_ROUTE_CLASSIFICATION) - live)
    assert not stale, f"classified but not mounted: {stale}"


def test_every_declared_operation_has_a_concrete_probe():
    missing = sorted(set(COLLECTOR_ROUTE_CLASSIFICATION) - set(SAMPLES))
    assert not missing, f"declared but untested: {missing}"


def test_classification_values_are_from_the_closed_set():
    for op, (cls, perm) in COLLECTOR_ROUTE_CLASSIFICATION.items():
        assert cls in CLASSES, f"{op} -> unknown class {cls}"
        if cls == MACHINE:
            assert perm is None, f"{op} · the HMAC webhook takes no permission"
        else:
            assert perm and perm.startswith("collectors."), (
                f"{op} · must reuse an existing collectors.* permission, "
                f"got {perm!r}")


def test_only_the_webhook_is_machine_classified():
    assert _MACHINE_OPS == [("POST", "/webhooks/{secret_id}")]


# ══════════════════════════════════════════════════════════════════
# CLAUSE 2 · AUTHENTICATION — anonymous is refused everywhere
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _NON_MACHINE_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_anonymous_is_refused(op):
    r = _call(op, {})
    assert r.status_code in (401, 403), f"{op} -> {r.status_code} {r.text}"
    assert _code(r) in ("ACCESS_DENIED", "MACHINE_ACCESS_DENIED"), \
        f"{op} -> {r.text}"


@pytest.mark.parametrize("op", _NON_MACHINE_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_a_valid_tenant_never_substitutes_for_authentication(op):
    """THE ladder-order clause. A `ten_*` id is an identifier, not a
    credential — `GET /api/xdr/tenants` hands them out — so an anonymous
    caller presenting a real, ACTIVE tenant must still be refused for
    AUTHENTICATION and must not receive a tenant-authority answer."""
    r = _call(op, {"X-Tenant-Id": TENANT_OK})
    assert r.status_code in (401, 403), f"{op} -> {r.status_code} {r.text}"
    assert _code(r) not in ("TENANT_REQUIRED", "TENANT_NOT_FOUND",
                            "TENANT_NOT_ACTIVE"), (
        f"{op} answered the TENANT question before the AUTHENTICATION "
        f"question: {r.text}")


def test_anonymous_mutation_attempts_created_nothing(admin):
    """Every mutating operation driven anonymously above must have created
    no connector."""
    before = _connector_count(admin)
    for op in _NON_MACHINE_OPS:
        if SAMPLES[op].get("mutating"):
            _call(op, {})
            _call(op, {"X-Tenant-Id": TENANT_OK})
    assert _connector_count(admin) == before


# ══════════════════════════════════════════════════════════════════
# CLAUSE 3 · PERMISSION — authenticated is not authorised
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _NON_MACHINE_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_authenticated_without_collectors_permission_is_refused(op, unprivileged):
    r = _call(op, {**unprivileged, "X-Tenant-Id": TENANT_OK})
    assert r.status_code == 403, f"{op} -> {r.status_code} {r.text}"
    assert _code(r) == "ACCESS_DENIED", f"{op} -> {r.text}"


# ══════════════════════════════════════════════════════════════════
# CLAUSE 4 · TENANT AUTHORITY — preserved, and only reached after auth
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _READ_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_human_control_requires_an_explicit_tenant(op, admin):
    r = _call(op, admin)
    assert r.status_code == 403, f"{op} -> {r.status_code} {r.text}"
    assert _code(r) == "TENANT_REQUIRED", f"{op} -> {r.text}"


@pytest.mark.parametrize("op", _READ_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_human_control_refuses_an_unknown_tenant(op, admin):
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_UNKNOWN})
    assert r.status_code == 403, f"{op} -> {r.status_code} {r.text}"
    assert _code(r) == "TENANT_NOT_FOUND", f"{op} -> {r.text}"


@pytest.mark.parametrize("op", _READ_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_human_control_refuses_a_non_active_tenant(op, admin):
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_ARCHIVED})
    assert r.status_code == 403, f"{op} -> {r.status_code} {r.text}"
    assert _code(r) == "TENANT_NOT_ACTIVE", f"{op} -> {r.text}"


@pytest.mark.parametrize("op", _READ_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_authorised_principal_with_the_authoritative_tenant_is_served(op, admin):
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_OK})
    assert r.status_code in (200, 404), f"{op} -> {r.status_code} {r.text}"


@pytest.mark.parametrize("op", _METADATA_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_product_metadata_is_authenticated_but_tenant_independent(op, admin):
    """PRODUCT_METADATA carries no tenant data, so it does not demand a
    tenant — but it is no longer public."""
    r = _call(op, admin)
    assert r.status_code == 200, f"{op} -> {r.status_code} {r.text}"


# ══════════════════════════════════════════════════════════════════
# CLAUSE 5 · MACHINE PRINCIPAL
# ══════════════════════════════════════════════════════════════════
def test_webhook_keeps_its_hmac_contract_and_sees_no_jwt():
    """MACHINE passthrough: the webhook must reach its own connector lookup,
    not an RBAC refusal. An unknown secret_id is `404 webhook_not_configured`
    — proof that no analyst credential was demanded."""
    r = requests.post(f"{BASE_URL}{PREFIX}/webhooks/no-such-secret-id",
                      json={"probe": True}, timeout=30)
    assert r.status_code == 404, f"{r.status_code} {r.text}"
    assert "webhook_not_configured" in r.text


def test_unknown_machine_api_key_is_refused():
    """The machine lane is wired and fails closed. No key is minted here."""
    r = requests.get(f"{BASE_URL}{PREFIX}/connectors",
                     headers={"X-XDR-API-Key": "nvx_" + "0" * 48,
                              "X-Tenant-Id": TENANT_OK}, timeout=30)
    assert r.status_code in (401, 403), f"{r.status_code} {r.text}"


def test_presenting_both_a_jwt_and_an_api_key_is_ambiguous(admin):
    r = requests.get(f"{BASE_URL}{PREFIX}/connectors",
                     headers={**admin, "X-XDR-API-Key": "nvx_" + "0" * 48,
                              "X-Tenant-Id": TENANT_OK}, timeout=30)
    assert r.status_code in (401, 403), f"{r.status_code} {r.text}"
    assert "ambiguous" in r.text.lower()


# ══════════════════════════════════════════════════════════════════
# CLAUSE 6 · TEST PLANE — synthetic evidence cannot be injected
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("op", _TEST_PLANE_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_inject_is_refused_anonymously(op):
    r = _call(op, {})
    assert r.status_code in (401, 403)
    assert _code(r) == "ACCESS_DENIED"


@pytest.mark.parametrize("op", _TEST_PLANE_OPS, ids=lambda o: f"{o[0]} {o[1]}")
def test_inject_is_refused_even_for_an_authorised_admin_without_the_flag(op, admin):
    """`NIVX_COLLECTOR_TEST_PLANE` is not set on this deployment, so
    fabricated evidence cannot enter the canonical pipeline even with a
    valid admin session and the debug header."""
    r = _call(op, {**admin, "X-Tenant-Id": TENANT_OK})
    assert r.status_code == 403, f"{r.status_code} {r.text}"
    assert _code(r) == "TEST_PLANE_DISABLED", r.text


def test_inject_without_the_debug_header_is_still_refused(admin):
    r = requests.post(f"{BASE_URL}{PREFIX}/connectors/probe/inject",
                      headers={**admin, "X-Tenant-Id": TENANT_OK},
                      json={"payload": {"probe": True}}, timeout=30)
    assert r.status_code == 403, r.text


# ══════════════════════════════════════════════════════════════════
# CLAUSE 7 · RUNTIME / INFRASTRUCTURE DISCLOSURE
# ══════════════════════════════════════════════════════════════════
def test_collector_identity_discloses_no_infrastructure_hostname(admin):
    import socket
    r = requests.get(f"{BASE_URL}{PREFIX}/collectors",
                     headers={**admin, "X-Tenant-Id": TENANT_OK}, timeout=30)
    assert r.status_code == 200, r.text
    row = r.json()["collectors"][0]
    assert "host" not in row, row
    assert "runtime" not in row, row
    assert socket.gethostname() not in r.text
    assert "python-3." not in r.text


def test_undeclared_collector_route_fails_closed():
    """The guard's default branch: a path under the collector prefix that
    nobody classified is refused, never served."""
    r = requests.get(f"{BASE_URL}{PREFIX}/zzz-undeclared-operation", timeout=30)
    assert r.status_code in (403, 404), r.text
