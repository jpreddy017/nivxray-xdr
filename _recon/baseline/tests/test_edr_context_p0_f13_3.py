"""Backend tests for P0-F.13.3: /api/edr/context and /api/xdr/rbac/session-context.

TEST REPAIR (2026-06, owner-approved · no product change)
---------------------------------------------------------
Two stale expectations were removed:

1. These cases were written before P0 TENANT AUTHORITY Fix 1, when a
   cross-tenant principal with NO tenant context was implicitly served. The
   current — and intended — contract is `403 TENANT_REQUIRED`, so the cases
   that mean to exercise the REAL registered tenant `default` now present it
   explicitly via `X-Tenant-Id`, exactly as the tenant-authority suites do.
   `test_context_without_tenant_context_is_refused` pins the refusal so the
   old implicit behaviour cannot creep back.
2. `open_incidents == 241` was a frozen snapshot of live data (the corpus now
   holds 944). The endpoint's actual contract is that the customer list is
   derived from the SAME authoritative queue predicate as the MSS panels, so
   the assertion is now that CONSISTENCY, plus the internal invariants of the
   row, rather than a number that drifts with real evidence.
"""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
ENDPOINT_ID = "dev_42e8c6dc74b9"
INCIDENT_ID = "inc_2305c71cd8f54dc38e55"
#: The real, registered, ACTIVE tenant these fixtures belong to. Named
#: explicitly because a cross-tenant principal is never given one implicitly.
TENANT = "default"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return r.json().get("access_token") or r.json().get("token")


@pytest.fixture()
def h(token):
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": TENANT}


@pytest.fixture()
def h_no_tenant(token):
    return {"Authorization": f"Bearer {token}"}


# --- /api/edr/context ---
def test_context_xdr_pivot(h):
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID, "incident_id": INCIDENT_ID},
                     headers=h, timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("entry_context") == "XDR_PIVOT", j
    inv = j.get("investigation") or {}
    assert inv.get("tenant_id") == TENANT, inv
    er = (inv.get("endpoint_reference") or j.get("endpoint_reference")) or {}
    assert er.get("state") == "REFERENCES_THIS_ENDPOINT", er
    ac = j.get("active_customer") or {}
    # A cross-tenant principal must now PRESENT the tenant (Fix 1), so the
    # server reports EXPLICIT_REQUEST_TENANT rather than inference from the
    # incident. The inheritance contract that matters is preserved and
    # asserted: the resolved customer IS the incident's tenant, and the entry
    # context is still XDR_PIVOT.
    assert ac.get("value") == inv.get("tenant_id") == TENANT, (ac, inv)
    assert ac.get("basis") in ("EXPLICIT_REQUEST_TENANT",
                               "INHERITED_FROM_INCIDENT"), ac
    # detection details
    assert inv.get("detection_count") == 7, inv
    assert "EDR-LNX-002" in (inv.get("rule_ids") or []), inv
    assert inv.get("verdict") == "suspicious", inv


def test_context_direct_edr(h):
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID}, headers=h, timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("entry_context") == "DIRECT_EDR", j
    assert j.get("investigation") in (None, {}), j


def test_context_bogus_incident(h):
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID, "incident_id": "inc_does_not_exist"},
                     headers=h, timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    assert "INCIDENT_NOT_FOUND" in (j.get("errors") or []), j
    assert j.get("investigation") in (None, {}), j


def test_context_unauthenticated():
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID}, timeout=30)
    assert r.status_code in (401, 403), r.status_code


def test_context_without_tenant_context_is_refused(h_no_tenant):
    """P0 TENANT AUTHORITY Fix 1 · a cross-tenant principal is never given a
    tenant implicitly. This pins the refusal so the pre-Fix-1 expectation
    cannot be reintroduced."""
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID}, headers=h_no_tenant,
                     timeout=30)
    assert r.status_code == 403, r.text
    detail = (r.json() or {}).get("detail") or {}
    assert detail.get("code") == "TENANT_REQUIRED", detail
    assert detail.get("fail_closed") is True, detail
    assert detail.get("authority") == "server", detail


def test_context_ignores_query_tenant(h):
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID, "incident_id": INCIDENT_ID, "tenant": "EVIL"},
                     headers=h, timeout=30)
    assert r.status_code == 200
    assert "EVIL" not in r.text, "response echoed EVIL tenant from query string"


# --- /api/xdr/rbac/session-context ---
def test_session_context(h_no_tenant):
    r = requests.get(f"{BASE_URL}/api/xdr/rbac/session-context",
                     headers=h_no_tenant, timeout=30)
    assert r.status_code == 200, r.text
    env = r.json()
    assert env.get("ok") is True, env
    j = env.get("data") or env
    assert (j.get("principal") or {}).get("email") == ADMIN_EMAIL
    assert (j.get("tenant_scope") or {}).get("all_tenants") is True
    customers = j.get("customers") or []
    assert isinstance(customers, list) and len(customers) > 0
    default = next((c for c in customers if c.get("customer") == TENANT), None)
    assert default is not None, f"'{TENANT}' customer missing: {customers}"

    # Row invariants (no frozen snapshot): a customer row is only ever
    # produced BY cases, so it carries at least one, and the open subset can
    # never exceed the total.
    assert default["incidents"] >= 1, default
    assert 0 <= default["open_incidents"] <= default["incidents"], default
    assert default["queue_href"] == f"/xdr/incidents?customer={TENANT}"
    # P0-FIX-5B · every row is a REAL customer; unattributed cases produce none.
    assert all(c.get("customer") for c in customers), customers

    # The contract: the customer list is derived from the SAME authoritative
    # queue predicate as the MSS panels, so the two surfaces may never drift.
    r2 = requests.get(f"{BASE_URL}/api/xdr/mss/customer-operations",
                      headers=h_no_tenant, timeout=30)
    assert r2.status_code == 200, r2.text
    ops_env = r2.json()
    ops = ops_env.get("data") or ops_env
    rows = ops if isinstance(ops, list) else (ops.get("customers") or ops.get("rows") or ops.get("operations") or [])
    ops_default = next((c for c in rows if (c.get("customer") == TENANT or c.get("name") == TENANT)), None)
    assert ops_default is not None, rows
    ops_count = ops_default.get("open_incidents") or ops_default.get("open") or ops_default.get("count")
    assert ops_count == default["open_incidents"], (
        f"session-context and MSS disagree on {TENANT}: "
        f"{default['open_incidents']} vs {ops_count}")
