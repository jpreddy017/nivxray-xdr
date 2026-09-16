"""Backend tests for P0-F.13.3: /api/edr/context and /api/xdr/rbac/session-context."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"
ENDPOINT_ID = "dev_42e8c6dc74b9"
INCIDENT_ID = "inc_2305c71cd8f54dc38e55"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return r.json().get("access_token") or r.json().get("token")


@pytest.fixture()
def h(token):
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
    assert inv.get("tenant_id") == "default", inv
    er = (inv.get("endpoint_reference") or j.get("endpoint_reference")) or {}
    assert er.get("state") == "REFERENCES_THIS_ENDPOINT", er
    ac = j.get("active_customer") or {}
    assert ac.get("basis") == "INHERITED_FROM_INCIDENT", ac
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


def test_context_ignores_query_tenant(h):
    r = requests.get(f"{BASE_URL}/api/edr/context",
                     params={"endpoint_id": ENDPOINT_ID, "incident_id": INCIDENT_ID, "tenant": "EVIL"},
                     headers=h, timeout=30)
    assert r.status_code == 200
    assert "EVIL" not in r.text, "response echoed EVIL tenant from query string"


# --- /api/xdr/rbac/session-context ---
def test_session_context(h):
    r = requests.get(f"{BASE_URL}/api/xdr/rbac/session-context", headers=h, timeout=30)
    assert r.status_code == 200, r.text
    env = r.json()
    assert env.get("ok") is True, env
    j = env.get("data") or env
    assert (j.get("principal") or {}).get("email") == ADMIN_EMAIL
    assert (j.get("tenant_scope") or {}).get("all_tenants") is True
    customers = j.get("customers") or []
    assert isinstance(customers, list) and len(customers) > 0
    default = next((c for c in customers if c.get("customer") == "default"), None)
    assert default is not None, f"'default' customer missing: {customers}"
    assert default.get("open_incidents") == 241, default
    # cross-check via mss/customer-operations
    r2 = requests.get(f"{BASE_URL}/api/xdr/mss/customer-operations", headers=h, timeout=30)
    assert r2.status_code == 200, r2.text
    ops_env = r2.json()
    ops = ops_env.get("data") or ops_env
    rows = ops if isinstance(ops, list) else (ops.get("customers") or ops.get("rows") or ops.get("operations") or [])
    ops_default = next((c for c in rows if (c.get("customer") == "default" or c.get("name") == "default")), None)
    assert ops_default is not None, rows
    ops_count = ops_default.get("open_incidents") or ops_default.get("open") or ops_default.get("count")
    assert ops_count == 241, f"mss default open={ops_count}"
