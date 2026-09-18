"""
E2E test suite for the new GET /api/xdr/rbac/me/effective endpoint,
plus RBAC surface regression and anonymous fail-closed on core XDR
control-plane endpoints. Tests the live preview backend URL.
"""
import os
import pytest
import requests
from pathlib import Path

# Load backend/.env so ADMIN_EMAIL / ADMIN_PASSWORD exist locally too
env_file = Path("/app/backend/.env")
if env_file.exists():
    for line in env_file.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"'))

# Prefer public preview URL from frontend/.env, fall back to backend .env
def _base_url():
    fe = Path("/app/frontend/.env")
    if fe.exists():
        for line in fe.read_text().splitlines():
            if line.startswith("REACT_APP_BACKEND_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    raise RuntimeError("REACT_APP_BACKEND_URL not found")

BASE = _base_url()

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASS  = "uulVDp5cCSB3Hva99s7UUAwK"
ANALYST_EMAIL = "analyst@nivx-live.com"
ANALYST_PASS  = "NivxLive!Analyst2026"


def _login(email, password):
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": email, "password": password}, timeout=20)
    assert r.status_code == 200, f"login failed for {email}: {r.status_code} {r.text}"
    tok = r.json().get("token") or r.json().get("access_token") or r.json().get("jwt")
    if not tok:
        data = r.json()
        tok = (data.get("data") or {}).get("token") or (data.get("data") or {}).get("access_token")
    assert tok, f"no token in login response for {email}: {r.text[:300]}"
    return tok


@pytest.fixture(scope="module")
def admin_token():
    return _login(ADMIN_EMAIL, ADMIN_PASS)


@pytest.fixture(scope="module")
def analyst_token():
    return _login(ANALYST_EMAIL, ANALYST_PASS)


# ─── /api/xdr/rbac/me/effective ───

def test_effective_unauth_is_403():
    r = requests.get(f"{BASE}/api/xdr/rbac/me/effective", timeout=15)
    assert r.status_code in (401, 403), f"expected 401/403, got {r.status_code}: {r.text[:200]}"


def test_effective_admin_cross_tenant(admin_token):
    r = requests.get(f"{BASE}/api/xdr/rbac/me/effective",
                     headers={"Authorization": f"Bearer {admin_token}"}, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    data = body.get("data") or body
    assert data.get("basis") == "CROSS_TENANT_ADMIN_ROLE"
    assert data.get("cross_tenant") is True
    perms = data.get("permissions") or []
    assert isinstance(perms, list) and len(perms) > 0
    assert data.get("principal") == ADMIN_EMAIL


def test_effective_analyst_tenant_scoped(analyst_token):
    r = requests.get(f"{BASE}/api/xdr/rbac/me/effective",
                     headers={"Authorization": f"Bearer {analyst_token}"}, timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    data = body.get("data") or body
    assert data.get("basis") == "TENANT_SCOPED_RBAC_GRANT", data
    assert data.get("tenant") == "nivx-live"
    assert data.get("cross_tenant") is False
    assert "l1_analyst" in (data.get("roles") or [])
    perms = data.get("permissions") or []
    assert len(perms) == 11, f"expected 11 permissions, got {len(perms)}: {perms}"


# ─── Pre-existing RBAC surfaces regression (admin 200) ───

@pytest.mark.parametrize("path", [
    "/api/xdr/rbac/permissions",
    "/api/xdr/rbac/roles",
    "/api/xdr/rbac/users",
    "/api/xdr/rbac/groups",
    "/api/xdr/rbac/session-context",
])
def test_rbac_admin_200(admin_token, path):
    r = requests.get(f"{BASE}{path}",
                     headers={"Authorization": f"Bearer {admin_token}"}, timeout=15)
    assert r.status_code == 200, f"{path} -> {r.status_code}: {r.text[:200]}"


# ─── Anonymous & header-spoof fail-closed on control plane ───

@pytest.mark.parametrize("path", [
    "/api/xdr/collectors",
    "/api/xdr/secrets",
    "/api/xdr/api-keys",
    "/api/xdr/rule-studio/rules",
])
def test_control_plane_anon_403(path):
    r = requests.get(f"{BASE}{path}", timeout=15)
    assert r.status_code in (401, 403), f"{path} anon -> {r.status_code}"


@pytest.mark.parametrize("path", [
    "/api/xdr/collectors",
    "/api/xdr/secrets",
    "/api/xdr/api-keys",
    "/api/xdr/rule-studio/rules",
])
def test_control_plane_header_spoof_403(path):
    r = requests.get(f"{BASE}{path}",
                     headers={"X-Tenant-Id": "default",
                              "X-Principal-Id": "admin@nivxray.com"}, timeout=15)
    assert r.status_code in (401, 403), f"{path} spoof -> {r.status_code}: {r.text[:200]}"


# ─── Analyst should NOT be able to hit /api/xdr/api-keys ───

def test_analyst_cannot_list_api_keys(analyst_token):
    r = requests.get(f"{BASE}/api/xdr/api-keys",
                     headers={"Authorization": f"Bearer {analyst_token}"}, timeout=15)
    assert r.status_code in (401, 403), f"analyst api-keys -> {r.status_code}"
