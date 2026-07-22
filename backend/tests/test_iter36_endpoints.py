"""Iter36: verify rc5/parse correlation block + golden/history endpoint."""
import os, requests, pytest

BASE = "http://localhost:8001"
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASS = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=90)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in {r.json()}"
    return tok


@pytest.fixture(scope="module")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_rc5_parse_has_correlation_block(auth_headers):
    payload = {"input": "powershell.exe -NoProfile -Command Get-ChildItem C:\\Windows"}
    r = requests.post(f"{BASE}/api/rc5/parse", json=payload, headers=auth_headers, timeout=180)
    assert r.status_code == 200, f"{r.status_code} {r.text[:300]}"
    data = r.json()
    assert "correlation" in data, f"no correlation in keys={list(data.keys())}"
    corr = data["correlation"]
    # arrays present (may be empty)
    assert "contradictions" in corr, f"contradictions missing, keys={list(corr.keys())}"
    assert isinstance(corr["contradictions"], list)


def test_golden_history_endpoint(auth_headers):
    r = requests.get(f"{BASE}/api/rc5/golden/history?limit=7", headers=auth_headers, timeout=20)
    assert r.status_code == 200, f"{r.status_code} {r.text[:300]}"
    data = r.json()
    # accept array or wrapper
    rows = data if isinstance(data, list) else data.get("history") or data.get("items") or []
    assert isinstance(rows, list), f"expected list-like, got {type(data)}: {str(data)[:200]}"
    # if any rows, validate fields
    for row in rows:
        for f in ("pass_rate", "passed", "total", "ts"):
            assert f in row, f"row missing '{f}': {row}"
