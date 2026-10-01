"""Iteration 35 verification — locale classifier + correlation sidecar on /rc5/parse."""
import os
import requests
import pytest

BASE_URL = "http://localhost:8001"

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=180)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok
    return tok


@pytest.fixture(scope="module")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# --- Entity classifier via HTTP (locale contexts) --------------------
class TestClassifyTokenLocales:
    def test_russian_ipv4(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/rc5/entities/classify-token",
                          json={"token": "203.0.113.5",
                                "context": "подключение к серверу 203.0.113.5"},
                          headers=auth_headers, timeout=120)
        assert r.status_code == 200, r.text[:200]
        assert r.json().get("kind") == "ipv4"

    def test_chinese_ipv4(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/rc5/entities/classify-token",
                          json={"token": "203.0.113.5",
                                "context": "目标服务器地址: 203.0.113.5"},
                          headers=auth_headers, timeout=120)
        assert r.status_code == 200, r.text[:200]
        assert r.json().get("kind") == "ipv4"

    def test_arabic_ipv4(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/rc5/entities/classify-token",
                          json={"token": "203.0.113.5",
                                "context": "اتصال إلى خادم 203.0.113.5"},
                          headers=auth_headers, timeout=120)
        assert r.status_code == 200, r.text[:200]
        assert r.json().get("kind") == "ipv4"

    def test_chinese_software_version(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/rc5/entities/classify-token",
                          json={"token": "9.0.0.0",
                                "context": "组件版本 9.0.0.0"},
                          headers=auth_headers, timeout=120)
        assert r.status_code == 200, r.text[:200]
        assert r.json().get("kind") == "software_version"


# --- /rc5/parse now carries `correlation` sidecar --------------------
class TestParseCorrelationSidecar:
    def test_parse_returns_evidence_graph_and_correlation(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/rc5/parse",
                          json={"input": "powershell -w hidden -e YWJj"},
                          headers=auth_headers, timeout=180)
        assert r.status_code == 200, r.text[:300]
        data = r.json()
        assert "evidence_graph" in data
        assert data["evidence_graph"] is not None, "evidence_graph missing/None"
        assert "correlation" in data
        assert data["correlation"] is not None, "correlation missing/None"
        stats = data["correlation"].get("stats") or {}
        for key in ("node_count", "edge_count", "temporal_spans",
                    "dependency_chains", "contradictions"):
            assert key in stats, f"missing correlation.stats.{key}: {stats}"


# --- /rc5/entities/correlate still works with a graph body ----------
class TestCorrelateEndpoint:
    def test_correlate_with_empty_graph(self, auth_headers):
        # minimal valid EvidenceGraph shape
        r = requests.post(f"{BASE_URL}/api/rc5/entities/correlate",
                          json={"graph": {"schema_version": 1, "nodes": [], "edges": []}},
                          headers=auth_headers, timeout=120)
        # Endpoint should respond (200) either ok:true with empty stats,
        # or ok:false with an error message. Either way, not 500.
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        assert "ok" in body

    def test_correlate_from_parse_graph(self, auth_headers):
        # First get an evidence graph from /parse, then feed it back.
        p = requests.post(f"{BASE_URL}/api/rc5/parse",
                          json={"input": "powershell -w hidden -e YWJj"},
                          headers=auth_headers, timeout=180)
        assert p.status_code == 200
        eg = p.json().get("evidence_graph")
        assert eg is not None
        r = requests.post(f"{BASE_URL}/api/rc5/entities/correlate",
                          json={"graph": eg},
                          headers=auth_headers, timeout=120)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        assert body.get("ok") is True
        assert "stats" in body
