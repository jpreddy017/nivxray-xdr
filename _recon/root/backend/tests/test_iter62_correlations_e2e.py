"""Iter-62 · Phase 4 P1 — /api/correlations/* E2E suite.

Tests exercise every route on the correlations router using a real preview URL
against a fresh admin session. Existing seed correlation (per handoff note)
is also exercised for read paths."""
from __future__ import annotations

import os
import time
import pytest
import requests

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASS = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
                      timeout=30)
    assert r.status_code == 200, r.text
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok
    return tok


@pytest.fixture(scope="module")
def client(token):
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.headers["Content-Type"] = "application/json"
    return s


@pytest.fixture(scope="module")
def some_case_id(client):
    """Grab any case from history for seeding a fresh investigation."""
    r = client.get(f"{BASE}/api/history?limit=5", timeout=30)
    assert r.status_code == 200, r.text
    items = r.json().get("items") or r.json().get("history") or []
    assert items, "no history cases available to seed a correlation"
    for it in items:
        cid = it.get("id") or it.get("_id")
        if cid:
            return str(cid)
    pytest.skip("no valid history id")


# ---------- Basics ----------
class TestListAndAuth:
    def test_list_correlations_authed(self, client):
        r = client.get(f"{BASE}/api/correlations", timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "correlations" in body
        assert "count" in body

    def test_list_correlations_unauth_rejected(self):
        r = requests.get(f"{BASE}/api/correlations", timeout=30)
        assert r.status_code in (401, 403), r.status_code


# ---------- CRUD ----------
class TestCorrelationCRUD:
    created_id = None

    def test_create_from_root_case(self, client, some_case_id):
        r = client.post(f"{BASE}/api/correlations",
                        json={"root_case_id": some_case_id,
                              "name": "TEST_iter62_investigation",
                              "description": "iter62 e2e",
                              "tags": ["iter62", "TEST"]}, timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        corr = body["correlation"]
        assert corr["root_case_id"] == some_case_id
        assert some_case_id in corr["case_ids"]
        assert corr["name"] == "TEST_iter62_investigation"
        # Root artifact node present
        nodes = corr.get("artifact_nodes") or []
        assert any(n.get("node_id") == f"case:{some_case_id}" for n in nodes)
        TestCorrelationCRUD.created_id = corr["id"]

    def test_create_idempotent_if_case_already_linked(self, client, some_case_id):
        r = client.post(f"{BASE}/api/correlations",
                        json={"root_case_id": some_case_id},
                        timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("created") is False
        assert body["correlation"]["id"] == TestCorrelationCRUD.created_id

    def test_get_detail(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/correlations/{cid}", timeout=30)
        assert r.status_code == 200, r.text
        corr = r.json()["correlation"]
        assert corr["id"] == cid
        assert "artifact_nodes" in corr
        assert "edges" in corr
        assert "case_ids" in corr

    def test_patch(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.patch(f"{BASE}/api/correlations/{cid}",
                         json={"name": "TEST_renamed", "description": "d2",
                               "tags": ["a", "b"]}, timeout=30)
        assert r.status_code == 200, r.text
        corr = r.json()["correlation"]
        assert corr["name"] == "TEST_renamed"
        assert corr["description"] == "d2"
        assert corr["tags"] == ["a", "b"]

    def test_get_bad_id_404(self, client):
        r = client.get(f"{BASE}/api/correlations/000000000000000000000000",
                       timeout=30)
        assert r.status_code == 404


# ---------- Views ----------
class TestViews:
    def test_chain(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/correlations/{cid}/chain", timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "steps" in body and "root" in body
        depths = [s.get("depth", 0) for s in body["steps"]]
        assert depths == sorted(depths), "chain depth not monotonically increasing"

    def test_graph(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/correlations/{cid}/graph", timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "nodes" in body
        assert "edges" in body
        assert isinstance(body["nodes"], list)

    def test_timeline(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/correlations/{cid}/timeline", timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        # ordered events
        assert "events" in body or "timeline" in body

    def test_summary(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/correlations/{cid}/summary", timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "summary" in body
        s = body["summary"]
        # Aggregation keys
        assert isinstance(s, dict)


# ---------- Suggestions / Scan ----------
class TestSuggestionsAndScan:
    def test_scan_lone_case(self, client, some_case_id):
        r = client.post(f"{BASE}/api/correlations/scan",
                        json={"case_id": some_case_id, "limit": 10},
                        timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["case_id"] == some_case_id
        assert "suggestions" in body
        assert body["min_score"] == 50

    def test_list_suggestions(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/correlations/{cid}/suggestions",
                       timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "suggestions" in body
        assert "count" in body


# ---------- Linking / unlink / delete ----------
class TestLinkingLifecycle:
    def test_unlink_root_refused(self, client, some_case_id):
        cid = TestCorrelationCRUD.created_id
        r = client.post(f"{BASE}/api/correlations/{cid}/unlink",
                        json={"case_id": some_case_id}, timeout=30)
        assert r.status_code == 400, r.text

    def test_link_and_unlink_second_case(self, client):
        cid = TestCorrelationCRUD.created_id
        r = client.get(f"{BASE}/api/history?limit=20", timeout=30)
        items = r.json().get("items") or r.json().get("history") or []
        # find another case not in this correlation and not already correlated
        corr = client.get(f"{BASE}/api/correlations/{cid}", timeout=30).json()["correlation"]
        member = set(corr["case_ids"])
        candidate = None
        for it in items:
            other = str(it.get("id") or it.get("_id"))
            if other and other not in member and not it.get("correlation_id"):
                candidate = other
                break
        if not candidate:
            pytest.skip("no free second case to link/unlink")
        # LINK
        r = client.post(f"{BASE}/api/correlations/{cid}/link",
                        json={"case_id": candidate, "source": "manual"},
                        timeout=30)
        assert r.status_code == 200, r.text
        assert candidate in r.json()["correlation"]["case_ids"]
        # Case doc should carry correlation_id back-ref
        hr = client.get(f"{BASE}/api/history?limit=100", timeout=30)
        items = hr.json().get("items") or hr.json().get("history") or []
        linked = [x for x in items if str(x.get("id") or x.get("_id")) == candidate]
        if linked:
            assert linked[0].get("correlation_id") == cid
        # UNLINK
        r = client.post(f"{BASE}/api/correlations/{cid}/unlink",
                        json={"case_id": candidate}, timeout=30)
        assert r.status_code == 200, r.text
        assert candidate not in r.json()["correlation"]["case_ids"]

    def test_delete_correlation_detaches_root(self, client, some_case_id):
        cid = TestCorrelationCRUD.created_id
        r = client.delete(f"{BASE}/api/correlations/{cid}", timeout=30)
        assert r.status_code == 200, r.text
        # Root case must still exist
        hr = client.get(f"{BASE}/api/history?limit=100", timeout=30)
        items = hr.json().get("items") or hr.json().get("history") or []
        still = [x for x in items if str(x.get("id") or x.get("_id")) == some_case_id]
        assert still, "root case was deleted along with correlation (should be detached only)"
        # And should NOT still have correlation_id pointing to deleted corr
        if still[0].get("correlation_id") == cid:
            pytest.fail("correlation_id was not cleared on delete")


# ---------- Existing endpoint regression ----------
class TestExistingEndpointsRegression:
    def test_history_still_works(self, client):
        r = client.get(f"{BASE}/api/history?limit=5", timeout=30)
        assert r.status_code == 200

    def test_investigations_event_log_still_works(self, client):
        # /api/investigations (event log) — sanity, may need id, so just probe list
        r = client.get(f"{BASE}/api/investigations", timeout=30)
        # accept 200 or 405 depending on route, but must not 500
        assert r.status_code < 500, r.text

    def test_artifacts_capabilities(self, client):
        r = client.get(f"{BASE}/api/artifacts/capabilities", timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        # 4 analyzers still present
        text = str(body).lower()
        for a in ("pe", "pdf", "office", "elf"):
            assert a in text
