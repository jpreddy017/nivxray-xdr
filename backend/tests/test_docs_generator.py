"""Tests for Feb-2026 Phase 1 — Documentation-as-a-product endpoints."""
from __future__ import annotations
import os

import pytest
import requests


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
if BASE_URL == "http://localhost:8001":
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                       json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                       timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestDocsStats:
    def test_stats_shape(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/stats", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["features"] >= 10
        assert d["workflows"] >= 3
        assert isinstance(d["categories"], list)


class TestDocsFeatures:
    def test_list_features(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/features", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        feats = r.json()["features"]
        ids = [f["id"] for f in feats]
        assert "base58_decode" in ids
        assert "candidate_explorer" in ids

    def test_get_one_feature(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/features/base58_decode",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        f = r.json()
        assert f["id"] == "base58_decode"
        assert "purpose" in f
        assert any("Bitcoin" in fmt for fmt in f.get("supported_formats", []))

    def test_missing_feature_404(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/features/nonexistent",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 404


class TestDocsGuide:
    @pytest.mark.parametrize("audience", ["user", "admin", "developer"])
    def test_guide_generates(self, auth_headers, audience):
        r = requests.get(f"{BASE_URL}/api/docs/guide?audience={audience}",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["audience"] == audience
        md = d["markdown"]
        assert "# NivXRay" in md
        assert "## " in md  # at least one heading

    def test_guide_invalid_audience(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/guide?audience=hacker",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 422


class TestDocsSearch:
    def test_search_finds_base58(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/search?q=base58",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        ids = [f["id"] for f in d["features"]]
        assert "base58_decode" in ids

    def test_search_finds_workflow(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/search?q=powershell",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        wf_ids = [w["id"] for w in d["workflows"]]
        assert "encoded_powershell" in wf_ids

    def test_empty_query_returns_empty(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/search?q=", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["features"] == [] and d["workflows"] == []


class TestDocsExplain:
    def test_explain_static_fallback(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                           headers=auth_headers,
                           json={"page": "regression_dashboard"}, timeout=30)
        assert r.status_code == 200
        d = r.json()
        # Provider is either LLM-driven or static-registry — both must return text
        assert d["provider"] in {"emergent-claude", "static-registry"}
        assert d["explanation"]

    def test_explain_unknown_page(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain",
                           headers=auth_headers,
                           json={"page": "totally-not-a-page"}, timeout=30)
        assert r.status_code == 200
        # Should still succeed with a graceful fallback
        assert "explanation" in r.json()


class TestDocsWorkflows:
    def test_list_workflows(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/workflows",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        wfs = r.json()["workflows"]
        assert any(w["id"] == "encoded_powershell" for w in wfs)
        assert any(w["id"] == "corpus_promote" for w in wfs)

    def test_workflow_has_steps(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/workflows/encoded_powershell",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        w = r.json()
        assert len(w["steps"]) >= 3
        for step in w["steps"]:
            assert "title" in step
            assert "action" in step
            assert "expected" in step
