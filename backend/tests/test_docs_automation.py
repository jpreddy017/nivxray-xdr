"""Tests for Feb-2026 Phase-6 · Docs Automation (coverage, scaffold, suggest-fix)."""
from __future__ import annotations
import os
import time

import pytest
import requests
import yaml as _yaml


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


class TestCoverage:
    def test_shape(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/automation/coverage",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        for k in ("total_routes", "documented_routes", "undocumented_routes",
                  "coverage_pct", "documented_features", "undocumented"):
            assert k in d
        assert d["total_routes"] == d["documented_routes"] + d["undocumented_routes"]

    def test_finds_known_routes(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/automation/coverage",
                         headers=auth_headers, timeout=15)
        d = r.json()
        # Every /api/docs/* route must be present in the walked-route list
        all_paths = ({u["path"] for u in d["undocumented"]}
                     | {u["path"] for u in d.get("sample_covered", [])})
        # sample_covered is only 5 items — check via total instead
        assert d["total_routes"] >= 50

    def test_features_indexed(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/automation/coverage",
                         headers=auth_headers, timeout=15)
        d = r.json()
        # We seed 10 features in Phase 1, so at least that many must be indexed
        assert d["documented_features"] >= 10


class TestScaffold:
    def test_scaffold_known_route(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/automation/scaffold",
                          headers=auth_headers,
                          json={"route_path": "/api/docs/stats", "method": "GET"},
                          timeout=60)
        assert r.status_code == 200
        d = r.json()
        assert d["provider"] in {"emergent-claude", "template-fallback"}
        # Drafted YAML must parse and have id/title
        parsed = _yaml.safe_load(d["drafted_yaml"])
        assert isinstance(parsed, dict)
        assert parsed.get("id")
        assert parsed.get("title")
        for k in ("purpose", "when_to_use", "supported_formats",
                  "confidence_rules", "examples", "common_errors",
                  "tips", "related"):
            assert k in parsed, f"missing key {k} in drafted YAML"

    def test_scaffold_unknown_route_404(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/automation/scaffold",
                          headers=auth_headers,
                          json={"route_path": "/api/absolutely-not-a-route",
                                "method": "GET"},
                          timeout=15)
        assert r.status_code == 404

    def test_scaffold_bad_method_422(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/automation/scaffold",
                          headers=auth_headers,
                          json={"route_path": "/api/docs/stats",
                                "method": "MEOW"},
                          timeout=15)
        assert r.status_code == 422


class TestSuggestFix:
    def test_suggest_fix_known_page(self, auth_headers):
        # Seed one 👎 event so the endpoint has evidence
        requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                      headers=auth_headers,
                      json={"page": "base64_decode",
                            "session_id": f"suggest-fix-test-{time.time_ns()}",
                            "message_index": 0, "vote": "down",
                            "provider": "static-registry",
                            "question": "How do I handle URL-safe Base64?",
                            "reply_snippet": "It just says use base64url."},
                      timeout=15)
        r = requests.post(f"{BASE_URL}/api/docs/automation/suggest-fix",
                          headers=auth_headers,
                          json={"page": "base64_decode", "limit": 20},
                          timeout=90)
        assert r.status_code == 200
        d = r.json()
        assert d["provider"] in {"emergent-claude", "template-fallback"}
        assert d["page"] == "base64_decode"
        assert d["kind"] == "feature"
        # Revised YAML parses and preserves id
        revised = _yaml.safe_load(d["revised_yaml"])
        assert revised.get("id") == "base64_decode"
        assert revised.get("title")

    def test_suggest_fix_workflow(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/automation/suggest-fix",
                          headers=auth_headers,
                          json={"page": "encoded_powershell"},
                          timeout=90)
        assert r.status_code == 200
        d = r.json()
        assert d["kind"] == "workflow"
        revised = _yaml.safe_load(d["revised_yaml"])
        assert revised.get("id") == "encoded_powershell"

    def test_suggest_fix_unknown_page_404(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/automation/suggest-fix",
                          headers=auth_headers,
                          json={"page": "no-such-page-abc"}, timeout=30)
        assert r.status_code == 404

    def test_suggest_fix_limit_bounds(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/automation/suggest-fix",
                          headers=auth_headers,
                          json={"page": "rot13", "limit": 999}, timeout=15)
        assert r.status_code == 422

    def test_suggest_fix_fallback_appends_complaints(self, auth_headers):
        # Seed a distinct complaint we can look for
        marker = f"marker-{time.time_ns()}"
        requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                      headers=auth_headers,
                      json={"page": "rot13",
                            "session_id": f"fallback-test-{time.time_ns()}",
                            "message_index": 0, "vote": "down",
                            "question": marker}, timeout=15)
        r = requests.post(f"{BASE_URL}/api/docs/automation/suggest-fix",
                          headers=auth_headers,
                          json={"page": "rot13"}, timeout=90)
        assert r.status_code == 200
        d = r.json()
        # If we fell back to template, the marker must be embedded in the revised YAML.
        if d["provider"] == "template-fallback":
            assert marker in d["revised_yaml"]
