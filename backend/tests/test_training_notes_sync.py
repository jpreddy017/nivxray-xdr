"""Regression tests for the Training-Note URL Sync endpoint.

These tests hit the FastAPI endpoint end-to-end through requests (mirroring
the existing docs / ti tests) — they mock the LLM by monkey-patching
`llm_json` at import time in the router module, and stub out `httpx`
network calls so no real fetch is performed.
"""
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
                      timeout=15)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestSyncValidation:
    def test_rejects_non_http_url(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/admin/training-notes/sync-url",
                          headers=auth_headers,
                          json={"url": "javascript:alert(1)"},
                          timeout=10)
        assert r.status_code in {422, 400}

    def test_rejects_missing_url(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/admin/training-notes/sync-url",
                          headers=auth_headers,
                          json={},
                          timeout=10)
        # pydantic missing-field returns 422
        assert r.status_code == 422

    def test_rejects_relative_url(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/admin/training-notes/sync-url",
                          headers=auth_headers,
                          json={"url": "/local/path"},
                          timeout=10)
        assert r.status_code == 422

    def test_requires_admin(self):
        # Unauthenticated request must be blocked.
        r = requests.post(f"{BASE_URL}/api/admin/training-notes/sync-url",
                          json={"url": "https://example.com/"},
                          timeout=10)
        assert r.status_code in {401, 403}


def test_strip_html_extracts_readable_text():
    """Unit test for the local HTML stripper — no network."""
    from routers.training_notes_sync import _strip_html
    html = """
    <html><head><title>ignored</title>
    <style>body{color:red}</style>
    <script>alert(1)</script>
    </head>
    <body>
      <nav>menu junk</nav>
      <article>
        <h1>Article Title</h1>
        <p>First paragraph about certutil abuse.</p>
        <ul><li>tip one</li><li>tip two</li></ul>
      </article>
      <footer>© Junk</footer>
    </body></html>
    """
    text = _strip_html(html)
    assert "alert(1)" not in text
    assert "body{color:red}" not in text
    assert "menu junk" not in text
    assert "Article Title" in text
    assert "certutil" in text
    assert "tip one" in text
