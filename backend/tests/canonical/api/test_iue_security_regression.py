"""Security regression tests · SEC-001 · SEC-002 · SEC-003.

Each finding from the 2026-02-14 audit is locked here.  These tests
MUST stay green forever.  Removing any assertion regresses shipped
security posture.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from server import app
    return TestClient(app)


# ── SEC-001 · unauthenticated /analyze must be rejected ───────────
def test_sec001_lane_a_analyze_requires_auth(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    files = {"file": ("in.ndjson", io.BytesIO(b'{"a":1}\n'),
                        "application/x-ndjson")}
    r = client.post("/api/iue/lane-a/analyze",
                     files=files, data={"parser": "ndjson"})
    # No auth header → get_current_user rejects
    assert r.status_code in (401, 403), (
        f"SEC-001 REGRESSED — anonymous Lane A upload accepted "
        f"(status {r.status_code}, body {r.text!r})"
    )


def test_sec001_lane_b_analyze_requires_auth(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    r = client.post("/api/iue/lane-b/analyze",
                     json={"url": "https://example.com"})
    assert r.status_code in (401, 403), (
        f"SEC-001 REGRESSED — anonymous Lane B URL analyse accepted "
        f"(status {r.status_code}, body {r.text!r})"
    )


# ── SEC-002 · prod tenant context preserved · no __prev_public__ ──
def test_sec002_url_lane_defaults_disallow_prev_fallback():
    """The exported ``analyze_url`` signature defaults
    ``allow_prev_fallback=False``.  Any router that forgets to pass
    an authenticated session_ctx WILL fail with tenant_context_missing,
    not silently stamp __prev_public__."""
    import inspect
    from services.iue.lanes.url_lane import analyze_url
    sig = inspect.signature(analyze_url)
    default = sig.parameters["allow_prev_fallback"].default
    assert default is False, (
        f"SEC-002 REGRESSED — analyze_url default is {default!r}, "
        f"must be False"
    )


def test_sec002_router_threads_authenticated_tenant(client, monkeypatch):
    """When authenticated, Lane B stamps the user's tenant, NOT
    __prev_public__."""
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")

    # Bypass auth by overriding the FastAPI dependency
    from server import app
    from deps import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {
        "tenant_id": "tenant-real-corp",
        "email": "analyst@real-corp.example",
        "sub": "u-42",
    }

    # Mock acquisition so we don't touch the network
    from services.ida import acquisition as acq
    class _S:
        ok = True; url = "https://example.gov/a"
        final_url = "https://example.gov/a"; status_code = 200
        content_type = "text/html"; fetched_bytes = 10; truncated = False
        duration_ms = 5; title = "x"; sitename = "example.gov"
        language = "en"; article_text = ""; article_chars = 0
        outbound_links = []; structured_blocks = []; veee_records = []
        engine = "trafilatura"; source_kind = ""; fallback_chain = []
        error_code = ""; error_detail = ""
        def to_dict(self):
            return {"ok": True, "url": self.url, "final_url": self.url,
                     "status_code": 200, "content_type": "text/html",
                     "fetched_bytes": 10, "truncated": False,
                     "duration_ms": 5, "title": "x", "sitename": "example.gov",
                     "language": "en", "article_text": "",
                     "article_chars": 0, "outbound_links": [],
                     "engine": "trafilatura", "source_kind": "",
                     "fallback_chain": [], "error_code": "", "error_detail": ""}
    monkeypatch.setattr(acq, "acquire_url", lambda u: _S(), raising=True)

    try:
        r = client.post("/api/iue/lane-b/analyze",
                         json={"url": "https://example.gov/a"})
        assert r.status_code == 200, r.text
        tenant = r.json()["intake_decision"]["tenant_id"]
        assert tenant == "tenant-real-corp", (
            f"SEC-002 REGRESSED — expected tenant-real-corp, got {tenant!r}"
        )
        assert tenant != "__prev_public__"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


# ── SEC-003 · Fix-1 envelope whitelisted ──────────────────────────
def test_sec003_fix1_envelope_whitelists_acquired_fields():
    """The acquisition_failure sub-dict must contain ONLY the fields
    the original Prev-mode Fix 1 whitelists — never the full acquired
    dict, which would leak final_url, fallback_chain, and internal
    error diagnostics."""
    from services.iue.lanes.url_lane import _fix1_report_extraction
    leaky_acquired = {
        # Legit fields (allowed)
        "url": "https://x",
        "host": "x",
        "engine": "trafilatura",
        "status_code": 403,
        "error_code": "http_error",
        "error_detail": "HTTP 403",
        "fetched_bytes": 0,
        "article_chars": 0,
        # Sensitive / leaky fields that MUST NOT appear
        "final_url": "https://x/redirected?token=SECRET",
        "fallback_chain": ["internal-info"],
        "internal_traceback": "Traceback (most recent call last): ...",
        "auth_header":  "Bearer ey…",
        "cookies": {"sessionid": "SECRET"},
        "final_html_path": "/tmp/leaky.html",
    }
    envelope = _fix1_report_extraction(leaky_acquired)
    fail = envelope["acquisition_failure"]

    forbidden = {
        "final_url", "fallback_chain", "internal_traceback",
        "auth_header", "cookies", "final_html_path",
    }
    leaked = forbidden.intersection(fail.keys())
    assert not leaked, f"SEC-003 REGRESSED — leaked fields: {leaked}"

    # Sanity: allowed fields still present
    assert set(fail.keys()) == {
        "url", "host", "engine", "ok", "status_code", "reason",
        "error_code", "anti_bot", "fallback_tried", "fetched_bytes",
        "article_chars",
    }
    assert fail["ok"] is False
    assert fail["status_code"] == 403
    assert fail["error_code"] == "http_error"

    # Top-level `error` MUST NOT expose the raw traceback
    assert "Traceback" not in envelope["error"]
    assert envelope["error"] == "HTTP 403"
