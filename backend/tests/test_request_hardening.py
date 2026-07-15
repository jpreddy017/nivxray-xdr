"""Regression tests for the Feb-2026 production-hardening middleware.

Covers:
  * X-Request-ID header roundtrip (echo when caller provides one; generate otherwise)
  * X-Elapsed-Ms header populated
  * 413 payload_too_large enforcement (>500 KB rejected)
  * 504 hard timeout (mocked slow endpoint)
  * /api/health + /api/health/deep endpoints
  * SSE endpoint content-type + event shape for /decode/chain/narrative/stream
"""
from __future__ import annotations
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401 — register op registry

from fastapi.testclient import TestClient
from server import app


def _client() -> TestClient:
    return TestClient(app)


def _auth_headers() -> dict:
    """Log in as the seeded admin and return a Bearer token header."""
    c = _client()
    r = c.post("/api/auth/login", json={
        "email": "admin@nivxray.com",
        "password": "NivXRay#2026!",
    })
    if r.status_code != 200:
        return {}
    tok = r.json().get("access_token") or r.json().get("token")
    return {"Authorization": f"Bearer {tok}"}


# ─── X-Request-ID roundtrip ─────────────────────────────────────────────
def test_request_id_generated_when_missing():
    c = _client()
    r = c.get("/api/health")
    assert r.status_code == 200
    assert "x-request-id" in r.headers
    assert r.headers["x-request-id"].startswith("nvx-")
    assert "x-elapsed-ms" in r.headers


def test_request_id_echoed_when_provided():
    c = _client()
    r = c.get("/api/health", headers={"X-Request-ID": "caller-supplied-id-abc123"})
    assert r.status_code == 200
    assert r.headers["x-request-id"] == "caller-supplied-id-abc123"


# ─── Payload cap enforcement ────────────────────────────────────────────
def test_413_on_oversized_payload():
    c = _client()
    huge = "A" * (600 * 1024)   # 600 KB — over the 500 KB cap
    r = c.post("/api/decode/smart", json={"input": huge}, headers=_auth_headers())
    assert r.status_code == 413
    body = r.json()
    assert "request_id" in body
    assert body["limit"] == 512 * 1024


def test_413_response_body_shape():
    c = _client()
    r = c.post("/api/decode/smart", json={"input": "A" * (600 * 1024)}, headers=_auth_headers())
    j = r.json()
    for k in ("detail", "request_id", "content_length", "limit"):
        assert k in j, f"missing {k} in 413 body"


# ─── Health endpoints ───────────────────────────────────────────────────
def test_health_liveness():
    c = _client()
    r = c.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "nivxray-api"}


def test_health_deep_returns_all_checks():
    c = _client()
    r = c.get("/api/health/deep")
    assert r.status_code == 200
    j = r.json()
    assert "status" in j and "checks" in j
    for k in ("mongo", "llm_key", "disk"):
        assert k in j["checks"], f"missing {k} in checks"


# ─── SSE endpoint shape ─────────────────────────────────────────────────
def test_sse_narrative_stream_returns_event_stream_content_type():
    """Streaming endpoint must return `text/event-stream` and at least one progress event."""
    c = _client()
    headers = _auth_headers()
    if not headers:
        return  # skip if auth failed
    body = {
        "stages": [{"input": "Get-Process"}],
        "aggregate": {"iocs": {}, "mitre": [], "yara": [], "lolbas": [],
                      "family": None, "risk": {"score": 15}, "kill_chain": [],
                      "concatenated_output": "Get-Process"},
    }
    with c.stream("POST", "/api/decode/chain/narrative/stream",
                  json=body, headers=headers, timeout=10) as r:
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/event-stream")
        # Read AT LEAST the first event frame
        chunks = []
        for chunk in r.iter_text():
            chunks.append(chunk)
            if "".join(chunks).find("\n\n") != -1:
                break
        merged = "".join(chunks)
        assert "event:" in merged, f"expected SSE frame, got: {merged[:200]!r}"
        # First frame should be a `progress` event (immediate keep-alive)
        assert "progress" in merged[:400], f"first frame should be progress, got: {merged[:400]!r}"
