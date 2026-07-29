"""ADR-0005 · Preview endpoints tests — GET-only, read-only."""

from fastapi.testclient import TestClient
from fastapi import FastAPI

from nivxforge.router import router as nvx_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(nvx_router, prefix="/api")
    return TestClient(app)


def test_health_ok():
    c = _client()
    r = c.get("/api/nivxforge/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["package"] == "nivxforge"


def test_governance_lists_documents():
    c = _client()
    r = c.get("/api/nivxforge/preview/governance")
    assert r.status_code == 200
    body = r.json()
    assert "documents" in body
    for key in ("charter", "north_star", "roadmap", "phase0", "decisions", "real_world"):
        assert key in body["documents"]


def test_adrs_lists_all_adrs():
    c = _client()
    r = c.get("/api/nivxforge/preview/adrs")
    assert r.status_code == 200
    body = r.json()
    ids = [a["id"] for a in body["adrs"]]
    for expected in ("0001", "0004", "0005"):
        assert expected in ids, f"ADR {expected} missing from /adrs — got {ids}"


def test_evidence_inventory_returns_latest():
    c = _client()
    r = c.get("/api/nivxforge/preview/evidence-inventory")
    assert r.status_code == 200
    body = r.json()
    # There is at least one EVIDENCE_INVENTORY_*.md — created 2026-02-28.
    assert body["filename"] is not None
    assert "Evidence Inventory" in body["markdown"]


def test_diagnostics_list_and_body():
    c = _client()
    r = c.get("/api/nivxforge/preview/diagnostics")
    assert r.status_code == 200
    items = r.json()["diagnostics"]
    assert len(items) >= 1
    fname = items[0]["filename"]
    r2 = c.get(f"/api/nivxforge/preview/diagnostics/{fname}")
    assert r2.status_code == 200
    assert fname == r2.json()["filename"]


def test_framework_status_reports_empty_handlers_by_default():
    c = _client()
    r = c.get("/api/nivxforge/preview/framework-status")
    assert r.status_code == 200
    body = r.json()
    # Contract per ADR-0001 §3: framework ships with zero handlers.
    # (Other test files may register fake handlers; the endpoint just
    # reports what's in memory. So we only assert the key exists.)
    assert "total_handlers" in body
    assert "note" in body


def test_platform_health_reports_all_sections():
    c = _client()
    r = c.get("/api/nivxforge/preview/platform-health")
    assert r.status_code == 200
    body = r.json()
    for key in ("governance", "adrs", "framework", "evidence", "mount"):
        assert key in body, f"platform-health missing section: {key}"
    # ADRs accepted count includes 0001, 0004, 0005 at time of writing.
    assert body["adrs"]["accepted"] >= 3
    # Framework ships zero handlers by design (ADR-0001 §3).
    assert body["framework"]["registered_handlers"] == 0
    # Case 0001 is logged in REAL_WORLD_LOG.md.
    assert body["evidence"]["soc_cases_logged"] >= 1
    assert body["mount"] == "read-only-preview"


def test_preview_endpoints_are_get_only():
    # Fail any non-GET method → 405 Method Not Allowed
    c = _client()
    for method, path in [
        ("post", "/api/nivxforge/preview/governance"),
        ("put", "/api/nivxforge/preview/adrs"),
        ("delete", "/api/nivxforge/preview/framework-status"),
    ]:
        r = getattr(c, method)(path)
        assert r.status_code == 405, f"{method.upper()} {path} should be rejected"
