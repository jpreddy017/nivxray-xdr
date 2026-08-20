"""Lane-B · URL lane contract tests.

Covers:
  - Wire contract parity with Lane A (same T2 shape)
  - Fix 1 ``acquisition_failed`` envelope byte-for-byte preservation
  - Provenance chain walks Intake → Collect → Parse → Normalize → Aggregate
  - Discovered outbound links surface as separate LogicalEvents
  - Uses controlled/mocked acquisition — never hits a live URL
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


# ── Deterministic AcquiredResource fixtures ────────────────────────
def _mk_success(monkeypatch):
    """Install a fake acquire_url that returns a fully populated success."""
    from services.ida import acquisition as acq

    class _Success:
        ok = True
        url = "https://example.gov/advisory/aa26-014a"
        final_url = "https://example.gov/advisory/aa26-014a"
        status_code = 200
        content_type = "text/html"
        fetched_bytes = 42_000
        truncated = False
        duration_ms = 800
        title = "CISA Advisory · Test Ransomware Campaign"
        author = ""
        published_date = "2026-01-15"
        sitename = "example.gov"
        language = "en"
        article_text = ("Ransomware advisory · deterministic evidence surface\n"
                        "PowerShell downloader observed.\n"
                        "certutil.exe URL-cache abuse observed.")
        article_chars = 130
        outbound_links = [
            "https://example.gov/download/ioc-list.csv",
            "https://cdn.example.gov/img/logo.png",
            "https://example.gov/advisory/aa26-014a-appendix",
            "https://example.gov/download/ioc-list.csv",  # duplicate
        ]
        structured_blocks = []
        veee_records = []
        engine = "trafilatura"
        source_kind = "Static article"
        fallback_chain = ["trafilatura"]
        error_code = ""
        error_detail = ""
        def to_dict(self):
            return {
                "ok": True, "url": self.url, "final_url": self.final_url,
                "status_code": 200, "content_type": self.content_type,
                "fetched_bytes": self.fetched_bytes,
                "truncated": False, "duration_ms": self.duration_ms,
                "title": self.title, "sitename": self.sitename,
                "language": "en", "article_text": self.article_text,
                "article_chars": self.article_chars,
                "outbound_links": list(self.outbound_links),
                "engine": self.engine, "source_kind": self.source_kind,
                "fallback_chain": ["trafilatura"],
                "error_code": "", "error_detail": "",
            }

    monkeypatch.setattr(acq, "acquire_url", lambda u: _Success(),
                         raising=True)


def _mk_failure(monkeypatch, *, code="http_error", detail="HTTP 403"):
    from services.ida import acquisition as acq

    class _Fail:
        ok = False
        url = "https://blocked.example.gov/advisory/403"
        final_url = ""
        status_code = 403
        content_type = ""
        fetched_bytes = 0
        truncated = False
        duration_ms = 100
        title = ""
        author = ""
        published_date = ""
        sitename = ""
        language = ""
        article_text = ""
        article_chars = 0
        outbound_links = []
        structured_blocks = []
        veee_records = []
        engine = "trafilatura"
        source_kind = ""
        fallback_chain = []
        error_code = code
        error_detail = detail
        def to_dict(self):
            return {
                "ok": False, "url": self.url, "final_url": "",
                "status_code": 403, "content_type": "",
                "fetched_bytes": 0, "truncated": False, "duration_ms": 100,
                "title": "", "sitename": "", "language": "",
                "article_text": "", "article_chars": 0, "outbound_links": [],
                "engine": "trafilatura", "source_kind": "",
                "fallback_chain": [],
                "error_code": code, "error_detail": detail,
            }

    monkeypatch.setattr(acq, "acquire_url", lambda u: _Fail(),
                         raising=True)


# ── Wire-contract parity ───────────────────────────────────────────
def test_lane_b_success_produces_t2_wire_contract(monkeypatch):
    _mk_success(monkeypatch)
    from services.iue.lanes.url_lane import analyze_url

    wire = analyze_url("https://example.gov/advisory/aa26-014a")

    # Same top-level keys the EVIDENCE tab consumes
    assert set(wire.keys()) >= {
        "intake_decision", "raw_payload", "logical_events",
        "malformed", "report_extraction_fragment",
    }

    # At least 1 primary + 3 unique discovered links (4th is a dup)
    events = wire["logical_events"]
    assert len(events) >= 4
    primary = [e for e in events
                if e["canonical_fields"].get("canonical.event.action") == "url_acquire"]
    assert len(primary) == 1
    discovered = [e for e in events
                    if e["canonical_fields"].get("canonical.event.action") == "url_discovered"]
    assert len(discovered) == 3, (
        f"expected 3 unique discovered links (dup deduped by parser), "
        f"got {len(discovered)}"
    )

    # Canonical fields are populated (destination.url is a grouping key
    # → surfaces in canonical_fields; host + domain are non-grouping so
    # they land in variability).
    p_ev = primary[0]
    p = p_ev["canonical_fields"]
    var = p_ev["variability"]
    assert p.get("canonical.destination.url") == "https://example.gov/advisory/aa26-014a"
    assert var.get("canonical.destination.host") == ["example.gov"]
    assert var.get("canonical.destination.domain") == ["example.gov"]
    assert p.get("canonical.event.action") == "url_acquire"


def test_lane_b_wire_provenance_chain_walkable(monkeypatch):
    _mk_success(monkeypatch)
    from services.iue.lanes.url_lane import analyze_url

    wire = analyze_url("https://example.gov/advisory/aa26-014a")
    ev = wire["logical_events"][0]
    prov = ev["provenance"]
    # Composed from canonical.ssot.models.Provenance
    assert set(prov.keys()) == {"engine", "version", "at", "upstream_evidence_ids"}
    assert prov["engine"] == "iue.aggregator"
    chain = prov["upstream_evidence_ids"]
    # Must reference the immediate normalize upstream
    assert any("iue.normalizers.field_map" in s for s in chain)
    # And the parser
    assert any("iue.parsers.acquired_url" in s for s in chain)


def test_lane_b_wire_shape_identical_key_surface_to_lane_a(monkeypatch):
    """The EVIDENCE tab consumes ONE wire shape; both lanes must produce
    the same top-level keys."""
    _mk_success(monkeypatch)
    from services.iue.lanes.url_lane import analyze_url

    wire = analyze_url("https://example.gov/advisory/aa26-014a")
    for ev in wire["logical_events"]:
        assert set(ev.keys()) == {
            "canonical_fields", "count", "event_id", "first_seen",
            "input_id", "last_seen", "provenance", "record_refs",
            "source_file_id", "tenant_id", "variability",
        }


# ── Fix 1 preservation ─────────────────────────────────────────────
def test_lane_b_failure_reproduces_fix1_envelope(monkeypatch):
    _mk_failure(monkeypatch, code="http_error", detail="HTTP 403")
    from services.iue.lanes.url_lane import analyze_url

    wire = analyze_url("https://blocked.example.gov/advisory/403")
    frag = wire["report_extraction_fragment"]

    # ── The exact Fix 1 on-wire contract ─────────────────────────
    assert frag["source"] == "acquisition_failed"
    assert frag["status"] == "acquisition_failed"
    assert frag["evidence_source_url"] == "https://blocked.example.gov/advisory/403"
    assert frag["evidence_source"] == "acquisition_failed:http_error"
    assert isinstance(frag["acquisition_failure"], dict)
    assert frag["acquisition_failure"]["ok"] is False
    assert frag["acquisition_failure"]["error_code"] == "http_error"
    assert frag["acquisition_failure"]["error_detail"] == "HTTP 403"
    assert frag["error"] == "HTTP 403"

    # Additive keys empty on failure — same shape uniformity Lane A has
    for k in ("commands", "command_investigations",
                "mitre_techniques", "body_artifacts",
                "threat_actors", "malware_families",
                "behaviors"):
        assert frag[k] == [] or frag[k] == {}, k
    assert wire["logical_events"] == []
    assert isinstance(wire["iue_failure"], dict)
    assert wire["iue_failure"]["stage"] == "collect"


def test_lane_b_success_report_extraction_source_is_not_acquisition_failed(monkeypatch):
    """Success path MUST NOT emit the acquisition_failed sentinel."""
    _mk_success(monkeypatch)
    from services.iue.lanes.url_lane import analyze_url

    wire = analyze_url("https://example.gov/advisory/aa26-014a")
    frag = wire["report_extraction_fragment"]
    assert frag.get("source") != "acquisition_failed"
    assert "logical_events" in frag
    assert frag["logical_event_count"] >= 3


# ── Non-URL input rejection ────────────────────────────────────────
def test_lane_b_rejects_non_url_input(monkeypatch):
    from services.iue.lanes.url_lane import analyze_url

    wire = analyze_url("just some plain text, not a url")
    # intake will classify this as raw_text; Lane B rejects.
    assert "iue_failure" in wire
    assert wire["iue_failure"]["stage"] == "intake"
    assert wire["iue_failure"]["error_code"] == "intake_unknown_kind"


# ── Router smoke ───────────────────────────────────────────────────
@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from server import app
    return TestClient(app)


def test_lane_b_router_503_when_flag_off(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "off")
    r = client.post("/api/iue/lane-b/analyze",
                     json={"url": "https://example.gov"})
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "iue_structured_lane_disabled"


def test_lane_b_router_success_when_flag_on(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    _mk_success(monkeypatch)
    r = client.post("/api/iue/lane-b/analyze",
                     json={"url": "https://example.gov/advisory/aa26-014a"})
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) >= {
        "intake_decision", "logical_events", "report_extraction_fragment",
    }
    events = body["logical_events"]
    assert any(
        e["canonical_fields"].get("canonical.event.action") == "url_acquire"
        for e in events
    )


def test_lane_b_router_rejects_missing_url(client, monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    r = client.post("/api/iue/lane-b/analyze", json={"url": ""})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "missing_url"
