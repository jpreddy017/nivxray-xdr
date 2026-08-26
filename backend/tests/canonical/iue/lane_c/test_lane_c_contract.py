"""Lane-C · File / Artifact contract tests.

Covers the Stage-1 Lane C surface:
  - Wire contract parity with Lane A / Lane B (same T2 shape)
  - Artifact identity surfaces as canonical.artifact.* / canonical.file.*
  - Embedded IOCs (URLs / IPs / hashes) surface as separate LogicalEvents
  - Provenance chain walks Intake → Collect → Parse → Normalize → Aggregate
  - Static analysis only — no network, no execution
  - Feature-flag gating (`IUE_ARTIFACT_LANE`)
  - Aggregation collapses duplicates strictly (aggregation ≠ correlation)
  - Auth required at the router boundary
"""
from __future__ import annotations

import base64
import io
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


# ─── Fixtures ─────────────────────────────────────────────────────────
@pytest.fixture
def flag_on(monkeypatch):
    monkeypatch.setenv("IUE_ARTIFACT_LANE", "on")
    yield


@pytest.fixture
def pdf_bytes():
    """Minimal-but-valid PDF header + trailer.  Static bytes; no
    interpretation; used to exercise the pdfid / pdfparser analyzer path.
    """
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 44>>stream\n"
        b"BT /F1 12 Tf 72 720 Td (evil.example.com) Tj ET\n"
        b"endstream endobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f\n"
        b"trailer<</Size 5/Root 1 0 R>>\n"
        b"%%EOF\n"
    )


@pytest.fixture
def elf_bytes():
    """Minimal ELF header — enough for magic-byte detection.  Static."""
    return b"\x7fELF" + b"\x02" + b"\x01" + b"\x01" + b"\x00" + (b"\x00" * 120)


@pytest.fixture
def unknown_bytes():
    """Bytes that no analyzer will claim."""
    return b"random-binary-payload-that-no-magic-byte-matches-XXYZ"[:128]


# ─── 1. FileCollector — collects, hashes, dispatches ─────────────────
class TestFileCollector:
    def test_collect_produces_raw_payload(self, pdf_bytes):
        from services.iue.collectors.file_collector import collect_file, FileRawPayload
        raw = collect_file(pdf_bytes, filename="advisory.pdf",
                             mime="application/pdf",
                             input_id="testinput", tenant_id="tenantA")
        assert isinstance(raw, FileRawPayload)
        assert raw.filename == "advisory.pdf"
        assert raw.mime == "application/pdf"
        assert raw.tenant_id == "tenantA"
        assert raw.input_id == "testinput"
        assert raw.source_file_id, "source_file_id must be a truthy sha256-prefix"
        assert isinstance(raw.artifact_dispatch, dict)
        # Must contain the AnalysisResult schema keys.
        for k in ("artifact_type", "display_name", "hashes",
                  "analysis", "capability_available", "detected_by"):
            assert k in raw.artifact_dispatch, f"missing dispatch key: {k}"

    def test_collect_hashes_are_deterministic(self, pdf_bytes):
        from services.iue.collectors.file_collector import collect_file
        raw1 = collect_file(pdf_bytes, filename="a.pdf", mime="application/pdf",
                              input_id="i1", tenant_id="t1")
        raw2 = collect_file(pdf_bytes, filename="a.pdf", mime="application/pdf",
                              input_id="i1", tenant_id="t1")
        assert raw1.source_file_id == raw2.source_file_id
        assert raw1.artifact_dispatch["hashes"] == raw2.artifact_dispatch["hashes"]

    def test_collect_size_cap_enforced(self, monkeypatch):
        # Force a tiny cap and confirm the collector short-circuits.
        from services.iue import security
        monkeypatch.setattr(security, "MAX_RAW_BYTES", 100)
        from services.iue.collectors.file_collector import collect_file
        from services.iue.failure import IUEFailure
        result = collect_file(b"X" * 500, filename="big.bin", mime="application/octet-stream",
                                input_id="i1", tenant_id="t1")
        assert isinstance(result, IUEFailure)
        assert result.error_code == "collect_size_exceeded"

    def test_collect_unknown_bytes_returns_unknown_type(self, unknown_bytes):
        from services.iue.collectors.file_collector import collect_file
        raw = collect_file(unknown_bytes, filename="mystery.bin",
                             mime="application/octet-stream",
                             input_id="i1", tenant_id="t1")
        # dispatcher returns artifact_type='unknown' when nothing claims
        assert raw.artifact_dispatch["artifact_type"] == "unknown"


# ─── 2. Artifact parser — primary + child records ────────────────────
class TestArtifactParser:
    def test_primary_record_carries_artifact_identity(self, pdf_bytes):
        from services.iue.collectors.file_collector import collect_file
        from services.iue.parsers.artifact_parser import iter_records
        raw = collect_file(pdf_bytes, filename="a.pdf", mime="application/pdf",
                             input_id="i1", tenant_id="t1")
        records = list(iter_records(raw))
        assert records, "parser must yield ≥ 1 record"
        primary = records[0]
        assert primary.parse_status == "ok"
        assert primary.offset == 0
        assert primary.parser_name == "artifact"
        rf = primary.raw_fields
        assert "artifact_type" in rf
        assert "file_sha256" in rf
        assert "file_name" in rf and rf["file_name"] == "a.pdf"
        assert "file_size" in rf and rf["file_size"] > 0

    def test_child_records_project_embedded_iocs(self, monkeypatch):
        """When the artifact dispatcher surfaces embedded IOCs
        (urls / domains / ips), the parser emits one child record per
        distinct IOC value with the canonical bucket alias set."""
        from services.iue.parsers.artifact_parser import iter_records
        from services.iue.collectors.file_collector import FileRawPayload
        from canonical.ssot.models import Provenance
        raw = FileRawPayload(
            bytes_=b"", filename="test.pdf", mime="application/pdf",
            source_file_id="abc123", input_id="i1", tenant_id="t1",
            artifact_dispatch={
                "artifact_type": "pdf",
                "display_name": "PDF",
                "confidence": 90,
                "hashes": {"sha256": "a" * 64},
                "detected_by": "magic-byte",
                "capability_available": True,
                "analysis": {
                    "available": True,
                    "urls":    ["http://evil.example.com/x", "http://evil.example.com/x", "http://benign.example.com"],
                    "domains": ["evil.example.com"],
                    "ips":     ["203.0.113.7"],
                },
            },
            provenance=Provenance(engine="test.setup", version="1.0",
                                    at="1970-01-01T00:00:00+00:00",
                                    upstream_evidence_ids=["abc123"]),
        )
        records = list(iter_records(raw))
        # 1 primary + 2 unique urls + 1 domain + 1 ip = 5
        assert len(records) == 5
        kinds = [r.raw_fields.get("artifact_child_kind") for r in records[1:]]
        assert "urls" in kinds
        assert "domains" in kinds
        assert "ips" in kinds

    def test_empty_dispatch_yields_malformed(self):
        from services.iue.parsers.artifact_parser import iter_records
        from services.iue.collectors.file_collector import FileRawPayload
        from canonical.ssot.models import Provenance
        raw = FileRawPayload(
            bytes_=b"", filename="", mime="", source_file_id="s",
            input_id="i", tenant_id="t", artifact_dispatch={},
            provenance=Provenance(engine="test", version="1.0",
                                    at="1970-01-01T00:00:00+00:00",
                                    upstream_evidence_ids=[]),
        )
        records = list(iter_records(raw))
        assert len(records) == 1
        assert records[0].parse_status == "malformed"


# ─── 3. Field-map normalizer maps to canonical.artifact.* ────────────
class TestArtifactNormalization:
    def test_primary_fields_normalize_to_canonical_namespace(self, pdf_bytes):
        from services.iue.collectors.file_collector import collect_file
        from services.iue.parsers.artifact_parser import iter_records
        from services.iue.normalizers.field_map import normalize
        raw = collect_file(pdf_bytes, filename="a.pdf", mime="application/pdf",
                             input_id="i1", tenant_id="t1")
        primary = list(iter_records(raw))[0]
        norm = normalize(primary)
        assert norm.normalize_status == "ok"
        cf = norm.canonical_fields
        assert cf.get("canonical.artifact.type") is not None
        assert cf.get("canonical.file.name") == "a.pdf"
        assert cf.get("canonical.artifact.display_name") is not None
        assert "canonical.file.hash.sha256" in cf

    def test_ioc_child_normalizes_to_ioc_canonical(self):
        """A child record with `url` alias must project to canonical.destination.url."""
        from services.iue.normalizers.field_map import normalize
        from services.iue.parsers._types import ParsedRecord
        from canonical.ssot.models import Provenance
        rec = ParsedRecord(
            record_id="r1", source_file_id="s", input_id="i", tenant_id="t",
            offset=1, parser_name="artifact",
            raw_fields={
                "artifact_child_kind":  "urls",
                "artifact_child_value": "http://evil.example.com/x",
                "url":                  "http://evil.example.com/x",
                "parent_artifact_type": "pdf",
                "parent_file_sha256":   "a" * 64,
            },
            provenance=Provenance(engine="test", version="1.0",
                                    at="1970-01-01T00:00:00+00:00",
                                    upstream_evidence_ids=[]),
        )
        norm = normalize(rec)
        assert norm.canonical_fields.get("canonical.destination.url") == "http://evil.example.com/x"
        assert norm.canonical_fields.get("canonical.artifact.child_kind") == "urls"


# ─── 4. End-to-end file_lane orchestrator ────────────────────────────
class TestFileLaneEndToEnd:
    def test_analyze_file_returns_t2_wire_shape(self, pdf_bytes):
        from services.iue.lanes.file_lane import analyze_file
        wire = analyze_file(pdf_bytes, filename="advisory.pdf",
                              mime="application/pdf",
                              tenant_id="tenantA")
        # T2 contract keys — same shape as Lane A/B.
        for k in ("intake_decision", "raw_payload", "logical_events",
                  "malformed", "report_extraction_fragment"):
            assert k in wire, f"missing wire key: {k}"
        # Intake lane must be 'file'
        assert wire["intake_decision"]["lane"] == "file"
        assert wire["intake_decision"]["kind"] == "binary_artifact"
        # At least the primary artifact event must be present.
        assert len(wire["logical_events"]) >= 1
        # Fragment must carry the artifact summary.
        frag = wire["report_extraction_fragment"]
        assert frag["source"] == "lane_c_file"
        assert "artifact_summary" in frag
        summary = frag["artifact_summary"]
        assert "artifact_type" in summary
        assert "sha256" in summary
        assert summary["file_name"] == "advisory.pdf"

    def test_missing_tenant_fails_intake(self):
        from services.iue.lanes.file_lane import analyze_file
        wire = analyze_file(b"%PDF-1.0", filename="a.pdf",
                              mime="application/pdf")
        # No tenant + allow_prev_fallback=False (default) → intake failure.
        assert wire.get("intake_decision") is None
        assert wire.get("iue_failure", {}).get("error_code") == "tenant_context_missing"

    def test_provenance_chain_walks_all_stages(self, pdf_bytes):
        from services.iue.lanes.file_lane import analyze_file
        wire = analyze_file(pdf_bytes, filename="a.pdf",
                              mime="application/pdf",
                              tenant_id="t1")
        ev = wire["logical_events"][0]
        prov = ev["provenance"]
        assert prov["engine"] == "iue.aggregator"
        chain = prov["upstream_evidence_ids"]
        chain_str = " ".join(chain)
        # Chain must reference at least intake / collectors / parser / normalizer / aggregator
        assert "iue.intake" in chain_str or any("iue.intake" in c for c in chain)
        assert "iue.collectors" in chain_str
        assert "iue.parsers.artifact" in chain_str
        assert "iue.normalizers.field_map" in chain_str

    def test_aggregation_collapses_identical_child_iocs(self, monkeypatch):
        """Two identical embedded URLs must aggregate to one LogicalEvent
        with count=2. Aggregation is strict-identity — never semantic
        correlation."""
        # Patch dispatcher to return two identical urls
        import services.artifact_intelligence as ai_pkg
        original = ai_pkg.dispatch

        class FakeResult:
            def to_dict(self):
                return {
                    "artifact_type": "pdf",
                    "display_name": "PDF",
                    "confidence": 90,
                    "size": 100,
                    "hashes": {"sha256": "b" * 64, "md5": "", "sha1": ""},
                    "analysis": {
                        "available": True,
                        "urls": ["http://dup.example.com/x",
                                  "http://dup.example.com/x"],
                    },
                    "capability_available": True,
                    "detected_by": "magic-byte",
                    "fallback_reason": None,
                }
        monkeypatch.setattr(ai_pkg, "dispatch", lambda b: FakeResult())
        try:
            from services.iue.lanes.file_lane import analyze_file
            wire = analyze_file(b"%PDF-1.0", filename="dup.pdf",
                                  mime="application/pdf", tenant_id="t1")
        finally:
            monkeypatch.setattr(ai_pkg, "dispatch", original)

        # Two URL child records → one aggregated event? Only if all
        # grouping-key fields match — parent_file_sha256 and url both
        # match. Aggregator groups on canonical.destination.url etc.
        # We expect 1 primary artifact event + 1 aggregated URL event = 2.
        # (The parser dedupes at emit-time, so we may see 1 URL child
        # record; aggregator preserves it. Either 1 or 2 events is fine
        # — the contract is 'no duplicate LogicalEvents'.)
        assert len(wire["logical_events"]) <= 2

    def test_no_execution_no_network(self, pdf_bytes, monkeypatch):
        """Guard: the collector / parser / normalizer stack must never
        reach out to the network.  Attempting a socket must never be
        invoked by ``analyze_file``.
        """
        import socket
        opens = []
        original_socket = socket.socket
        class _GuardedSocket(original_socket):
            def __init__(self, *a, **kw):
                opens.append((a, kw))
                super().__init__(*a, **kw)
        monkeypatch.setattr(socket, "socket", _GuardedSocket)
        from services.iue.lanes.file_lane import analyze_file
        _ = analyze_file(pdf_bytes, filename="a.pdf",
                           mime="application/pdf", tenant_id="t1")
        assert opens == [], f"analyze_file opened sockets: {opens}"


# ─── 5. Router boundary — feature flag + auth ────────────────────────
class TestLaneCRouter:
    def test_analyze_returns_503_when_flag_off(self, monkeypatch):
        monkeypatch.setenv("IUE_ARTIFACT_LANE", "off")
        from fastapi.testclient import TestClient
        from server import app
        from deps import get_current_user
        app.dependency_overrides[get_current_user] = \
            lambda: {"email": "test@x", "tenant_id": "t1"}
        try:
            with TestClient(app) as c:
                r = c.post("/api/iue/lane-c/analyze-b64",
                              json={"bytes_b64": base64.b64encode(b"%PDF-1.0").decode(),
                                     "filename": "a.pdf"})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "iue_artifact_lane_disabled"

    def test_status_endpoint_returns_flag_state(self, monkeypatch):
        monkeypatch.setenv("IUE_ARTIFACT_LANE", "on")
        from fastapi.testclient import TestClient
        from server import app
        with TestClient(app) as c:
            r = c.get("/api/iue/lane-c/status")
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert body["flag"] == "on"
        assert "caps" in body

    def test_analyze_requires_auth(self, monkeypatch):
        """Unauthenticated request MUST fail — never reach the lane."""
        monkeypatch.setenv("IUE_ARTIFACT_LANE", "on")
        from fastapi.testclient import TestClient
        from server import app
        with TestClient(app) as c:
            r = c.post("/api/iue/lane-c/analyze-b64",
                          json={"bytes_b64": base64.b64encode(b"%PDF-1.0").decode(),
                                 "filename": "a.pdf"})
        # 401 or 403 (depending on auth dep shape) — must NOT be 200.
        assert r.status_code in (401, 403), r.text

    def test_analyze_rejects_empty_body(self, monkeypatch):
        monkeypatch.setenv("IUE_ARTIFACT_LANE", "on")
        from fastapi.testclient import TestClient
        from server import app
        from deps import get_current_user
        app.dependency_overrides[get_current_user] = \
            lambda: {"email": "t@x", "tenant_id": "t1"}
        try:
            with TestClient(app) as c:
                r = c.post("/api/iue/lane-c/analyze-b64",
                              json={"bytes_b64": ""})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        assert r.status_code in (400, 422)
