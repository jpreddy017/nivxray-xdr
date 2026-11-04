"""Artifact Intelligence Layer — Phase 3 · Cycle A · 2026-02.

Verifies the registry-based dispatcher wires the PE and PDF analyzers
correctly and gracefully degrades for unknown / capability-missing
payloads.
"""
import base64
import hashlib
import pytest

from services.artifact_intelligence import dispatch, registered_types


SAMPLE_PE = "/root/.venv/lib/python3.11/site-packages/pip/_vendor/distlib/t32.exe"


def _make_pdf() -> bytes:
    """Create a valid single-page PDF via pypdf (deterministic bytes)."""
    from io import BytesIO
    from pypdf import PdfWriter
    w = PdfWriter()
    w.add_blank_page(width=595, height=842)
    w.add_metadata({"/Title": "artifact-router-test", "/Producer": "nivx-test"})
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_registry_contains_pe_and_pdf():
    types = registered_types()
    ids = {t["artifact_type"] for t in types}
    assert "pe" in ids and "pdf" in ids


def test_dispatch_pe_routes_to_pe_analyzer():
    with open(SAMPLE_PE, "rb") as f:
        data = f.read()
    r = dispatch(data)
    assert r.artifact_type == "pe"
    assert r.capability_available is True
    assert r.confidence >= 85
    assert r.analysis.get("available") is True
    # Delegated to services.pe_analyzer — must carry same shape.
    assert "sections" in r.analysis
    assert "findings" in r.analysis
    assert r.hashes["md5"] == hashlib.md5(data).hexdigest()


def test_dispatch_pdf_routes_to_pdf_analyzer():
    data = _make_pdf()
    r = dispatch(data)
    assert r.artifact_type == "pdf"
    assert r.capability_available is True
    assert r.confidence >= 80
    assert r.analysis.get("available") is True
    assert r.analysis["overview"]["page_count"] == 1
    assert r.analysis["overview"]["producer"] == "nivx-test"


def test_dispatch_unknown_returns_unknown_artifact_type():
    r = dispatch(b"just some random text with no magic bytes anywhere here 12345678")
    assert r.artifact_type == "unknown"
    assert r.confidence == 0
    assert r.capability_available is False
    assert r.fallback_reason == "no_analyzer_claimed_the_payload"


def test_dispatch_empty_input():
    r = dispatch(b"")
    assert r.artifact_type == "unknown"
    assert r.fallback_reason == "input_too_small"


def test_dispatch_is_deterministic():
    with open(SAMPLE_PE, "rb") as f:
        data = f.read()
    r1 = dispatch(data)
    r2 = dispatch(data)
    assert r1.to_dict() == r2.to_dict()


def test_pe_analyzer_pretext_pretext_does_not_false_match():
    """A plain sentence starting with 'MZ' must not be labelled as PE."""
    r = dispatch(b"MZ is the CEO of Meta, and today the sky is blue. " * 4)
    # The PE plugin's magic_matcher applies a printable-ratio guard.
    assert r.artifact_type != "pe"


def test_binary_artifact_carries_routed_analysis():
    """When the IEDDE pipeline detects a PE, it must attach BOTH the legacy
    `pe_analysis` and the new `routed_analysis` fields."""
    from services.recipe_planner import _detect_binary_artifact
    with open(SAMPLE_PE, "rb") as f:
        data = f.read()
    ba = _detect_binary_artifact(data.decode("latin-1", errors="replace"), ["manual"])
    assert ba is not None
    assert ba.kind == "PE"
    assert isinstance(ba.pe_analysis, dict)
    assert isinstance(ba.routed_analysis, dict)
    assert ba.routed_analysis["artifact_type"] == "pe"
    assert ba.routed_analysis["capability_available"] is True
    # to_dict must be JSON-serializable and include both fields.
    d = ba.to_dict()
    assert "pe_analysis" in d
    assert "routed_analysis" in d
