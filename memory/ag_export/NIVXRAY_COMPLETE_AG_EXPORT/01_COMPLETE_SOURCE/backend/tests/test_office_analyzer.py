"""Office OOXML Analyzer — Phase 3 · Cycle B · 2026-02."""
import hashlib
import io
import zipfile

import pytest

from services.artifact_intelligence import dispatch
from services.artifact_intelligence.analyzers.office import OfficeAnalyzer


def _make_docx(with_macro: bool = False, with_dde: bool = False,
               ext_url: str | None = None, ext_tpl: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        doc = "<w:document xmlns:w=\"http://\">"
        if with_dde:
            doc += "<w:fldSimple w:instr=\" DDEAUTO cmd.exe \" />"
        doc += "</w:document>"
        z.writestr("word/document.xml", doc)
        if with_macro:
            z.writestr(
                "word/vbaProject.bin",
                b"\x00Sub AutoOpen()\x00 Document_Open handler\x00 payload here",
            )
        if ext_tpl:
            z.writestr(
                "word/_rels/settings.xml.rels",
                f'<Relationships><Relationship Target="{ext_tpl}" TargetMode="External"/></Relationships>',
            )
        if ext_url:
            z.writestr(
                "word/_rels/document.xml.rels",
                f'<Relationships><Relationship Target="{ext_url}" TargetMode="External"/></Relationships>',
            )
        z.writestr(
            "docProps/core.xml",
            "<cp:coreProperties xmlns:dc=\"http://\" xmlns:cp=\"http://\">"
            "<dc:title>t</dc:title><dc:creator>c</dc:creator></cp:coreProperties>",
        )
    return buf.getvalue()


def test_analyzer_recognizes_docx_and_produces_findings():
    data = _make_docx(with_macro=True, with_dde=True, ext_url="https://evil/a", ext_tpl="https://evil/tpl.dotm")
    r = dispatch(data)
    assert r.artifact_type == "office"
    assert r.capability_available is True
    assert r.confidence == 99
    a = r.analysis
    assert a["overview"]["family"] == "docx"
    assert a["overview"]["has_macros"] is True
    assert a["overview"]["has_dde"] is True
    assert a["macros"]["triggers"] == ["AutoOpen", "Document_Open"]
    findings = a["findings"]
    codes = {f["code"] for f in findings}
    assert "vba_macros_present" in codes
    assert "macro_autoexec_trigger" in codes
    assert "dde_present" in codes
    assert "external_template" in codes
    # Highest severity finding must be sorted first.
    assert findings[0]["severity"] in ("critical", "high")


def test_analyzer_is_deterministic():
    data = _make_docx(with_macro=True, ext_url="https://a/b")
    r1 = dispatch(data)
    r2 = dispatch(data)
    assert r1.to_dict() == r2.to_dict()


def test_analyzer_gracefully_handles_plain_zip():
    # A non-OOXML ZIP should NOT be claimed by the Office analyzer.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("README", "just a plain zip, no OOXML markers")
    r = dispatch(buf.getvalue())
    # No PE, no PDF, and no OOXML — must be routed to unknown.
    assert r.artifact_type == "unknown"


def test_binary_artifact_routes_ooxml_via_recipe_planner():
    from services.recipe_planner import _detect_binary_artifact
    data = _make_docx(with_macro=True)
    ba = _detect_binary_artifact(data.decode("latin-1", errors="replace"), ["manual"])
    assert ba is not None
    assert ba.kind == "ZIP"                               # magic byte
    routed = ba.routed_analysis
    assert routed is not None
    assert routed["artifact_type"] == "office"
    assert routed["capability_available"] is True


def test_no_macros_no_findings():
    data = _make_docx(with_macro=False)
    r = dispatch(data)
    assert r.artifact_type == "office"
    assert r.analysis["macros"]["found"] is False
    assert r.analysis["overview"]["has_macros"] is False
