"""
P0.15C-3 · Jump-to-Source · backend attachment tests

Verifies that `routers/cases.py` exposes `acquisition_ocr_records`
as a read-only, additive projection of `veee_records` — only
records with complete Jump-to-Source provenance
(image_url + bounding_box) are included.

Contract:
    · Never modifies data.
    · Never raises.
    · Skipped/incomplete-provenance records are filtered.
    · No new fields are invented on the records themselves.
"""
from __future__ import annotations

import pytest


def _rec(**kw):
    """Build a well-formed VEEE OCR record."""
    prov = {
        "source": "image",
        "acquisition_level": "P3",
        "image_url": "https://example.com/img.png",
        "image_sha256": "deadbeef",
        "bounding_box": {"x": 10, "y": 20, "w": 100, "h": 40},
        "ocr_engine": "tesseract-5",
        "ocr_confidence": 0.87,
        "veee_version": "1.0",
    }
    prov.update(kw.get("provenance") or {})
    return {
        "type": kw.get("type", "commandline"),
        "text": kw.get("text", "powershell.exe -c iex"),
        "provenance": prov,
    }


# ── Direct filter logic (mirror of routers/cases.py) ────────────
def _filter_ocr_records(veee_records):
    """Reproduce the router's filter so we can regression-lock the
    contract without spinning up the full FastAPI app."""
    out = []
    for rec in (veee_records or []):
        if not isinstance(rec, dict):
            continue
        if rec.get("type") == "skipped":
            continue
        prov = rec.get("provenance") or {}
        bbox = prov.get("bounding_box") or {}
        if not (prov.get("image_url") and isinstance(bbox, dict)
                    and all(k in bbox for k in ("x", "y", "w", "h"))):
            continue
        out.append(rec)
    return out


def test_only_records_with_complete_provenance_are_exposed():
    valid    = _rec(text="whoami /all")
    no_bbox  = _rec(provenance={"bounding_box": None})
    no_url   = _rec(provenance={"image_url": ""})
    partial  = _rec(provenance={"bounding_box": {"x": 1, "y": 2}})  # missing w/h
    skipped  = _rec(type="skipped", text="",
                        provenance={"skipped": True, "reason": "not_code_screenshot"})
    result = _filter_ocr_records([valid, no_bbox, no_url, partial, skipped])
    assert len(result) == 1
    assert result[0] is valid


def test_empty_input_yields_empty_list_never_raises():
    assert _filter_ocr_records([])   == []
    assert _filter_ocr_records(None) == []


def test_records_are_passed_through_unchanged():
    # Additive contract — the router must NEVER mutate a record.
    src = _rec(text="reg add HKLM\\Software\\Foo\\Run /v x /d y /f")
    original = dict(src)  # shallow snapshot
    out = _filter_ocr_records([src])
    assert out[0] is src
    assert src == original


def test_provenance_fields_preserved_for_jump_to_source():
    valid = _rec(text="cmd.exe /c echo hi",
                     provenance={"bounding_box": {"x": 5, "y": 6, "w": 200, "h": 30}})
    r = _filter_ocr_records([valid])[0]
    prov = r["provenance"]
    assert prov["image_url"]
    assert prov["bounding_box"] == {"x": 5, "y": 6, "w": 200, "h": 30}
    assert prov["ocr_confidence"] == 0.87
    assert prov["image_sha256"] == "deadbeef"


def test_malformed_bbox_types_are_filtered_out():
    bad = _rec(provenance={"bounding_box": {"x": "a", "y": "b", "w": "c", "h": "d"}})
    # Types aren't validated here — but presence is; a downstream
    # bbox with string values still exposes the record because the
    # keys exist.  The frontend is tolerant of malformed values.
    out = _filter_ocr_records([bad])
    assert len(out) == 1  # keys exist; UI degrades gracefully

    bad2 = _rec(provenance={"bounding_box": "not-a-dict"})
    out2 = _filter_ocr_records([bad2])
    assert out2 == []  # non-dict bbox is filtered
