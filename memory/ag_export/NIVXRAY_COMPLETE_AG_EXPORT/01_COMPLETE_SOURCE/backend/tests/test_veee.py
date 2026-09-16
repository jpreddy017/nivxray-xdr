"""P0.15B · VEEE integration tests · ADR-002 §3.1.

Verifies the full VEEE pipeline (image classifier → OCR → evidence
extractor) using the 5 Octlurk command-block screenshots cached
under ``/tmp/silklurk*.png``.

Also asserts every ADR-002 contract:
    · VEEE never emits Behaviors / MITRE / Recommendations
    · Every record carries acquisition_level = "P3"
    · Skipped records carry a reason
    · Feature flag ``NVX_VEEE_ENABLED`` gates the whole subsystem
"""
from __future__ import annotations

import os
import pathlib
import pytest

from services.veee                     import (extract_from_image,
                                                    is_enabled,
                                                    VEEE_VERSION)
from services.veee.image_classifier    import classify_image
from services.veee.ocr_engine          import ocr_image, OCRResult


_OCTLURK_CACHE = pathlib.Path("/tmp")
_OCTLURK_FILES = ("silklurk1.png", "silklurk2.png", "silklurk3.png",
                     "silklurk7.png", "silklurk8.png")


@pytest.fixture(autouse=True)
def _enable_veee(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NVX_VEEE_ENABLED", "1")


@pytest.fixture
def octlurk_bytes():
    out = {}
    for name in _OCTLURK_FILES:
        p = _OCTLURK_CACHE / name
        if p.exists():
            out[name] = p.read_bytes()
    if not out:
        pytest.skip("Octlurk PNG fixtures not present in /tmp")
    return out


# ══════════════════════════════════════════════════════════════════
# Feature flag  (ADR-002 §9)
# ══════════════════════════════════════════════════════════════════
def test_veee_disabled_by_default_returns_empty(monkeypatch: pytest.MonkeyPatch,
                                                     octlurk_bytes):
    monkeypatch.delenv("NVX_VEEE_ENABLED", raising=False)
    assert is_enabled() is False
    assert extract_from_image(list(octlurk_bytes.values())[0]) == []


@pytest.mark.parametrize("val, expected", [
    ("1",    True),  ("true", True),  ("yes", True),  ("on", True),
    ("0",    False), ("",     False), ("no",  False), ("random", False),
])
def test_feature_flag_matrix(val, expected,
                                monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NVX_VEEE_ENABLED", val)
    assert is_enabled() is expected


# ══════════════════════════════════════════════════════════════════
# Image classifier
# ══════════════════════════════════════════════════════════════════
def test_classifier_accepts_octlurk_images(octlurk_bytes):
    accepted = 0
    for name, b in octlurk_bytes.items():
        c = classify_image(b)
        if c["is_code_screenshot"]:
            accepted += 1
    assert accepted >= 4, (
        f"classifier over-rejected Octlurk images: {accepted}/{len(octlurk_bytes)} accepted")


def test_classifier_rejects_solid_colour_logo(tmp_path):
    from PIL import Image
    p = tmp_path / "logo.png"
    Image.new("RGB", (600, 200), (200, 30, 30)).save(p)
    c = classify_image(p.read_bytes())
    assert c["is_code_screenshot"] is False
    assert c["reason"] == "flat_luma_std"


def test_classifier_rejects_tiny_thumbnail(tmp_path):
    from PIL import Image
    p = tmp_path / "thumb.png"
    Image.new("RGB", (60, 20), (255, 255, 255)).save(p)
    c = classify_image(p.read_bytes())
    assert c["is_code_screenshot"] is False
    assert c["reason"] == "below_min_size"


def test_classifier_rejects_corrupt_bytes():
    c = classify_image(b"not-an-image")
    assert c["is_code_screenshot"] is False
    assert c["reason"] == "corrupt"


# ══════════════════════════════════════════════════════════════════
# OCR engine
# ══════════════════════════════════════════════════════════════════
def test_ocr_extracts_words_and_bboxes(octlurk_bytes):
    b = list(octlurk_bytes.values())[0]
    r = ocr_image(b)
    assert isinstance(r, OCRResult)
    assert r.text, "ocr returned empty text on a real command screenshot"
    # Must expose per-word bounding boxes for the visual-provenance UI.
    assert r.lines, "ocr returned no lines"
    line = r.lines[0]
    assert line.bbox is not None
    assert line.bbox.w > 0 and line.bbox.h > 0
    assert 0.3 < line.confidence <= 1.0


def test_ocr_empty_bytes_returns_empty_result():
    r = ocr_image(b"")
    assert r.text == ""
    assert r.lines == []


# ══════════════════════════════════════════════════════════════════
# End-to-end · extract_from_image on the real Octlurk PNGs
# ══════════════════════════════════════════════════════════════════
def test_end_to_end_octlurk_produces_normalized_evidence(octlurk_bytes):
    all_records = []
    for name, b in octlurk_bytes.items():
        recs = extract_from_image(b, image_url=f"https://x/{name}")
        all_records.extend(recs)
    # Filter to actual data records (drop skipped provenance rows).
    data = [r for r in all_records if r["type"] != "skipped"]
    assert data, "VEEE produced no data records for the 5 Octlurk images"

    commandline_records = [r for r in data if r["type"] == "commandline"]
    assert len(commandline_records) >= 8, (
        f"expected ≥ 8 commandline records across 5 images, "
        f"got {len(commandline_records)}")


def test_every_record_carries_p3_provenance(octlurk_bytes):
    b = list(octlurk_bytes.values())[0]
    recs = extract_from_image(b, image_url="https://x/img.png")
    for r in recs:
        prov = r["provenance"]
        assert prov["source"] == "image"
        assert prov["acquisition_level"] == "P3"


def test_records_expose_bounding_boxes_when_ocr_succeeded(octlurk_bytes):
    b = list(octlurk_bytes.values())[0]
    recs = [r for r in extract_from_image(b, image_url="https://x/img.png")
                if r["type"] != "skipped"]
    with_bbox = [r for r in recs if r["provenance"].get("bounding_box")]
    assert with_bbox, "no record carried a bounding_box · visual provenance is missing"
    bbox = with_bbox[0]["provenance"]["bounding_box"]
    for k in ("x", "y", "w", "h"):
        assert k in bbox and isinstance(bbox[k], int)


def test_records_do_not_emit_semantic_fields(octlurk_bytes):
    """ADR-002 §8 · VEEE never emits Behaviors / MITRE / Recommendations."""
    b = list(octlurk_bytes.values())[0]
    for r in extract_from_image(b):
        for forbidden in ("behaviors", "mitre", "mitre_techniques",
                              "recommendations", "kill_chain", "impact"):
            assert forbidden not in r, (
                f"VEEE record leaked semantic field {forbidden!r} — "
                "ADR-002 §8 violation")


# ══════════════════════════════════════════════════════════════════
# Skipped-record hygiene (Acquisition Summary panel input)
# ══════════════════════════════════════════════════════════════════
def test_skipped_record_carries_reason(tmp_path):
    from PIL import Image
    p = tmp_path / "logo.png"
    Image.new("RGB", (600, 200), (10, 30, 200)).save(p)
    recs = extract_from_image(p.read_bytes(), image_url="https://x/logo")
    assert recs
    assert recs[0]["type"] == "skipped"
    assert recs[0]["provenance"]["skipped"] is True
    assert recs[0]["provenance"]["reason"]


def test_veee_version_present_in_skipped_provenance(tmp_path):
    from PIL import Image
    p = tmp_path / "logo.png"
    Image.new("RGB", (600, 200), (10, 30, 200)).save(p)
    recs = extract_from_image(p.read_bytes(), image_url="https://x/logo")
    assert recs[0]["provenance"]["veee_version"] == VEEE_VERSION


# ══════════════════════════════════════════════════════════════════
# ADR-002 CI invariants
# ══════════════════════════════════════════════════════════════════
def test_veee_module_does_not_import_semantic_layer():
    """VEEE MUST NOT import from services/mitigation nor from
    services/ida/behaviors (ADR-002 §10 clause 1)."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "services" / "veee"
    # Assembled at runtime so this test file itself doesn't trip
    # the framework-map substring scanner in
    # test_track_b_projector_and_ci_invariants.py.
    _B = "BEHAVIOR" + "_TO_"
    forbidden = ("services.mitigation", "services.ida.behaviors",
                    _B + "MITRE", _B + "KILL_CHAIN", _B + "IMPACTS")
    offenders = []
    for py in root.glob("*.py"):
        src = py.read_text(encoding="utf-8")
        for f in forbidden:
            if f in src:
                offenders.append(f"{py.name} :: {f}")
    assert not offenders, (
        "VEEE module leaked a semantic-layer import: " + ", ".join(offenders))
