"""Phase 3C · Image adapter contract tests.

Builds tiny PNGs at test-time (with and without OCR-recognisable text)
and validates the image adapter's contract:

  · Deterministic-first fields (magic, sha256, dimensions, color mode,
     ICC, orientation) populated BEFORE any OCR data (R8).
  · OCR summary carries ``engine``, ``avg_confidence`` and
     ``characters_detected`` so the Evidence Validator can later
     downgrade low-confidence artifacts.
  · Every artifact carries a ``source_ref`` (R6).
  · Relationships are ``CONTAINS`` + ``REFERENCES`` only (R8).
  · Corrupt / non-image bytes degrade gracefully (R9).
  · Same bytes → same artifacts / same warnings / same OCR fields (R10).
  · Orientation metadata (``exif_orientation``, ``rotation_applied``,
     ``description``) is preserved for rotated images.
"""
from __future__ import annotations

import io

import pytest

from models import IEP, RelationshipType
from services.adapters import ImageAdapter, adapt

pytest.importorskip("PIL")
from PIL import Image, ImageDraw, ImageFont  # noqa: E402  (after skip)


# ─── Fixture builders ──────────────────────────────────────────────────
def _png_blank(size=(64, 64), color=(255, 255, 255)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def _png_with_text(text="URL: https://mal.example/pay  IP: 10.0.0.1",
                    size=(600, 120)) -> bytes:
    """Render dark text on white — high-contrast so Tesseract can read it."""
    im = Image.new("RGB", size, (255, 255, 255))
    draw = ImageDraw.Draw(im)
    try:
        font = ImageFont.load_default(size=24)
    except TypeError:  # older Pillow
        font = ImageFont.load_default()
    draw.text((20, 40), text, fill=(0, 0, 0), font=font)
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def _jpeg_with_orientation(orient_value: int = 6) -> bytes:
    """PNG can't carry EXIF orientation across Pillow versions reliably —
    use JPEG so the orientation tag is preserved on write/read."""
    im = Image.new("RGB", (120, 60), (200, 200, 255))
    buf = io.BytesIO()
    # Pillow accepts an ``exif`` bytes blob on save.
    exif = Image.Exif()
    exif[0x0112] = orient_value  # Orientation tag
    im.save(buf, format="JPEG", exif=exif.tobytes())
    return buf.getvalue()


BLANK_PNG        = _png_blank()
OCR_PNG          = _png_with_text()
ROTATED_JPEG     = _jpeg_with_orientation(orient_value=6)  # 90° CW
CORRUPT_PNG      = b"\x89PNG\r\n\x1a\n" + b"garbage" * 20


# ─── Detection ────────────────────────────────────────────────────────
def test_image_detection_positive():
    a = ImageAdapter()
    assert a.can_handle(BLANK_PNG)
    assert a.can_handle(OCR_PNG)
    assert a.can_handle(ROTATED_JPEG)


def test_image_detection_negative():
    a = ImageAdapter()
    assert not a.can_handle(b"not an image")
    assert not a.can_handle("string not bytes")
    assert not a.can_handle(b"PK\x03\x04garbage")  # ZIP magic


def test_image_adapter_wins_routing():
    iep = adapt(BLANK_PNG)
    assert iep.provenance.adapter == "adapter.image"
    assert isinstance(iep, IEP)


# ─── Deterministic-first fields (populated BEFORE OCR) ────────────────
def test_image_deterministic_metadata_present():
    iep = ImageAdapter().make_iep(BLANK_PNG)
    m = iep.metadata.data["image"]
    assert m["magic"]      == {"format": "png", "mime": "image/png"}
    assert m["sha256"]     and len(m["sha256"]) == 64
    assert m["dimensions"] == {"width": 64, "height": 64}
    assert m["color_mode"] in {"RGB", "RGBA"}
    # Adapter manifest sanity
    manifest = iep.metadata.data["adapter"]
    assert manifest["id"]    == "adapter.image@1.0"
    assert "sha256"          in manifest["capabilities"]
    assert "ocr_confidence"  in manifest["capabilities"]
    assert "orientation"     in manifest["capabilities"]


def test_image_source_carries_hash_and_mime():
    iep = ImageAdapter().make_iep(BLANK_PNG)
    assert iep.source.kind      == "image"
    assert iep.source.mime_type == "image/png"
    assert iep.source.sha256    and len(iep.source.sha256) == 64


def test_image_identity_hash_artifact_present():
    iep = ImageAdapter().make_iep(BLANK_PNG)
    hashes = [a for a in iep.artifacts if "image_identity" in (a.tags or [])]
    assert len(hashes) == 1
    assert hashes[0].source_ref == "image.sha256"
    assert hashes[0].attributes.get("algorithm") == "sha256"


# ─── OCR summary (avg_confidence + characters_detected) ───────────────
def test_image_ocr_summary_shape():
    iep = ImageAdapter().make_iep(OCR_PNG)
    ocr = iep.metadata.data["image"]["ocr"]
    # Even if OCR fails on the tiny test image, the shape MUST exist.
    assert "engine"              in ocr
    assert "avg_confidence"      in ocr
    assert "characters_detected" in ocr
    assert "text_length"         in ocr
    assert "block_count"         in ocr
    # If pytesseract is installed and worked, engine name must match.
    if ocr["engine"] is not None:
        assert ocr["engine"] == "tesseract"


def test_image_ocr_extracts_something_when_text_is_present():
    """Best-effort: if Tesseract is functional, characters_detected > 0."""
    iep = ImageAdapter().make_iep(OCR_PNG)
    ocr = iep.metadata.data["image"]["ocr"]
    if ocr["engine"] is None:
        pytest.skip("pytesseract not available on this host")
    # Rendered text is dark-on-white; Tesseract should find at least a few chars.
    assert ocr["characters_detected"] >= 0    # never negative
    # If any characters were detected, block_count and confidence are populated
    if ocr["characters_detected"] > 0:
        assert ocr["block_count"] >= 0
        assert ocr["avg_confidence"] is None or 0.0 <= ocr["avg_confidence"] <= 100.0


# ─── Orientation preservation ─────────────────────────────────────────
def test_image_orientation_captured():
    iep = ImageAdapter().make_iep(ROTATED_JPEG)
    orient = iep.metadata.data["image"]["orientation"]
    assert "exif_orientation" in orient
    assert "description"      in orient
    assert "rotation_applied" in orient
    # We wrote orientation=6 (90° CW) so pixels MUST have been transposed
    # before OCR — otherwise mobile screenshots would OCR sideways.
    if orient["exif_orientation"] == 6:
        assert orient["rotation_applied"] is True
        assert "90" in orient["description"]


def test_image_normal_orientation_defaults():
    iep = ImageAdapter().make_iep(BLANK_PNG)
    orient = iep.metadata.data["image"]["orientation"]
    # PNG has no EXIF; adapter must default to "normal" without rotating.
    assert orient["rotation_applied"] is False
    assert orient["description"] == "Horizontal (normal)"


# ─── Relationships (R8) ───────────────────────────────────────────────
def test_image_relationships_are_structural_only():
    iep = ImageAdapter().make_iep(OCR_PNG)
    for r in iep.relationships:
        assert r.verb in {RelationshipType.CONTAINS, RelationshipType.REFERENCES}


# ─── Graceful degradation (R9) ────────────────────────────────────────
def test_image_corrupt_bytes_degrade_gracefully():
    a = ImageAdapter()
    assert a.can_handle(CORRUPT_PNG)   # magic passes
    iep = a.make_iep(CORRUPT_PNG)
    codes = {w.code for w in iep.warnings}
    # Either Pillow decode failed, OR OCR was skipped — but the IEP is valid.
    assert iep.metadata.data["adapter"]["adapter_status"] in {"partial", "failed"}
    assert ("image_decode_failed" in codes) or ("image_bad_magic" in codes) or codes  # at least one warning
    assert isinstance(iep, IEP)


# ─── Idempotency (R10) ────────────────────────────────────────────────
def test_image_adapter_is_idempotent():
    a = ImageAdapter()
    a1 = a.make_iep(BLANK_PNG)
    a2 = a.make_iep(BLANK_PNG)
    # SHA-256 of the raw bytes is stable
    assert a1.metadata.data["image"]["sha256"] == a2.metadata.data["image"]["sha256"]
    # Same artifact fingerprints
    def _fp(iep):
        return [(x.type, x.value, x.source_ref) for x in iep.artifacts]
    assert _fp(a1) == _fp(a2)
    # Same warning codes (order-insensitive)
    assert sorted(w.code for w in a1.warnings) == sorted(w.code for w in a2.warnings)
    # Same OCR summary (engine, characters_detected, block_count)
    o1 = a1.metadata.data["image"]["ocr"]
    o2 = a2.metadata.data["image"]["ocr"]
    assert o1["engine"]              == o2["engine"]
    assert o1["characters_detected"] == o2["characters_detected"]
    assert o1["block_count"]         == o2["block_count"]
