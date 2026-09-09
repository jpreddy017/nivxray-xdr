"""
NivXRay · VEEE · Image Classifier (P0.15B · ADR-002 §3.1 stage 1)
─────────────────────────────────────────────────────────────────

Decides whether an image is worth OCR'ing.  Deterministic, pure
Python — no ML models.  Uses conservative heuristics that map to
the "code-screenshot" signature vendors like Kaspersky, Talos,
Unit42, Mandiant, Volexity actually publish:

    · aspect ratio wider than a square (typical code block)
    · minimum pixel size (nothing tiny)
    · not TOO large (skip full-page infographics)
    · pixel-density heuristic — code screenshots are text-heavy,
      producing a specific mean/std distribution of luminance;
      diagrams / logos have flat backgrounds or many gradients.

The classifier NEVER emits Behaviors / MITRE / Recommendations —
its only output is a boolean ``is_code_screenshot`` with a
``reason`` explaining the decision so the acquisition summary
can show ``Skipped Logos: 18 · Skipped Charts: 6``.
"""
from __future__ import annotations

import io
from typing import Any, Dict


# Bounds derived from real Kaspersky Securelist / Talos code
# screenshots.  Anything outside is skipped.
_MIN_W, _MIN_H = 200,  40      # smaller than this → thumbnail / icon
_MAX_W, _MAX_H = 8000, 8000    # larger than this → infographic / poster
_ASPECT_MIN    = 1.2            # wider-than-tall (code lines) — logos are usually 1:1


def classify_image(image_bytes: bytes) -> Dict[str, Any]:
    """Return ``{is_code_screenshot: bool, reason: str, width, height,
    aspect, mean_luma, std_luma}``.

    Never raises — on any decode failure returns
    ``is_code_screenshot=False`` with ``reason="corrupt"``.
    """
    try:
        from PIL import Image
    except Exception:
        # PIL missing — fall back to conservative default (skip).
        return {"is_code_screenshot": False,
                    "reason":              "pillow_unavailable"}

    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
    except Exception:
        return {"is_code_screenshot": False, "reason": "corrupt"}

    w, h = img.size
    if w < _MIN_W or h < _MIN_H:
        return {"is_code_screenshot": False,
                    "reason": "below_min_size",
                    "width": w, "height": h}
    if w > _MAX_W or h > _MAX_H:
        return {"is_code_screenshot": False,
                    "reason": "above_max_size",
                    "width": w, "height": h}

    aspect = w / h if h else 0.0
    if aspect < _ASPECT_MIN:
        return {"is_code_screenshot": False,
                    "reason": "aspect_below_threshold",
                    "width": w, "height": h, "aspect": round(aspect, 2)}

    # Luminance stats — code screenshots have a bimodal distribution
    # (background bright OR dark, text near-opposite).  Diagrams /
    # gradients have a broader distribution.  We accept a wide band
    # so this heuristic never over-rejects; VEEE's downstream OCR
    # confidence check gives us a second filter.
    try:
        luma = img.convert("L")
        pixels = list(luma.getdata())
        n = len(pixels) or 1
        mean = sum(pixels) / n
        var = sum((p - mean) ** 2 for p in pixels) / n
        std = var ** 0.5
    except Exception:
        return {"is_code_screenshot": False, "reason": "luma_decode_failed"}

    # Flat solid colour (logo) has near-zero std.
    if std < 8.0:
        return {"is_code_screenshot": False,
                    "reason": "flat_luma_std",
                    "width": w, "height": h,
                    "mean_luma": round(mean, 1),
                    "std_luma":  round(std, 1)}

    return {
        "is_code_screenshot": True,
        "reason":             "heuristic_accepted",
        "width":              w,
        "height":             h,
        "aspect":             round(aspect, 2),
        "mean_luma":          round(mean, 1),
        "std_luma":           round(std, 1),
    }


__all__ = ["classify_image"]
