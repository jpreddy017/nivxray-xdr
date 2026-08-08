"""
NivXRay · VEEE · OCR Engine (P0.15B · ADR-002 §3.1 stage 2)
────────────────────────────────────────────────────────────

Deterministic, offline OCR wrapper.  Uses Tesseract 5 via
``--tsv`` output so per-word bounding boxes and per-word
confidence scores are preserved — required for the visual
provenance UI (P0.15C).

The engine is behind a ``VEEEOCRAdapter`` interface so future
OCR providers can be registered without touching the extractor.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib     import Path
from typing      import List, Optional


OCR_ENGINE_ID = "tesseract-5"


@dataclass
class OCRWord:
    text:       str
    confidence: float          # 0.0 - 1.0
    bbox:       "OCRBBox"


@dataclass
class OCRBBox:
    x:  int
    y:  int
    w:  int
    h:  int


@dataclass
class OCRLine:
    text:       str
    words:      List[OCRWord]  = field(default_factory=list)
    bbox:       Optional[OCRBBox] = None
    confidence: float          = 0.0


@dataclass
class OCRResult:
    text:            str
    lines:           List[OCRLine] = field(default_factory=list)
    mean_confidence: float = 0.0
    engine:          str   = OCR_ENGINE_ID


# ══════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════
def ocr_image(image_bytes: bytes,
                 psm:       int  = 6,
                 timeout:   float = 8.0,
                 ) -> OCRResult:
    """Run Tesseract 5 on ``image_bytes`` and return an
    ``OCRResult`` with per-word bboxes.

    Never raises — on tesseract missing / crash / low-confidence
    returns an empty ``OCRResult`` with the reason surfaceable via
    ``mean_confidence = 0.0``.
    """
    if not image_bytes:
        return OCRResult(text="")
    if not _tesseract_available():
        return OCRResult(text="", engine="unavailable")

    with tempfile.TemporaryDirectory() as tmp:
        img_path = Path(tmp) / "input.png"
        img_path.write_bytes(image_bytes)
        try:
            proc = subprocess.run(
                ["tesseract", str(img_path), "-",
                    "-l", "eng",
                    "--psm", str(psm),
                    "--dpi", "150",
                    "-c", "preserve_interword_spaces=1",
                    "tsv"],
                capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return OCRResult(text="", engine="unavailable")

    if proc.returncode != 0:
        return OCRResult(text="", engine=OCR_ENGINE_ID)

    return _parse_tsv(proc.stdout)


# ══════════════════════════════════════════════════════════════════
# Internals
# ══════════════════════════════════════════════════════════════════
_TESSERACT_OK: Optional[bool] = None


def _tesseract_available() -> bool:
    """Cached check — probes ``tesseract --version`` once."""
    global _TESSERACT_OK
    if _TESSERACT_OK is None:
        try:
            r = subprocess.run(["tesseract", "--version"],
                                    capture_output=True, timeout=3)
            _TESSERACT_OK = (r.returncode == 0)
        except Exception:
            _TESSERACT_OK = False
    return _TESSERACT_OK


def _parse_tsv(tsv: str) -> OCRResult:
    """Parse Tesseract TSV output → grouped OCRResult.

    TSV columns (Tesseract 5):
        level page_num block_num par_num line_num word_num
        left top width height conf text
    """
    if not tsv:
        return OCRResult(text="")
    header, *rows = tsv.splitlines()
    if not header or "conf" not in header.lower():
        return OCRResult(text="")

    # Group tokens by (block, par, line) — that's Tesseract's own
    # notion of a "line" and preserves logical command lines.
    line_map: dict = {}
    for row in rows:
        parts = row.split("\t")
        if len(parts) < 12:
            continue
        try:
            level   = int(parts[0])
            block   = int(parts[2])
            par     = int(parts[3])
            line_n  = int(parts[4])
            left    = int(parts[6]);  top   = int(parts[7])
            width   = int(parts[8]);  height = int(parts[9])
            conf    = float(parts[10])
        except Exception:
            continue
        # Level 5 = word · lower levels are structural aggregations.
        if level != 5:
            continue
        text = parts[11] if len(parts) >= 12 else ""
        if not text.strip():
            continue
        # Discard extremely low-confidence junk — Tesseract emits -1
        # for unrecognised tokens.  Keep tokens ≥ 30 % confidence.
        if conf < 30.0:
            continue
        key = (block, par, line_n)
        line_map.setdefault(key, []).append(OCRWord(
            text       = text,
            confidence = conf / 100.0,
            bbox       = OCRBBox(x=left, y=top, w=width, h=height),
        ))

    lines: List[OCRLine] = []
    all_words: List[OCRWord] = []
    for key in sorted(line_map.keys()):
        words = line_map[key]
        if not words:
            continue
        line_text = " ".join(w.text for w in words)
        # Union bounding box across the line's words.
        x1 = min(w.bbox.x for w in words)
        y1 = min(w.bbox.y for w in words)
        x2 = max(w.bbox.x + w.bbox.w for w in words)
        y2 = max(w.bbox.y + w.bbox.h for w in words)
        line_conf = sum(w.confidence for w in words) / len(words)
        lines.append(OCRLine(
            text       = line_text,
            words      = words,
            bbox       = OCRBBox(x=x1, y=y1, w=x2 - x1, h=y2 - y1),
            confidence = line_conf,
        ))
        all_words.extend(words)

    text = "\n".join(line.text for line in lines)
    mean_conf = (sum(w.confidence for w in all_words) / len(all_words)
                     if all_words else 0.0)
    return OCRResult(
        text            = text,
        lines           = lines,
        mean_confidence = mean_conf,
        engine          = OCR_ENGINE_ID,
    )


__all__ = [
    "ocr_image",
    "OCRResult", "OCRLine", "OCRWord", "OCRBBox",
    "OCR_ENGINE_ID",
]
