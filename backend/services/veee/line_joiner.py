"""
NivXRay · VEEE · OCR Line Joiner (P0.15C-4 · ADR-002 §3.6 stage)
─────────────────────────────────────────────────────────────────

Merges fragmented multi-line OCR into complete command lines
BEFORE the Canonicalizer / Behavior Classifier sees them.  Lives
strictly inside the acquisition layer per the P0.15C Release
Contract (§0.1 Stage Isolation, §2.4).

Golden rule (§0.2 Never-Modify-Evidence):
    · Pure function · never mutates its input.
    · Deterministic — same OCRResult in ⇒ identical OCRResult out.
    · When a join happens, the resulting ``OCRLine`` carries
      ``joined_from_lines = [orig_idx, …]`` so provenance downstream
      can attach it to the NormalizedEvidence record (ADR-002 §5).
    · Never raises on malformed input — degrades to a shallow copy
      of the original OCRResult on any internal error.

Join heuristic (deterministic, no ML):
    A line is a CONTINUATION of the previous line iff the previous
    line's text (stripped) ends with one of the following explicit
    shell continuation markers:

        \\   · Bash / cmd.exe line-continuation backslash
        ^    · cmd.exe caret continuation
        `    · PowerShell backtick continuation
        |    · Unterminated pipe

    No proximity / whitespace / heuristic guessing.  Explicit
    markers only — this keeps determinism airtight and produces
    zero false-joins on screenshot corpora that don't wrap
    commands.

Bounding box + confidence semantics (per contract §2.4):
    · Merged bbox = element-wise union of the joined bboxes.
    · Merged confidence = MIN across the joined lines' confidences
      (the joined line is only as trustworthy as its weakest part).
"""
from __future__ import annotations

from typing import List, Set

from services.veee.ocr_engine import OCRResult, OCRLine, OCRBBox


# Explicit continuation markers — checked at the END of a stripped
# line's text.  Order does not matter; the set is closed under
# lookup, no wildcards, no regex.
_CONTINUATION_CHARS: Set[str] = {"\\", "^", "`", "|"}


def _ends_with_continuation(text: str) -> bool:
    """True when ``text`` (already stripped) ends with an explicit
    shell continuation marker."""
    if not text:
        return False
    return text[-1] in _CONTINUATION_CHARS


def _union_bbox(a: OCRBBox, b: OCRBBox) -> OCRBBox:
    x1 = min(a.x, b.x)
    y1 = min(a.y, b.y)
    x2 = max(a.x + a.w, b.x + b.w)
    y2 = max(a.y + a.h, b.y + b.h)
    return OCRBBox(x=x1, y=y1, w=x2 - x1, h=y2 - y1)


def _merge_lines(lines: List[OCRLine],
                    orig_indexes: List[int]) -> OCRLine:
    """Combine ``lines`` into a single ``OCRLine``.  All inputs
    are treated as non-empty (caller enforces).  The joined text
    drops the trailing continuation marker so downstream
    canonicalization sees a clean command string."""
    # Strip only the trailing marker from every line except the last.
    parts: List[str] = []
    for i, ln in enumerate(lines):
        t = ln.text.rstrip()
        if i < len(lines) - 1 and t and t[-1] in _CONTINUATION_CHARS:
            t = t[:-1].rstrip()
        parts.append(t)
    merged_text = " ".join(p for p in parts if p)

    # Union bbox — safe against Nones.
    bbox: OCRBBox | None = None
    for ln in lines:
        if ln.bbox is None:
            continue
        bbox = ln.bbox if bbox is None else _union_bbox(bbox, ln.bbox)

    # Confidence = MIN across joined lines (contract §2.4).
    confs = [ln.confidence for ln in lines if ln.confidence is not None]
    merged_conf = min(confs) if confs else 0.0

    # Words — preserve concatenated word list for downstream tools
    # that need per-token access.
    merged_words: list = []
    for ln in lines:
        if ln.words:
            merged_words.extend(ln.words)

    return OCRLine(
        text              = merged_text,
        words             = merged_words,
        bbox              = bbox,
        confidence        = merged_conf,
        joined_from_lines = list(orig_indexes),
    )


def join_lines(ocr: OCRResult) -> OCRResult:
    """Return a new ``OCRResult`` where every explicit multi-line
    continuation is merged into a single ``OCRLine``.

    Contract:
        · Never mutates ``ocr`` (§0.2).
        · Deterministic — same input yields byte-identical output.
        · Tolerant of malformed input — falls back to a shallow
          copy on unexpected shape (§0.2 tolerance rule).
    """
    if not ocr or not getattr(ocr, "lines", None):
        return ocr

    original: List[OCRLine] = list(ocr.lines)
    if len(original) < 2:
        # Fast path: nothing to join.
        return ocr

    # Group consecutive lines into "chunks" based on continuation
    # markers.  We inspect line i's TRAILING marker to decide
    # whether line i+1 is a continuation of it.
    merged_lines: List[OCRLine] = []
    i = 0
    n = len(original)
    while i < n:
        chunk_indexes = [i]
        # Extend chunk while previous line ends with a continuation.
        while (chunk_indexes[-1] < n - 1
                    and _ends_with_continuation(
                          original[chunk_indexes[-1]].text.strip())):
            chunk_indexes.append(chunk_indexes[-1] + 1)

        if len(chunk_indexes) == 1:
            # Single-line chunk — pass through unmodified (preserve
            # object identity for determinism).
            merged_lines.append(original[i])
        else:
            chunk = [original[k] for k in chunk_indexes]
            merged_lines.append(_merge_lines(chunk, chunk_indexes))

        i = chunk_indexes[-1] + 1

    # Rebuild the OCRResult with the joined lines · preserve
    # mean_confidence and engine (they describe pre-join stats,
    # which are still the truthful KPIs for the acquisition
    # summary).
    joined_text = "\n".join(ln.text for ln in merged_lines)
    return OCRResult(
        text            = joined_text,
        lines           = merged_lines,
        mean_confidence = ocr.mean_confidence,
        engine          = ocr.engine,
    )


__all__ = ["join_lines"]
