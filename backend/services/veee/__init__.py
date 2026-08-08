"""
NivXRay · Visual Evidence Extraction Engine (VEEE) · P0.15B · ADR-002
────────────────────────────────────────────────────────────────────

Isolated capability that converts image bytes into
``NormalizedEvidence`` records.  It NEVER emits Behaviors, MITRE
tids, or Recommendations.  Semantic interpretation happens
downstream via the Evidence Canonicalizer + Behavior Classifier.

Public entry point
------------------
    >>> from services.veee import extract_from_image, extract_from_url
    >>> records = extract_from_image(png_bytes, image_url=…)

Feature flag
------------
``NVX_VEEE_ENABLED`` — when unset or ``0`` VEEE is a no-op.  The
Workspace continues to behave exactly as it did before P0.15B.

Provenance
----------
Every ``NormalizedEvidence`` record carries the P1-P4 provenance
level defined in ADR-002 §5.  VEEE emits P3 (OCR).
"""
from __future__ import annotations

import os
from typing  import Any, Dict, List, Optional

from services.veee.image_classifier import classify_image
from services.veee.ocr_engine       import ocr_image, OCRResult
from services.veee.evidence_extractor import extract_evidence


VEEE_VERSION = "1.0"


def is_enabled() -> bool:
    """Feature flag · Workspace continues to behave exactly as it
    did before P0.15B when this returns False.  ADR-002 §9."""
    val = os.environ.get("NVX_VEEE_ENABLED", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def extract_from_image(image_bytes: bytes,
                          image_url: str = "",
                          page: Optional[int] = None,
                          ) -> List[Dict[str, Any]]:
    """Convert one image into 0..N ``NormalizedEvidence`` records.

    Never raises. On any internal failure returns a single
    ``skipped`` provenance record so the acquisition summary can
    account for it (ADR-002 §6 golden rule).
    """
    if not is_enabled():
        return []
    if not image_bytes:
        return [_skipped_record(image_url, "empty_bytes")]

    # 1. Image classifier — decide whether to invest OCR cycles.
    cls = classify_image(image_bytes)
    if not cls.get("is_code_screenshot"):
        return [_skipped_record(image_url,
                                     cls.get("reason") or "not_code_screenshot",
                                     page=page, extra=cls)]

    # 2. OCR (deterministic, offline · Tesseract 5).
    ocr = ocr_image(image_bytes)
    if not ocr.text:
        return [_skipped_record(image_url,
                                     "ocr_low_confidence",
                                     page=page,
                                     extra={"mean_conf": ocr.mean_confidence})]

    # 3. Evidence extractor — group tokens into lines / IOCs.
    return extract_evidence(ocr, image_url=image_url, page=page)


def extract_from_url(image_url: str,
                        timeout: float = 5.0,
                        page: Optional[int] = None,
                        ) -> List[Dict[str, Any]]:
    """Fetch ``image_url`` and pipe through ``extract_from_image``.
    Fetch failures produce a ``skipped`` provenance record — never
    raise (ADR-002 §6)."""
    if not is_enabled():
        return []
    if not image_url:
        return []
    try:
        import urllib.request
        req = urllib.request.Request(image_url, headers={
            "User-Agent": "NivXRay/1.0 (+veee)",
        })
        image_bytes = urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as e:
        return [_skipped_record(image_url, "fetch_failed",
                                     page=page,
                                     extra={"error": type(e).__name__})]
    return extract_from_image(image_bytes, image_url=image_url, page=page)


# ══════════════════════════════════════════════════════════════════
# Provenance helpers
# ══════════════════════════════════════════════════════════════════
def _skipped_record(image_url: str,
                       reason:    str,
                       page:      Optional[int] = None,
                       extra:     Optional[Dict[str, Any]] = None,
                       ) -> Dict[str, Any]:
    """Deterministic skipped-provenance record.  Never carries text
    — the acquisition-summary panel reads only ``provenance.*``."""
    prov: Dict[str, Any] = {
        "source":               "image",
        "acquisition_level":    "P3",
        "image_url":            image_url or None,
        "skipped":              True,
        "reason":               reason,
        "ocr_engine":           None,
        "veee_version":         VEEE_VERSION,
    }
    if page is not None:
        prov["page"] = page
    if extra:
        for k, v in extra.items():
            prov.setdefault(k, v)
    return {
        "type":       "skipped",
        "text":       "",
        "provenance": prov,
    }


__all__ = [
    "extract_from_image",
    "extract_from_url",
    "is_enabled",
    "VEEE_VERSION",
]
