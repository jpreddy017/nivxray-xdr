"""
NivXRay · VEEE Stage · Image Discovery (P0.15C-1 · ADR-002)
────────────────────────────────────────────────────────────

Walks an HTML document and returns the deterministic list of
``<img>`` URLs worth handing to the OCR pipeline.

Single-responsibility per Stage Isolation Rule (§0.1):
    · pure function
    · deterministic output (sorted, deduped)
    · no OCR, no classification, no downloading
    · no side effects
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin


# Only accept image URLs on http(s).  Never file://, data:, etc.
_IMG_URL_RX = re.compile(
    r'<img[^>]+src=(?:"([^"]+)"|\'([^\']+)\')',
    re.IGNORECASE,
)


def discover_images(html: str, base_url: str = "") -> List[str]:
    """Return the deduped, ordered list of absolute image URLs.

    Order-preserving so re-runs produce byte-identical output
    (Deterministic Acquisition · §3.5).
    """
    if not html or not isinstance(html, str):
        return []
    seen: set = set()
    out:  List[str] = []
    for m in _IMG_URL_RX.finditer(html):
        raw = (m.group(1) or m.group(2) or "").strip()
        if not raw:
            continue
        # Skip inline / non-http schemes — VEEE is scoped to
        # network-fetchable code screenshots.
        if raw.startswith("data:") or raw.startswith("file:") or raw.startswith("//"):
            # Note · protocol-relative URLs `//host/…` skipped
            # deliberately because we can't guarantee scheme from
            # the article context in a deterministic way.
            continue
        # Resolve relative URLs.
        try:
            abs_url = urljoin(base_url, raw) if base_url else raw
        except Exception:
            continue
        if not (abs_url.startswith("http://") or abs_url.startswith("https://")):
            continue
        if abs_url in seen:
            continue
        seen.add(abs_url)
        out.append(abs_url)
    return out


__all__ = ["discover_images"]
