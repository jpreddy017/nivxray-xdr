"""Shared helpers for Intent Rule plugins.

Deliberately small — rules are pure regex/keyword classifiers that
convert low-level syntax into analyst-facing intent. No I/O, no
mutation, no decoding.
"""
from __future__ import annotations

import re
from typing import Iterable

# Canonical URL / IP grammar used by every rule that needs to
# reference a remote source in its evidence. Kept intentionally
# conservative — we would rather MISS a URL than fabricate one.
_URL_RE = re.compile(
    r"(?i)\bhttps?://[a-z0-9\-._~%!$&'()*+,;=:@/?#\[\]]+",
)


def extract_urls(text: str) -> list[str]:
    """Return every http(s) URL found in ``text`` in first-match order."""
    return _URL_RE.findall(text or "")


def has_any(text: str, needles: Iterable[str]) -> str | None:
    """Return the first matching needle (case-insensitive substring)
    or ``None``. Used by rules that fire on a keyword set."""
    lower = (text or "").lower()
    for n in needles:
        if n.lower() in lower:
            return n
    return None


def match_any(text: str, patterns: Iterable[re.Pattern]) -> re.Match | None:
    """Return the first pattern that matches ``text``, or ``None``."""
    for p in patterns:
        m = p.search(text or "")
        if m:
            return m
    return None


__all__ = ["extract_urls", "has_any", "match_any"]
