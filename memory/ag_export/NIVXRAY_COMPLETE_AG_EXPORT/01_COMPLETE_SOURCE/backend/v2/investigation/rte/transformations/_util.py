"""Shared helpers for RTE transformation plugins.

Pure functions. No I/O. No mutation of the source Artifact — plugins
never modify the input; they only produce new content that the engine
wraps into a NEW artefact layer.
"""
from __future__ import annotations

import re
import string

_PRINTABLE = set(string.printable)


def looks_like_base64(text: str, min_len: int = 12) -> bool:
    """Cheap grammar check — does the text look like a plausible base64
    blob? Refuses very short strings so we don't decode incidental
    tokens (variable names, GUIDs) as base64."""
    t = text.strip().strip("'").strip('"')
    if len(t) < min_len:
        return False
    # Base64 alphabet + padding + optional whitespace between chunks.
    return bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", t)) and "=" != t[0]


def strip_quotes(text: str) -> str:
    """Strip a single balanced pair of surrounding quotes."""
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ('"', "'"):
        return t[1:-1]
    return t


def printable_ratio(text: str) -> float:
    """Fraction of characters that are printable ASCII (incl. whitespace)."""
    if not text:
        return 0.0
    good = sum(1 for c in text if c in _PRINTABLE)
    return good / len(text)


def bytes_to_text(raw: bytes) -> str | None:
    """Try strict decodes in the order Windows attackers most often
    use. Return ``None`` if nothing produced predominantly printable
    text — never return latin-1 garbage."""
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "ascii"):
        try:
            candidate = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if printable_ratio(candidate) >= 0.90:
            return candidate
    return None


__all__ = [
    "looks_like_base64",
    "strip_quotes",
    "printable_ratio",
    "bytes_to_text",
]
