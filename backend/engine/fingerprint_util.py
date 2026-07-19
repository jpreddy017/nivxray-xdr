"""Lightweight L0 fingerprint helper for Phase A.

A richer probe framework lands in Phase B (dedicated `/backend/fingerprint/`
package with pluggable probes). Today we compute the fingerprint inline so
the orchestrator has something to feed decoders' detect() methods.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .models import Fingerprint

_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
_WORD_RE = re.compile(r"[A-Za-z]{3,}")
_COMMON_EN = {
    "the", "and", "for", "not", "you", "are", "with", "this", "that", "have",
    "from", "will", "http", "https", "www", "com", "net", "org", "exe", "cmd",
    "powershell", "user", "system", "invoke", "expression", "download", "script",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _english_density(text: str) -> float:
    words = _WORD_RE.findall(text.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in _COMMON_EN)
    return min(1.0, hits / max(1, len(words)))


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    hits = sum(1 for c in text if ord(c) < 256 and ord(c) in _PRINTABLE)
    return hits / len(text)


def _wrapper_hint(text: str) -> str | None:
    t = text.lower()
    if any(k in t for k in ("powershell", "iex(", "invoke-expression", "frombase64string")):
        return "powershell"
    if re.search(r"\bcmd(\.exe)?\s+/[cq]", t) or "cmd /c" in t:
        return "cmd"
    if "<script" in t or "activexobject" in t:
        return "jscript"
    if "wmic" in t or "win32_process" in t:
        return "wmi"
    if "mshta" in t:
        return "mshta"
    if "hta:application" in t:
        return "hta"
    return None


def compute(payload: str) -> Fingerprint:
    """Cheap L0 fingerprint — good enough for detect() gating in Phase A."""
    raw_bytes = payload.encode("latin-1", errors="replace")
    entropy = _entropy(raw_bytes)
    printable = _printable_ratio(payload)
    english = _english_density(payload)
    return Fingerprint(
        input_len=len(payload),
        printable_ratio=printable,
        english_density=english,
        entropy=round(entropy, 3),
        is_binary=printable < 0.85,
        wrapper_type=_wrapper_hint(payload),
        encoding_candidates=[],
        notes=[],
    )
