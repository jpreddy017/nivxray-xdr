"""Shared helpers used by multiple Plane-A codecs.

Owner-locked (Gate 2D-B3.1 · migration integrity):
    · Same input → same output as the legacy implementations in
      services/die/preprocessor/recursive_decoder.
    · No behavioural change during migration.
    · Static-only.  No execution.  No network.  No LLM.

These symbols were previously private inside recursive_decoder.py.
They move here so services/decoder/base/* becomes the single
authoritative location for codec logic — a hard requirement of the
B3 migration.  `recursive_decoder.py` continues to work via a
backward-compat import shim (legacy/reference wrapper only, no new
callers permitted).
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple


# ── @@RAWBYTES@@ sentinel ─────────────────────────────────────────
# Emitted by upstream codecs (e.g. from_base64_string) when a
# decoded blob is binary and cannot be represented as printable text.
# The GZIP / Zlib / shellcode / PE analyzers all look for this
# sentinel to recover the raw bytes.
_RAWBYTES_RE = re.compile(r"@@RAWBYTES@@([0-9a-fA-F]+)")


def _extract_rawbytes(text: str) -> Optional[Tuple[bytes, int, int]]:
    m = _RAWBYTES_RE.search(text or "")
    if not m:
        return None
    hex_str = m.group(1)
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return None
    return raw, m.start(), m.end()


# ── Printability floor ───────────────────────────────────────────
def _mostly_printable(s: str, threshold: float = 0.85) -> bool:
    if not s:
        return False
    total = len(s)
    ok = sum(1 for c in s
              if (32 <= ord(c) < 127) or ord(c) in (9, 10, 13))
    return (ok / total) >= threshold


# ── ASCII-embedded IOC extraction inside decoded byte payloads ───
# Used by the GZIP terminal-layer path when the innermost payload is
# raw shellcode (non-printable) that still carries the C2 config as
# ASCII substrings.
_IP_RE  = re.compile(rb"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])")
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
_DOM_RE = re.compile(rb"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,24}(?![A-Za-z0-9])")


def _shellcode_string_scan(raw: bytes) -> List[str]:
    """Extract ASCII-embedded C2 indicators from raw byte payloads
    (shellcode / packed configs)."""
    if not raw:
        return []
    findings: List[str] = []
    for ip in _IP_RE.findall(raw):
        try:
            s = ip.decode("ascii")
            parts = s.split(".")
            if all(0 <= int(p) <= 255 for p in parts) and s not in ("0.0.0.0", "127.0.0.1"):
                findings.append(f"ip:{s}")
        except (UnicodeDecodeError, ValueError):
            continue
    for u in _URL_RE.findall(raw):
        try:
            findings.append(f"url:{u.decode('ascii', 'ignore')}")
        except Exception:  # pragma: no cover
            pass
    for d in _DOM_RE.findall(raw):
        try:
            s = d.decode("ascii", "ignore").rstrip(".")
            if "." in s and len(s) >= 4 and not s.replace(".", "").isdigit():
                findings.append(f"domain:{s}")
        except Exception:  # pragma: no cover
            pass
    seen, out = set(), []
    for x in findings:
        if x not in seen:
            seen.add(x); out.append(x)
    return out


__all__ = [
    "_RAWBYTES_RE",
    "_extract_rawbytes",
    "_mostly_printable",
    "_IP_RE",
    "_URL_RE",
    "_DOM_RE",
    "_shellcode_string_scan",
]
