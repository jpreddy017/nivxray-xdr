"""Plane-A codec · Transformations & Byte-array XOR loop.

Gate 2D-B3.1 · Family 3 (byte-array XOR loop) authoritative module.
Authoritative, zero-dependency implementation of PowerShell Base64 + single-byte XOR loop extraction.
Never executes shellcode. Deterministic, static-only, bounded.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional, Tuple

from ._shared import _mostly_printable, _shellcode_string_scan

# ── Deterministic patterns ─────────────────────────────────────────
# Base64 literal inside FromBase64String('...') or FromBase64String("...").
_B64_RE = re.compile(
    r"""FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)""",
    re.IGNORECASE | re.DOTALL,
)

# The XOR-loop signature. We accept both decimal keys and 0x-prefixed hex keys.
_XOR_LOOP_RE = re.compile(
    r"""[\$]\w+\s*\[\s*\$?\w+\s*\]\s*=\s*[\$]\w+\s*\[\s*\$?\w+\s*\]\s*
        -bxor\s+(0[xX][0-9a-fA-F]+|\d+)""",
    re.VERBOSE,
)

# Re-exports for recursive_decoder and legacy callers
_BYTE_ARRAY_XOR_LOOP_RE = _XOR_LOOP_RE
_shellcode_ascii_strings = _shellcode_string_scan


def _extract(text: str) -> Optional[Tuple[bytes, int]]:
    """Return (base64-decoded bytes, xor_key) if text contains both patterns."""
    if not text:
        return None
    m_b64 = _B64_RE.search(text)
    m_xor = _XOR_LOOP_RE.search(text)
    if not m_b64 or not m_xor:
        return None
    b64_blob = re.sub(r"\s+", "", m_b64.group(1))
    key_str = m_xor.group(1)
    try:
        key = int(key_str, 16) if key_str.lower().startswith("0x") else int(key_str)
    except ValueError:
        return None
    if not (0 <= key <= 0xFF):
        return None
    try:
        raw = base64.b64decode(b64_blob, validate=False)
    except Exception:
        return None
    if not raw:
        return None
    return raw, key


def decode_byte_array_xor_loop(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Extract Base64 buffer and XOR key, decode and apply single-byte XOR.
    
    Returns (decoded_text, meta_dict) on match, or None.
    """
    if not text:
        return None
    pair = _extract(text)
    if pair is None:
        return None
    raw, key = pair
    decoded = bytes(b ^ key for b in raw)
    if not decoded:
        return None

    # Check for printable text first
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            plaintext = decoded.decode(enc)
            if _mostly_printable(plaintext):
                return plaintext, {
                    "key": key,
                    "xor_key_hex": f"0x{key:02x}",
                    "encoding": enc,
                    "bytes_in": len(raw),
                    "bytes_out": len(decoded),
                }
        except UnicodeDecodeError:
            continue

    # Shellcode IOC check
    embedded = _shellcode_string_scan(decoded)
    if embedded and not (decoded[0:2] == b"\x1F\x8B" or (decoded[0] == 0x78 and decoded[1] in (0x01, 0x5E, 0x9C, 0xDA))):
        tag = f"[shellcode-payload: {len(decoded)} bytes · embedded_iocs=" + ", ".join(embedded) + "]"
        return tag, {
            "key": key,
            "xor_key_hex": f"0x{key:02x}",
            "encoding": "shellcode",
            "bytes_in": len(raw),
            "bytes_out": len(decoded),
            "embedded_iocs": embedded,
            "shellcode": True,
        }

    # Non-printable raw payload for downstream decompression
    return "@@RAWBYTES@@" + decoded.hex(), {
        "key": key,
        "xor_key_hex": f"0x{key:02x}",
        "encoding": "raw",
        "bytes_in": len(raw),
        "bytes_out": len(decoded),
    }


__all__ = [
    "_BYTE_ARRAY_XOR_LOOP_RE",
    "_XOR_LOOP_RE",
    "_shellcode_ascii_strings",
    "_extract",
    "decode_byte_array_xor_loop",
]
