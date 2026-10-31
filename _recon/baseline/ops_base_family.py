"""NivXRay — Base-family decoders (Feb-2026 roadmap).

Adds first-class support for Base58, Base62, Base64URL, and Z85 alongside
the existing Base32/Base64/ASCII85 decoders. Registered into the shared
OPERATIONS registry via the same `op` decorator.

All decoders return `str`. Binary output that isn't clean UTF-8 falls back
to LATIN-1 (1:1 codepoint↔byte preservation) so the next chain stage sees
the raw bytes intact.
"""
from __future__ import annotations

import base64
import re
from typing import Optional

from operations import op


# ============================================================
# Base58 (Bitcoin / IPFS alphabet)
# ============================================================
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _decode_base58(s: str) -> bytes:
    """Bitcoin-style Base58 decoder. Raises ValueError on invalid input."""
    s = s.strip()
    if not s:
        raise ValueError("empty base58 input")
    n = 0
    for c in s:
        if c not in _B58_IDX:
            raise ValueError(f"invalid base58 char: {c!r}")
        n = n * 58 + _B58_IDX[c]
    # Preserve leading '1's as leading zero bytes (Bitcoin convention).
    leading = 0
    for c in s:
        if c == "1":
            leading += 1
        else:
            break
    h = hex(n)[2:]
    if len(h) % 2:
        h = "0" + h
    raw = bytes.fromhex(h) if h else b""
    return b"\x00" * leading + raw


@op("base58-decode", "Base58 Decode (Bitcoin)", "Cryptography",
    "Decode a Base58 (Bitcoin alphabet) string. Alphabet is "
    "'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' — "
    "no 0/O/I/l to avoid ambiguity.")
def _b58_decode(data: str) -> str:
    raw = _decode_base58(data)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ============================================================
# Base62 (Alphanumeric, no padding)
# ============================================================
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_IDX = {c: i for i, c in enumerate(_B62_ALPHABET)}


def _decode_base62(s: str) -> bytes:
    """Base62 decoder — no padding, no length constraint."""
    s = s.strip()
    if not s:
        raise ValueError("empty base62 input")
    n = 0
    for c in s:
        if c not in _B62_IDX:
            raise ValueError(f"invalid base62 char: {c!r}")
        n = n * 62 + _B62_IDX[c]
    if n == 0:
        return b"\x00"
    h = hex(n)[2:]
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h)


@op("base62-decode", "Base62 Decode", "Cryptography",
    "Decode a Base62 (0-9, A-Z, a-z) alphanumeric string. Commonly used "
    "in shortened URLs, JWT-like tokens, and Firebase-style identifiers.")
def _b62_decode(data: str) -> str:
    raw = _decode_base62(data)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ============================================================
# Base64URL (RFC 4648 §5 — URL-safe: '-' instead of '+', '_' instead of '/')
# ============================================================
@op("base64url-decode", "Base64URL Decode (RFC 4648 §5)", "Cryptography",
    "Decode Base64URL-encoded data. Uses URL-safe alphabet: '-' replaces "
    "'+', '_' replaces '/'. Commonly seen in JWTs, OAuth tokens, and web "
    "APIs that pack binary into URLs.")
def _b64url_decode(data: str) -> str:
    cleaned = re.sub(r"\s+", "", data)
    # Auto-pad if truncated (JWT often omits padding).
    padded = cleaned + "=" * (-len(cleaned) % 4)
    raw = base64.urlsafe_b64decode(padded)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ============================================================
# Z85 (ZeroMQ Base85 variant — RFC 32)
# ============================================================
_Z85_ALPHABET = (
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ".-:+=^!/*?&<>()[]{}@%$#"
)
_Z85_IDX = {c: i for i, c in enumerate(_Z85_ALPHABET)}


def _decode_z85(s: str) -> bytes:
    """Z85 decoder (RFC 32). Input length MUST be a multiple of 5."""
    s = s.strip()
    if len(s) % 5:
        raise ValueError(f"z85 input length must be multiple of 5, got {len(s)}")
    out = bytearray()
    for i in range(0, len(s), 5):
        n = 0
        for c in s[i:i + 5]:
            if c not in _Z85_IDX:
                raise ValueError(f"invalid z85 char: {c!r}")
            n = n * 85 + _Z85_IDX[c]
        out.extend(n.to_bytes(4, "big"))
    return bytes(out)


@op("z85-decode", "Z85 Decode (ZeroMQ Base85)", "Cryptography",
    "Decode Z85-encoded data (RFC 32 — ZeroMQ variant of Base85). "
    "Alphabet excludes shell-hostile characters (', \", `, |, ;, ,).")
def _z85_decode(data: str) -> str:
    raw = _decode_z85(data)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ============================================================
# Public helper: try a base-family decode without raising
# ============================================================
def try_decode(op_id: str, data: str) -> Optional[str]:
    """Attempt a decode; return None on any failure."""
    fn = {
        "base58-decode": _b58_decode,
        "base62-decode": _b62_decode,
        "base64url-decode": _b64url_decode,
        "z85-decode": _z85_decode,
    }.get(op_id)
    if fn is None:
        return None
    try:
        return fn(data)
    except Exception:
        return None
