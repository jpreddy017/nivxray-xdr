"""Plane-A codec · PowerShell ``-EncodedCommand`` (UTF-16LE base64).

Migrated from `services/die/preprocessor/recursive_decoder.py`
under Gate 2D-B3.1 · Family 7 (UTF-16LE).  Byte-for-byte
behavioural parity with the legacy implementation is REQUIRED.

This is the *only* UTF-16LE runtime path in the codebase — the
PowerShell CLI ``-encodedcommand`` flag mandates UTF-16LE base64.
Extracting UTF-16LE without also extracting its host codec would
leave the primary UTF-16LE dispatcher inside recursive_decoder,
which contradicts the B3 goal of a single authoritative Plane-A
runtime.

Contract:
    fn(text: str) -> Optional[Tuple[str, Dict[str, Any]]]

Static-only.  No execution.  No network.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, Optional, Tuple

from ._shared import _mostly_printable


# --- 1. PowerShell -EncodedCommand (base64 → UTF-16LE) ────────────
_ENC_CMD_RE = re.compile(
    r"""
    (?ix)
    (?:^|\s|['"`])
    (?:powershell(?:_ise)?(?:\.exe)?|pwsh(?:\.exe)?)
    (?:\s+\S+)*?
    (?:\s+-(?:e|en|enc|encode|encoded|encodedcommand|ec))\b
    \s*(?P<b64>[A-Za-z0-9+/]{16,}={0,2})
    """,
    re.VERBOSE,
)


def _looks_like_powershell(text: str) -> bool:
    """Cheap PowerShell-signature detector.

    Used as a fallback acceptance gate on the ``-encodedcommand``
    utf-16-le decode when the ASCII-strict ``_mostly_printable``
    check rejects a partially-garbled tail.  PowerShell has very
    distinctive tokens that ASCII-decodable garbage or binary rarely
    produces together, so requiring ≥ 2 of them is a reliable
    positive signal without opening the door to false accepts.
    """
    if not text:
        return False
    hay = text[:4096]
    markers = (
        "New-Object", "Invoke-Expression", "IEX", "[Convert]::",
        "FromBase64String", "GzipStream", "MemoryStream", "StreamReader",
        "IO.Compression", "System.Text.Encoding", "powershell",
        "-EncodedCommand", "$s=", "$c=", "$x=", "$h=", "-bxor",
    )
    lower = hay.lower()
    hits = sum(1 for m in markers if m.lower() in lower)
    return hits >= 2 and "$" in hay


def _utf16le_realign(raw: bytes) -> bytes:
    """Heal a utf-16-le byte stream that has a mid-payload alignment
    shift (common in real-world Windows PowerShell ``-encodedcommand``
    payloads when a stager mishandles wide-char boundaries).

    Well-formed utf-16-le ASCII PowerShell has ``raw[i] = 0x00`` at
    every ODD byte index.  We walk the bytes and, at the FIRST
    index where that invariant breaks by a stray non-zero, drop
    that single byte and re-anchor.  Applied at most once — after
    that we trust the decoder's ``errors='replace'`` to handle any
    remaining slop cheaply.

    Returns the healed (possibly shorter) byte string ready for
    ``.decode('utf-16-le')``.  If no alignment shift is detected,
    returns ``raw`` unchanged (aside from trimming a trailing odd
    byte so the decoder never trips on truncated data).
    """
    n = len(raw)
    if n < 4:
        return raw
    for i in range(3, min(n, 65536), 2):
        if raw[i] != 0 and raw[i - 2] == 0:
            healed = raw[: i - 1] + raw[i:]
            if len(healed) % 2:
                healed = healed[:-1]
            return healed
    return raw if (n % 2 == 0) else raw[:-1]


def decode_ps_encoded_command(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """PowerShell ``-EncodedCommand`` → UTF-16LE base64 decode.

    Fix history:
      2026-02-14 · user-reported "Notdecoded" class — real-world
      Empire/Metasploit stagers concatenating strings without
      wide-char boundary discipline caused a mid-stream alignment
      shift the strict ASCII gate rejected.  We now heal the shift
      via ``_utf16le_realign`` and accept a decode when the
      recovered text has ≥ 2 strong PowerShell markers.
    """
    m = _ENC_CMD_RE.search(text or "")
    if not m:
        return None
    b64 = m.group("b64")
    padded = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    healed_utf16 = _utf16le_realign(raw)
    for enc, source_bytes in (
        ("utf-16-le", healed_utf16),
        ("utf-16-le", raw),
        ("utf-8",     raw),
        ("latin-1",   raw),
    ):
        try:
            decoded = source_bytes.decode(enc, errors="replace")
        except UnicodeDecodeError:
            continue
        if not decoded:
            continue
        if _mostly_printable(decoded) or _looks_like_powershell(decoded):
            return decoded, {"encoding": enc, "b64_len": len(padded),
                              "healed": source_bytes is healed_utf16
                                          and healed_utf16 is not raw}
    return None


__all__ = [
    "decode_ps_encoded_command",
    "_utf16le_realign",
    "_looks_like_powershell",
    "_ENC_CMD_RE",
]
