"""Plane-A codec · Compression (GZIP, Zlib / Deflate).

Migrated from `services/die/preprocessor/recursive_decoder.py`
under Gate 2D-B3.1.  Byte-for-byte behavioural parity with the
legacy implementation is REQUIRED — verified against the
pre-migration snapshot.

Contract per codec (both codecs share this shape):
    fn(text: str) -> Optional[Tuple[str, Dict[str, Any]]]
        · Returns None if the payload does not contain this codec's
          magic bytes (via the @@RAWBYTES@@ sentinel).
        · On success returns (new_text, meta) where `new_text` is
          the input text with the sentinel replaced by decoded
          content and `meta` describes what was decoded.
        · Never executes anything.  Never touches the network.

Static-only:
    · No file I/O.
    · No process execution.
    · No LLM.
    · Bounded input via peel_recursively's max_bytes wrapper.
"""
from __future__ import annotations

import gzip
import zlib
from typing import Any, Dict, Optional, Tuple

from ._shared import _extract_rawbytes, _mostly_printable, _shellcode_string_scan


def decode_gzip_bytes(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """GZip inflate (magic 0x1F 0x8B).

    2026-02-04 · R28.7.5 · Partial-gzip recovery.  Truncated Sophos-
    shape payloads previously returned None here — the gzip stage
    silently gave up.  We now attempt a streaming
    ``zlib.decompressobj`` inflate with ``wbits=31`` (gzip header) so
    partial output can still be recovered and IOCs surfaced.  Never
    breaks well-formed streams — the standard ``gzip.decompress``
    path runs first and only falls back on failure.
    """
    hit = _extract_rawbytes(text)
    if not hit:
        return None
    raw, start, end = hit
    if len(raw) < 4 or raw[0] != 0x1F or raw[1] != 0x8B:
        return None
    inflated: Optional[bytes] = None
    inflation_mode = "clean"
    try:
        inflated = gzip.decompress(raw)
    except (OSError, EOFError, zlib.error):
        try:
            do = zlib.decompressobj(wbits=31)
            part = do.decompress(raw) + do.flush()
            if part:
                inflated = part
                inflation_mode = "partial"
        except (zlib.error, EOFError):
            return None
    if not inflated:
        return None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            plaintext = inflated.decode(enc)
            if _mostly_printable(plaintext):
                new_text = text[:start] + plaintext + text[end:]
                return new_text, {"encoding": enc,
                                    "bytes_in": len(raw),
                                    "bytes_out": len(inflated),
                                    "inflation": inflation_mode}
        except UnicodeDecodeError:
            continue
    # Terminal shellcode layer — extract embedded IOCs.
    iocs = _shellcode_string_scan(inflated)
    tag = (
        f"[shellcode-payload: {len(inflated)} bytes"
        + (f" · embedded_iocs=" + ", ".join(iocs) if iocs else "")
        + "]"
    )
    new_text = text[:start] + tag + text[end:]
    return new_text, {
        "encoding":         "shellcode",
        "bytes_in":         len(raw),
        "bytes_out":        len(inflated),
        "shellcode":        True,
        "embedded_iocs":    iocs,
        "inflation":        inflation_mode,
    }


def decode_zlib_bytes(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Zlib inflate (magic 0x78 followed by 0x01/0x5E/0x9C/0xDA).

    Partial-inflate recovery via `zlib.decompressobj()` — see
    `decode_gzip_bytes` rationale.  Reserved for Gate 2D-B3.1 · Family 2.
    """
    hit = _extract_rawbytes(text)
    if not hit:
        return None
    raw, start, end = hit
    if len(raw) < 2 or raw[0] != 0x78 or raw[1] not in (0x01, 0x5E, 0x9C, 0xDA):
        return None
    inflated: Optional[bytes] = None
    inflation_mode = "clean"
    try:
        inflated = zlib.decompress(raw)
    except zlib.error:
        try:
            do = zlib.decompressobj()   # wbits=15 (default zlib header)
            part = do.decompress(raw) + do.flush()
            if part:
                inflated = part
                inflation_mode = "partial"
        except zlib.error:
            return None
    if not inflated:
        return None
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            plaintext = inflated.decode(enc)
            if _mostly_printable(plaintext):
                new_text = text[:start] + plaintext + text[end:]
                return new_text, {"encoding": enc,
                                    "bytes_in": len(raw),
                                    "bytes_out": len(inflated),
                                    "inflation": inflation_mode}
        except UnicodeDecodeError:
            continue
    return None


__all__ = ["decode_gzip_bytes", "decode_zlib_bytes"]
