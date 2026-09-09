"""UTF-16LE / UTF-16BE decoder plugin.

Motivation
----------
PowerShell's `-EncodedCommand` accepts Base64-encoded UTF-16LE bytes. After
Base64 decode we get a byte stream like:

    b"I\\x00E\\x00X\\x00 \\x00(\\x00N\\x00e\\x00w\\x00..."

The orchestrator receives this as a Latin-1 string (since base64 marks it
`output_is_binary=True`), which then looks like `I\\x00E\\x00X\\x00...` —
gibberish to every downstream decoder. This plugin recognises the pattern
"printable ASCII byte alternating with null byte" and re-decodes as UTF-16
so the analyst gets the actual command line.

Also handles BOM-prefixed UTF-16 (`\\xff\\xfe` LE / `\\xfe\\xff` BE) and
plain UTF-16BE (nulls at even positions).
"""
from __future__ import annotations

from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


def _as_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


def _detect_variant(b: bytes) -> str:
    """Return 'utf-16-le', 'utf-16-be' or '' if payload isn't UTF-16."""
    if len(b) < 8 or len(b) % 2 != 0:
        return ""
    # BOM
    if b[:2] == b"\xff\xfe":
        return "utf-16-le-bom"
    if b[:2] == b"\xfe\xff":
        return "utf-16-be-bom"
    # Statistical: fraction of null bytes at odd positions (LE) vs even (BE).
    n = min(len(b), 4096)
    odd_nulls = sum(1 for i in range(1, n, 2) if b[i] == 0)
    even_nulls = sum(1 for i in range(0, n, 2) if b[i] == 0)
    odd_ratio = odd_nulls / max(1, n // 2)
    even_ratio = even_nulls / max(1, n // 2)
    # UTF-16LE ASCII text: every odd byte is 0, every even byte is printable.
    if odd_ratio >= 0.85 and even_ratio <= 0.15:
        return "utf-16-le"
    if even_ratio >= 0.85 and odd_ratio <= 0.15:
        return "utf-16-be"
    return ""


class Utf16Decoder(BaseDecoder):
    id = "utf16-decode"
    name = "UTF-16 Decode"
    category = "encoding"
    cost = 1
    tags = ("utf-16", "unicode", "text-to-text")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload:
            return DetectResult(confidence=0.0, why="Empty payload")
        b = _as_bytes(payload)
        variant = _detect_variant(b)
        if not variant:
            return DetectResult(confidence=0.0, why="Not UTF-16 byte pattern")
        return DetectResult(
            confidence=0.9,
            why=f"UTF-16 byte pattern detected ({variant})",
            args={"variant": variant},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = _as_bytes(payload)
        variant = args.get("variant") or _detect_variant(b)
        if variant == "utf-16-le-bom":
            enc = "utf-16-le"
            b = b[2:]
        elif variant == "utf-16-be-bom":
            enc = "utf-16-be"
            b = b[2:]
        elif variant == "utf-16-le":
            enc = "utf-16-le"
        elif variant == "utf-16-be":
            enc = "utf-16-be"
        else:
            return PluginResult(output=payload, notes=["utf16: no variant match at decode"])
        try:
            text = b.decode(enc, errors="replace")
        except Exception as exc:                          # pragma: no cover
            return PluginResult(output="", notes=[f"utf16 decode failed: {exc}"])
        # Strip a residual BOM char if any
        text = text.lstrip("\ufeff")
        return PluginResult(
            output=text,
            notes=[f"Decoded as {enc}"],
            explanation=f"Payload was {enc} bytes (common after PowerShell -EncodedCommand Base64).",
        )


DecoderRegistry.register(Utf16Decoder())
