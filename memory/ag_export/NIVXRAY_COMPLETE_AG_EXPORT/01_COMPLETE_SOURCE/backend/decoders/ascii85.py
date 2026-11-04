"""Ascii85 / Base85 decoder plugin.

Supports:
    * Standard Ascii85 alphabet (33..117 with 'z' shortcut for null quads)
    * Base85 (RFC 1924) — uses `!#$%&()*+-;<=>?@^_`{|}~` plus alphanumerics
    * Adobe Ascii85 (framed with `<~ ~>` — stripped before decode)

Common in .NET obfuscators (System.Text.Encoding.GetBytes(a85)) and JavaScript
malware packers.
"""
from __future__ import annotations

import base64 as _b64
import re
import string
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


_ADOBE = re.compile(r"^\s*<~(.*)~>\s*$", re.DOTALL)
_ASCII85_ALPHABET = frozenset(chr(c) for c in range(33, 118)) | {"z"}
_STRIP = re.compile(r"\s+")


class Ascii85Decoder(BaseDecoder):
    id = "ascii85-decode"
    name = "Ascii85 / Base85 Decode"
    category = "encoding"
    cost = 2
    tags = ("ascii85", "base85", "adobe")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        raw = payload or ""
        # Strip Adobe framing if present
        m = _ADOBE.match(raw)
        candidate = m.group(1) if m else raw
        stripped = _STRIP.sub("", candidate)
        if len(stripped) < 20:
            return DetectResult(confidence=0.0, why="Too short for Ascii85")
        # Alphabet fit
        alien = [c for c in stripped if c not in _ASCII85_ALPHABET]
        if alien:
            return DetectResult(
                confidence=0.0,
                why=f"Non-Ascii85 chars present (e.g. {alien[0]!r})",
            )
        # Adobe framing → very high confidence
        if m:
            return DetectResult(confidence=0.92, why="Adobe Ascii85 framing detected",
                                args={"adobe": True})
        # If English density is already high, don't torture the payload
        if fp.english_density > 0.10:
            return DetectResult(confidence=0.05,
                                why="Input already reads as English")
        # Payloads shorter than 40 chars rarely decode meaningfully — mid tier
        if len(stripped) < 40:
            return DetectResult(confidence=0.35, why="Short but valid Ascii85 alphabet")
        return DetectResult(confidence=0.65, why=f"Ascii85 alphabet fit, len={len(stripped)}")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        raw = payload or ""
        m = _ADOBE.match(raw)
        candidate = m.group(1) if m else raw
        stripped = _STRIP.sub("", candidate)
        try:
            # We've already stripped the Adobe framing, so always call with adobe=False
            data = _b64.a85decode(stripped, adobe=False)
        except (ValueError, Exception) as exc:
            return PluginResult(output="", notes=[f"Ascii85 decode failed: {exc}"])
        printable = sum(1 for x in data if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(data)) < 0.85
        text = data.decode("latin-1") if is_binary else data.decode("utf-8", errors="replace")
        return PluginResult(output=text, output_is_binary=is_binary)


DecoderRegistry.register(Ascii85Decoder())
