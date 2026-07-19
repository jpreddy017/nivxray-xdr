"""Base32 decoder plugin (RFC 4648).

Base32 uses `A-Z` and `2-7` (case-insensitive when parsed). Common in tools
that embed indicators where '/' and '+' are unwelcome (URLs, DNS).
"""
from __future__ import annotations

import base64 as _b64
import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry

_WS = re.compile(r"\s+")
_B32 = re.compile(r"^[A-Z2-7=]+$")


class Base32Decoder(BaseDecoder):
    id = "base32-decode"
    name = "Base32 Decode"
    category = "encoding"
    cost = 1
    tags = ("base32", "text-to-bytes")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        s = _WS.sub("", payload or "").upper()
        if len(s) < 8 or len(s) % 8 != 0:
            return DetectResult(confidence=0.0, why="Length must be multiple of 8 and ≥ 8")
        if not _B32.match(s):
            return DetectResult(confidence=0.0, why="Non-base32 characters present")
        # Reject prose payloads (multiple whitespace-separated tokens)
        stripped_input = (payload or "").strip()
        tokens = len(re.split(r"\s+", stripped_input)) if stripped_input else 0
        if tokens > 1:
            return DetectResult(
                confidence=0.05,
                why=f"Contains internal whitespace ({tokens} tokens) — likely prose",
            )
        # avoid clashing with all-caps hex (which would also match)
        if re.match(r"^[A-F0-9]+$", s):
            return DetectResult(confidence=0.15, why="Ambiguous: also valid hex")
        return DetectResult(confidence=0.75, why=f"Base32 alphabet fit, len={len(s)}")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        s = _WS.sub("", payload or "").upper()
        try:
            raw = _b64.b32decode(s, casefold=True)
        except Exception as exc:
            return PluginResult(output="", notes=[f"base32 decode failed: {exc}"])
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return PluginResult(output=out, output_is_binary=is_binary)


DecoderRegistry.register(Base32Decoder())
