"""Hexadecimal decoder plugin.

Accepts common styles:
    - unbroken hex: "48656c6c6f"
    - space/colon-separated: "48 65 6c 6c 6f", "48:65:6c:6c:6f"
    - `\\x`-prefixed: "\\x48\\x65\\x6c\\x6c\\x6f"
    - 0x-prefixed comma/space list: "0x48,0x65,0x6c"
"""
from __future__ import annotations

import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DecodeResult, DetectResult, Fingerprint
from engine.registry import DecoderRegistry

_HEX_STRIP = re.compile(r"(?:\\x|0x|,|\s|:)+", re.IGNORECASE)
_HEX_ONLY = re.compile(r"^[0-9A-Fa-f]+$")


class HexDecoder(BaseDecoder):
    id = "hex-decode"
    name = "Hex Decode"
    category = "encoding"
    cost = 1
    tags = ("hex", "text-to-bytes")
    schema_version = "1.0"

    def detect(self, payload: str, fingerprint: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        stripped = _HEX_STRIP.sub("", payload or "")
        if len(stripped) < 8 or len(stripped) % 2 != 0:
            return DetectResult(confidence=0.0, why="Length must be even and ≥ 8")
        if not _HEX_ONLY.match(stripped):
            return DetectResult(confidence=0.0, why="Non-hex characters present")
        # High confidence when the raw payload actually used a hex-ish separator
        used_prefix = bool(re.search(r"\\x|0x|:", payload or ""))
        conf = 0.9 if used_prefix else 0.75
        return DetectResult(
            confidence=conf,
            why=f"Hex alphabet fit, {len(stripped) // 2} bytes",
            args={"cleaned": stripped},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> DecodeResult:
        cleaned = args.get("cleaned") or _HEX_STRIP.sub("", payload or "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            return DecodeResult(output="", notes=[f"hex decode failed: {exc}"])
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return DecodeResult(output=out, output_is_binary=is_binary)


DecoderRegistry.register(HexDecoder())
