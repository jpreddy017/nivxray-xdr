"""Zlib / raw-deflate decompression plugin.

Detects both:
    - zlib-framed streams (magic `78 9c`, `78 da`, `78 01`, `78 5e`)
    - raw deflate streams — best-effort probe (try decompress with -MAX_WBITS)

Zlib is common under Base64 in .NET malware droppers; raw deflate appears
inside PowerShell obfuscators that skip the zlib header for size.
"""
from __future__ import annotations

import zlib
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry

# Zlib CMF+FLG combinations seen in the wild
_ZLIB_MAGIC = {b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"}


def _as_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


class ZlibDecoder(BaseDecoder):
    id = "zlib-deflate-decompress"
    name = "Zlib / Deflate Decompress"
    category = "compression"
    cost = 2
    tags = ("zlib", "deflate", "compression")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        b = _as_bytes(payload)
        if len(b) < 8:
            return DetectResult(confidence=0.0, why="Too short for zlib/deflate")
        if b[:2] in _ZLIB_MAGIC:
            return DetectResult(confidence=0.9, why=f"Zlib magic {b[:2].hex()}")
        # Raw deflate probe — try a very small decompress; expensive so gated
        # to binary/high-entropy payloads only.
        if fp.is_binary and fp.entropy >= 6.5:
            try:
                zlib.decompress(b, -zlib.MAX_WBITS, bufsize=64)
                return DetectResult(confidence=0.5, why="Raw deflate probe succeeded", args={"raw": True})
            except zlib.error:
                pass
        return DetectResult(confidence=0.0, why="No zlib/deflate signature")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = _as_bytes(payload)
        raw_deflate = bool(args.get("raw"))
        try:
            if raw_deflate:
                out = zlib.decompress(b, -zlib.MAX_WBITS)
            else:
                out = zlib.decompress(b)
        except zlib.error:
            # Try the other framing as a fallback
            try:
                out = zlib.decompress(b, -zlib.MAX_WBITS)
            except zlib.error as exc:
                return PluginResult(output="", notes=[f"zlib decompress failed: {exc}"])
        printable = sum(1 for x in out if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(out)) < 0.85
        text = out.decode("latin-1") if is_binary else out.decode("utf-8", errors="replace")
        return PluginResult(output=text, output_is_binary=is_binary)


DecoderRegistry.register(ZlibDecoder())
