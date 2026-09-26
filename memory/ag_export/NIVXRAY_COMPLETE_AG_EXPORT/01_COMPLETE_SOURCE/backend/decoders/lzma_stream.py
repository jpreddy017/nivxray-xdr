"""LZMA/XZ decompression plugin (RC2.3).

Handles both `.xz` streams (magic `FD 37 7A 58 5A 00`) and raw LZMA streams.
Raw LZMA has no reliable magic so we speculatively decode and gate on English
recovery — same approach as brotli/zstd plugins.
"""
from __future__ import annotations

import lzma
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.fingerprint_util import compute as _fp
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


_XZ_MAGIC = b"\xfd7zXZ\x00"


def _as_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


class LzmaDecoder(BaseDecoder):
    id = "lzma-decompress"
    name = "LZMA/XZ Decompress"
    category = "compression"
    cost = 3
    tags = ("lzma", "xz", "compression")
    schema_version = "1.0"

    _MIN_LEN = 16

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        b = _as_bytes(payload)
        if len(b) < self._MIN_LEN:
            return DetectResult(confidence=0.0, why="Too short for lzma stream")
        if b.startswith(_XZ_MAGIC):
            return DetectResult(confidence=0.95, why="XZ magic FD 37 7A 58 5A 00 present")
        if fp.english_density >= 0.15:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        if fp.printable_ratio >= 0.90 and fp.entropy < 4.0:
            return DetectResult(confidence=0.0, why="Printable low-entropy → unlikely lzma")
        # Speculative decode against raw LZMA
        try:
            out = lzma.decompress(b, format=lzma.FORMAT_ALONE)
        except lzma.LZMAError:
            try:
                out = lzma.decompress(b, format=lzma.FORMAT_RAW,
                                      filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}])
            except lzma.LZMAError:
                return DetectResult(confidence=0.0, why="Not a valid lzma stream")
        of = _fp(out.decode("latin-1"))
        if of.english_density >= max(0.15, fp.english_density + 0.10):
            return DetectResult(
                confidence=min(0.9, 0.5 + of.english_density),
                why=f"LZMA decompress recovers English (density {of.english_density:.2f})",
            )
        return DetectResult(confidence=0.0, why="LZMA decoded but output not English")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = _as_bytes(payload)
        raw = None
        for fmt in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE, lzma.FORMAT_AUTO):
            try:
                raw = lzma.decompress(b, format=fmt)
                break
            except lzma.LZMAError:
                continue
        if raw is None:
            return PluginResult(output="", notes=["lzma decompress failed"])
        printable = sum(1 for x in raw if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return PluginResult(output=out, output_is_binary=is_binary)


DecoderRegistry.register(LzmaDecoder())
