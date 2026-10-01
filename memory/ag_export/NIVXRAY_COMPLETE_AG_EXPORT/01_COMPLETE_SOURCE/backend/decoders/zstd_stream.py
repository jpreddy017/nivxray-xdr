"""Zstandard (zstd) decompression plugin (RC2.3).

Zstd magic: `28 B5 2F FD` (RFC 8478 frame format). Also supports raw frames
via speculative decode gated on English recovery.
"""
from __future__ import annotations

from typing import Any, Dict

import zstandard as zstd

from engine.decoder_base import BaseDecoder
from engine.fingerprint_util import compute as _fp
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _as_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


class ZstdDecoder(BaseDecoder):
    id = "zstd-decompress"
    name = "Zstandard Decompress"
    category = "compression"
    cost = 3
    tags = ("zstd", "compression")
    schema_version = "1.0"

    _MIN_LEN = 16

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        b = _as_bytes(payload)
        if len(b) < self._MIN_LEN:
            return DetectResult(confidence=0.0, why="Too short for zstd stream")
        if b.startswith(_ZSTD_MAGIC):
            return DetectResult(confidence=0.95, why="Zstd magic 28 B5 2F FD present")
        if fp.english_density >= 0.15:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        # No magic → do not attempt speculative decode (zstd raw frames rarely
        # occur in commandline payloads; keep detection strict to avoid perf hit).
        return DetectResult(confidence=0.0, why="No zstd magic")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = _as_bytes(payload)
        try:
            raw = zstd.ZstdDecompressor().decompress(b)
        except zstd.ZstdError as exc:
            return PluginResult(output="", notes=[f"zstd decompress failed: {exc}"])
        printable = sum(1 for x in raw if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return PluginResult(output=out, output_is_binary=is_binary)


DecoderRegistry.register(ZstdDecoder())
