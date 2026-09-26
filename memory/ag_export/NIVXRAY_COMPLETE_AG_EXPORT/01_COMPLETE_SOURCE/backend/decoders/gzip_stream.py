"""Gzip decompression plugin.

Fires when the payload (as Latin-1 bytes) starts with the gzip magic `1f 8b`.
The orchestrator will typically feed us Latin-1 encoded bytes after a base64
or hex step surfaced the raw gzip stream.
"""
from __future__ import annotations

import gzip
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


def _as_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


class GzipDecoder(BaseDecoder):
    id = "gzip-decompress"
    name = "Gzip Decompress"
    category = "compression"
    cost = 2
    tags = ("gzip", "compression")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        b = _as_bytes(payload)
        if len(b) < 10:
            return DetectResult(confidence=0.0, why="Too short for gzip header")
        if b[0] == 0x1F and b[1] == 0x8B:
            return DetectResult(confidence=0.95, why="Gzip magic 0x1F 0x8B present")
        return DetectResult(confidence=0.0, why="No gzip magic")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = _as_bytes(payload)
        try:
            raw = gzip.decompress(b)
        except OSError as exc:
            return PluginResult(output="", notes=[f"gzip decompress failed: {exc}"])
        printable = sum(1 for x in raw if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return PluginResult(output=out, output_is_binary=is_binary)


DecoderRegistry.register(GzipDecoder())
