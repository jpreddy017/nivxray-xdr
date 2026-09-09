"""Brotli decompression plugin (RC2.3).

Brotli streams have no reliable magic bytes at position 0, so detection relies
on a *speculative decode*: we attempt Brotli decompression and only accept the
result when it materially improves the printable/English density of the payload.
This mirrors how the orchestrator's XOR-brute decides confidence based on the
recovered plaintext, not the ciphertext structure.
"""
from __future__ import annotations

from typing import Any, Dict

import brotli

from engine.decoder_base import BaseDecoder
from engine.fingerprint_util import compute as _fp
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


def _as_bytes(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


class BrotliDecoder(BaseDecoder):
    id = "brotli-decompress"
    name = "Brotli Decompress"
    category = "compression"
    cost = 3
    tags = ("brotli", "compression")
    schema_version = "1.0"

    _MIN_LEN = 16

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        b = _as_bytes(payload)
        if len(b) < self._MIN_LEN:
            return DetectResult(confidence=0.0, why="Too short for brotli stream")
        if fp.english_density >= 0.15:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        # Brotli requires binary-ish or high-entropy data
        if fp.printable_ratio >= 0.90 and fp.entropy < 4.0:
            return DetectResult(confidence=0.0, why="Printable low-entropy → unlikely brotli")
        try:
            out = brotli.decompress(b)
        except brotli.error:
            return DetectResult(confidence=0.0, why="Not a valid brotli stream")
        of = _fp(out.decode("latin-1"))
        if of.english_density >= max(0.15, fp.english_density + 0.10) \
                or of.printable_ratio >= fp.printable_ratio + 0.20:
            return DetectResult(
                confidence=min(0.9, 0.5 + of.english_density),
                why=(f"Brotli decompress recovers printable text "
                     f"(english {of.english_density:.2f}, printable {of.printable_ratio:.2f})"),
            )
        return DetectResult(confidence=0.0, why="Brotli decoded but output not English")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = _as_bytes(payload)
        try:
            raw = brotli.decompress(b)
        except brotli.error as exc:
            return PluginResult(output="", notes=[f"brotli decompress failed: {exc}"])
        printable = sum(1 for x in raw if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(raw)) < 0.85
        out = raw.decode("latin-1") if is_binary else raw.decode("utf-8", errors="replace")
        return PluginResult(output=out, output_is_binary=is_binary)


DecoderRegistry.register(BrotliDecoder())
