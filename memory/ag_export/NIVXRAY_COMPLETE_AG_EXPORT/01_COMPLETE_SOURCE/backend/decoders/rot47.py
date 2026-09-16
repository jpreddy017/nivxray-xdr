"""ROT47 decoder plugin.

Rotation-by-47 over the printable-ASCII range 33..126. Common in JS/PS
obfuscators. Same "result-driven confidence" strategy as ROT13 — we only
fire when the rotated output reads better than the input.
"""
from __future__ import annotations

from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


def _rot47(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            out.append(c)
    return "".join(out)


class Rot47Decoder(BaseDecoder):
    id = "rot47-decode"
    name = "ROT47"
    category = "cipher"
    cost = 1
    tags = ("rot47", "printable")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 6:
            return DetectResult(confidence=0.0, why="Too short for ROT47 evaluation")
        if fp.english_density >= 0.15:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        # Cheap probe: rotate and check English density.
        from engine.fingerprint_util import compute as _fp
        rotated = _rot47(payload)
        rf = _fp(rotated)
        if rf.english_density >= max(0.15, fp.english_density + 0.10):
            return DetectResult(
                confidence=min(0.8, 0.4 + rf.english_density),
                why=f"ROT47 rotation lifts english_density to {rf.english_density:.2f}",
            )
        return DetectResult(confidence=0.0, why="ROT47 rotation does not improve English density")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        return PluginResult(output=_rot47(payload))


DecoderRegistry.register(Rot47Decoder())
