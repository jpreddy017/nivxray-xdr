"""ROT13 decoder plugin.

Classic Caesar-13 rotation over ASCII letters. Non-letters are passed through.
Confidence relies on the *result* — we only fire when both the input and the
rotated output look plausibly English/alphabetic. Otherwise we would rotate
random text and pretend it was ROT13.
"""
from __future__ import annotations

import codecs
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


def _letters(s: str) -> int:
    return sum(1 for c in s if c.isalpha())


class Rot13Decoder(BaseDecoder):
    id = "rot13-decode"
    name = "ROT13"
    category = "cipher"
    cost = 1
    tags = ("rot13", "caesar")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 6:
            return DetectResult(confidence=0.0, why="Too short for ROT13 evaluation")
        letters = _letters(payload)
        if letters < 4:
            return DetectResult(confidence=0.0, why="Too few letters to be ROT13-encoded prose")
        # If the input already reads like English, do NOT rotate it.
        if fp.english_density >= 0.15:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        # Try the rotation and see if the OUTPUT reads better.
        rotated = codecs.encode(payload, "rot_13")
        # Cheap English density check on rotated text
        from engine.fingerprint_util import compute as _fp
        rf = _fp(rotated)
        if rf.english_density >= max(0.15, fp.english_density + 0.10):
            return DetectResult(
                confidence=min(0.8, 0.4 + rf.english_density),
                why=f"Rotated output english_density {rf.english_density:.2f} > input",
            )
        return DetectResult(confidence=0.0, why="ROT13 rotation does not improve English density")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        return PluginResult(output=codecs.encode(payload, "rot_13"))


DecoderRegistry.register(Rot13Decoder())
