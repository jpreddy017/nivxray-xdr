"""General Caesar-cipher decoder plugin (RC2.3).

ROT13 has its own plugin; this one covers **all 25 non-trivial rotations**
(1-25) — used by weaker obfuscators that pick a random shift instead of the
canonical 13. The decode phase returns the rotation that produces the highest
English-density output.

Detection is strict: the input must already look like *rotated* prose
(letters-dominated but low english_density). If the payload has non-letter
noise, structured data, or already reads as English we skip.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from engine.decoder_base import BaseDecoder
from engine.fingerprint_util import compute as _fp
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


def _rot(s: str, shift: int) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 0x41 <= o <= 0x5A:                       # A-Z
            out.append(chr(((o - 0x41 + shift) % 26) + 0x41))
        elif 0x61 <= o <= 0x7A:                     # a-z
            out.append(chr(((o - 0x61 + shift) % 26) + 0x61))
        else:
            out.append(c)
    return "".join(out)


def _best_rotation(s: str) -> Tuple[int, str, float]:
    """Return (best_shift, best_plain, best_english_density). Skip shift=0."""
    best_shift, best_plain, best_density = 0, s, 0.0
    for shift in range(1, 26):
        rotated = _rot(s, shift)
        density = _fp(rotated).english_density
        if density > best_density:
            best_shift, best_plain, best_density = shift, rotated, density
    return best_shift, best_plain, best_density


class CaesarDecoder(BaseDecoder):
    id = "caesar-decode"
    name = "Caesar Cipher (shift 1-25)"
    category = "cipher"
    cost = 2
    tags = ("caesar", "rot", "cipher")
    schema_version = "1.0"

    _MIN_LEN = 12

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if len(payload) < self._MIN_LEN:
            return DetectResult(confidence=0.0, why="Too short for Caesar")
        letters = sum(1 for c in payload if c.isalpha())
        if letters / len(payload) < 0.5:
            return DetectResult(confidence=0.0, why="Insufficient letter density for Caesar")
        if fp.english_density >= 0.15:
            return DetectResult(confidence=0.0, why="Input already reads as English")
        # Try all rotations; only fire if some shift produces English
        best_shift, _, best_density = _best_rotation(payload)
        if best_density >= max(0.20, fp.english_density + 0.15) and best_shift not in (0, 13):
            return DetectResult(
                confidence=min(0.85, 0.4 + best_density),
                why=(f"Caesar shift {best_shift} recovers English "
                     f"(density {best_density:.2f})"),
                args={"shift": best_shift},
            )
        return DetectResult(
            confidence=0.0,
            why=f"No Caesar shift improves English density (best={best_density:.2f})",
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        shift = args.get("shift")
        if shift is None:
            shift, _, _ = _best_rotation(payload)
        out = _rot(payload, int(shift))
        return PluginResult(
            output=out,
            notes=[f"caesar shift={shift}"],
        )


DecoderRegistry.register(CaesarDecoder())
