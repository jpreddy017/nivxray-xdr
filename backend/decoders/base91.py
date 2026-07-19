"""basE91 decoder plugin.

basE91 achieves ~92% efficiency vs. 75% of base64. Common in:
    * Custom .NET packers
    * Some PowerShell obfuscators
    * Malicious Office macro droppers

Alphabet: A-Z, a-z, 0-9, and: !#$%&()*+,./:;<=>?@[]^_`{|}~"
Notably excludes: - (hyphen), single quote, backslash.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry


_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}
_ALPHABET_SET = frozenset(_ALPHABET)
_STRIP = re.compile(r"\s+")


def _b91_decode(s: str) -> bytes:
    """Pure-Python basE91 decoder (spec: base91.sourceforge.net)."""
    b = 0
    n = 0
    v = -1
    out = bytearray()
    for ch in s:
        if ch not in _INDEX:
            raise ValueError(f"Character {ch!r} not in basE91 alphabet")
        c = _INDEX[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v > -1:
        out.append((b | v << n) & 255)
    return bytes(out)


class Base91Decoder(BaseDecoder):
    id = "base91-decode"
    name = "basE91 Decode"
    category = "encoding"
    cost = 3                                # more expensive than base64/85
    tags = ("base91", "encoding")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        stripped = _STRIP.sub("", payload or "")
        if len(stripped) < 32:
            return DetectResult(confidence=0.0, why="Too short for basE91")
        alien = [c for c in stripped if c not in _ALPHABET_SET]
        if alien:
            return DetectResult(
                confidence=0.0,
                why=f"Non-basE91 characters present (e.g. {alien[0]!r})",
            )
        # Skip likely-English prose (basE91 alphabet is a superset of a-zA-Z)
        if fp.english_density > 0.05:
            return DetectResult(confidence=0.0,
                                why="Input already reads as English")
        # Uses characters uncommon in casual text? — high-confidence
        signature_chars = set("~$^|`{}")
        if any(c in signature_chars for c in stripped):
            return DetectResult(confidence=0.75,
                                why="basE91 alphabet fit + signature chars present")
        # Long alphanumeric strings are more likely base64 → yield to it
        if re.match(r"^[A-Za-z0-9]+$", stripped):
            return DetectResult(confidence=0.25,
                                why="Ambiguous with base64 — deferring")
        return DetectResult(confidence=0.55,
                            why=f"basE91 alphabet fit, len={len(stripped)}")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        stripped = _STRIP.sub("", payload or "")
        try:
            data = _b91_decode(stripped)
        except ValueError as exc:
            return PluginResult(output="", notes=[f"basE91 decode failed: {exc}"])
        printable = sum(1 for x in data if 32 <= x < 127 or x in (9, 10, 13))
        is_binary = printable / max(1, len(data)) < 0.85
        text = data.decode("latin-1") if is_binary else data.decode("utf-8", errors="replace")
        return PluginResult(output=text, output_is_binary=is_binary)


DecoderRegistry.register(Base91Decoder())
