"""Nibble-swap decoder plugin.

Rebuilds a byte stream that was obfuscated by swapping the high and low
nibbles of every byte:

    original      encoded (nibbles swapped)
    -------       -------------------------
    0x3d '='   →  0xd3
    0x67 'g'   →  0x76
    0x4d 'M'   →  0xd4

Deployed by AsyncRAT / DarkGate variants and homebrew PS loaders to hide
Base64/URL-encoded payloads from static keyword scans.

Detection heuristic
-------------------
Nibble-swap the input in-place. If the result looks dramatically more
"printable" and contains hallmark tokens (base64 alphabet, URL characters,
common English trigrams), we accept.
"""
from __future__ import annotations

from typing import Any, Dict

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
)
from engine.registry import DecoderRegistry


def _swap_nibbles(data: bytes) -> bytes:
    return bytes(((b << 4) & 0xF0) | (b >> 4) for b in data)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


class NibbleSwapDecoder(BaseDecoder):
    id = "nibble-swap"
    name = "Nibble-Swap"
    category = "cipher"
    cost = 2
    tags = ("nibble-swap", "obfuscation", "byte-transform")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 24:
            return DetectResult(confidence=0.0, why="Too short")
        # Only fire on binary-looking inputs — never on already-printable
        # text (would be a false positive on English or Base64 that just
        # happens to include letters swapping into other letters).
        if fp.printable_ratio > 0.90:
            return DetectResult(
                confidence=0.0,
                why=f"Input already printable ({fp.printable_ratio:.2f}) — no swap needed",
            )
        b = payload.encode("latin-1", errors="replace")
        swapped = _swap_nibbles(b)
        before = fp.printable_ratio
        after = _printable_ratio(swapped)
        # Only accept if swap DRAMATICALLY improves printability
        if after < 0.85 or (after - before) < 0.30:
            return DetectResult(
                confidence=0.0,
                why=(f"Swap does not sufficiently improve printability "
                     f"({before:.2f}→{after:.2f})"),
            )
        # Bonus: look for base64 / URL alphabet after swap
        low = swapped.lower()
        signal_hits = sum(1 for tok in (b"http", b"exe", b"cmd", b"powershell",
                                          b".com", b".net", b"://", b"%20",
                                          b"iex", b"invoke")
                          if tok in low)
        conf = 0.85 if signal_hits >= 1 else 0.65
        return DetectResult(
            confidence=conf,
            why=(f"Nibble-swap raises printability {before:.2f}→{after:.2f}; "
                 f"{signal_hits} hint token(s) found"),
            args={"before_ratio": before, "after_ratio": after,
                  "signal_hits": signal_hits},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        b = payload.encode("latin-1", errors="replace")
        swapped = _swap_nibbles(b)
        text = swapped.decode("latin-1")
        return PluginResult(
            output=text,
            output_is_binary=False,
            notes=[f"Nibble-swapped {len(b)} byte(s) "
                   f"(printable {args.get('before_ratio',0):.2f} → "
                   f"{args.get('after_ratio',0):.2f})"],
            mitre_hints=[
                MitreHint(
                    id="T1027", technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence="Nibble-swap byte transform",
                    source="heuristic",
                ),
            ],
            explanation=(
                "Recovered the payload by swapping the high and low nibbles of "
                "every byte — a lightweight XOR-free obfuscation trick used by "
                "AsyncRAT / DarkGate droppers and custom PS loaders."
            ),
        )


DecoderRegistry.register(NibbleSwapDecoder())
