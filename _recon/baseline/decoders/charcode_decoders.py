"""Decimal + octal char-code decoder plugin (RC2.9 gap-close from April case).

Handles two commonly-chained obfuscation primitives that appear in CTF /
training / advanced adversary payloads:

  "49 50 54 32 49 50 52 32 49 48 49"    →  "126 124 101"   (decimal codes)
  "126 124 101 65 122 105 154 106"      →  "VTA5RElFTm9Z"  (octal codes)

Design
------
* detect() fires when the payload is entirely whitespace-separated integer
  tokens (no floats, no negatives, no letters) AND the tokens decode to a
  mostly-printable ASCII result.  Two variants:
    - decimal: any digits allowed (0-9); codes fit 0x00-0x7f
    - octal:   digits 0-7 only (no 8 or 9); codes fit 0x00-0x7f
* decode() converts each token to its char and joins.
* Precision-first: refuses to emit output if <80% printable ratio — this
  is what prevents false-positive hits on binary blobs that happen to be
  written as space-separated bytes.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# Matches a payload consisting only of whitespace-separated integer tokens.
_RX_DECIMAL_ONLY = re.compile(r"^\s*(?:\d{1,4}\s+){3,}\d{1,4}\s*$")
# Same but octal (digits 0-7 only).
_RX_OCTAL_ONLY   = re.compile(r"^\s*(?:[0-7]{1,4}\s+){3,}[0-7]{1,4}\s*$")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if (0x20 <= ord(c) < 0x7f) or c in "\r\n\t")
    return ok / len(s)


def _try_decode(tokens: List[str], base: int) -> str | None:
    try:
        codes = [int(t, base) for t in tokens]
    except (ValueError, OverflowError):
        return None
    if any(c < 0 or c > 0x10ffff for c in codes):
        return None
    out = "".join(chr(c) for c in codes)
    if _printable_ratio(out) < 0.80:
        return None
    return out


class DecimalCharcodeDecoder(BaseDecoder):
    """Space-separated decimal character codes → ASCII chars.

    Real-world use: CTF challenges, advanced APT payload obfuscation,
    training / red-team samples. Sample chain (April case):
        base32 → decimal-charcode → octal-charcode → base64 → base64 → text
    """
    id = "decimal-charcode-decode"
    name = "Decimal Char-Code Decode"
    category = "encoding"
    cost = 1
    tags = ("charcode", "decimal", "reconstruct")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 12:
            return DetectResult(confidence=0.0, why="Too short for decimal-charcode")
        if not _RX_DECIMAL_ONLY.match(payload):
            return DetectResult(confidence=0.0, why="Not whitespace-separated integers")
        # Cheap dry-run to make sure decode would succeed AND be printable.
        tokens = payload.split()
        result = _try_decode(tokens, base=10)
        if result is None:
            return DetectResult(confidence=0.0, why="Would decode to binary — not decimal-charcode")
        # High confidence — this pattern is unambiguous when it fires.
        return DetectResult(
            confidence=0.9,
            why=f"Whitespace-separated decimal codes ({len(tokens)} tokens, output printable)",
            args={"token_count": len(tokens)},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        tokens = payload.split()
        result = _try_decode(tokens, base=10)
        if result is None:
            return PluginResult(output=payload, notes=["decimal-charcode: no printable decode"])
        return PluginResult(
            output=result,
            notes=[f"Decoded {len(tokens)} decimal char codes"],
            mitre_hints=[
                MitreHint(
                    id="T1027",
                    technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"Decimal char-code encoding ({len(tokens)} tokens)",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="decimal-charcode-obfuscation",
                    severity="low",
                    evidence=f"{len(tokens)} space-separated decimal codes",
                ),
            ],
            explanation=(
                "Rebuilt string from space-separated decimal ASCII character "
                "codes. Common in CTF-style multi-layer obfuscation and "
                "advanced APT payloads."
            ),
        )


class OctalCharcodeDecoder(BaseDecoder):
    """Space-separated octal character codes → ASCII chars.

    Same pattern as decimal but with base-8 digits (0-7 only). Used when
    the attacker wants to further obfuscate by masking that these are
    decimal — the octal representation of ASCII printable characters
    looks similar enough to fool casual analysts.
    """
    id = "octal-charcode-decode"
    name = "Octal Char-Code Decode"
    category = "encoding"
    cost = 1
    tags = ("charcode", "octal", "reconstruct")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 12:
            return DetectResult(confidence=0.0, why="Too short for octal-charcode")
        if not _RX_OCTAL_ONLY.match(payload):
            return DetectResult(confidence=0.0, why="Contains non-octal digits (8/9) or non-digits")
        tokens = payload.split()
        result = _try_decode(tokens, base=8)
        if result is None:
            return DetectResult(confidence=0.0, why="Would decode to binary — not octal-charcode")
        # Marginally lower conf than decimal — octal is rarer, we want
        # decimal to win when both would match a truly-decimal payload.
        # (For pure-octal payloads only octal matches anyway.)
        return DetectResult(
            confidence=0.88,
            why=f"Whitespace-separated octal codes ({len(tokens)} tokens, output printable)",
            args={"token_count": len(tokens)},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        tokens = payload.split()
        result = _try_decode(tokens, base=8)
        if result is None:
            return PluginResult(output=payload, notes=["octal-charcode: no printable decode"])
        return PluginResult(
            output=result,
            notes=[f"Decoded {len(tokens)} octal char codes"],
            mitre_hints=[
                MitreHint(
                    id="T1027",
                    technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"Octal char-code encoding ({len(tokens)} tokens)",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="octal-charcode-obfuscation",
                    severity="low",
                    evidence=f"{len(tokens)} space-separated octal codes",
                ),
            ],
            explanation=(
                "Rebuilt string from space-separated octal (base-8) character "
                "codes. Commonly chained with base32/base64/decimal-charcode "
                "in CTF-style multi-layer obfuscation."
            ),
        )


DecoderRegistry.register(DecimalCharcodeDecoder())
DecoderRegistry.register(OctalCharcodeDecoder())
