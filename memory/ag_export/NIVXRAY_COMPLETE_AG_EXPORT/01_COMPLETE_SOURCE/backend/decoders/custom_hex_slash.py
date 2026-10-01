"""Custom hex-with-separator decoder plugin.

Recognises byte-arrays hidden as ASCII hex tokens joined by a fixed
separator. Common in AsyncRAT / DarkGate / custom PowerShell obfuscators:

    d3x\\d3x\\76x\\d4x\\97x\\55x\\...          (separator = "x\\")
    d3;d3;76;d4;97;55;...                        (separator = ";")
    0xd3, 0xd4, 0x97, ...                        (already handled by hex-decode)

Detection heuristic
-------------------
The input must contain ≥ 10 occurrences of the pattern `[0-9a-f]{2}<SEP>`
where <SEP> is one of a small allow-list of exotic separators. This is
kept intentionally narrow so we don't collide with real hex-decode.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

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


# Separators observed in real-world samples. Ordered by specificity —
# multi-char separators tried first so we don't misclassify.
_SEPARATORS: Tuple[str, ...] = (
    r"x\\",         # `d3x\d3x\`   (raw two chars: `x` + backslash)
    r"\\x",         # `\xd3\xd4`   (C-style escapes)
    r"\\k",         # `\kNN` variant (letter-digit stream, handled elsewhere)
)


def _try_extract(text: str) -> Tuple[str, bytes, int]:
    """Return (separator_used, byte_data, token_count) for the best-fit sep."""
    best: Tuple[str, bytes, int] = ("", b"", 0)
    # Style A — token FOLLOWED by separator:  `d3x\d3x\76x\`
    for sep_re in _SEPARATORS:
        rx = re.compile(rf"([0-9a-fA-F]{{2}}){sep_re}")
        tokens = rx.findall(text)
        if len(tokens) >= 10 and len(tokens) > best[2]:
            try:
                data = bytes.fromhex("".join(tokens))
                best = (sep_re, data, len(tokens))
            except ValueError:
                continue
    # Style B — token PRECEDED by `\x`  (C-style hex escapes)
    #   \x3b\x34\x35   OR   \\x3b\\x34\\x35 (double-escaped in strings)
    for prefix in (r"\\x", r"\\\\x"):
        rx = re.compile(rf"{prefix}([0-9a-fA-F]{{2}})")
        tokens = rx.findall(text)
        if len(tokens) >= 10 and len(tokens) > best[2]:
            try:
                data = bytes.fromhex("".join(tokens))
                best = (f"prefix:{prefix}", data, len(tokens))
            except ValueError:
                continue
    return best


class CustomHexSlashDecoder(BaseDecoder):
    id = "custom-hex-slash"
    name = "Custom Hex-with-Separator Decode"
    category = "encoding"
    cost = 2
    tags = ("custom-hex", "obfuscation", "asyncrat", "darkgate")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 40:
            return DetectResult(confidence=0.0, why="Too short")
        sep, data, count = _try_extract(payload)
        if count < 10:
            return DetectResult(confidence=0.0,
                                why="No hex-with-separator pattern")
        # High confidence when the entire payload is basically all hex tokens.
        # The 0.95 tier at density > 0.75 is intentional: `d3x\d3x\d3x\…` is
        # a completely unambiguous custom-hex-slash signature and must beat
        # `utf16le-or-utf8-decode` (which produces plausible-looking but
        # scrambled output on the same bytes). See March1 regression.
        density = (count * 4) / max(1, len(payload))
        if density > 0.75:
            conf = 0.95
        elif density > 0.40:
            conf = 0.85
        else:
            conf = 0.70
        return DetectResult(
            confidence=conf,
            why=(f"Detected {count} hex token(s) separated by {sep!r} "
                 f"(density={density:.2f})"),
            args={"sep": sep, "token_count": count},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        # Feb 2026 — RECURSIVE peel (max 5 iterations). Real-world samples
        # (Immediate1/3, Finetune, Big Whale) wrap the payload in 2-3 nested
        # layers of hex-with-separator; the pipeline used to stop after the
        # FIRST peel, leaving `;3;;3;;3;;` residue that the downstream
        # xor-brute then misinterpreted. Bounded loop prevents infinite
        # regress on pathological inputs.
        current = payload
        total_tokens = 0
        peels = 0
        for _ in range(5):
            _, data, count = _try_extract(current)
            if not data or count < 10:
                break
            current = data.decode("latin-1")
            total_tokens += count
            peels += 1
        if peels == 0:
            return PluginResult(output="", notes=["no hex tokens matched"])
        return PluginResult(
            output=current,
            output_is_binary=True,
            notes=[
                f"Extracted {total_tokens} byte(s) via {peels}× recursive "
                f"custom hex-separator peel",
            ],
            mitre_hints=[
                MitreHint(
                    id="T1027.001",
                    technique="Binary Padding",
                    tactic="Defense Evasion",
                    evidence=f"Nested ASCII-hex encoding ({peels} layers deep)",
                    source="heuristic",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="custom-hex-obfuscation", severity="medium",
                    evidence=f"{total_tokens} hex tokens across {peels} nested layers",
                ),
            ],
            explanation=(
                "Peeled a custom hex-with-separator encoding often used by "
                "loader scripts to smuggle binary through Base64 wrappers."
                + (f" Detected {peels} nested layers." if peels > 1 else "")
            ),
        )


DecoderRegistry.register(CustomHexSlashDecoder())
