"""PowerShell hex-escape decoder plugin.

Handles the C-style `\\xNN` byte-escape pattern that appears in PowerShell
obfuscators (Invoke-PSObfuscation, custom loader scripts) and in commodity
malware command-lines where each byte of the intended plaintext has been
encoded as `\\xNN`:

    \\x49\\x45\\x58                        →  "IEX"
    \\x3b\\x34\\x35\\x36\\x37 …            →  ";45678 …"

Real-world case (December_Commandline sample):
    powershell -c "$s='\\x3b\\x34\\x35\\x36…';iex $s"

Design
------
* This is a byte-transform, not a script-reconstructor. The plugin looks at
  the WHOLE payload for `\\xNN` (or `\\\\xNN` when the payload was captured
  through a doubly-escaping wrapper) sequences and rebuilds the resulting
  byte stream.
* Precision-first: only fires when we count ≥ 10 `\\xNN` escapes AND their
  cumulative footprint exceeds 40% of the payload length. Otherwise a stray
  hex escape inside a long PowerShell one-liner would trigger the plugin.
* We deliberately do NOT fire on the JS charcode `String.fromCharCode`
  pattern (that has its own plugin/op).

Sibling ops
-----------
* `js-unescape`         — operations.py manual op for the same transform;
                          kept for the Chain-Recipe UI.
* `js-hex-strings-decode` (op wrapper added to operations.py in the same
                           change so the manual runner never errors out).
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
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# `\xNN` OR `\\xNN`  (single- or double-backslash — the latter shows up when
# the payload was routed through a JSON/CSV wrapper that escaped the slash).
_RX_HEX_ESCAPE = re.compile(r"\\{1,2}x([0-9a-fA-F]{2})")


def _decode_escapes(payload: str) -> tuple[str, int]:
    """Return (decoded_text, escape_count). Bytes are emitted as latin-1
    codepoints so the pipeline can hand them off to a downstream decoder
    (utf-16, base64, gzip …) without lossy re-encoding.
    """
    count = 0

    def _sub(m: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return chr(int(m.group(1), 16))

    return _RX_HEX_ESCAPE.sub(_sub, payload), count


class PsHexEscapeDecoder(BaseDecoder):
    id = "ps-hex-escape"
    name = "PowerShell / C-style Hex Escape (\\xNN)"
    category = "encoding"
    cost = 1
    tags = ("powershell", "hex-escape", "obfuscation", "reconstruct")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 24:
            return DetectResult(confidence=0.0, why="Too short for hex-escape")
        matches = _RX_HEX_ESCAPE.findall(payload)
        n = len(matches)
        if n < 10:
            return DetectResult(
                confidence=0.0,
                why=f"Only {n} \\xNN escape(s) — need ≥ 10 to trigger",
            )
        # Density: how much of the payload is occupied by `\xNN` tokens.
        # Each token is 4 chars (or 5 for `\\xNN`), take the average.
        density = (n * 4) / max(1, len(payload))
        if density < 0.40:
            return DetectResult(
                confidence=0.0,
                why=(f"{n} hex escapes but density {density:.2f} < 0.40 — "
                     "likely embedded escape, not primary encoding"),
            )
        # Dry-run: verify the decode is majority-printable so we don't
        # rebuild a binary blob that isn't actually text.
        decoded, _ = _decode_escapes(payload)
        printable = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\r\n\t")
        pr = printable / max(1, len(decoded))
        conf = 0.9 if pr >= 0.9 else (0.75 if pr >= 0.7 else 0.55)
        return DetectResult(
            confidence=conf,
            why=(f"Detected {n} `\\xNN` byte escape(s) "
                 f"(density={density:.2f}, printable_after={pr:.2f})"),
            args={"token_count": n, "density": density, "printable_ratio": pr},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        decoded, n = _decode_escapes(payload)
        if n == 0:
            return PluginResult(output=payload, notes=["ps-hex-escape: no escapes matched"])
        return PluginResult(
            output=decoded,
            notes=[f"Decoded {n} `\\xNN` hex escape(s)"],
            mitre_hints=[
                MitreHint(
                    id="T1027",
                    technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"C-style \\xNN hex escapes ({n} tokens)",
                    source="heuristic",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="ps-hex-escape-obfuscation",
                    severity="medium",
                    evidence=f"{n} \\xNN byte escapes in payload",
                ),
            ],
            explanation=(
                "Rebuilt payload by converting every `\\xNN` C-style hex "
                "escape to its byte value. Common in PowerShell obfuscators "
                "(Invoke-PSObfuscation) and homebrew loader scripts that "
                "smuggle IEX / net.webclient calls past static keyword scans."
            ),
        )


DecoderRegistry.register(PsHexEscapeDecoder())
