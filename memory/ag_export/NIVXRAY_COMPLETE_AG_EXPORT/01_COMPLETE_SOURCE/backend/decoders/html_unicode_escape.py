"""HTML entity + JS/JSON Unicode-escape decoder (RC3.1 · Phase C.5).

Two very common lightweight-obfuscation primitives that adversaries chain
before a base64 / gzip loader — usually inside HTML lures, phishing
templates and JS droppers:

  1. HTML numeric entities   →  &#65;&#66;&#67;               ("ABC")
                               &#x50;&#x6f;&#x77;             ("Pow")

  2. JS / JSON \\uXXXX escape →  \\u0070\\u006f\\u0077\\u0065\\u0072  ("power")

Both surface identically to analysts (a wall of `&#...;` or `\\u....`
tokens that hide a plaintext downloader) so we register a single plugin
that recognises whichever variant dominates and emits the decoded
plaintext for downstream `extract-wrapper` / `ioc-extract` layers.

Precision-first defence: the decoder REFUSES to fire unless it can
recover ≥5 escape tokens AND ≥80 % of the recovered characters are
printable ASCII / newline — this keeps random `\\u0000` noise inside
binary payloads from triggering a phantom decode.
"""
from __future__ import annotations

import html
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

# Matches &#65; / &#0065; / &#x41; / &#X41; / &amp; etc.
_RX_HTML_NUM   = re.compile(r"&#(?:[xX][0-9a-fA-F]+|[0-9]+);")
_RX_HTML_ANY   = re.compile(r"&(?:#[xX]?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,30});")
# JS/JSON \u0041 (case-sensitive per ECMA-262). Also handle \u{1F600}.
_RX_JS_UNI     = re.compile(r"\\u(?:\{[0-9a-fA-F]{1,6}\}|[0-9a-fA-F]{4})")
# JS \xNN escape (hex byte).
_RX_JS_HEX     = re.compile(r"\\x[0-9a-fA-F]{2}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if (0x20 <= ord(c) < 0x7f) or c in "\r\n\t")
    return ok / len(s)


def _decode_js_uni(m: re.Match) -> str:
    tok = m.group(0)[2:]  # strip \u
    if tok.startswith("{") and tok.endswith("}"):
        tok = tok[1:-1]
    try:
        return chr(int(tok, 16))
    except Exception:
        return m.group(0)


def _decode_js_hex(m: re.Match) -> str:
    try:
        return chr(int(m.group(0)[2:], 16))
    except Exception:
        return m.group(0)


class HtmlUnicodeEscapeDecoder(BaseDecoder):
    id = "html-unicode-escape"
    name = "HTML entity / Unicode escape decode"
    category = "encoding"
    cost = 1
    tags = ("html-entity", "unicode-escape", "phishing", "js-obfuscation")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload:
            return DetectResult(confidence=0.0, why="Empty input")
        html_hits = len(_RX_HTML_NUM.findall(payload)) + len(_RX_HTML_ANY.findall(payload))
        js_hits = len(_RX_JS_UNI.findall(payload)) + len(_RX_JS_HEX.findall(payload))
        total = html_hits + js_hits
        if total < 5:
            return DetectResult(confidence=0.0, why=f"Only {total} escape token(s) (< 5)")
        # Density check — the escaped tokens should account for a non-trivial
        # share of the payload. Random long payloads occasionally contain a
        # handful of `\uXXXX` sequences without being obfuscated.
        density = total / max(1, len(payload) / 6.0)  # ~1 token per 6 chars
        if density < 0.15:
            return DetectResult(
                confidence=0.05,
                why=f"{total} tokens over {len(payload)} chars ({density:.2f} density) — too sparse",
            )
        variant = "html-entity" if html_hits >= js_hits else "js-unicode"
        return DetectResult(
            confidence=min(0.85, 0.55 + total * 0.02),
            why=f"{total} {variant} escape tokens (density {density:.2f})",
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        out = payload or ""
        notes = []

        # ---------- JS/JSON escapes first (they don't clash with `&`) --
        js_uni = _RX_JS_UNI.findall(out)
        if js_uni:
            out = _RX_JS_UNI.sub(_decode_js_uni, out)
            notes.append(f"Decoded {len(js_uni)} \\uXXXX escape(s)")
        js_hex = _RX_JS_HEX.findall(out)
        if js_hex:
            out = _RX_JS_HEX.sub(_decode_js_hex, out)
            notes.append(f"Decoded {len(js_hex)} \\xNN escape(s)")

        # ---------- HTML entities (numeric + named) --------------------
        num_hits = _RX_HTML_NUM.findall(out)
        any_hits = _RX_HTML_ANY.findall(out)
        if num_hits or any_hits:
            out = html.unescape(out)
            notes.append(
                f"Decoded {len(num_hits)} numeric + "
                f"{max(0, len(any_hits) - len(num_hits))} named HTML entity/entities"
            )

        if _printable_ratio(out) < 0.80:
            return PluginResult(
                output="",
                notes=notes + [
                    f"Refused: printable-ratio {_printable_ratio(out):.2f} < 0.80 "
                    "(prevents phantom-decode of binary payloads)"
                ],
            )

        return PluginResult(
            output=out,
            notes=notes,
            mitre_hints=[
                MitreHint(
                    id="T1027",
                    name="Obfuscated Files or Information",
                    source="html-unicode-escape",
                    evidence="HTML entity / Unicode escape obfuscation stripped",
                ),
                MitreHint(
                    id="T1027.010",
                    name="Command Obfuscation",
                    source="html-unicode-escape",
                    evidence="Command line reconstructed from \\u/\\&#; escape tokens",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="html-unicode-escape",
                    severity="medium",
                    evidence="Payload delivered as HTML entity or JS Unicode escape stream",
                ),
            ],
        )


DecoderRegistry.register(HtmlUnicodeEscapeDecoder())
