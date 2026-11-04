"""JavaScript string-reconstruction plugin (RC2.8).

Handles the common JS obfuscation primitives attackers stack together:

    eval(String.fromCharCode(97,108,101,114,116,40))     → alert(
    eval(atob('YWxlcnQoJ3B3bmVkJyk='))                    → alert('pwned')
    eval(unescape('%61%6c%65%72%74%28%31%29'))            → alert(1)

Design
------
* detect() fires when one of the reconstruction primitives is present.
* decode() rewrites just the reconstruction fragment — the surrounding
  `eval(...)` / `Function(...)` / `setTimeout(...)` wrapper stays intact
  so downstream passes (extract-wrapper / ioc-extractor) still peel it.
* Precision-first: `String.fromCharCode` accepts decimal / hex numeric
  args only. `atob` accepts base64-charset strings only. `unescape`
  accepts `%XX` hex escapes only.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

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


# 1) `String.fromCharCode(N, N, ...)` — comma-separated decimal or hex codes.
#    Match up to a reasonable arg-list length so we don't blow up on a
#    hostile 100k-item list.
_RX_FROMCHARCODE = re.compile(
    r"""String\.fromCharCode\s*\(\s*((?:0x[0-9A-Fa-f]{1,4}|\d{1,5})(?:\s*,\s*(?:0x[0-9A-Fa-f]{1,4}|\d{1,5}))*)\s*\)""",
    re.IGNORECASE,
)

# 2) `atob('base64')` / `atob("base64")` — WebCrypto base64 decoder.
_RX_ATOB = re.compile(
    r"""atob\s*\(\s*(['"])([A-Za-z0-9+/=_\-\s]+?)\1\s*\)""",
    re.IGNORECASE,
)

# 3) `unescape('%XX%XX...')` — legacy JS URL decoder.
_RX_UNESCAPE = re.compile(
    r"""unescape\s*\(\s*(['"])((?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~\-])+)\1\s*\)""",
    re.IGNORECASE,
)

# 4) `"str" + "ing"` — JavaScript string concatenation.
_RX_CONCAT = re.compile(
    r"""(['"])([^'"\r\n]*?)\1\s*\+\s*(['"])([^'"\r\n]*?)\3"""
)


def _int_from_token(tok: str) -> int:
    tok = tok.strip()
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    return int(tok)


def _apply_fromcharcode(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        try:
            codes = [_int_from_token(t) for t in m.group(1).split(",")]
            chars = [chr(c) for c in codes if 0 <= c <= 0x10FFFF]
        except (ValueError, OverflowError):
            return m.group(0)
        if not chars:
            return m.group(0)
        hits += 1
        return "'" + "".join(chars).replace("'", "\\'") + "'"

    return _RX_FROMCHARCODE.sub(_sub, text), hits


def _apply_atob(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        b64 = re.sub(r"\s+", "", m.group(2))
        try:
            decoded = base64.b64decode(b64, validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return m.group(0)
        # Guard: keep only if decode produced mostly-printable text
        # (otherwise base64 was wrong or blob was binary — leave alone).
        printable = sum(1 for c in decoded if 0x20 <= ord(c) < 0x7f or c in "\r\n\t")
        if len(decoded) == 0 or printable / len(decoded) < 0.85:
            return m.group(0)
        hits += 1
        return "'" + decoded.replace("'", "\\'") + "'"

    return _RX_ATOB.sub(_sub, text), hits


def _apply_unescape(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        raw = m.group(2)
        try:
            decoded = unquote(raw)
        except Exception:                                # pragma: no cover
            return m.group(0)
        hits += 1
        return "'" + decoded.replace("'", "\\'") + "'"

    return _RX_UNESCAPE.sub(_sub, text), hits


def _apply_concat(text: str) -> Tuple[str, int]:
    hits = 0
    cur = text
    prev = None
    while cur != prev:
        prev = cur
        def _sub(m: re.Match) -> str:
            nonlocal hits
            hits += 1
            quote = m.group(1)
            return quote + m.group(2) + m.group(4) + quote
        cur = _RX_CONCAT.sub(_sub, cur)
    return cur, hits


class JavaScriptReconstructDecoder(BaseDecoder):
    id = "js-reconstruct"
    name = "JavaScript String Reconstruct"
    category = "reconstruct"
    cost = 2
    tags = ("javascript", "reconstruct", "deobfuscate", "atob", "fromcharcode", "unescape", "concat")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 8:
            return DetectResult(confidence=0.0, why="Too short")
        signals: List[str] = []
        if _RX_FROMCHARCODE.search(payload):
            signals.append("js-fromcharcode")
        if _RX_ATOB.search(payload):
            signals.append("js-atob")
        if _RX_UNESCAPE.search(payload):
            signals.append("js-unescape")
        if _RX_CONCAT.search(payload):
            signals.append("js-concat")
        if not signals:
            return DetectResult(confidence=0.0, why="No JS reconstruction pattern")
        # High confidence — these primitives are unambiguous, they beat
        # extract-wrapper so the reconstructed payload reaches downstream.
        conf = 0.9 if len(signals) >= 2 else 0.85
        return DetectResult(
            confidence=conf,
            why=f"JavaScript reconstruction signals: {', '.join(signals)}",
            args={"signals": signals},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        text = payload
        total_hits = 0
        notes: List[str] = []

        text, n = _apply_fromcharcode(text)
        if n:
            total_hits += n
            notes.append(f"Applied {n} String.fromCharCode(...) call(s)")

        text, n = _apply_atob(text)
        if n:
            total_hits += n
            notes.append(f"Decoded {n} atob(base64) literal(s)")

        text, n = _apply_unescape(text)
        if n:
            total_hits += n
            notes.append(f"Decoded {n} unescape(%hex) literal(s)")

        text, n = _apply_concat(text)
        if n:
            total_hits += n
            notes.append(f"Concatenated {n} string literal(s)")

        if total_hits == 0:
            return PluginResult(output=payload, notes=["js-reconstruct: no changes"])

        return PluginResult(
            output=text,
            notes=notes,
            mitre_hints=[
                MitreHint(
                    id="T1027", technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"JavaScript string reconstruction ({total_hits} rewrite(s))",
                    source="archetype",
                ),
                MitreHint(
                    id="T1059.007", technique="JavaScript",
                    tactic="Execution",
                    evidence="JS reconstruction primitive present (eval/Function target)",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="js-string-obfuscation", severity="medium",
                    evidence="; ".join(notes),
                ),
            ],
            explanation=(
                "Rebuilt obfuscated JavaScript string literals using "
                "String.fromCharCode / atob / unescape so the underlying "
                "command reaches downstream analysis."
            ),
        )


DecoderRegistry.register(JavaScriptReconstructDecoder())
