"""PowerShell string-reconstruction plugin.

Handles common obfuscation patterns that rebuild a plaintext command from
character arithmetic without any encoding transform:

    [char]0x49 + [char]0x45 + [char]0x58                       → "IEX"
    [char]73 + [char]69 + [char]88                             → "IEX"
    [char[]](73,69,88) -join ''                                → "IEX"
    'IX' -f 'E' style                                          → best-effort
    'p'+'o'+'w'+'ers'+'hell'                                   → "powershell"
    -join ('IEX'.ToCharArray())                                → passthrough

Design
------
* detect() fires only when at least one of the reconstruction patterns is
  present in the payload — cheap regex scan.
* decode() rewrites *only the reconstruction fragments*, leaving the
  surrounding script structure intact so the next layer (extract_wrapper /
  base64 / hex) can still peel it further.
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


# 1) [char]0xNN or [char]NN  (single-char accessor) — supports chained
#    concatenation like `[char]0x49 + [char]0x45 + [char]0x58` which we
#    collapse to a single quoted string.
_RX_CHAR_CHAIN = re.compile(
    r"""(?:\[\s*char\s*\]\s*(?:0x[0-9A-Fa-f]{1,4}|\d{1,5})\s*\+?\s*){2,}""",
    re.IGNORECASE,
)
_RX_CHAR = re.compile(
    r"""\[\s*char\s*\]\s*(0x[0-9A-Fa-f]{1,4}|\d{1,5})""",
    re.IGNORECASE,
)

# 2) [char[]]  ( 73 , 69 , 88 )  -join ''    (array to string)
_RX_CHAR_ARRAY = re.compile(
    r"""\[\s*char\s*\[\s*\]\s*\]\s*\(\s*([0-9xXA-Fa-f,\s]+?)\s*\)\s*-\s*join\s*(['"])(.*?)\2""",
    re.IGNORECASE | re.DOTALL,
)

# 3) simple string concat 'a'+'b'+'c'
_RX_STR_CONCAT = re.compile(
    r"""(['"])((?:(?!\1).)+?)\1(?:\s*\+\s*(['"])((?:(?!\3).)+?)\3){1,}""",
    re.DOTALL,
)

# 4) PowerShell backtick escapes inside identifiers / keywords: p`ow`e`r`shell
_RX_BACKTICK = re.compile(r"(?<!`)`(?![nrt0abfv`\"'])")


def _int_from_token(tok: str) -> int:
    tok = tok.strip()
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    return int(tok)


def _replace_char_arrays(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        numlist = m.group(1)
        try:
            chars = [chr(_int_from_token(t)) for t in re.split(r"[\s,]+", numlist) if t.strip()]
        except (ValueError, OverflowError):
            return m.group(0)
        hits += 1
        return "'" + "".join(chars).replace("'", "''") + "'"

    return _RX_CHAR_ARRAY.sub(_sub, text), hits


def _replace_char_singletons(text: str) -> Tuple[str, int]:
    hits = 0

    # First pass — collapse chained `[char]NN + [char]MM + ...` into a
    # single quoted literal so downstream regexes see a clean string.
    def _sub_chain(m: re.Match) -> str:
        nonlocal hits
        nums = _RX_CHAR.findall(m.group(0))
        try:
            chars = [chr(_int_from_token(n)) for n in nums]
        except (ValueError, OverflowError):
            return m.group(0)
        hits += 1
        return "'" + "".join(chars).replace("'", "''") + "'"

    text = _RX_CHAR_CHAIN.sub(_sub_chain, text)

    # Second pass — leftover standalone `[char]NN` (not part of a chain).
    def _sub(m: re.Match) -> str:
        nonlocal hits
        try:
            v = _int_from_token(m.group(1))
            if 0 <= v <= 0x10FFFF:
                hits += 1
                return chr(v)
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    return _RX_CHAR.sub(_sub, text), hits


def _replace_str_concat(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        # Grab every quoted fragment in the match
        frags = re.findall(r"""(['"])((?:(?!\1).)+?)\1""", m.group(0), re.DOTALL)
        if len(frags) < 2:
            return m.group(0)
        joined = "".join(f[1] for f in frags)
        hits += 1
        return "'" + joined.replace("'", "''") + "'"

    return _RX_STR_CONCAT.sub(_sub, text), hits


def _strip_ps_backticks(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        hits += 1
        return ""

    return _RX_BACKTICK.sub(_sub, text), hits


class PowerShellReconstructDecoder(BaseDecoder):
    id = "ps-reconstruct"
    name = "PowerShell String Reconstruct"
    category = "reconstruct"
    cost = 2
    tags = ("powershell", "reconstruct", "deobfuscate", "char-arithmetic", "backtick")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 6:
            return DetectResult(confidence=0.0, why="Too short")
        signals: List[str] = []
        if _RX_CHAR_ARRAY.search(payload):
            signals.append("char[]-join")
        if _RX_CHAR.search(payload):
            signals.append("[char]NN")
        # Only count string-concat if it contains at least one non-word bridge
        # (i.e. real obfuscation like 'p'+'o'+'w' → not casual 'x'+'y' text).
        m = _RX_STR_CONCAT.search(payload)
        if m and m.group(0).count("+") >= 2:
            signals.append("str-concat")
        if _RX_BACKTICK.search(payload) and re.search(r"[A-Za-z]`[A-Za-z]", payload):
            signals.append("ps-backtick")
        if not signals:
            return DetectResult(confidence=0.0, why="No PS reconstruction pattern")
        # Confidence: single mild signal is 0.6, multiple is 0.9
        conf = 0.6 if len(signals) == 1 else 0.9
        return DetectResult(
            confidence=conf,
            why=f"PowerShell reconstruction signals: {', '.join(signals)}",
            args={"signals": signals},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        text = payload
        total_hits = 0
        notes: List[str] = []

        text, n = _replace_char_arrays(text)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} [char[]]-join(...) block(s)")

        text, n = _replace_char_singletons(text)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} [char]NN literal(s)")

        text, n = _replace_str_concat(text)
        if n:
            total_hits += n
            notes.append(f"Collapsed {n} string-concat chain(s)")

        text, n = _strip_ps_backticks(text)
        if n:
            total_hits += n
            notes.append(f"Stripped {n} PowerShell backtick escape(s)")

        if total_hits == 0:
            return PluginResult(output=payload, notes=["ps-reconstruct: no changes"])

        return PluginResult(
            output=text,
            notes=notes,
            mitre_hints=[
                MitreHint(
                    id="T1027", technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"PowerShell string reconstruction ({total_hits} rewrite(s))",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="ps-string-obfuscation", severity="medium",
                    evidence="; ".join(notes),
                ),
            ],
            explanation=(
                "Rebuilt obfuscated PowerShell string literals using char-arithmetic / "
                "string-concat / backtick removal so the underlying command surfaces."
            ),
        )


DecoderRegistry.register(PowerShellReconstructDecoder())
