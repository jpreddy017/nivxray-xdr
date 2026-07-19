"""VBScript string-reconstruction plugin (RC2.8).

Handles the classic VBScript primitives:

    Chr(77) & Chr(115) & Chr(103) & Chr(66) & ...    → "MsgBox..."
    ChrW(77) & ChrW(115) & ChrW(103) & ...           → "Msg..." (Unicode)
    CreateObject("WScript.Shell").Run "cmd.exe ..."  → surfaces WScript.Shell + command

Design
------
* detect() fires when `Chr(N)` concatenation OR `CreateObject("...")` is
  present. Both are strong deobfuscation signals — VBScript-in-the-wild
  almost always uses one or both.
* decode() rewrites just the primitives; the surrounding `Execute()` /
  `Eval()` / `.Run` wrapper stays intact for downstream extractors.
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


# 1) Chained Chr()/ChrW() concatenation.  Match sequences of 2+ Chr(N)
#    calls joined by `&`.  We allow interleaved plain string literals so
#    `Chr(77) & Chr(115) & "Box"` collapses to `"Ms" & "Box"` cleanly.
_RX_CHR_CHAIN = re.compile(
    r"""(?:Chr[Ww]?\s*\(\s*\d{1,5}\s*\)\s*&?\s*){2,}""",
    re.IGNORECASE,
)
_RX_CHR_SINGLE = re.compile(r"""Chr[Ww]?\s*\(\s*(\d{1,5})\s*\)""", re.IGNORECASE)

# 2) CreateObject("ProgID").Method — the classic COM invocation entry
#    point. Detection only; reveal happens by keeping the ProgID visible
#    in output alongside any downstream .Run "cmd..." argument.
_RX_CREATE_OBJECT = re.compile(
    r"""CreateObject\s*\(\s*(['"])([A-Za-z_][A-Za-z0-9_.]*)\1\s*\)""",
    re.IGNORECASE,
)


def _collapse_chr_chain(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        codes = [int(x) for x in _RX_CHR_SINGLE.findall(m.group(0))]
        try:
            chars = [chr(c) for c in codes if 0 <= c <= 0x10FFFF]
        except (ValueError, OverflowError):
            return m.group(0)
        if not chars:
            return m.group(0)
        hits += 1
        return '"' + "".join(chars).replace('"', '""') + '"'

    return _RX_CHR_CHAIN.sub(_sub, text), hits


def _reveal_createobject(text: str) -> Tuple[str, int]:
    """Emit each CreateObject ProgID as a plain-text token so IOC/MITRE
    extractors can key on `WScript.Shell`, `Scripting.FileSystemObject`,
    `MSXML2.XMLHTTP`, etc.  Uses the same `<#=> ... <#=>` marker as the
    ps-reconstruct / cmd-reconstruct reveal for consistency."""
    hits = 0
    pieces: List[str] = []
    last = 0
    for m in _RX_CREATE_OBJECT.finditer(text):
        prog = m.group(2)
        pieces.append(text[last:m.end()])
        pieces.append(f" <#=> {prog} <#=>")
        last = m.end()
        hits += 1
    if hits == 0:
        return text, 0
    pieces.append(text[last:])
    return "".join(pieces), hits


class VBScriptReconstructDecoder(BaseDecoder):
    id = "vbs-reconstruct"
    name = "VBScript String Reconstruct"
    category = "reconstruct"
    cost = 2
    tags = ("vbscript", "reconstruct", "deobfuscate", "chr", "createobject")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 8:
            return DetectResult(confidence=0.0, why="Too short")
        signals: List[str] = []
        if _RX_CHR_CHAIN.search(payload):
            signals.append("vbs-chr-chain")
        if _RX_CREATE_OBJECT.search(payload):
            signals.append("vbs-createobject")
        if not signals:
            return DetectResult(confidence=0.0, why="No VBScript reconstruction pattern")
        # VBScript primitives are unambiguous. Confidence must beat
        # extract-wrapper's cmd /c heuristic (0.95) when a CreateObject
        # ProgID is present — otherwise VBS-hosted `cmd.exe /c ...` gets
        # peeled as a plain CMD wrapper and the ProgID vanishes.
        conf = 0.97 if len(signals) >= 2 else (0.96 if "vbs-createobject" in signals else 0.85)
        return DetectResult(
            confidence=conf,
            why=f"VBScript reconstruction signals: {', '.join(signals)}",
            args={"signals": signals},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        text = payload
        total_hits = 0
        notes: List[str] = []

        text, n = _collapse_chr_chain(text)
        if n:
            total_hits += n
            notes.append(f"Collapsed {n} Chr()/ChrW() chain(s)")

        text, n = _reveal_createobject(text)
        if n:
            total_hits += n
            notes.append(f"Revealed {n} CreateObject ProgID(s)")

        if total_hits == 0:
            return PluginResult(output=payload, notes=["vbs-reconstruct: no changes"])

        return PluginResult(
            output=text,
            notes=notes,
            mitre_hints=[
                MitreHint(
                    id="T1027", technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"VBScript string reconstruction ({total_hits} rewrite(s))",
                    source="archetype",
                ),
                MitreHint(
                    id="T1059.005", technique="Visual Basic",
                    tactic="Execution",
                    evidence="VBScript reconstruction primitive present (Chr/CreateObject)",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="vbs-string-obfuscation", severity="medium",
                    evidence="; ".join(notes),
                ),
            ],
            explanation=(
                "Rebuilt obfuscated VBScript string literals using Chr()/ChrW() "
                "concatenation and surfaced CreateObject ProgIDs for downstream "
                "analysis."
            ),
        )


DecoderRegistry.register(VBScriptReconstructDecoder())
