"""Workspace Interpreter Ownership — structural, not keyword-based.

Owner directive 2026-02-XX (Workspace Recovery Directive · Path B):
Workspace must decide interpreter ownership by **structural evidence**,
not by "does the literal word `powershell` appear anywhere in the
input?" scans. Comments, string literals, URLs, and rendered narratives
that happen to mention an interpreter name must never influence
ownership.

Historical design flaw (present since ≥ July 29):
    `\\b(powershell|pwsh)\\b` regex on whole src → fires on
    `# powershell rewrite\\necho hi | tr ...` and rewrites Bash
    aliases as if the whole payload were PowerShell.

Structural rules (this module):
    1. Shebang            (#!/bin/bash, #!/usr/bin/env python …)
    2. Leading launcher   (bash / powershell / cmd / python / …
                           as first non-whitespace, non-comment token)
    3. Bash grammar       ($(...) or `...` at pos 0; VAR=… command;
                           if [ / for … in / while [)
    4. Bash-only utils    (tr, awk, sed, grep, openssl, curl, wget,
                           xxd, base64, tar, gzip) at command position
    5. PS command verbs   (Invoke-Expression / Get-* / Set-* /
                           New-Object / IEX / Invoke-WebRequest /
                           iwr) at command position — checked against
                           source with comments & string literals
                           masked out
    6. CMD grammar        (cmd /c leading; %VAR% expansions; set VAR=)
    7. Default            UNKNOWN

Returns a typed `InterpreterOwnership` with the winning interpreter,
confidence in [0..1], the ordered list of rules that fired, and the
deterministic structural evidence snippets.

This module has ZERO imports from `backend/decoders/`,
`backend/nivxforge/`, or `backend/operations.py`. Only stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


# ── Interpreter enum ─────────────────────────────────────────────────

class Interpreter(str, Enum):
    BASH        = "bash"
    POWERSHELL  = "powershell"
    CMD         = "cmd"
    PYTHON      = "python"
    UNKNOWN     = "unknown"


# ── Result dataclasses ───────────────────────────────────────────────

@dataclass(frozen=True)
class OwnershipRule:
    """One structural test that contributed to (or refuted) ownership."""

    name: str            # "shebang" / "launcher_token" / …
    matched: bool
    interpreter: Interpreter
    strength: float      # 0..1 — how strong a signal this rule is
    detail: str          # deterministic explanation


@dataclass(frozen=True)
class InterpreterOwnership:
    interpreter: Interpreter
    confidence: float
    rules_fired: Tuple[OwnershipRule, ...]
    structural_evidence: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "interpreter": self.interpreter.value,
            "confidence": self.confidence,
            "rules_fired": [
                {"name": r.name, "matched": r.matched,
                 "interpreter": r.interpreter.value,
                 "strength": r.strength, "detail": r.detail}
                for r in self.rules_fired
            ],
            "structural_evidence": list(self.structural_evidence),
        }


# ── Masking: strip comments + string literals + URLs ────────────────

_STRING_LITERAL_RE = re.compile(
    r"""("([^"\\]|\\.)*"|'([^'\\]|\\.)*')""", re.DOTALL,
)
_URL_RE = re.compile(r"\bhttps?://[^\s'\"`|;&<>]+", re.IGNORECASE)
_BASH_LINE_COMMENT_RE = re.compile(r"(^|\s)#[^\n]*", re.MULTILINE)


def _mask(src: str) -> str:
    """Replace comments, string literals and URLs with placeholders of
    equal length so downstream position math is preserved. Deterministic."""
    if not src:
        return ""
    masked = _STRING_LITERAL_RE.sub(
        lambda m: "\x00" * len(m.group(0)), src)
    masked = _URL_RE.sub(
        lambda m: "\x01" * len(m.group(0)), masked)
    masked = _BASH_LINE_COMMENT_RE.sub(
        lambda m: m.group(1) + "\x02" * (len(m.group(0)) - len(m.group(1))),
        masked)
    return masked


# ── Launcher / grammar dictionaries ─────────────────────────────────

_LAUNCHER_MAP: dict = {
    # Bash family
    "bash": Interpreter.BASH, "sh": Interpreter.BASH,
    "zsh": Interpreter.BASH, "ksh": Interpreter.BASH,
    "dash": Interpreter.BASH,
    # PowerShell family
    "powershell": Interpreter.POWERSHELL,
    "powershell.exe": Interpreter.POWERSHELL,
    "pwsh": Interpreter.POWERSHELL,
    "pwsh.exe": Interpreter.POWERSHELL,
    # CMD family
    "cmd": Interpreter.CMD, "cmd.exe": Interpreter.CMD,
    # Python / interpreters
    "python": Interpreter.PYTHON, "python3": Interpreter.PYTHON,
    "python.exe": Interpreter.PYTHON,
    "perl": Interpreter.PYTHON,   # collapse "scripting" bucket
    "ruby": Interpreter.PYTHON, "node": Interpreter.PYTHON,
}

# Bash-only utilities. If any of these appears as the head of a
# command in the pipeline, that alone is strong Bash evidence.
_BASH_ONLY_UTILS: frozenset = frozenset({
    "tr", "awk", "sed", "grep", "cut", "head", "tail", "wc",
    "openssl", "curl", "wget", "xxd", "base64", "od", "hexdump",
    "tar", "gzip", "gunzip", "zcat", "chmod", "chown",
})

# PowerShell command-position verbs. Case-insensitive; must appear at
# start of a command (start of masked source or after `;` `|` `&&`).
_PS_COMMAND_VERBS = re.compile(
    r"(?im)(?:^|[;|&\n])\s*("
    r"Invoke-Expression|IEX|Invoke-WebRequest|iwr|"
    r"Get-[A-Za-z]+|Set-[A-Za-z]+|New-Object|Add-Type|"
    r"Import-Module|Start-Process|Write-Host|Write-Output|"
    r"Out-String|ConvertTo-[A-Za-z]+|ConvertFrom-[A-Za-z]+"
    r")\b",
)

# CMD grammar hints on masked source.
_CMD_PERCENT_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")
_CMD_SET_ASSIGN = re.compile(r"(?im)^\s*set\s+[A-Za-z_][A-Za-z0-9_]*=")

# Bash variable assignment then command:  KEY=value cmd
_BASH_VAR_ASSIGN_CMD = re.compile(
    r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+\S")

_BASH_CTRL_KWS = re.compile(
    r"(?m)^\s*(?:if|for|while|case|until)\s")

_SHEBANG_INTERPRETER: dict = {
    "bash": Interpreter.BASH, "sh": Interpreter.BASH,
    "zsh": Interpreter.BASH, "ksh": Interpreter.BASH,
    "dash": Interpreter.BASH,
    "python": Interpreter.PYTHON,
    "pwsh": Interpreter.POWERSHELL,
}


# ── Rule helpers ─────────────────────────────────────────────────────

def _first_command_token(masked: str) -> Optional[str]:
    """First non-whitespace, non-comment token — the leading command."""
    m = re.search(r"[^\s\x00\x01\x02;&|]+", masked)
    if not m:
        return None
    head = m.group(0).lower()
    if "/" in head:
        head = head.rsplit("/", 1)[-1]
    if "\\" in head:
        head = head.rsplit("\\", 1)[-1]
    return head


def _pipeline_heads(masked: str) -> List[str]:
    """Head token of every command in the pipeline (split by `;` `|`
    `&&` `||`). Used to detect bash-only utils anywhere in the chain."""
    heads: List[str] = []
    # Replace pipe-separators with a common delimiter, then split.
    tmp = re.sub(r"(\|\||\&\&|[;|])", "\x03", masked)
    for chunk in tmp.split("\x03"):
        m = re.search(r"[^\s\x00\x01\x02]+", chunk)
        if not m:
            continue
        h = m.group(0).lower()
        if "/" in h:
            h = h.rsplit("/", 1)[-1]
        heads.append(h)
    return heads


# ── Individual structural rules ──────────────────────────────────────

def _rule_shebang(src: str) -> Optional[OwnershipRule]:
    stripped = src.lstrip()
    if not stripped.startswith("#!"):
        return None
    line = stripped.split("\n", 1)[0].lower()
    for name, interp in _SHEBANG_INTERPRETER.items():
        if name in line:
            return OwnershipRule(
                name="shebang", matched=True, interpreter=interp,
                strength=1.0,
                detail=f"shebang line references {name!r}")
    return None


def _rule_launcher_token(masked: str) -> Optional[OwnershipRule]:
    head = _first_command_token(masked)
    if not head:
        return None
    if head in _LAUNCHER_MAP:
        interp = _LAUNCHER_MAP[head]
        return OwnershipRule(
            name="launcher_token", matched=True, interpreter=interp,
            strength=0.95,
            detail=f"leading launcher token {head!r}")
    return None


def _rule_bash_grammar_leading(masked: str) -> Optional[OwnershipRule]:
    stripped = masked.lstrip()
    if stripped.startswith("$(") or stripped.startswith("`"):
        return OwnershipRule(
            name="bash_grammar_leading", matched=True,
            interpreter=Interpreter.BASH, strength=0.9,
            detail="leading Bash grammar $( or `")
    if _BASH_VAR_ASSIGN_CMD.search(masked[:200]):
        return OwnershipRule(
            name="bash_grammar_leading", matched=True,
            interpreter=Interpreter.BASH, strength=0.85,
            detail="Bash-style KEY=value command assignment")
    if _BASH_CTRL_KWS.search(masked[:400]):
        return OwnershipRule(
            name="bash_grammar_leading", matched=True,
            interpreter=Interpreter.BASH, strength=0.85,
            detail="Bash control keyword at start of line")
    return None


def _rule_bash_only_utils(masked: str) -> Optional[OwnershipRule]:
    for head in _pipeline_heads(masked):
        if head in _BASH_ONLY_UTILS:
            return OwnershipRule(
                name="bash_only_util", matched=True,
                interpreter=Interpreter.BASH, strength=0.7,
                detail=f"pipeline contains bash-only util {head!r}")
    return None


def _rule_ps_command_verb(masked: str) -> Optional[OwnershipRule]:
    m = _PS_COMMAND_VERBS.search(masked)
    if not m:
        return None
    return OwnershipRule(
        name="ps_command_verb", matched=True,
        interpreter=Interpreter.POWERSHELL, strength=0.85,
        detail=f"PS verb {m.group(1)!r} at command position")


def _rule_cmd_grammar(masked: str) -> Optional[OwnershipRule]:
    if _CMD_SET_ASSIGN.search(masked):
        return OwnershipRule(
            name="cmd_grammar", matched=True,
            interpreter=Interpreter.CMD, strength=0.85,
            detail="`set VAR=` assignment at line start")
    if _CMD_PERCENT_VAR.search(masked):
        return OwnershipRule(
            name="cmd_grammar", matched=True,
            interpreter=Interpreter.CMD, strength=0.6,
            detail="%VAR% expansion")
    return None


# ── Public API ───────────────────────────────────────────────────────

def detect(src: str) -> InterpreterOwnership:
    """Return the interpreter that owns `src` on structural evidence
    alone. Deterministic — same input → identical output.

    Ranking:
        1. shebang            → returns immediately (1.0)
        2. launcher_token     → returns immediately (0.95)
        3. bash_grammar_leading → strong Bash signal (0.85–0.90)
        4. bash_only_util     → Bash signal (0.70)
        5. ps_command_verb    → PS signal (0.85)
        6. cmd_grammar        → CMD signal (0.60–0.85)
        7. UNKNOWN            → 0.0
    """
    if not isinstance(src, str) or not src.strip():
        return InterpreterOwnership(
            interpreter=Interpreter.UNKNOWN,
            confidence=0.0,
            rules_fired=(),
            structural_evidence=(),
        )

    fired: List[OwnershipRule] = []
    evidence: List[str] = []

    # (1) Shebang — checked against the raw source, not the mask
    #     (the "#!" marker is a comment-shaped construct that we
    #     specifically want to see).
    sheb = _rule_shebang(src)
    if sheb:
        fired.append(sheb)
        evidence.append(src.lstrip().split("\n", 1)[0][:120])
        return InterpreterOwnership(
            interpreter=sheb.interpreter,
            confidence=sheb.strength,
            rules_fired=tuple(fired),
            structural_evidence=tuple(evidence),
        )

    masked = _mask(src)

    # (2) Launcher token — decisive on its own.
    launcher = _rule_launcher_token(masked)
    if launcher:
        fired.append(launcher)
        evidence.append(masked.lstrip().split(None, 1)[0][:60])
        return InterpreterOwnership(
            interpreter=launcher.interpreter,
            confidence=launcher.strength,
            rules_fired=tuple(fired),
            structural_evidence=tuple(evidence),
        )

    # (3) Bash leading grammar.
    grammar = _rule_bash_grammar_leading(masked)
    if grammar:
        fired.append(grammar)
        evidence.append(masked[:120].strip())

    # (4) Bash-only utility in pipeline.
    util = _rule_bash_only_utils(masked)
    if util:
        fired.append(util)
        heads = _pipeline_heads(masked)
        evidence.append(f"pipeline heads: {heads[:6]}")

    # (5) PS command-position verb.
    ps = _rule_ps_command_verb(masked)
    if ps:
        fired.append(ps)

    # (6) CMD grammar.
    cmdr = _rule_cmd_grammar(masked)
    if cmdr:
        fired.append(cmdr)

    # Combine — pick the interpreter with the highest total strength.
    if not fired:
        return InterpreterOwnership(
            interpreter=Interpreter.UNKNOWN,
            confidence=0.0,
            rules_fired=(),
            structural_evidence=(),
        )

    tally: dict = {}
    for r in fired:
        tally[r.interpreter] = tally.get(r.interpreter, 0.0) + r.strength

    winner_interp, winner_score = max(tally.items(), key=lambda kv: kv[1])
    total = sum(tally.values())
    confidence = winner_score / total if total > 0 else 0.0

    return InterpreterOwnership(
        interpreter=winner_interp,
        confidence=round(confidence, 4),
        rules_fired=tuple(fired),
        structural_evidence=tuple(evidence),
    )


def is_powershell(src: str) -> bool:
    """Sugar for the two call sites in `routers/ops.py` that currently
    use `\\b(powershell|pwsh)\\b` keyword scans. Returns True only when
    the structural detector concludes PowerShell ownership with at
    least moderate confidence."""
    result = detect(src)
    return (result.interpreter == Interpreter.POWERSHELL
            and result.confidence >= 0.5)


__all__ = [
    "Interpreter", "OwnershipRule", "InterpreterOwnership",
    "detect", "is_powershell",
]
