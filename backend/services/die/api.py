"""
DIE · orchestrator
──────────────────
Single-entry ``analyze(...)`` API used by the FastAPI router and the
internal recursive pipeline.  Dispatches to the right sub-analyzer
based on a lightweight language signal, then merges outputs into a
uniform envelope so callers never have to branch on language.
"""
from __future__ import annotations
import re
from typing import Any, Dict, Optional

from .powershell_ast import parse_powershell
from .lolbas import lolbas_lookup
from .ioc_semantic import extract_iocs, summarize_iocs

# ── language detector ─────────────────────────────────────────────
_PS_HINTS = re.compile(
    r"(?i)"
    r"(powershell(\.exe)?\s|-encodedcommand|-nop|iex\s|invoke-expression|"
    r"invoke-webrequest|new-object\s+system\.net|invoke-restmethod|"
    r"\$env:|\[system\.\w+]::|frombase64string)"
)
_CMD_HINTS = re.compile(
    r"(?i)(^|\s)(cmd\.exe|\bset\s+[A-Z_]+=|%[A-Z_]+%|\bfor\s+/[a-z]|\bcall\s+|\bstart\s+/)"
)
_JS_HINTS = re.compile(
    r"(?i)(new\s+ActiveXObject|WScript\.Shell|createobject\(|eval\(|"
    r"function\s+\w+\s*\(|=>\s*\{|require\(|\.prototype\.|document\.write)"
)
_VBS_HINTS = re.compile(
    r"(?i)(\bDim\s+\w+|Set\s+\w+\s*=\s*Create[Oo]bject|End\s+Sub|End\s+Function|"
    r"On\s+Error\s+Resume|WScript\.CreateObject)"
)
_BASH_HINTS = re.compile(
    r"(?i)(^#!\s*/(bin|usr).*sh|\becho\s+-n\s+|curl\s+-|wget\s+|/bin/sh\b|/bin/bash\b)"
)


def detect_language(src: str) -> str:
    """Return one of ``powershell|cmd|javascript|vbscript|bash|unknown``.

    Deterministic priority order: PowerShell dominates when both PS
    and CMD hints exist (the majority of dual-string launchers wrap
    PowerShell). This ordering is stable so repeated runs match.
    """
    if not src:
        return "unknown"
    if _PS_HINTS.search(src):
        return "powershell"
    # VBScript checked before JavaScript because `createobject(` triggers
    # both — but Dim/Set/End Sub is a VBScript-only signature.
    if _VBS_HINTS.search(src):
        return "vbscript"
    if _JS_HINTS.search(src):
        return "javascript"
    if _CMD_HINTS.search(src):
        return "cmd"
    if _BASH_HINTS.search(src):
        return "bash"
    return "unknown"


def analyze(src: str, language: Optional[str] = None) -> Dict[str, Any]:
    """Single-entry semantic analysis over any command-line input.

    Cycle A ships PowerShell fully.  Non-PowerShell inputs receive a
    minimal envelope with IOC + LOLBAS + language classification so
    downstream analyzers can still act.  Cycle B replaces the stubs
    with real ASTs.
    """
    if not src:
        return _empty_envelope("unknown")
    lang = language or detect_language(src)

    if lang == "powershell":
        ast = parse_powershell(src)
        return {
            "language":  "powershell",
            "ast":       ast,
            "cmdlets":   ast["cmdlets"],
            "lolbins":   ast["lolbins"],
            "techniques": ast["techniques"],
            "iocs":      ast["iocs"],
            "iocs_summary": summarize_iocs(ast["iocs"]),
            "obfuscation_score": ast["complexity"]["obfuscation_score"],
        }

    # Cycle-B fallback for other languages — still returns useful
    # deterministic evidence (LOLBAS + IOC + language flag).
    iocs = extract_iocs(src)
    lolbins = _scan_lolbins(src)
    return {
        "language":         lang,
        "ast":              None,     # populated by Cycle B parsers
        "cmdlets":          [],
        "lolbins":          lolbins,
        "techniques":       _lolbin_techniques(lolbins),
        "iocs":             iocs,
        "iocs_summary":     summarize_iocs(iocs),
        "obfuscation_score": 0,
    }


def analyze_powershell(src: str) -> Dict[str, Any]:
    return analyze(src, language="powershell")


def analyze_command(src: str) -> Dict[str, Any]:
    return analyze(src, language=None)


# ── helpers ───────────────────────────────────────────────────────
def _empty_envelope(lang: str) -> Dict[str, Any]:
    return {
        "language": lang, "ast": None, "cmdlets": [], "lolbins": [],
        "techniques": [], "iocs": [], "iocs_summary": {},
        "obfuscation_score": 0,
    }


def _scan_lolbins(src: str):
    seen: Dict[str, Dict[str, Any]] = {}
    for m in re.finditer(r"[A-Za-z][\w\-]*\.exe", src, re.I):
        entry = lolbas_lookup(m.group(0))
        if entry:
            key = m.group(0).lower()
            seen[key] = {"binary": key, **entry}
    return sorted(seen.values(), key=lambda x: x["binary"])


def _lolbin_techniques(lolbins):
    seen: Dict[str, Dict[str, str]] = {}
    for lb in lolbins:
        for t in lb.get("mitre", []) or []:
            seen[t] = {"id": t, "name": "", "evidence": f"LOLBAS: {lb['binary']}"}
    return sorted(seen.values(), key=lambda x: x["id"])
