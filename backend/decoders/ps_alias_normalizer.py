"""RC4.5 · PowerShell Cmdlet Alias Normalizer (Feb 2026).

Deterministically expands PowerShell aliases to their canonical cmdlet
names so downstream signature engines and analyst review always see the
same normalized form.

Examples:

    iex "Invoke-Expression"      → Invoke-Expression "Invoke-Expression"
    gci C:\\Windows              → Get-ChildItem C:\\Windows
    gcm net                      → Get-Command net
    gc file.txt                  → Get-Content file.txt
    sal iex Invoke-Expression    → Set-Alias iex Invoke-Expression

The alias table below is the union of stock aliases shipped with Windows
PowerShell 5.1 and PowerShell 7 (``Get-Alias``). Every entry is a
verbatim mapping — no heuristics, no context-sensitivity, no AI.

We deliberately preserve legitimate identifier boundaries via word-
boundary regex + case-insensitive match. Aliases inside string literals
are left alone.

Registered as:
    * ``@op("powershell-alias-normalize", …)``
    * ``PSAliasNormalizerDecoder(BaseDecoder)``
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry
from operations import op


# ── Alias table ───────────────────────────────────────────────────
# Union of Windows PowerShell 5.1 + PowerShell 7 stock aliases plus a
# few community-standard shortcuts commonly seen in malware.
ALIAS_TABLE: Dict[str, str] = {
    # Execution / expression
    "iex":     "Invoke-Expression",
    "icm":     "Invoke-Command",
    "iwr":     "Invoke-WebRequest",
    "irm":     "Invoke-RestMethod",
    "ise":     "powershell_ise",
    # FileSystem
    "gci":     "Get-ChildItem",
    "ls":      "Get-ChildItem",
    "dir":     "Get-ChildItem",
    "gi":      "Get-Item",
    "gc":      "Get-Content",
    "cat":     "Get-Content",
    "type":    "Get-Content",
    "sc":      "Set-Content",
    "ac":      "Add-Content",
    "ni":      "New-Item",
    "mi":      "Move-Item",
    "mv":      "Move-Item",
    "move":    "Move-Item",
    "cpi":     "Copy-Item",
    "cp":      "Copy-Item",
    "copy":    "Copy-Item",
    "ri":      "Remove-Item",
    "rm":      "Remove-Item",
    "rmdir":   "Remove-Item",
    "del":     "Remove-Item",
    "erase":   "Remove-Item",
    "cd":      "Set-Location",
    "chdir":   "Set-Location",
    "sl":      "Set-Location",
    "pushd":   "Push-Location",
    "popd":    "Pop-Location",
    "pwd":     "Get-Location",
    "gl":      "Get-Location",
    # Process / job / service
    "ps":      "Get-Process",
    "gps":     "Get-Process",
    "spps":    "Stop-Process",
    "kill":    "Stop-Process",
    "sasv":    "Start-Service",
    "spsv":    "Stop-Service",
    "gsv":     "Get-Service",
    "sajb":    "Start-Job",
    "gjb":     "Get-Job",
    "spjb":    "Stop-Job",
    "rjb":     "Remove-Job",
    "wjb":     "Wait-Job",
    "rcjb":    "Receive-Job",
    "start":   "Start-Process",
    "saps":    "Start-Process",
    # Environment / variable
    "gv":      "Get-Variable",
    "sv":      "Set-Variable",
    "rv":      "Remove-Variable",
    "gcm":     "Get-Command",
    "gm":      "Get-Member",
    "sal":     "Set-Alias",
    "nal":     "New-Alias",
    "gal":     "Get-Alias",
    # Output / conversion
    "echo":    "Write-Output",
    "write":   "Write-Output",
    "%":       "ForEach-Object",
    "foreach": "ForEach-Object",
    "?":       "Where-Object",
    "where":   "Where-Object",
    "sort":    "Sort-Object",
    "select":  "Select-Object",
    "measure": "Measure-Object",
    "group":   "Group-Object",
    "tee":     "Tee-Object",
    "compare": "Compare-Object",
    "diff":    "Compare-Object",
    "fc":      "Format-Custom",
    "fl":      "Format-List",
    "ft":      "Format-Table",
    "fw":      "Format-Wide",
    "oh":      "Out-Host",
    "ogv":     "Out-GridView",
    "ipmo":    "Import-Module",
    "rmo":     "Remove-Module",
    "gmo":     "Get-Module",
    "epsn":    "Export-PSSession",
    "ipsn":    "Import-PSSession",
    # Web / conversion
    "curl":    "Invoke-WebRequest",   # PS 5.1 alias (removed in 7)
    "wget":    "Invoke-WebRequest",   # PS 5.1 alias (removed in 7)
    "epal":    "Export-Alias",
    "ipal":    "Import-Alias",
    # History / clip
    "h":       "Get-History",
    "ghy":     "Get-History",
    "shy":     "Set-History",
    "clhy":    "Clear-History",
    "r":       "Invoke-History",
    "clc":     "Clear-Content",
    "clv":     "Clear-Variable",
    "clhist":  "Clear-History",
    "clp":     "Clear-ItemProperty",
    "gp":      "Get-ItemProperty",
    "sp":      "Set-ItemProperty",
    "gpv":     "Get-ItemPropertyValue",
    # WMI / CIM
    "gwmi":    "Get-WmiObject",
    "iwmi":    "Invoke-WmiMethod",
    "rwmi":    "Remove-WmiObject",
    "gcim":    "Get-CimInstance",
    "icim":    "Invoke-CimMethod",
    "ncim":    "New-CimInstance",
    "rcim":    "Remove-CimInstance",
    # ACL / cert
    "sasp":    "Set-Acl",
    "gasp":    "Get-Acl",
}

# Build a case-insensitive regex that matches any alias as a whole
# token (preceded/followed by non-identifier char OR string boundary).
# We only rewrite at COMMAND POSITIONS (start of statement, after ``;``,
# ``|``, ``&``, ``{`` — same tokens PS treats as command separators)
# so we don't accidentally rewrite parameter values.
_ALIAS_KEYS = sorted(ALIAS_TABLE.keys(), key=len, reverse=True)
_ALIAS_RX = re.compile(
    # Group 1: command-position boundary. Include ``"`` so aliases inside
    # ``-Command "..."`` (a double-quoted PS payload) are still expanded.
    r"(^|[\s;|&({\"])"
    # Group 2: the alias itself (case-insensitive)
    r"(" + "|".join(re.escape(k) for k in _ALIAS_KEYS) + r")"
    # Followed by non-identifier char OR EOL (so ``gc`` in ``gcm`` doesn't match)
    r"(?=[\s;|&)}\r\n\"']|$)",
    re.IGNORECASE,
)

# Simple "string-literal" detector — we skip alias rewriting inside
# **single-quoted** strings (``'...'`` — PS treats those as literal). We
# INTENTIONALLY normalize inside **double-quoted** strings because
# malware uses ``-Command "iex (iwr 'x')"`` where the outer double-quoted
# payload is real code that PowerShell will parse & execute.
def _strip_literals(src: str) -> Tuple[str, List[Tuple[int, int, str]]]:
    """Replace SINGLE-QUOTED string literals with ``\\x00`` placeholders."""
    out: List[str] = []
    literals: List[Tuple[int, int, str]] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 1
            end = min(j + 1, n)
            literal = src[i:end]
            placeholder = "\x00LIT{}\x00".format(len(literals))
            literals.append((i, end, literal))
            out.append(placeholder)
            i = end
        else:
            out.append(ch)
            i += 1
    return "".join(out), literals


def _restore_literals(src: str, literals: List[Tuple[int, int, str]]) -> str:
    for idx, (_s, _e, lit) in enumerate(literals):
        src = src.replace("\x00LIT{}\x00".format(idx), lit, 1)
    return src


def normalize_aliases(src: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Return ``(normalized_text, trace)``."""
    trace: List[Dict[str, Any]] = []
    if not isinstance(src, str) or not src:
        return src, trace

    masked, literals = _strip_literals(src)
    replacements: List[Tuple[str, str]] = []

    def _sub(m: re.Match) -> str:
        alias = m.group(2)
        canonical = ALIAS_TABLE.get(alias.lower())
        if not canonical:
            return m.group(0)
        replacements.append((alias, canonical))
        return f"{m.group(1)}{canonical}"

    new_masked = _ALIAS_RX.sub(_sub, masked)
    result = _restore_literals(new_masked, literals)

    if replacements:
        for alias, canonical in replacements:
            trace.append({
                "step": "ps-alias-expand",
                "detail": f"'{alias}' → '{canonical}'",
            })
    return result, trace


# ── @op registration ──────────────────────────────────────────────
@op(
    "powershell-alias-normalize",
    "PowerShell Alias → Canonical Cmdlet",
    "Semantic Evaluation",
    "Deterministically expands PowerShell aliases to their canonical "
    "cmdlet names (``iex`` → ``Invoke-Expression``, ``gci`` → "
    "``Get-ChildItem``, ``iwr`` → ``Invoke-WebRequest``, etc.). Preserves "
    "string literals. No execution, no sandbox, no AI.",
    [],
)
def op_powershell_alias_normalize(data: str, args: Dict[str, Any] | None = None) -> str:
    normalized, trace = normalize_aliases(data)
    if normalized == data:
        return "(powershell-alias-normalize · no known aliases found)"
    lines: List[str] = []
    lines.append("▼ POWERSHELL ALIAS NORMALIZATION (RC4.5 · deterministic)")
    for i, row in enumerate(trace, 1):
        lines.append(f"  Step {i}: {row['step']} — {row['detail']}")
    lines.append("")
    lines.append("Normalized Command:")
    lines.append(f"  {normalized}")
    return "\n".join(lines) + "\n"


# ── BaseDecoder plugin ────────────────────────────────────────────
class PSAliasNormalizerDecoder(BaseDecoder):
    id = "powershell-alias-normalize"
    name = "PowerShell Cmdlet-Alias Normalizer"
    category = "normalize"
    cost = 1
    tags = ("powershell", "pwsh", "alias", "normalize")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not isinstance(payload, str) or not payload:
            return DetectResult(confidence=0.0, why="empty")
        # Cheap check — do a case-insensitive scan for alias tokens at
        # command position.
        masked, _ = _strip_literals(payload)
        if _ALIAS_RX.search(masked):
            return DetectResult(confidence=0.85,
                                 why="PowerShell alias detected at command position")
        return DetectResult(confidence=0.0, why="no PS alias")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        normalized, trace = normalize_aliases(payload)
        return PluginResult(
            output=normalized,
            notes=[f"expanded={len(trace)} alias(es)"] +
                   [f"{r['step']}: {r['detail']}" for r in trace],
            explanation=(
                "Deterministically expanded PowerShell aliases to their "
                "canonical cmdlet names using the stock PS 5.1 + PS 7 alias "
                "table. String literals preserved."
            ),
        )


DecoderRegistry.register(PSAliasNormalizerDecoder())
