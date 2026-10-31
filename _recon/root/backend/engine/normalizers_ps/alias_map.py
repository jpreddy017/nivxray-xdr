"""Known PowerShell alias → cmdlet map (baseline set).

Populated from `Get-Alias` output on a stock PS 5.1 + PS 7 host. Analysts
regularly obfuscate command lines with these — the normalizer resolves them
so downstream detectors see the canonical name.

Adding entries here is safe (no schema-version bump); removing / renaming
requires a compliance-report note.
"""
from __future__ import annotations
from typing import Dict


ALIAS_MAP: Dict[str, str] = {
    # Core execution / eval
    "iex":  "Invoke-Expression",
    "icm":  "Invoke-Command",
    "ise":  "powershell_ise",
    "sal":  "Set-Alias",
    "nal":  "New-Alias",
    "%":    "ForEach-Object",
    "foreach": "ForEach-Object",
    "?":    "Where-Object",
    "where": "Where-Object",
    # File ops
    "ls":   "Get-ChildItem",
    "dir":  "Get-ChildItem",
    "gci":  "Get-ChildItem",
    "gc":   "Get-Content",
    "cat":  "Get-Content",
    "type": "Get-Content",
    "sc":   "Set-Content",
    "ac":   "Add-Content",
    "ni":   "New-Item",
    "mi":   "Move-Item",
    "cpi":  "Copy-Item",
    "cp":   "Copy-Item",
    "copy": "Copy-Item",
    "rm":   "Remove-Item",
    "ri":   "Remove-Item",
    "del":  "Remove-Item",
    "mv":   "Move-Item",
    "rni":  "Rename-Item",
    # Text ops
    "echo": "Write-Output",
    "write": "Write-Output",
    "sls":  "Select-String",
    # Networking
    "iwr":  "Invoke-WebRequest",
    "wget": "Invoke-WebRequest",
    "curl": "Invoke-WebRequest",
    "irm":  "Invoke-RestMethod",
    # Process
    "gps":  "Get-Process",
    "ps":   "Get-Process",
    "spps": "Stop-Process",
    "kill": "Stop-Process",
    "start": "Start-Process",
    "saps": "Start-Process",
    # Registry / env
    "gv":   "Get-Variable",
    "sv":   "Set-Variable",
    # Misc
    "select": "Select-Object",
    "sort": "Sort-Object",
    "group": "Group-Object",
    "measure": "Measure-Object",
    "tee":  "Tee-Object",
    "compare": "Compare-Object",
}


def resolve(name: str) -> str:
    """Return the canonical cmdlet for a PS alias (case-insensitive), or the
    input unchanged if it's not a known alias."""
    return ALIAS_MAP.get(name.lower(), name)


# ---------------------------------------------------------------------------
# Known AMSI-bypass fingerprints. When any of these substrings appear on the
# reconstructed command of an ExecNode, the interpreter tags the node with
# `attrs["semantic_tag"] = "amsi_bypass"`. Detectors (Phase 5+) consume this
# tag; verdicts (Phase 7) apply intent+defense_evasion weight — never verdict
# solely from the fingerprint match (§ 12 invariant).
# ---------------------------------------------------------------------------
AMSI_BYPASS_MARKERS = (
    "amsiInitFailed",
    "amsi.dll",
    "AmsiUtils",
    "AmsiScanBuffer",
    "System.Management.Automation.AmsiUtils",
    # obfuscated forms (unicode / concat) — normalizer resolves these to
    # canonical form so this list stays small.
)


ETW_BYPASS_MARKERS = (
    "EtwEventWrite",
    "System.Diagnostics.Eventing.EventProvider",
    "ETW",
)
