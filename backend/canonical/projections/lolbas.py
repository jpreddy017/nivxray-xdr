"""project_lolbas — canonical LOLBAS projection.

Reads command evidence nodes and detects known Living-off-the-Land
binaries. Pure function; byte_identity comparison.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ._helpers import command_nodes


# Canonical LOLBAS set (deterministic; alphabetical).
_LOLBAS = {
    "bitsadmin",
    "certutil",
    "cmd",
    "cscript",
    "mshta",
    "powershell",
    "regsvr32",
    "rundll32",
    "wmic",
    "wscript",
}


def project_lolbas(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """LOLBAS matches derived from command evidence.

    Output shape:
        {
          "binaries": ["<binary>", ...],           # sorted-unique
          "matches":  [                             # per-node hits
            {"binary": "...", "snippet": "...",
             "evidence_id": "ev.cmd.0000"}, ...
          ]
        }
    Empty when no command nodes reference a LOLBAS binary.
    """
    binaries: List[str] = []
    matches: List[Dict[str, Any]] = []

    for n in command_nodes(ssot):
        tool = str(n.attrs.get("tool", "")).lower()
        if tool in _LOLBAS:
            if tool not in binaries:
                binaries.append(tool)
            matches.append({
                "binary": tool,
                "snippet": n.label,
                "evidence_id": n.id,
            })

    return {
        "binaries": sorted(binaries),
        "matches": matches,
    }
