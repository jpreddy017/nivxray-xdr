"""LOLBAS chain + Sigma/KQL export endpoints (L2 · L3 · L5).

Reuses the deterministic `scan_lolbas()` scanner + the new
`compute_lolbas_chain()` helper to expose:

- POST /api/lolbas/chain   {text}                — chain metadata for a payload
- POST /api/lolbas/export  {binary, argv?, fmt}  — Sigma / KQL / SPL rule
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import require_user
from lolbas import scan_lolbas, _ACTIVE  # noqa: F401 — _ACTIVE used only for metadata lookup
from lolbas_chain import compute_lolbas_chain

router = APIRouter()


class ChainIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=200_000)


@router.post("/lolbas/chain")
async def lolbas_chain(body: ChainIn, user=Depends(require_user)):
    """Return LOLBAS chain metadata (stages · parent-child · severity)."""
    hits = scan_lolbas(body.text)
    chain = compute_lolbas_chain(hits, body.text)
    return {"hits": hits, "chain": chain}


class ExportIn(BaseModel):
    binary: str = Field(..., min_length=2, max_length=64)
    argv:   Optional[str] = None
    fmt:    str = Field("sigma", pattern="^(sigma|kql|spl)$")


def _lookup_rule(binary: str) -> Optional[Dict[str, Any]]:
    b = binary.lower()
    for r in _ACTIVE:
        if r["bin"].lower() == b:
            return r
    # allow bare-name match without .exe
    if not b.endswith(".exe"):
        for r in _ACTIVE:
            if r["bin"].lower() == f"{b}.exe":
                return r
    return None


def _yaml_str(s: str) -> str:
    """Escape a string for single-line YAML in a Sigma rule."""
    return "'" + s.replace("'", "''") + "'"


def _extract_argv_hints(argv: Optional[str], rule: Dict[str, Any]) -> List[str]:
    """Return a de-duplicated list of concrete argv token hints for the rule.

    Prefers analyst-supplied `argv` snippet; falls back to concrete tokens
    from the rule's argv regex (words / dashes / paths, no meta-chars).
    """
    src = argv or rule.get("argv") or ""
    # Only keep tokens that read like real substrings — skip regex meta.
    toks: List[str] = []
    for tok in re.split(r"\|", src):
        tok = tok.strip()
        if not tok:
            continue
        if re.search(r"[()\[\]\\?*+^$]", tok):
            # Try to salvage the literal prefix.
            m = re.match(r"^([A-Za-z0-9_/:.\-]+)", tok)
            if not m:
                continue
            tok = m.group(1)
        if tok and tok not in toks:
            toks.append(tok)
    return toks[:8]


def _sigma_rule(binary: str, rule: Dict[str, Any], argv_hints: List[str]) -> str:
    mitre = ", ".join(rule.get("mitre", []) or ["T1218"])
    purposes = ", ".join(rule.get("purposes", []) or ["Execute"])
    hint_lines = "\n".join(f"      - {_yaml_str(h)}" for h in argv_hints) or "      - '# adjust for your environment'"
    return f"""title: LOLBAS · {binary} suspicious command-line
id: nivxray-lolbas-{binary.replace('.', '-').lower()}
status: experimental
description: |
  {rule.get('desc', '(no description)')}
author: NivXRay auto-export
references:
  - {rule.get('url') or 'https://lolbas-project.github.io/'}
tags:
  - attack.execution
  - attack.defense_evasion
{"".join(f"  - attack.{m.lower()}\n" for m in rule.get('mitre', []) or ['T1218']).rstrip()}
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\\{binary}'
  selection_cmd:
    CommandLine|contains:
{hint_lines}
  condition: selection_image and selection_cmd
falsepositives:
  - Legitimate administrative usage of {binary}
  - Software-deployment tooling
level: high
# MITRE ATT&CK: {mitre}
# Purposes:    {purposes}
"""


def _kql_rule(binary: str, argv_hints: List[str]) -> str:
    hints = " or ".join(f'ProcessCommandLine has "{h}"' for h in argv_hints) \
            or 'ProcessCommandLine has "-"'
    return f"""// NivXRay auto-export — Defender Advanced Hunting (KQL)
// Suspicious {binary} invocation
DeviceProcessEvents
| where FileName =~ "{binary}"
| where {hints}
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
"""


def _spl_rule(binary: str, argv_hints: List[str]) -> str:
    hints = " OR ".join(f'CommandLine="*{h}*"' for h in argv_hints) or 'CommandLine="*-*"'
    return f"""# NivXRay auto-export — Splunk SPL
# Suspicious {binary} invocation
index=* sourcetype IN (WinEventLog:Security, Sysmon)
    EventCode IN (1, 4688)
    (Image="*\\\\{binary}" OR NewProcessName="*\\\\{binary}")
    ({hints})
| table _time host user ParentImage Image CommandLine
| sort - _time
"""


@router.post("/lolbas/export")
async def lolbas_export(body: ExportIn, user=Depends(require_user)):
    """Emit a Sigma / KQL / SPL rule for a single LOLBAS finding."""
    rule = _lookup_rule(body.binary)
    if not rule:
        raise HTTPException(status_code=404,
                            detail=f"unknown LOLBAS binary: {body.binary}")
    hints = _extract_argv_hints(body.argv, rule)
    if body.fmt == "sigma":
        content = _sigma_rule(rule["bin"], rule, hints)
    elif body.fmt == "kql":
        content = _kql_rule(rule["bin"], hints)
    else:  # spl
        content = _spl_rule(rule["bin"], hints)
    return {"fmt": body.fmt, "binary": rule["bin"], "content": content,
            "mitre": rule.get("mitre", []),
            "purposes": rule.get("purposes", []),
            "hints_used": hints}
