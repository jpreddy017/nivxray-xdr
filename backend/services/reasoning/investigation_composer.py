"""
Deterministic Investigation Summary composer (P2 preview).

Consumes a raw input (typically the workspace INPUT text) and produces
every analyst-facing narrative section the workspace was missing:

  1. Classification              — one-line label + confidence tier
  2. Overall Assessment          — 3–4 sentence paragraph
  3. Observed Behaviors           — literal evidence the pipeline saw
  4. Inferred Objectives          — behavior → likely attacker goal
  5. Kill Chain (MITRE ordering)  — deduped by behavior + tactic
  6. MITRE ATT&CK Techniques      — with corroborating evidence count
  7. Attack Story                 — narrative sentence per kill-chain phase
  8. Recommendations              — behavior-driven hunt list
  9. Investigation Conclusion     — TL;DR for the SOC ticket

Deterministic — pure projection of the behavior graph. No LLM.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from services.normalization.powershell_folding import fold_text
from services.reasoning.behavior_extractor import (
    correlate_behaviors, extract_behaviors, to_lane_map, to_mitre_techniques,
)

# ─── Behavior → inferred objective mapping (deterministic) ────────────
_OBJECTIVE_MAP: Dict[str, str] = {
    "execution_policy_bypass":    "Bypass local PowerShell script-signing enforcement",
    "hidden_window":              "Reduce user-visible signals during execution",
    "encoded_command":            "Evade static string / signature scanners",
    "in_memory_execution":        "Execute downloaded / decoded payload without touching disk",
    "download_cradle":            "Retrieve remote payload from attacker infrastructure",
    "wmi_process_creation":       "Spawn processes via WMI to bypass command-line auditing",
    "service_enumeration":        "Enumerate services for follow-on targeting / persistence",
    "proxy_credential_theft":     "Reuse cached user credentials to blend with legit traffic",
    "string_concat_obfuscation":  "Hide identifiers from static string matchers",
    "variable_alias_hiding":      "Assign class references to variables to bypass name-based detection",
}

# ─── Behavior → hunt / detection recommendation ───────────────────────
_RECOMMENDATION_MAP: Dict[str, str] = {
    "execution_policy_bypass":
        "Alert on `powershell.exe -ExecutionPolicy Bypass` / `-EP Bypass` in ScriptBlockLogging (EID 4104).",
    "hidden_window":
        "Alert on PowerShell processes launched with `-WindowStyle Hidden` — nearly always attacker-driven.",
    "encoded_command":
        "Decode every `-EncodedCommand` blob at ingest; alert on repeated occurrences per host.",
    "in_memory_execution":
        "Hunt `Invoke-Expression` / `IEX` following any base64 decode within a single event chain (EID 4104).",
    "download_cradle":
        "Alert on `System.Net.WebClient.DownloadString` / `Invoke-WebRequest` originating from `powershell.exe`.",
    "wmi_process_creation":
        "Correlate EID 4688 (child cmd.exe) with `Invoke-WmiMethod Win32_Process Create` in EID 4104.",
    "service_enumeration":
        "Baseline `Get-Service` frequency per host; alert on interactive shells enumerating > 5 hosts / hour.",
    "proxy_credential_theft":
        "Alert when `[Net.CredentialCache]::DefaultCredentials` is assigned to a WebClient.Proxy.",
    "string_concat_obfuscation":
        "Flag any script with ≥ 3 adjacent `'x'+'y'` chains — legitimate scripts rarely require this.",
    "variable_alias_hiding":
        "Alert on `Set-Item Variable:X` immediately followed by `[Type]([Type]::…)` cast.",
}


def _classify_severity(behaviors) -> Dict[str, Any]:
    """Deterministic classification tier from behavior mix."""
    ids = {b.id for b in behaviors}
    n = len(ids)
    # Two independent execution / delivery signals + defense evasion → Malicious
    signals = 0
    for combo in ("in_memory_execution", "download_cradle"):
        signals += combo in ids
    signals += ("encoded_command" in ids) + ("execution_policy_bypass" in ids)
    if signals >= 3 and n >= 5:
        return {"label": "Malicious PowerShell Execution Chain", "tier": "High"}
    if signals >= 2:
        return {"label": "Suspicious PowerShell Execution Chain", "tier": "Medium"}
    if n >= 1:
        return {"label": "Anomalous PowerShell Activity",         "tier": "Low"}
    return {"label": "Undetermined",                                "tier": "Info"}


def _overall_assessment(behaviors, command_count: int) -> str:
    ids = {b.id for b in behaviors}
    lanes = to_lane_map(behaviors)
    phrases: List[str] = []
    if "encoded_command" in ids:      phrases.append("Base64-encoded payloads")
    if "execution_policy_bypass" in ids: phrases.append("execution-policy bypass")
    if "in_memory_execution" in ids:  phrases.append("in-memory execution via Invoke-Expression")
    if "download_cradle" in ids:      phrases.append("remote payload retrieval via WebClient / DownloadString")
    if "hidden_window" in ids:        phrases.append("hidden PowerShell windows")
    if "wmi_process_creation" in ids: phrases.append("WMI-based process creation")
    if "service_enumeration" in ids:  phrases.append("service enumeration")
    if "string_concat_obfuscation" in ids or "variable_alias_hiding" in ids:
        phrases.append("string-concatenation and variable-alias obfuscation")
    parts = ", ".join(phrases[:-1]) + (", and " + phrases[-1] if len(phrases) > 1 else phrases[0]) \
            if phrases else "no distinctive behaviors"
    return (
        f"{command_count} PowerShell command(s) were analyzed. The chain exhibits "
        f"{parts}. Behaviors span {len(lanes)} kill-chain phase(s), producing "
        f"{len(behaviors)} deduplicated behavior node(s) across "
        f"{sum(len(b.evidence) for b in behaviors)} evidence item(s)."
    )


def _attack_story(behaviors) -> List[str]:
    """One sentence per kill-chain phase, ordered."""
    lanes = to_lane_map(behaviors)
    _ORDER = ["Reconnaissance", "Delivery", "Execution", "Defense Evasion",
              "Credential Access", "Discovery", "Lateral Movement",
              "Command and Control", "Actions on Objectives", "Impact"]
    story: List[str] = []
    for phase in _ORDER:
        if phase not in lanes:
            continue
        titles = ", ".join(b.title for b in lanes[phase])
        story.append(f"**{phase}** — {titles}.")
    return story


def _inferred_objectives(behaviors) -> List[str]:
    seen = set()
    out: List[str] = []
    for b in behaviors:
        obj = _OBJECTIVE_MAP.get(b.id)
        if obj and obj not in seen:
            out.append(obj); seen.add(obj)
    return out


def _recommendations(behaviors) -> List[str]:
    seen = set()
    out: List[str] = []
    for b in behaviors:
        rec = _RECOMMENDATION_MAP.get(b.id)
        if rec and rec not in seen:
            out.append(rec); seen.add(rec)
    # Add generic IOC recommendations if any URLs / IPs were behavior-adjacent.
    return out


def compose_investigation_summary(text: str) -> Dict[str, Any]:
    """Full deterministic composer.  Accepts raw workspace input."""
    if not isinstance(text, str) or not text.strip():
        return {"error": "empty_input"}

    # Line-level extraction so evidence carries a stable location.
    lines   = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        lines = [text]
    per_line = [
        extract_behaviors(ln, location_prefix=f"cmd.{i+1}")
        for i, ln in enumerate(lines)
    ]
    merged     = correlate_behaviors(per_line)
    lanes      = to_lane_map(merged)
    mitre      = to_mitre_techniques(merged)
    folded     = [fold_text(ln) for ln in lines]

    classification = _classify_severity(merged)
    return {
        "classification":       classification,
        "confidence":           {
            "score": min(99, 60 + 4 * len(merged)),  # deterministic tier
            "tier":  classification["tier"],
        },
        "overall_assessment":   _overall_assessment(merged, len(lines)),
        "observed_behaviors": [
            {
                "id":               b.id,
                "title":            b.title,
                "kill_chain":       b.kill_chain,
                "mitre_techniques": b.mitre_techniques,
                "mitre_tactic":     b.mitre_tactic,    # deprecated (kept for old UI)
                "mitre_tactics":    b.mitre_tactics,   # canonical R8
                "severity":         b.severity,
                "order":            b.order,
                "confidence":       b.confidence,
                "description":      b.description,
                "evidence": [
                    {"text": e.text, "location": e.location} for e in b.evidence
                ],
            }
            for b in merged
        ],
        "inferred_objectives":  _inferred_objectives(merged),
        "kill_chain_lanes":     {
            phase: [
                {"id": b.id, "title": b.title, "confidence": b.confidence,
                 "mitre": b.mitre_techniques}
                for b in bs
            ]
            for phase, bs in lanes.items()
        },
        "mitre_techniques":     mitre,
        "attack_story":         _attack_story(merged),
        "recommendations":      _recommendations(merged),
        "conclusion":           (
            f"Classification: {classification['label']}. "
            f"Confidence: {classification['tier']}. "
            f"{len(merged)} distinct behavior(s) across "
            f"{len(lanes)} kill-chain phase(s). "
            f"{len(mitre)} MITRE ATT&CK technique(s) identified. "
            f"Recommend immediate hunt on the domains / URLs / hashes "
            f"observed in the source commands."
        ),
        "folded_input":         "\n".join(folded),
        "line_count":           len(lines),
    }
