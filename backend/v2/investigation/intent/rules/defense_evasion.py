"""defense_evasion · the artefact takes deterministic steps to hide
from defensive tooling (AMSI bypass, ETW patch, Defender tamper,
execution policy bypass, hidden window).
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

_SIGNATURES: list[tuple[re.Pattern, str, str, RiskBand, str]] = [
    (
        re.compile(r"(?i)amsiInitFailed|amsi\s*\.\s*dll|amsiscanbuffer"),
        "AMSI bypass",
        "Disables Anti-Malware Scan Interface so subsequent script "
        "content is not inspected by AV / EDR.",
        RiskBand.HIGH,
        "T1562.001",
    ),
    (
        re.compile(r"(?i)EtwEventWrite|etw\s*\.\s*dll"),
        "ETW patch",
        "Patches Event Tracing for Windows to blind kernel-level "
        "telemetry collection.",
        RiskBand.HIGH,
        "T1562.006",
    ),
    (
        re.compile(r"(?i)Set-MpPreference|Add-MpPreference|"
                    r"Defender\s+.*(?:Disable|Exclusion)"),
        "Defender tamper",
        "Modifies Microsoft Defender policy (disable / add exclusion) "
        "to suppress detection of subsequent execution.",
        RiskBand.HIGH,
        "T1562.001",
    ),
    (
        re.compile(r"(?i)-ExecutionPolicy\s+(?:Bypass|Unrestricted)|"
                    r"-ep\s+(?:bypass|unrestricted)|-exec\s+bypass"),
        "Execution Policy bypass",
        "Runs PowerShell with `-ExecutionPolicy Bypass` so the "
        "script executes without policy checks.",
        RiskBand.MEDIUM,
        "T1059.001",
    ),
    (
        re.compile(r"(?i)-WindowStyle\s+Hidden|-w\s+Hidden|-noni|-noninteractive"),
        "Hidden window",
        "Runs the interpreter with a hidden / non-interactive window "
        "to avoid user awareness of the running process.",
        RiskBand.LOW,
        "T1564.003",
    ),
    (
        re.compile(r"(?i)\[Ref\]\.Assembly\.GetType|System\.Management\.Automation\.AmsiUtils"),
        "Reflective AmsiUtils tamper",
        "Reflects into `System.Management.Automation.AmsiUtils` to "
        "disable AMSI at runtime — the canonical AmsiBypass pattern.",
        RiskBand.HIGH,
        "T1562.001",
    ),
]


class DefenseEvasionRule:
    NAME = "defense_evasion"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        intents: list[Intent] = []
        for pat, name, rationale, risk, tid in _SIGNATURES:
            m = pat.search(text)
            if not m:
                continue
            evidence = [Evidence(
                source="intent.defense_evasion",
                observation=m.group(0)[:120],
                confidence=90,
                rationale=rationale,
                meta={"signature": name, "mitre": tid},
            )]
            intents.append(Intent(
                category=IntentCategory.DEFENSE_EVASION,
                purpose=f"Evade defensive tooling via {name}.",
                risk=risk,
                rationale=rationale,
                evidence=evidence,
                confidence=90 if risk == RiskBand.HIGH else 80,
                mitre_ids=[tid],
            ))
        return intents


RULE = DefenseEvasionRule()
