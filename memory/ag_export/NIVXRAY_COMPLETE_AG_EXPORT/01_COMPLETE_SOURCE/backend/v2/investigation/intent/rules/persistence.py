"""persistence · the artefact installs a mechanism to survive a reboot
or user logoff (registry Run key, scheduled task, service, WMI event
subscription, Startup folder drop)."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

_SIGNATURES: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"(?i)HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
                    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
                    r"HKLM\\System\\CurrentControlSet\\Services|"
                    r"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
                    r"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        "registry Run key",
        "Registry Run key modification — the classic autorun persistence "
        "location. Anything written here executes on user logon.",
        "T1547.001",
    ),
    (
        re.compile(r"(?i)\bschtasks(?:\.exe)?\s+/create\b|\bRegister-ScheduledTask\b"),
        "scheduled task",
        "Scheduled task registration — persists across reboots and can "
        "run under SYSTEM.",
        "T1053.005",
    ),
    (
        re.compile(r"(?i)\bNew-Service\b|\bsc(?:\.exe)?\s+create\b"),
        "service creation",
        "Windows service creation — persists across reboots and runs "
        "under the service account.",
        "T1543.003",
    ),
    (
        re.compile(r"(?i)__EventFilter|__FilterToConsumerBinding|"
                    r"CommandLineEventConsumer"),
        "WMI event subscription",
        "WMI event subscription — a fileless persistence mechanism that "
        "survives reboots without modifying the registry Run key.",
        "T1546.003",
    ),
    (
        re.compile(r"(?i)\\Startup\\|shell:startup|CurrentVersion\\Explorer\\Startup"),
        "startup folder drop",
        "Startup-folder drop — anything placed here runs on user logon.",
        "T1547.001",
    ),
]


class PersistenceRule:
    NAME = "persistence"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        intents: list[Intent] = []
        for pat, name, rationale, tid in _SIGNATURES:
            m = pat.search(text)
            if not m:
                continue
            evidence = [Evidence(
                source="intent.persistence",
                observation=m.group(0)[:120],
                confidence=90,
                rationale=rationale,
                meta={"signature": name, "mitre": tid},
            )]
            intents.append(Intent(
                category=IntentCategory.PERSISTENCE,
                purpose=f"Install persistence via {name}.",
                risk=RiskBand.HIGH,
                rationale=rationale,
                evidence=evidence,
                confidence=90,
                mitre_ids=[tid],
            ))
        return intents


RULE = PersistenceRule()
