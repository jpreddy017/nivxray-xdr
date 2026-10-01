"""discovery · the artefact enumerates the host, user, network,
process, or Active Directory environment."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

_SIGNATURES: list[tuple[re.Pattern, str, str, str, bool]] = [
    # tuple: (pattern, name, rationale, mitre, high_signal)
    # high_signal = a discovery primitive that ON ITS OWN is enough
    # to fire the intent. Lower-signal primitives (whoami / ipconfig /
    # Get-Process) require corroborating hits — they are common in
    # benign admin activity and should not fire alone.
    (re.compile(r"(?i)\bwhoami(?:\.exe)?\b"),                    "whoami",              "Enumerate current user identity.",           "T1033",    False),
    (re.compile(r"(?i)\bGet-ADUser\b|\bGet-ADGroup\b"),           "AD enumeration",      "Enumerate Active Directory users / groups.", "T1087.002", True),
    (re.compile(r"(?i)\bGet-DomainUser\b|\bGet-DomainGroup\b"),   "PowerView AD enum",   "PowerView-style Active Directory enumeration.", "T1087.002", True),
    (re.compile(r"(?i)\bnet\s+(?:user|group|localgroup)\b"),      "net user/group",      "Enumerate local / domain users and groups.", "T1087",    True),
    (re.compile(r"(?i)\bnltest\b"),                               "nltest",              "Enumerate domain trusts and controllers.",   "T1482",    True),
    (re.compile(r"(?i)\bipconfig\b|\bGet-NetIPConfiguration\b"),  "ip enumeration",      "Enumerate host network configuration.",      "T1016",    False),
    (re.compile(r"(?i)\barp\s+-a\b|\bGet-NetNeighbor\b"),         "arp enumeration",     "Enumerate ARP / neighbour table.",           "T1016",    False),
    (re.compile(r"(?i)\btasklist\b|\bGet-Process\b"),             "process enumeration", "Enumerate running processes.",               "T1057",    False),
    (re.compile(r"(?i)\bsysteminfo\b|\bGet-ComputerInfo\b"),      "systeminfo",          "Enumerate detailed host system info.",       "T1082",    False),
]


class DiscoveryRule:
    NAME = "discovery"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        hits: list[tuple[str, str, str, bool]] = []
        for pat, name, rationale, tid, high in _SIGNATURES:
            m = pat.search(text)
            if m:
                hits.append((name, m.group(0), tid, high))
        if not hits:
            return []
        # Conservative gate — a SINGLE low-signal primitive (whoami,
        # Get-Process, ipconfig) is common in benign admin activity;
        # only fire when either a high-signal primitive is present
        # OR two-or-more low-signal primitives co-occur.
        high_signal_present = any(h[3] for h in hits)
        if not high_signal_present and len(hits) < 2:
            return []

        evidence = [
            Evidence(
                source="intent.discovery",
                observation=snip[:120],
                confidence=88,
                rationale=f"`{name}` is a canonical discovery primitive.",
                meta={"signature": name, "mitre": tid},
            )
            for name, snip, tid, _ in hits
        ]

        seen = set()
        mitre = []
        for _, _, tid, _ in hits:
            if tid not in seen:
                seen.add(tid)
                mitre.append(tid)

        primary = hits[0][0]
        return [Intent(
            category=IntentCategory.DISCOVERY,
            purpose=(
                f"Enumerate the host / user / network environment starting "
                f"with `{primary}` — reconnaissance for downstream stages."
            ),
            risk=RiskBand.MEDIUM,
            rationale=(
                "Discovery primitive(s) observed in the effective payload. "
                "Reconnaissance output typically drives lateral movement, "
                "privilege escalation, or targeted exfiltration."
            ),
            evidence=evidence,
            confidence=85,
            mitre_ids=mitre,
        )]


RULE = DiscoveryRule()
