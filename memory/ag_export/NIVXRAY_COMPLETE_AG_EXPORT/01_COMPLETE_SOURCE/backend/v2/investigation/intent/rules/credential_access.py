"""credential_access · the artefact accesses credential material
(LSASS memory, DPAPI vault, browser stores, SAM / SECURITY hives)."""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

_SIGNATURES: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"(?i)\blsass(?:\.exe)?\b|MiniDumpWriteDump|"
                    r"comsvcs\.dll.*MiniDump|procdump.*lsass"),
        "LSASS dump",
        "Attempt to read or dump the LSASS process memory — the canonical "
        "path to plaintext / hashed credentials of interactive users.",
        "T1003.001",
    ),
    (
        re.compile(r"(?i)\bDPAPI\b|CryptUnprotectData|dpapi\s*::\s*"),
        "DPAPI decryption",
        "Data Protection API decryption — used to extract Chrome / Edge / "
        "Windows Credential Manager secrets from the local vault.",
        "T1555.003",
    ),
    (
        re.compile(r"(?i)mimikatz|sekurlsa|kerberos::"),
        "Mimikatz primitive",
        "Direct Mimikatz-style credential-extraction primitive.",
        "T1003",
    ),
    (
        re.compile(r"(?i)Login\s+Data|Cookies|Web\s+Data|Local\s+State",),
        "browser credential store",
        "Reference to Chromium / Edge credential / cookie / Web Data "
        "store — often harvested for cookie theft or password recovery.",
        "T1555.003",
    ),
    (
        re.compile(r"(?i)reg\s+save\s+HKLM\\SAM|reg\s+save\s+HKLM\\SECURITY|"
                    r"Copy-Item\s+.*ntds\.dit"),
        "SAM / NTDS extraction",
        "Attempt to export the SAM / SECURITY hives or ntds.dit — offline "
        "credential extraction preparation.",
        "T1003.002",
    ),
]


class CredentialAccessRule:
    NAME = "credential_access"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        intents: list[Intent] = []
        for pat, name, rationale, tid in _SIGNATURES:
            m = pat.search(text)
            if not m:
                continue
            evidence = [Evidence(
                source="intent.credential_access",
                observation=m.group(0)[:120],
                confidence=92,
                rationale=rationale,
                meta={"signature": name, "mitre": tid},
            )]
            intents.append(Intent(
                category=IntentCategory.CREDENTIAL_ACCESS,
                purpose=f"Access credential material via {name}.",
                risk=RiskBand.HIGH,
                rationale=rationale,
                evidence=evidence,
                confidence=92,
                mitre_ids=[tid],
            ))
        return intents


RULE = CredentialAccessRule()
