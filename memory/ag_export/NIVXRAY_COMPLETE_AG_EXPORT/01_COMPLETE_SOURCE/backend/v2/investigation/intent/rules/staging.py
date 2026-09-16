"""staging · the artefact retrieves additional content to stage
further code (download cradle, IWR fetch, BITS transfer, certutil
download, etc.).

Fires when a fetch primitive is observed. Runtime-dependent — we do
NOT declare the eventual behaviour, only that additional content is
being fetched.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand
from ._util import extract_urls

# Every deterministic fetch primitive the Brain can recognise.
# Each entry is (regex, human-name, MITRE technique).
_FETCH_PRIMITIVES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)\bDownloadString\s*\(",              ), "WebClient.DownloadString",  "T1105"),
    (re.compile(r"(?i)\bDownloadFile\s*\(",                ), "WebClient.DownloadFile",    "T1105"),
    (re.compile(r"(?i)\bDownloadData\s*\(",                ), "WebClient.DownloadData",    "T1105"),
    (re.compile(r"(?i)\bInvoke-WebRequest\b|\biwr\b",      ), "Invoke-WebRequest",         "T1105"),
    (re.compile(r"(?i)\bInvoke-RestMethod\b|\birm\b",      ), "Invoke-RestMethod",         "T1105"),
    (re.compile(r"(?i)\bStart-BitsTransfer\b",             ), "Start-BitsTransfer",        "T1197"),
    (re.compile(r"(?i)\bbitsadmin(?:\.exe)?\b.*?/transfer"), "bitsadmin /transfer",       "T1197"),
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\b[^\n]*-urlcache"), "certutil -urlcache",     "T1105"),
    (re.compile(r"(?i)\bcurl(?:\.exe)?\s"                 ), "curl",                      "T1105"),
    (re.compile(r"(?i)\bwget(?:\.exe)?\s"                 ), "wget",                      "T1105"),
]


class StagingRule:
    NAME = "staging"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        intents: list[Intent] = []
        matched: list[tuple[str, str, str]] = []
        for pat, name, tid in _FETCH_PRIMITIVES:
            m = pat.search(text)
            if m:
                matched.append((name, m.group(0), tid))
        if not matched:
            return []

        urls = extract_urls(text)
        evidence: list[Evidence] = []
        for name, snippet, tid in matched:
            evidence.append(Evidence(
                source="intent.staging",
                observation=snippet[:120],
                confidence=90,
                rationale=(
                    f"`{name}` is a canonical remote-fetch primitive. "
                    "Retrieved content becomes the effective payload."
                ),
                meta={"primitive": name, "mitre": tid},
            ))
        for url in urls[:5]:
            evidence.append(Evidence(
                source="intent.staging",
                observation=url,
                confidence=85,
                rationale=(
                    "Remote URL supplied to a fetch primitive — the "
                    "download target. The response body is the actual "
                    "payload."
                ),
                meta={"kind": "url"},
            ))

        # Deterministic MITRE roll-up (dedup while preserving order).
        seen = set()
        mitre = []
        for _, _, tid in matched:
            if tid not in seen:
                seen.add(tid)
                mitre.append(tid)

        primary_name = matched[0][0]
        purpose = (
            f"Retrieve additional content from a remote source via "
            f"`{primary_name}`. The retrieved content becomes the "
            "next stage of execution."
        )
        rationale = (
            "Fetch primitive detected in the effective payload — the "
            "artefact is staging further code. Final behaviour depends "
            "on what the remote source returns."
        )

        intents.append(Intent(
            category=IntentCategory.STAGING,
            purpose=purpose,
            risk=RiskBand.HIGH if urls else RiskBand.MEDIUM,
            rationale=rationale,
            evidence=evidence,
            confidence=92,
            mitre_ids=mitre,
        ))
        return intents


RULE = StagingRule()
