"""remote_execution · the artefact executes code obtained from a
remote or dynamic source.

Fires when a fetch primitive is COMBINED with an execution primitive
(iex / Invoke-Expression, mshta, rundll32 remote, scriptblock create
on fetched string, etc.). Also fires when Invoke-Expression consumes
a variable known to hold fetched content.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

# Execution primitives — the "then run it" half of the pattern.
_EXEC_PRIMITIVES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)\biex\b|\bInvoke-Expression\b"),          "Invoke-Expression",       "T1059.001"),
    (re.compile(r"(?i)\[scriptblock\]::create\s*\("),           "ScriptBlock::Create",     "T1059.001"),
    (re.compile(r"(?i)\bInvoke-Command\s+-ScriptBlock"),        "Invoke-Command",          "T1059.001"),
    (re.compile(r"(?i)\bmshta(?:\.exe)?\b[^\n]*https?://"),     "mshta remote",            "T1218.005"),
    (re.compile(r"(?i)\brundll32(?:\.exe)?\b[^\n]*https?://"),  "rundll32 remote",         "T1218.011"),
    (re.compile(r"(?i)\bregsvr32(?:\.exe)?\b[^\n]*/i:https?://"), "regsvr32 remote",       "T1218.010"),
    (re.compile(r"(?i)\b\.Invoke\s*\("),                        "reflective .Invoke()",    "T1059.001"),
    # Local execution of a downloaded artefact — Invoke-Item, Start-Process,
    # or bare call operator `& $path`. Combined with a fetch primitive
    # (see _FETCH_MARKER) this is the canonical download-and-execute cradle
    # even when the interpreter is not another script host.
    (re.compile(r"(?i)\bInvoke-Item\b"),                        "Invoke-Item",             "T1204.002"),
    (re.compile(r"(?i)\bStart-Process\b"),                      "Start-Process",           "T1204.002"),
]

_FETCH_MARKER = re.compile(
    r"(?i)\b("
    r"downloadstring|downloadfile|downloaddata|"
    r"invoke-webrequest|invoke-restmethod|iwr|irm|"
    r"start-bitstransfer|bitsadmin|certutil.*urlcache|"
    r"curl\s|wget\s"
    r")"
)


class RemoteExecutionRule:
    NAME = "remote_execution"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""

        exec_hits: list[tuple[str, str, str]] = []
        for pat, name, tid in _EXEC_PRIMITIVES:
            m = pat.search(text)
            if m:
                exec_hits.append((name, m.group(0), tid))
        if not exec_hits:
            return []

        # For remote-execution intent we require an execution primitive
        # AND either a fetch primitive or an mshta/rundll32/regsvr32
        # with an embedded URL (already caught by their patterns).
        has_fetch = bool(_FETCH_MARKER.search(text))
        remote_lolbin = any(
            name in {"mshta remote", "rundll32 remote", "regsvr32 remote"}
            for name, _, _ in exec_hits
        )
        if not (has_fetch or remote_lolbin):
            return []

        evidence = [
            Evidence(
                source="intent.remote_execution",
                observation=snip[:120],
                confidence=90,
                rationale=(
                    f"`{name}` executes code from a dynamic source. Combined with "
                    "a fetch primitive this is a canonical download-and-run cradle."
                ),
                meta={"primitive": name, "mitre": tid},
            )
            for name, snip, tid in exec_hits
        ]

        seen = set()
        mitre = []
        for _, _, tid in exec_hits:
            if tid not in seen:
                seen.add(tid)
                mitre.append(tid)

        primary = exec_hits[0][0]
        purpose = (
            f"Execute code retrieved from a remote source using `{primary}`. "
            "The executed content is not present in the artefact — it is fetched at runtime."
        )
        rationale = (
            "Execution primitive combined with a fetch primitive. The final "
            "behaviour is runtime-dependent on the fetched content."
        )

        return [Intent(
            category=IntentCategory.REMOTE_EXECUTION,
            purpose=purpose,
            risk=RiskBand.HIGH,
            rationale=rationale,
            evidence=evidence,
            confidence=93,
            mitre_ids=mitre,
        )]


RULE = RemoteExecutionRule()
