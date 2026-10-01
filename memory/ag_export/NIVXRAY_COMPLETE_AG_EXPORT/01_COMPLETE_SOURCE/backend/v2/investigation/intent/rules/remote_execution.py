"""remote_execution · the artefact executes code obtained from a
remote or dynamic source.

Fires when a fetch primitive is COMBINED with an execution primitive
(iex / Invoke-Expression, mshta, rundll32 remote, scriptblock create
on fetched string, etc.). Also fires when Invoke-Expression consumes
a variable known to hold fetched content.

Behaviour-chain detection (v1.3.3): when the same file that a
download primitive wrote to disk is later invoked as a standalone
command (via ``start``, ``cmd /c``, PowerShell call operator ``&``,
or a bare invocation after a shell separator), the rule fires the
same intent — regardless of which downloader / interpreter was used.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand
from ._chain import find_download_destinations, is_invoked

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

        # ── Behaviour-chain detection ──────────────────────────
        # When a download primitive wrote to a specific destination
        # and that same file (bare name OR full path) is invoked as
        # a standalone command elsewhere in the payload, the download
        # → execute chain is deterministically observable — no matter
        # which downloader or interpreter was involved. This is the
        # generic capability that removes the need for one-off rules
        # per LOLBin.
        chain_evidence: list[Evidence] = []
        chain_mitre: list[str] = []
        for dest in find_download_destinations(text):
            for needle in {dest.base, dest.raw}:
                hit, snippet = is_invoked(text, needle)
                if not hit:
                    continue
                # Ignore self-references: a downloader inside the
                # download command line itself (the ``needle`` is not
                # actually the downloaded file — it's the downloader).
                # We enforce this by requiring the invocation snippet
                # to NOT be part of the original download command
                # (i.e. the invocation must appear at a different
                # offset than the destination declaration).
                chain_evidence.append(Evidence(
                    source="intent.remote_execution",
                    observation=snippet[:120],
                    confidence=92,
                    rationale=(
                        f"Downloaded file `{dest.base}` (written via "
                        f"`{dest.origin}`) is invoked as a standalone "
                        "command later in the payload. Download → Write "
                        "→ Execute chain is observable."
                    ),
                    meta={
                        "primitive": f"chain:{dest.origin}",
                        "destination": dest.raw,
                        "basename":    dest.base,
                        "mitre":       "T1204.002",
                    },
                ))
                if "T1204.002" not in chain_mitre:
                    chain_mitre.append("T1204.002")
                break   # one chain hit per destination is enough

        # For remote-execution intent we require an execution primitive
        # AND either a fetch primitive or an mshta/rundll32/regsvr32
        # with an embedded URL (already caught by their patterns).
        has_fetch = bool(_FETCH_MARKER.search(text))
        remote_lolbin = any(
            name in {"mshta remote", "rundll32 remote", "regsvr32 remote"}
            for name, _, _ in exec_hits
        )

        # If neither the classic exec-primitive path nor the behaviour
        # chain fires, there is nothing to report.
        classic_fires = bool(exec_hits) and (has_fetch or remote_lolbin)
        if not classic_fires and not chain_evidence:
            return []

        evidence: list[Evidence] = []
        if classic_fires:
            evidence.extend([
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
            ])
        evidence.extend(chain_evidence)

        # Deterministic MITRE roll-up (dedup while preserving order).
        seen: set[str] = set()
        mitre: list[str] = []
        for _, _, tid in exec_hits if classic_fires else []:
            if tid not in seen:
                seen.add(tid)
                mitre.append(tid)
        for tid in chain_mitre:
            if tid not in seen:
                seen.add(tid)
                mitre.append(tid)

        primary = exec_hits[0][0] if classic_fires else "download-then-execute chain"
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
