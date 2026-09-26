"""runtime_dependent · the artefact's final behaviour cannot be
determined statically because a critical value is only available at
runtime.

Fires when:
    * The RTE halted with ``NO_TRANSFORMATION`` and the artefact
      contains a fetch primitive whose response body is executed.
    * A crypto primitive uses a key derived from the environment,
      user input, or a network fetch.
    * A ``[Reflection.Assembly]::Load`` call is present without
      the assembly bytes visible statically.

The intent DELIBERATELY declines to speculate — its purpose is to
mark the boundary of what can be known statically so the analyst is
never given a fabricated verdict.
"""
from __future__ import annotations

import re

from ...evidence import Evidence
from ..models import Intent, IntentCategory, RiskBand

_RUNTIME_MARKERS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"(?i)\biex\b\s*[\(\s]*.*(?:downloadstring|invoke-webrequest|iwr|irm|downloaddata|downloadfile)"),
        "iex over fetched content",
        "Invoke-Expression executes a value obtained from a remote fetch. "
        "The final behaviour depends entirely on what the remote source returns.",
    ),
    (
        re.compile(r"(?i)\[reflection\.assembly\]::load\s*\("),
        "reflective assembly load",
        "In-memory .NET assembly load — the assembly bytes are supplied "
        "at runtime and the executed code cannot be recovered statically.",
    ),
    (
        re.compile(r"(?i)Get-Random|New-Guid|\[Guid\]::NewGuid"),
        "runtime-generated key",
        "Cryptographic material is generated at runtime — deterministic "
        "decryption of downstream content is not possible.",
    ),
    (
        re.compile(r"(?i)\$env:\w+|\[Environment\]::GetEnvironmentVariable"),
        "environment-dependent value",
        "Behaviour depends on an environment variable that is not known "
        "statically. Effective payload may differ per host / user context.",
    ),
    (
        re.compile(r"(?i)Read-Host|\bhost\.ui\.readline"),
        "user-input-dependent value",
        "Behaviour depends on interactive user input — cannot be resolved "
        "statically.",
    ),
]


class RuntimeDependentRule:
    NAME = "runtime_dependent"

    def detect(self, artefact_text: str, meta: dict) -> list[Intent]:
        text = artefact_text or ""
        intents: list[Intent] = []
        for pat, name, rationale in _RUNTIME_MARKERS:
            m = pat.search(text)
            if not m:
                continue
            evidence = [Evidence(
                source="intent.runtime_dependent",
                observation=m.group(0)[:120],
                confidence=88,
                rationale=rationale,
                meta={"marker": name},
            )]
            intents.append(Intent(
                category=IntentCategory.RUNTIME_DEPENDENT,
                purpose=(
                    f"Final behaviour is runtime-dependent ({name}) — the "
                    "artefact cannot be fully understood without runtime "
                    "context."
                ),
                risk=RiskBand.UNKNOWN,
                rationale=rationale,
                evidence=evidence,
                confidence=88,
                mitre_ids=[],
            ))
        return intents


RULE = RuntimeDependentRule()
