"""Plugin · Universal Family Recognizer (Priority 4 · frozen).

Wraps the existing production ``services.die.preprocessor.family_recognizer``
which classifies command families based on **option patterns** — not on
executable name — and covers ransomware / persistence / discovery /
LOLBIN tradecraft that appears identically in PowerShell, CMD, JScript,
HTA, WMI, VBS, and Office droppers.

The original module was only invoked from a single legacy code path
(the die preprocessor) at the very end of the pipeline.  This plugin
runs it on **every** artifact type that carries textual content so
every peeled child gets immediate family attribution:

    Text / PowerShell / PowerShell-normalized / Cmd / JavaScript /
    HTA / Office / Shellcode-string-form  → family evidence

R26 compliance
──────────────
    · Pure wrapper — same input → same output as
      ``family_recognizer.recognize_families``.
    · No re-implementation.
    · No hidden state.
"""
from __future__ import annotations

from time    import perf_counter
from typing  import List

from ...artifact   import Artifact
from ...recognizer import Recognition, Reason, HIGH, LIKELY
from ...capability import CapabilityResult, register
from ...evidence   import make_evidence
from .. import register_plugin

from services.die.preprocessor.family_recognizer import (
    recognize_families as _recognize_families,
)


NAME    = "family.universal_recognizer"
VERSION = "1.0.0"

# Every artifact type that can plausibly carry command-family text.
_TEXTUAL_TYPES = (
    "text", "cmd", "javascript", "vbscript", "hta", "office",
    "powershell", "powershell_normalized", "base64_decoded",
    "gzip_decoded", "zlib_decoded", "xor_decoded", "shellcode_bytes",
    "unknown",
)


def _payload_text(artifact: Artifact) -> str:
    """Best-effort UTF-8 first, then latin-1 fallback so this
    recognizer also works on partial-binary artefacts that carry
    embedded ASCII commands (e.g. cmd-line strings in shellcode)."""
    try:
        return artifact.payload.decode("utf-8", errors="ignore")
    except Exception:
        return artifact.payload.decode("latin-1", errors="ignore")


class _Recognizer:
    name = NAME

    def recognize(self, artifact: Artifact) -> List[Recognition]:
        if artifact.size < 8:
            return []
        text = _payload_text(artifact)
        if not text:
            return []
        fams = _recognize_families(text)
        if not fams:
            return []
        # Confidence: HIGH when 2+ families match (tradecraft cluster),
        # LIKELY when a single family matches.
        band = HIGH if len(fams) >= 2 else LIKELY
        return [Recognition(
            artifact_type=artifact.artifact_type or "text",
            confidence=band,
            reasons=[Reason("family_pattern", 0.60,
                              f"{len(fams)} family pattern(s) matched")],
            recognizer=NAME,
        )]


class _Capability:
    name = NAME
    # Runs on every textual artifact type — the recognizer decided if a
    # family matched; the capability just emits the evidence.
    requires_artifact_type = list(_TEXTUAL_TYPES)
    requires_evidence      = []

    def execute(self, artifact: Artifact) -> CapabilityResult:
        t0 = perf_counter()
        text = _payload_text(artifact)
        if not text:
            return CapabilityResult(elapsed_ms=(perf_counter() - t0) * 1000.0)

        fams = _recognize_families(text)
        if not fams:
            return CapabilityResult(
                notes={"family_status": "no_family_pattern_matched"},
                elapsed_ms=(perf_counter() - t0) * 1000.0,
            )

        evidence = []
        for f in fams:
            evidence.append(make_evidence(
                artifact_uri=artifact.uri,
                kind="family",
                value=f.label,
                source_capability=NAME,
                confidence=0.75,
                severity="high",
                mitre_techniques=list(f.mitre or []),
                kill_chain=[f.tactic] if f.tactic else [],
                location="family_recognizer.rx",
                meta={
                    "family_id":            f.id,
                    "tactic":               f.tactic,
                    "commonly_observed_in": list(f.commonly_observed_in or []),
                    "artifact_type":        artifact.artifact_type,
                },
            ))

        return CapabilityResult(
            evidence=evidence,
            notes={
                "family_status":  "matched",
                "family_count":   len(fams),
                "family_ids":     [f.id for f in fams],
            },
            elapsed_ms=(perf_counter() - t0) * 1000.0,
        )


recognizer = _Recognizer()
capability = _Capability()

register(capability)
register_plugin(NAME, VERSION, recognizer, capability,
                wraps_legacy="services.die.preprocessor.family_recognizer.recognize_families")
