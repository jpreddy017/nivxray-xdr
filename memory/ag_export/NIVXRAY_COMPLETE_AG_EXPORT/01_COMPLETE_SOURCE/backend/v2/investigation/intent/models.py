"""Semantic Intent Layer · canonical models.

The Semantic Intent Layer answers ONE question the earlier stages
cannot:

    "Why does this matter to an analyst?"

Input Understanding says what the artefact IS. CRE says what will
ACTUALLY EXECUTE. RTE reveals HIDDEN payloads. Semantic Intent
translates those low-level findings into analyst-facing intent —

    Purpose:  "Retrieve additional content from a remote source."
    Risk:     "The final behaviour depends on what the source returns."
    Evidence: DownloadString() invocation + remote URL.

Every Intent must cite canonical Evidence. Runtime-dependent outcomes
must remain runtime-dependent — the Intent layer never fabricates
a behaviour it cannot see statically.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..evidence import Evidence


class IntentCategory(str, Enum):
    """The finite set of intent categories the Brain can classify.

    Deliberately CLOSED — new categories are added only when a
    real-world sample proves a genuine gap. Ordered by the ATT&CK
    tactic they most commonly map to.
    """
    STAGING             = "staging"              # download / fetch to stage more code
    REMOTE_EXECUTION    = "remote_execution"     # execute code retrieved from a remote source
    DEFENSE_EVASION     = "defense_evasion"      # AMSI bypass, ETW patch, obfuscation
    DISCOVERY           = "discovery"            # host / user / network enumeration
    PERSISTENCE         = "persistence"          # registry Run, scheduled task, service
    CREDENTIAL_ACCESS   = "credential_access"    # LSASS, DPAPI, browser stores
    LATERAL_MOVEMENT    = "lateral_movement"     # WinRM, SMB, PsExec-style spread
    COLLECTION          = "collection"           # file harvesting, screen capture
    EXFILTRATION        = "exfiltration"         # data upload / DNS / covert channels
    IMPACT              = "impact"               # ransomware, wipe, shutdown
    RUNTIME_DEPENDENT   = "runtime_dependent"    # meaning depends on retrieved content


class RiskBand(str, Enum):
    """Analyst-facing risk band. Deterministic — same intent always
    produces the same band. Not a probability; a categorical judgement."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    UNKNOWN  = "unknown"    # only used for RUNTIME_DEPENDENT outcomes


@dataclass(frozen=True)
class Intent:
    """A single analyst-facing intent supported by canonical evidence.

    Fields:
        category    — the intent's canonical category (closed enum).
        purpose     — one plain-English sentence describing WHAT the
                       artefact is trying to accomplish.
        risk        — categorical risk band (LOW/MEDIUM/HIGH/UNKNOWN).
        rationale   — one sentence describing WHY this intent matters
                       to the analyst — always evidence-anchored.
        evidence    — canonical Evidence objects supporting the intent.
        confidence  — 0-100 strength of the intent inference (based on
                       evidence weight, not the analyst's opinion).
        mitre_ids   — the ATT&CK technique IDs this intent commonly
                       maps to. Mapping, not identity — always a hint.
    """
    category:   IntentCategory
    purpose:    str
    risk:       RiskBand
    rationale:  str
    evidence:   list[Evidence] = field(default_factory=list)
    confidence: int = 0
    mitre_ids:  list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category":   self.category.value,
            "purpose":    self.purpose,
            "risk":       self.risk.value,
            "rationale":  self.rationale,
            "evidence":   [e.to_dict() for e in self.evidence],
            "confidence": self.confidence,
            "mitre_ids":  list(self.mitre_ids),
        }


@dataclass
class IntentAssessment:
    """Complete Semantic Intent output for a single artefact.

    Fields:
        intents          — ordered list of Intent objects fired against
                            the artefact. Ordered by descending confidence,
                            ties broken by category enum order for
                            determinism.
        summary          — one-paragraph analyst-facing synthesis of the
                            fired intents. Deterministic — same intents
                            always produce the same paragraph.
        determinism_hash — SHA-256 of the canonical serialization.
    """
    intents: list[Intent] = field(default_factory=list)
    summary: str = ""
    determinism_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "intents":          [i.to_dict() for i in self.intents],
            "summary":          self.summary,
            "determinism_hash": self.determinism_hash,
        }


__all__ = [
    "Intent",
    "IntentAssessment",
    "IntentCategory",
    "RiskBand",
]
