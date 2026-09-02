"""
Narration Gateway contracts.

Every consumer speaks in `NarrationRequest` / `NarrationResult`.
Providers speak in `NarrationContext` (input) and produce a
`NarrationResult` (output).  The gateway is the only component
allowed to interpret them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NarrationKind(str, Enum):
    """Every distinct narration surface NivXRay XDR generates.

    Phase 1 only wires EXECUTIVE_SUMMARY end-to-end (that is the
    proof surface).  The remaining kinds are declared here so
    downstream consumers can rely on stable enum values, and so
    the deterministic narrator can advertise its supported set
    honestly."""
    EXECUTIVE_SUMMARY = "executive_summary"
    INCIDENT_SUMMARY  = "incident_summary"
    ATTACK_STORY      = "attack_story"
    KEY_FINDINGS      = "key_findings"
    ATTCK_SUMMARY     = "attck_summary"
    EVIDENCE_EXPLAIN  = "evidence_explanation"
    INVESTIGATION_CTX = "investigation_context"


class GenerationMode(str, Enum):
    LLM_CLOUD        = "llm_cloud"
    LLM_OFFLINE      = "llm_offline"
    DETERMINISTIC    = "deterministic"


class GroundingError(Exception):
    """Raised when an LLM output references an id/entity/verdict
    not present in the supplied context.  Callers translate this
    into a fallback to the next provider — never into a user
    error."""


# --------------------------------------------------------------------
@dataclass(frozen=True)
class NarrationContext:
    """The complete governed context an LLM provider is ALLOWED to
    reason over.  A grounded narration cannot reference an id,
    entity, verdict, severity or confidence value outside this
    envelope.  All fields are optional — the deterministic
    narrator handles missing pieces honestly."""
    incident_id:     str
    evidence_ids:    tuple[str, ...] = ()
    finding_ids:     tuple[str, ...] = ()
    technique_ids:   tuple[str, ...] = ()
    entities:        tuple[str, ...] = ()
    verdict:         str | None = None       # e.g. MALICIOUS
    severity:        str | None = None       # P1 / P2 / P3 / P4 / P5
    confidence:      float | None = None     # [0, 1]
    provenance:      tuple[dict[str, Any], ...] = ()
    # The composer-ready payload that the deterministic narrator
    # needs to emit prose without further backend calls.  LLM
    # providers may read this too, but they MUST NOT invent new
    # keys.
    composer_input:  dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NarrationRequest:
    kind:               NarrationKind
    context:            NarrationContext
    preferred_provider: str | None = None    # optional override
    session_id:         str | None = None


@dataclass(frozen=True)
class NarrationResult:
    """The single object every consumer receives.  Machine truth
    is inherited from the context verbatim; the LLM only supplies
    wording.  `text` is the analyst-facing prose.  `paragraphs`
    is the structured form (each paragraph pinned to evidence
    ids so the UI can render provenance badges)."""
    kind:               NarrationKind
    text:               str
    paragraphs:         tuple["NarrationParagraph", ...]
    evidence_ids:       tuple[str, ...]
    finding_ids:        tuple[str, ...]
    technique_ids:      tuple[str, ...]
    entities:           tuple[str, ...]
    verdict:            str | None
    severity:           str | None
    confidence:         float | None
    provenance:         tuple[dict[str, Any], ...]
    generation_mode:    GenerationMode
    provider:           str
    fallback_chain:     tuple[str, ...]      # providers we tried
    grounded:           bool = True
    caveats:            tuple[str, ...] = ()


@dataclass(frozen=True)
class NarrationParagraph:
    text:          str
    evidence_ids:  tuple[str, ...] = ()
    finding_ids:   tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
