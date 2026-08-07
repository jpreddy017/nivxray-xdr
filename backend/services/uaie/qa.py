"""UAIE Contract #7 · Artifact Quality Assurance Layer  (Rule R28.3)

The QA Layer is a permanent, generic component that sits between
a Capability's output and the orchestrator's re-queue step:

    Capability → produces child Artifact
        │
        ▼
    Validator (diagnose only)
        │
        ├── VALID   → queue child  ─►  investigation continues
        │
        └── INVALID → repair_candidates[]
                       │
                       ▼
                    Repair Planner (rank + schedule)
                       │
                       ▼
                    Repair Capability (transform only)
                       │
                       ▼
                    Validator (re-check)
                       │
                       ├── VALID   → queue child
                       └── INVALID → next candidate
                                       │
                                       ▼
                                   No candidates left
                                       │
                                       ▼
                                   UNREACHABLE  +  evidence(repair_failed)

Separation of concerns (frozen):
  · Validators DIAGNOSE — they never modify bytes.  They return
    a canonical failure code + confidence + ranked repair candidates.
  · The Planner RANKS repair strategies by confidence and hands the
    highest-confidence candidate to the matching Repair Capability.
  · Repair Capabilities TRANSFORM only — they never decide "should
    I run".  The validator already said "yes, try me".
  · Certificates document every validation and repair outcome, so
    the analyst can replay exactly why a child was accepted, healed,
    or ruled UNREACHABLE.

This module defines only the contracts, registries, taxonomies and
the Repair Planner.  Concrete validators live under
``plugins/validator_*/`` and repair capabilities under
``plugins/repair_*/``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing      import Any, Dict, List, Optional, Protocol, runtime_checkable

from .artifact import Artifact


# ══════════════════════════════════════════════════════════════════
# Artifact lifecycle states (tracked on OrchestratorResult.states)
# ══════════════════════════════════════════════════════════════════
STATE_NEW              = "NEW"
STATE_RECOGNIZED       = "RECOGNIZED"
STATE_EXECUTED         = "EXECUTED"
STATE_VALIDATED        = "VALIDATED"
STATE_REPAIR_PENDING   = "REPAIR_PENDING"
STATE_REPAIRED         = "REPAIRED"
STATE_UNREACHABLE      = "UNREACHABLE"
STATE_ANALYZED         = "ANALYZED"

LIFECYCLE_STATES = (
    STATE_NEW, STATE_RECOGNIZED, STATE_EXECUTED, STATE_VALIDATED,
    STATE_REPAIR_PENDING, STATE_REPAIRED, STATE_UNREACHABLE,
    STATE_ANALYZED,
)


# ══════════════════════════════════════════════════════════════════
# Structured failure taxonomy
# ══════════════════════════════════════════════════════════════════
# Validation failure codes (why an artifact is INVALID)
INVALID_MISSING_MAGIC          = "missing_magic"
INVALID_BAD_PADDING            = "bad_padding"
INVALID_BAD_ALPHABET           = "bad_alphabet"
INVALID_HTML_MANGLED           = "html_mangled"
INVALID_LOW_PRINTABLE_RATIO    = "low_printable_ratio"
INVALID_TRUNCATED              = "truncated"
INVALID_UNKNOWN_ENCODING       = "unknown_encoding"
INVALID_SIZE_BELOW_MIN         = "size_below_min"
INVALID_ALL_ZERO               = "all_zero"
INVALID_ALIGNMENT_SHIFT        = "alignment_shift"
INVALID_STRUCTURAL             = "structural_mismatch"

# Repair failure codes (why a repair attempt FAILED)
REPAIR_FAIL_IRREVERSIBLE       = "irreversible_corruption"
REPAIR_FAIL_TRUNCATED          = "truncated"
REPAIR_FAIL_UNSUPPORTED        = "unsupported_encoding"
REPAIR_FAIL_CHECKSUM           = "checksum_mismatch"
REPAIR_FAIL_MISSING_BYTES      = "missing_bytes"
REPAIR_FAIL_UNKNOWN_FORMAT     = "unknown_format"
REPAIR_FAIL_LOW_CONFIDENCE     = "low_confidence"
REPAIR_FAIL_VALIDATOR_REJECTED = "validator_rejected"     # repair ran but re-validation failed
REPAIR_FAIL_NO_CAPABILITY      = "no_repair_capability"   # no plugin registered for this strategy
REPAIR_FAIL_EXCEPTION          = "repair_exception"       # repair plugin raised

# Terminal outcome (all candidates exhausted)
UNREACHABLE_NO_STRATEGIES_LEFT = "no_strategies_left"


# ══════════════════════════════════════════════════════════════════
# Data contracts
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class RepairCandidate:
    """A diagnosed repair opportunity.  Validators emit candidates;
    they do NOT execute them.  ``strategy`` MUST match a registered
    Repair Capability's ``strategy`` field."""
    strategy:    str
    confidence:  float                        # 0.00 – 1.00
    reason:      str                          # canonical validation code that triggered it
    detail:      str = ""                     # human-readable diagnostic detail
    meta:        Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationResult:
    """A validator's structured verdict.  ``valid=True`` means the
    artifact is safe to consume downstream.  ``valid=False`` means
    the validator diagnosed a problem AND (optionally) proposed
    repair candidates."""
    valid:              bool
    validator:          str
    confidence:         float                             # confidence in the diagnosis
    reason:             str = ""                          # canonical INVALID_* code
    detail:             str = ""                          # free-text detail
    repair_candidates:  List[RepairCandidate] = field(default_factory=list)


@dataclass(frozen=True)
class RepairResult:
    """A repair capability's outcome.  ``success=True`` means the
    repair produced new bytes; ``success=False`` means the strategy
    was not applicable / failed / raised.  Callers still re-validate
    on success — a repair that produces bytes is not necessarily a
    valid artifact.

    ``repaired_artifact_type`` — optional type override.  Most repairs
    keep the source type (e.g. cleaning noise from a ``base64`` blob
    still yields a ``base64`` blob).  Repairs that also DECODE (e.g.
    ``gzip_partial_inflate``: ``gzip_bytes`` → ``gzip_decoded``) declare
    the new type here.  When ``None``, the source artifact's type is
    preserved.
    """
    success:                bool
    strategy:               str
    repaired_payload:       Optional[bytes] = None
    repaired_artifact_type: Optional[str]   = None
    reason:                 str = ""                          # REPAIR_FAIL_* on failure
    detail:                 str = ""
    meta:                   Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationCertificate:
    """Per-validation audit record — attached to
    ``OrchestratorResult.validation_certificates``."""
    artifact_uri:  str
    validator:     str
    valid:         bool
    reason:        str
    detail:        str
    confidence:    float
    candidates:    List[str]                              # strategy names in ranked order
    ts:            float = field(default_factory=lambda: time.time())


@dataclass(frozen=True)
class RepairCertificate:
    """Per-repair audit record — attached to
    ``OrchestratorResult.repair_certificates``."""
    source_uri:    str                                    # the invalid artifact
    repaired_uri:  Optional[str]                          # None if repair failed
    strategy:      str
    outcome:       str                                    # "success" | "failed" | "unreachable"
    reason:        str
    detail:        str
    ts:            float = field(default_factory=lambda: time.time())


# ══════════════════════════════════════════════════════════════════
# Protocols
# ══════════════════════════════════════════════════════════════════
@runtime_checkable
class Validator(Protocol):
    """Diagnoses an artifact — never mutates bytes."""
    name:                     str
    validates_artifact_type:  List[str]     # e.g. ["base64_decoded"] · [] = universal

    def validate(self, artifact: Artifact) -> ValidationResult: ...


@runtime_checkable
class RepairCapability(Protocol):
    """Executes ONE deterministic repair strategy — never decides
    whether to run.  The validator already selected this strategy
    for this artifact."""
    name:      str
    strategy:  str                                        # matches RepairCandidate.strategy

    def repair(self, artifact: Artifact,
                candidate: RepairCandidate) -> RepairResult: ...


# ══════════════════════════════════════════════════════════════════
# Registries
# ══════════════════════════════════════════════════════════════════
_VALIDATOR_REGISTRY:      Dict[str, List[Validator]] = {}
_REPAIR_REGISTRY:         Dict[str, RepairCapability] = {}


def register_validator(validator: Validator) -> None:
    for t in (validator.validates_artifact_type or ["*"]):
        _VALIDATOR_REGISTRY.setdefault(t, []).append(validator)


def register_repair(repair: RepairCapability) -> None:
    if repair.strategy in _REPAIR_REGISTRY:
        # Deterministic — LAST registration wins (with visible warning
        # for the operator).  Tests can clear + re-register safely.
        pass
    _REPAIR_REGISTRY[repair.strategy] = repair


def validators_for(artifact_type: str) -> List[Validator]:
    """Every validator registered for this type + universal ("*")
    validators.  Deterministic order = registration order."""
    return list(_VALIDATOR_REGISTRY.get(artifact_type, [])) \
         + list(_VALIDATOR_REGISTRY.get("*", []))


def repair_for(strategy: str) -> Optional[RepairCapability]:
    return _REPAIR_REGISTRY.get(strategy)


def all_validators() -> Dict[str, List[str]]:
    return {t: [v.name for v in vs] for t, vs in _VALIDATOR_REGISTRY.items()}


def all_repairs() -> Dict[str, str]:
    return {s: r.name for s, r in _REPAIR_REGISTRY.items()}


def clear() -> None:
    """Test helper — never call in production code path."""
    _VALIDATOR_REGISTRY.clear()
    _REPAIR_REGISTRY.clear()


# ══════════════════════════════════════════════════════════════════
# Repair Planner
# ══════════════════════════════════════════════════════════════════
def plan_repairs(candidates: List[RepairCandidate]) -> List[RepairCandidate]:
    """Rank repair candidates by (confidence DESC, strategy ASC) so
    the same set of validators always produces the same repair order.

    Deduplicates on ``strategy`` — the FIRST occurrence of a strategy
    wins (highest-confidence quote for that strategy).
    """
    # Group by strategy, keep the highest-confidence candidate per strategy
    best_by_strategy: Dict[str, RepairCandidate] = {}
    for c in candidates:
        prev = best_by_strategy.get(c.strategy)
        if prev is None or c.confidence > prev.confidence:
            best_by_strategy[c.strategy] = c
    return sorted(
        best_by_strategy.values(),
        key=lambda c: (-c.confidence, c.strategy),
    )


__all__ = [
    # states
    "STATE_NEW", "STATE_RECOGNIZED", "STATE_EXECUTED", "STATE_VALIDATED",
    "STATE_REPAIR_PENDING", "STATE_REPAIRED", "STATE_UNREACHABLE",
    "STATE_ANALYZED", "LIFECYCLE_STATES",
    # validation failure codes
    "INVALID_MISSING_MAGIC", "INVALID_BAD_PADDING", "INVALID_BAD_ALPHABET",
    "INVALID_HTML_MANGLED", "INVALID_LOW_PRINTABLE_RATIO", "INVALID_TRUNCATED",
    "INVALID_UNKNOWN_ENCODING", "INVALID_SIZE_BELOW_MIN", "INVALID_ALL_ZERO",
    "INVALID_ALIGNMENT_SHIFT", "INVALID_STRUCTURAL",
    # repair failure codes
    "REPAIR_FAIL_IRREVERSIBLE", "REPAIR_FAIL_TRUNCATED", "REPAIR_FAIL_UNSUPPORTED",
    "REPAIR_FAIL_CHECKSUM", "REPAIR_FAIL_MISSING_BYTES", "REPAIR_FAIL_UNKNOWN_FORMAT",
    "REPAIR_FAIL_LOW_CONFIDENCE", "REPAIR_FAIL_VALIDATOR_REJECTED",
    "REPAIR_FAIL_NO_CAPABILITY", "REPAIR_FAIL_EXCEPTION",
    "UNREACHABLE_NO_STRATEGIES_LEFT",
    # types
    "RepairCandidate", "ValidationResult", "RepairResult",
    "ValidationCertificate", "RepairCertificate",
    "Validator", "RepairCapability",
    # registries
    "register_validator", "register_repair", "validators_for", "repair_for",
    "all_validators", "all_repairs", "clear",
    # planner
    "plan_repairs",
]
