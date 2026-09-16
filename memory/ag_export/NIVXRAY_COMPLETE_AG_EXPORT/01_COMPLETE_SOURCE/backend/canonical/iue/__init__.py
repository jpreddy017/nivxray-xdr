"""Canonical IUE (Universal Investigation Engine) — Phase 1.

Public API:
    from canonical.iue import classify, IUEDecision

The composer aggregates existing sub-classifiers into a single
deterministic IUEDecision. It classifies + profiles + emits an
intent + emits a deterministic plan + emits a dispatch policy.
It never decodes, extracts, maps MITRE, fetches URLs, or computes
verdicts (see ADR-005 §3.4).
"""
from .composer import classify, COMPOSER_VERSION
from .models import (
    IUEDecision,
    InputProfile,
    IUEEvidence,
    PlanStep,
    ConfidenceMatrix,
    Capability,
    DispatchPolicy,
    Provenance,
    InputHealthResult,
    RawInput,
)

__all__ = [
    "classify",
    "COMPOSER_VERSION",
    "IUEDecision",
    "InputProfile",
    "IUEEvidence",
    "PlanStep",
    "ConfidenceMatrix",
    "Capability",
    "DispatchPolicy",
    "Provenance",
    "InputHealthResult",
    "RawInput",
]
