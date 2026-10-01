"""Semantic Intent Layer — Phase 4 of the Investigation Brain.

Translates low-level syntax findings (from IU / CRE / RTE) into
analyst-facing intent:

    Purpose:  what the artefact is trying to accomplish
    Risk:     categorical risk band the analyst can act on
    Evidence: canonical Evidence objects supporting the intent

Public API:
    assess(text, meta={...}) -> IntentAssessment
"""
from __future__ import annotations

from .engine import assess
from .models import Intent, IntentAssessment, IntentCategory, RiskBand

__all__ = [
    "assess",
    "Intent",
    "IntentAssessment",
    "IntentCategory",
    "RiskBand",
]
