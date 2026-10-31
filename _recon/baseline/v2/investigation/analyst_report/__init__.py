"""Analyst Report · flagship deterministic MDR-grade output.

Consumes an ``InvestigationResult`` and produces the 8-section
report an analyst can hand to customers or management:

    Executive Summary
    Observed Behaviors
    Intent
    Evidence
    MITRE
    IOCs
    Unknowns
    Recommended Next Steps
    (+ Confidence Signals — investigation-specific, NOT engineering
     trust metrics.)
"""
from __future__ import annotations

from .builder import generate
from .models import IOC, AnalystReport, MITREItem, Recommendation

__all__ = [
    "generate",
    "AnalystReport",
    "Recommendation",
    "IOC",
    "MITREItem",
]
