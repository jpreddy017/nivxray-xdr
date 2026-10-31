"""Analyst Report · canonical models.

The Analyst Report is the FLAGSHIP output an analyst can send
directly to customers or management. Every conclusion cites
canonical Evidence — nothing is fabricated. Deterministic and
evidence-anchored.

Report structure (locked by user directive):

    Executive Summary
    Observed Behaviors
    Intent
    Evidence
    MITRE
    IOCs
    Unknowns
    Recommended Next Steps
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Recommendation:
    """One analyst-facing next step. Deterministic — the same
    fired intents always produce the same recommendation set."""
    priority: str            # "immediate" | "short_term" | "long_term"
    action:   str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IOC:
    """A single indicator of compromise extracted from evidence."""
    kind:    str             # "url" | "ip" | "domain" | "file" | "registry" | "sha256"
    value:   str
    context: str = ""        # short analyst-facing context ("staging URL")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MITREItem:
    """One MITRE technique observed with the intent that fired it."""
    id:            str        # e.g. "T1105"
    name:          str        # e.g. "Ingress Tool Transfer"
    intent:        str        # which intent category cited it
    confidence:    int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalystReport:
    """Complete analyst-facing report.

    Every field is derived from the InvestigationResult — no
    fabrication, no LLM. Deterministic replay.
    """
    executive_summary:    str
    observed_behaviors:   list[dict[str, Any]] = field(default_factory=list)
    intent_narrative:     list[dict[str, Any]] = field(default_factory=list)
    evidence:             list[dict[str, Any]] = field(default_factory=list)
    mitre:                list[MITREItem] = field(default_factory=list)
    iocs:                 list[IOC] = field(default_factory=list)
    unknowns:             list[str] = field(default_factory=list)
    recommendations:      list[Recommendation] = field(default_factory=list)
    # Investigation-specific confidence signals shown to analysts —
    # NOT engineering quality metrics. Locked with user directive.
    confidence_signals:   dict[str, str] = field(default_factory=dict)
    # Canonical Behaviour Graph — the shared language between the
    # Verdict Engine, Analyst Report, and future Behaviour Correlation.
    # Deterministic — derived directly from the intent set.
    behavior_graph:       dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_summary":  self.executive_summary,
            "observed_behaviors": list(self.observed_behaviors),
            "intent_narrative":   list(self.intent_narrative),
            "evidence":           list(self.evidence),
            "mitre":              [m.to_dict() for m in self.mitre],
            "iocs":               [i.to_dict() for i in self.iocs],
            "unknowns":           list(self.unknowns),
            "recommendations":    [r.to_dict() for r in self.recommendations],
            "confidence_signals": dict(self.confidence_signals),
            "behavior_graph":     dict(self.behavior_graph),
        }


__all__ = [
    "AnalystReport",
    "Recommendation",
    "IOC",
    "MITREItem",
]
