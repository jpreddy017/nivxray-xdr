"""Stage-2 Verdict Engine — data model.

Owner-locked contract (decisions 1, 4, 5, 6 · 2026-08-26):

  case.verdict_stage2 = {
      label,                    # "malicious" | "suspicious" | "benign" | "unknown"
      confidence,               # "high" | "medium" | "low" | "insufficient"
      risk_score,               # 0..100 int
      contributing_signals,     # list[ContributingSignal]
      evidence_rows,            # list[EvidenceRow]     ← citable
      provenance_chain,         # list[str]
      fingerprint,              # deterministic hash (excludes volatile fields)
      generated_at,             # ISO ts — OPERATIONAL METADATA ONLY
      inputs_hash,              # sha256 of canonical inputs
      version,                  # engine schema version
  }

ADDITIVE only.  Never mutate the v3.x verdict/verdict_card contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# Fixed vocabulary — decision 4c.  Existing v3.x labels preserved
# verbatim; a confidence bucket is layered on top.
VERDICT_LABELS = ("malicious", "suspicious", "benign", "unknown")
CONFIDENCE_BUCKETS = ("high", "medium", "low", "insufficient")


@dataclass(frozen=True)
class EvidenceRow:
    """A single citable evidence row inside a Stage-2 verdict card.

    Every field is deterministically derivable from canonical inputs.
    The row is what the analyst clicks to pivot back to raw evidence.
    """
    row_id: str                          # deterministic id (sha256 of key fields)
    rule_id: str                         # rule that produced this row
    canonical_field_matched: str         # e.g. "canonical.process.command_line"
    matched_value: str                   # the actual matched value (truncated)
    weight_contribution: int             # +N or -N delta on risk_score
    lane: str                            # "log" | "url" | "file" | "narrative"
    event_ids: List[str] = field(default_factory=list)
    provenance_chain: List[str] = field(default_factory=list)
    display_summary: str = ""            # short one-liner for the UI card

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ContributingSignal:
    """A rule's overall contribution to the verdict.  Higher-level
    than EvidenceRow — one signal may summarise many rows.
    """
    rule_id: str
    rule_name: str
    weight: int
    hits: int                            # how many evidence rows this rule produced
    label_effect: str                    # "malicious" | "suspicious" | "benign" | "neutral"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Stage2Verdict:
    """The complete Stage-2 verdict envelope.  Additive to `case`."""
    label: str
    confidence: str
    risk_score: int
    contributing_signals: List[ContributingSignal]
    evidence_rows: List[EvidenceRow]
    provenance_chain: List[str]
    fingerprint: str                     # deterministic hash (see fingerprint.py)
    inputs_hash: str                     # sha256 of canonical inputs
    generated_at: str                    # ISO ts (OPERATIONAL, not in fingerprint)
    version: str = "stage2.v1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label":               self.label,
            "confidence":          self.confidence,
            "risk_score":          self.risk_score,
            "contributing_signals": [s.to_dict() for s in self.contributing_signals],
            "evidence_rows":       [r.to_dict() for r in self.evidence_rows],
            "provenance_chain":    list(self.provenance_chain),
            "fingerprint":         self.fingerprint,
            "inputs_hash":         self.inputs_hash,
            "generated_at":        self.generated_at,
            "version":             self.version,
        }


__all__ = [
    "VERDICT_LABELS", "CONFIDENCE_BUCKETS",
    "EvidenceRow", "ContributingSignal", "Stage2Verdict",
]
