"""Stage-2 Verdict Engine · deterministic composer.

Owner-locked contract (2026-08-26):
  - PURE function of canonical inputs → verdict envelope.
  - Zero LLM, zero probabilistic model, zero generative AI.
  - Byte-identical output for identical inputs (fingerprint-locked).
  - Additive to case (never mutates v3.x verdict/verdict_card).
  - Every evidence row traces back to canonical/raw evidence.

Score → label → confidence mapping (owner decision 4c):

    risk_score ≥ 80              → label=malicious   confidence=high
    60 ≤ risk_score < 80         → label=malicious   confidence=medium
    40 ≤ risk_score < 60         → label=suspicious  confidence=medium
    20 ≤ risk_score < 40         → label=suspicious  confidence=low
    0  ≤ risk_score < 20         → label=benign      confidence=medium
    risk_score < 0               → label=benign      confidence=high
    ← if fewer than 2 signals contributed → confidence=insufficient
    ← if no evidence rows at all           → label=unknown
"""
from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .model import (Stage2Verdict, EvidenceRow, ContributingSignal,
                     VERDICT_LABELS, CONFIDENCE_BUCKETS)
from .rules import RULES, MAX_ABS_WEIGHT
from .fingerprint import inputs_hash, verdict_fingerprint
from .inputs import Stage2Input, build_inputs


def _apply_rule_cap(rows: List[EvidenceRow]) -> List[EvidenceRow]:
    """Bound absolute contribution per rule so no single rule can
    dominate the score.  See rules.MAX_ABS_WEIGHT."""
    if not rows:
        return rows
    total = sum(abs(r.weight_contribution) for r in rows)
    if total <= MAX_ABS_WEIGHT:
        return rows
    factor = MAX_ABS_WEIGHT / total
    # Deterministic rescale, integer-rounded, preserving sign.
    out: List[EvidenceRow] = []
    for r in rows:
        scaled = int(round(r.weight_contribution * factor))
        if scaled == 0 and r.weight_contribution != 0:
            scaled = 1 if r.weight_contribution > 0 else -1
        out.append(EvidenceRow(
            row_id=r.row_id,
            rule_id=r.rule_id,
            canonical_field_matched=r.canonical_field_matched,
            matched_value=r.matched_value,
            weight_contribution=scaled,
            lane=r.lane,
            event_ids=list(r.event_ids),
            provenance_chain=list(r.provenance_chain),
            display_summary=r.display_summary,
        ))
    return out


def _label_and_confidence(risk_score: int,
                            distinct_rule_hits: int,
                            has_any_evidence: bool) -> Tuple[str, str]:
    if not has_any_evidence:
        return "unknown", "insufficient"
    if distinct_rule_hits < 2:
        # Not enough independent signals — mark confidence insufficient
        # regardless of the raw score to prevent single-signal spikes.
        if risk_score >= 40:
            return "suspicious", "insufficient"
        return "unknown", "insufficient"
    if risk_score >= 80:
        return "malicious", "high"
    if risk_score >= 60:
        return "malicious", "medium"
    if risk_score >= 40:
        return "suspicious", "medium"
    if risk_score >= 20:
        return "suspicious", "low"
    if risk_score >= 0:
        return "benign", "medium"
    return "benign", "high"


def compute_stage2(inputs: Stage2Input,
                     *, now_iso: Optional[str] = None) -> Stage2Verdict:
    """Run every registered rule against the canonical inputs and
    compose a deterministic Stage-2 verdict envelope.

    ``now_iso`` is injectable for tests — it sets ``generated_at`` only
    and MUST NOT enter the fingerprint (guarded by fingerprint.py).
    """
    all_rows: List[EvidenceRow] = []
    signals: List[ContributingSignal] = []

    for rule_id, rule_name, rule_fn, label_effect in RULES:
        raw_rows = rule_fn(inputs)
        rows = _apply_rule_cap(raw_rows)
        all_rows.extend(rows)
        if rows:
            weight = sum(r.weight_contribution for r in rows)
            signals.append(ContributingSignal(
                rule_id=rule_id,
                rule_name=rule_name,
                weight=weight,
                hits=len(rows),
                label_effect=label_effect,
                description=rows[0].display_summary if rows else "",
            ))

    # Deterministic ordering of evidence rows for stable fingerprint.
    all_rows.sort(key=lambda r: (r.rule_id, r.row_id))
    signals.sort(key=lambda s: s.rule_id)

    risk_score = sum(r.weight_contribution for r in all_rows)
    # Bound to [-100, 100] then squash to [0, 100] for the analyst-
    # facing "risk_score".  Preserve negative via the label mapping.
    risk_score_bounded = max(-100, min(100, risk_score))
    risk_score_display = max(0, risk_score_bounded)

    distinct_rules = len({r.rule_id for r in all_rows})
    label, confidence = _label_and_confidence(
        risk_score_bounded, distinct_rules, bool(all_rows))

    # Provenance chain — union of every row's provenance + engine marker.
    prov_set = set()
    for r in all_rows:
        prov_set.update(r.provenance_chain)
    prov_set.add("services.verdict_stage2.engine")
    provenance_chain = sorted(prov_set)

    # Canonical input hash for the envelope.
    ih = inputs_hash(inputs.to_dict())

    envelope_dict = {
        "label":                label,
        "confidence":           confidence,
        "risk_score":           risk_score_display,
        "contributing_signals": [s.to_dict() for s in signals],
        "evidence_rows":        [r.to_dict() for r in all_rows],
        "provenance_chain":     provenance_chain,
        "inputs_hash":          ih,
        "version":              "stage2.v1",
    }
    fp = verdict_fingerprint(envelope_dict)

    generated_at = now_iso or datetime.now(timezone.utc).isoformat()

    return Stage2Verdict(
        label=label,
        confidence=confidence,
        risk_score=risk_score_display,
        contributing_signals=signals,
        evidence_rows=all_rows,
        provenance_chain=provenance_chain,
        fingerprint=fp,
        inputs_hash=ih,
        generated_at=generated_at,
    )


__all__ = ["compute_stage2", "build_inputs", "Stage2Verdict"]
