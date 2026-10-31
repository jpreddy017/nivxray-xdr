"""Stage-2 Verdict Engine · canonical input builder.

Normalises heterogeneous upstream signals into ONE deterministic
dataclass consumed by the rule engine.

Inputs (owner rule #3):
  - canonical SSOT / case doc
  - reconstructed Timeline (services.iue.timeline.fuse)
  - Intent (services.die.intent.classify_intent)
  - Objectives (from intent output)
  - Lane analysis wires (Lane A/B/C)
  - existing v3.x signals/verdict
  - canonical evidence
  - provenance
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class Stage2Input:
    """Canonicalised inputs for the Stage-2 rule engine.  All fields
    deterministic — nothing volatile leaks in here."""
    case_id: Optional[str]
    tenant_id: Optional[str]
    timeline_events: List[Dict[str, Any]]       # projected TimelineEvent dicts
    observed_tactics: Set[str]                  # from intent
    objective_rule: Optional[str]               # e.g. "double_extortion_ransomware"
    objective_name: Optional[str]
    objective_confidence: float
    v3x_verdict: Optional[str]                  # "malicious"/"suspicious"/"benign"/…
    v3x_risk_score: Optional[float]
    lanes_present: List[str]                    # ["log","url","file"]
    provenance_seeds: List[str]                 # top-level provenance markers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id":              self.case_id,
            "tenant_id":            self.tenant_id,
            "timeline_events":      self.timeline_events,
            "observed_tactics":     sorted(self.observed_tactics),
            "objective_rule":       self.objective_rule,
            "objective_name":       self.objective_name,
            "objective_confidence": self.objective_confidence,
            "v3x_verdict":          self.v3x_verdict,
            "v3x_risk_score":       self.v3x_risk_score,
            "lanes_present":        sorted(self.lanes_present),
            "provenance_seeds":     sorted(self.provenance_seeds),
        }


def build_inputs(*,
                   case_id: Optional[str] = None,
                   tenant_id: Optional[str] = None,
                   timeline: Optional[Dict[str, Any]] = None,
                   intent: Optional[Dict[str, Any]] = None,
                   v3x_verdict_card: Optional[Dict[str, Any]] = None,
                   lane_wires: Optional[List[Dict[str, Any]]] = None
                   ) -> Stage2Input:
    """Assemble a Stage2Input from the sources the analyst passes.

    Every field is defensively normalised — missing inputs default
    to empty rather than raising, so a Stage-2 verdict can be computed
    incrementally as new evidence lands.
    """
    timeline = timeline or {}
    intent = intent or {}
    v3x_verdict_card = v3x_verdict_card or {}
    lane_wires = lane_wires or []

    events = list(timeline.get("events") or [])
    untimed = list(timeline.get("untimed_events") or [])
    all_events = events + untimed

    tactics: Set[str] = set()
    for step in (intent.get("steps") or []):
        t = step.get("intent")
        if t:
            tactics.add(t)
    for e in all_events:
        cf = e.get("canonical_fields") or {}
        t = cf.get("canonical.event.tactic") or cf.get("intent.tactic")
        if t:
            tactics.add(t)

    obj_rule = intent.get("rule")
    obj_name = intent.get("objective")
    obj_conf = float(intent.get("confidence") or 0.0)

    v3x_label = (v3x_verdict_card.get("verdict")
                    or v3x_verdict_card.get("label"))
    v3x_score = v3x_verdict_card.get("risk_score") \
                    or v3x_verdict_card.get("risk")
    try:
        v3x_score = float(v3x_score) if v3x_score is not None else None
    except (ValueError, TypeError):
        v3x_score = None

    lanes = set()
    for w in lane_wires:
        lane = (w.get("intake_decision") or {}).get("lane")
        if lane:
            lanes.add(lane)
    if not lanes:
        lanes = set(timeline.get("lanes") or [])

    seeds: List[str] = []
    for w in lane_wires:
        rp = w.get("raw_payload") or {}
        pid = rp.get("input_id")
        if pid:
            seeds.append(f"input:{pid}")

    return Stage2Input(
        case_id=case_id,
        tenant_id=tenant_id,
        timeline_events=all_events,
        observed_tactics=tactics,
        objective_rule=obj_rule,
        objective_name=obj_name,
        objective_confidence=obj_conf,
        v3x_verdict=v3x_label if isinstance(v3x_label, str) else None,
        v3x_risk_score=v3x_score,
        lanes_present=sorted(lanes),
        provenance_seeds=sorted(seeds),
    )


__all__ = ["Stage2Input", "build_inputs"]
