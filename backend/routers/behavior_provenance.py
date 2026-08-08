"""Behavior Provenance API · stable public schema.

Exposes the deterministic ``Evidence → Behavior → Projection →
Recommendation`` chain for a set of pre-computed Behaviors.

Design (per user directive · 2026-02-05):
    · The response is a STABLE PUBLIC CONTRACT (versioned by
      ``schema_version``).  Internal names like ``behaviors_full``
      are NOT surfaced.
    · Every consumer of a Behavior is attached to it — MITRE,
      kill-chain, impacts, and any recommendations that fire from
      the aggregated outcome.  No hidden downstream logic.
    · The endpoint NEVER re-analyzes raw evidence — it only
      composes projections and correlates recommendations off the
      caller-supplied Behavior list.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.ida.behaviors import (
    Behavior, collect_outcome_inputs_from_behaviors,
)
from services.ida.projections.mitre       import mitre_for
from services.ida.projections.kill_chain  import kill_chain_for
from services.ida.projections.impact      import impacts_for
from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations,
)
from services.mitigation.evidence_driven.investigation_outcome import (
    empty_outcome,
)
from services.mitigation.evidence_driven.attack_posture_normalizer import (
    normalize_attack_posture,
)


PROVENANCE_SCHEMA_VERSION = "1.0"


# ── Public API schema ───────────────────────────────────────────
class _BehaviorRequest(BaseModel):
    """Request shape · caller supplies pre-computed Behaviors."""
    behaviors: List[Dict[str, Any]] = Field(default_factory=list)


router = APIRouter(tags=["provenance"])


@router.post("/investigation/behaviors/explain")
def explain_behaviors(body: _BehaviorRequest) -> Dict[str, Any]:
    """Return the explainable Evidence → Behavior → Projection →
    Recommendation graph for a supplied set of Behaviors.

    Response shape (STABLE contract · versioned)::

        {
          "schema_version": "1.0",
          "behaviors": [
            {
              "id":            "sha1[:12]",
              "behavior_type": "shadow_copy_deletion",
              "label":         "Shadow copy deletion",
              "source":        "command_classifier",
              "provenance":    "command_execution",
              "confidence":    "deterministic",
              "evidence":      { ... raw entity that triggered ... },
              "observed_at":   { "artifact_id": ..., "line": ... },
              "projections": {
                "mitre":      ["T1490"],
                "kill_chain": ["impact"],
                "impacts":    ["recovery_inhibited"]
              },
              "recommendations": ["erad.protect_shadow_copies",
                                    "rec.restore_backups"]
            },
            ...
          ],
          "verdict": { "severity": "critical", "one_liner": "..." },
          "summary": {
            "kill_chain":   [...tactic tags...],
            "impacts":      [...impact tags...],
            "mitre":        [...ATT&CK ids...]
          }
        }
    """
    # ── Deserialize into Behavior dataclass (strict allowlist) ──
    behaviors: List[Behavior] = []
    _ALLOWED = {"behavior_type", "label", "source", "source_ref",
                  "provenance", "confidence", "evidence", "observed_at"}
    for raw in body.behaviors:
        if not isinstance(raw, dict) or "behavior_type" not in raw:
            raise HTTPException(status_code=400,
                                    detail="each behavior must include behavior_type")
        clean = {k: v for k, v in raw.items() if k in _ALLOWED}
        behaviors.append(Behavior(**clean))

    # ── Compose outcome inputs · once, via the aggregator ──────
    inputs = collect_outcome_inputs_from_behaviors(behaviors)

    # ── Run engine to determine which recommendations fire ────
    outcome = empty_outcome()
    outcome["behaviors"]        = inputs["behaviors"]
    outcome["impacts"]          = inputs["impacts"]
    outcome["mitre_techniques"] = inputs["mitre_techniques"]
    outcome = normalize_attack_posture(outcome)
    engine  = evidence_driven_recommendations(investigation_outcome=outcome)

    # ── Attribute each fired recommendation to the behaviors ──
    # that made it fire.  A rec is attributed to a Behavior if any
    # of the rec's MITRE ids appears in the Behavior's projection,
    # OR the rec's category maps to the Behavior's kill-chain tag.
    recs_by_behavior: Dict[str, List[str]] = {}
    for b in behaviors:
        b_mitre = set(mitre_for(b.behavior_type))
        b_kc    = set(kill_chain_for(b.behavior_type))
        b_imp   = set(impacts_for(b.behavior_type))
        matched: List[str] = []
        for r in engine.get("recommendations", []):
            r_mitre = set(r.get("mitre") or ())
            r_evid  = set(r.get("evidence_dims") or ())
            # ATT&CK overlap
            if b_mitre & r_mitre:
                matched.append(r["id"])
                continue
            # Behaviour / impact overlap surfaced by the engine
            if b_kc & r_evid or b_imp & r_evid:
                matched.append(r["id"])
        recs_by_behavior[b.id] = matched

    # ── Build the public schema ────────────────────────────────
    public_behaviors: List[Dict[str, Any]] = []
    for b in behaviors:
        public_behaviors.append({
            "id":            b.id,
            "behavior_type": b.behavior_type,
            "label":         b.label,
            "source":        b.source,
            "provenance":    b.provenance,
            "confidence":    b.confidence,
            "evidence":      b.evidence,
            "observed_at":   b.observed_at,
            "projections": {
                "mitre":      mitre_for(b.behavior_type),
                "kill_chain": kill_chain_for(b.behavior_type),
                "impacts":    impacts_for(b.behavior_type),
            },
            "recommendations": recs_by_behavior.get(b.id, []),
        })

    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "behaviors":      public_behaviors,
        "verdict":        engine.get("verdict") or {},
        "summary": {
            "kill_chain": inputs["behaviors"],
            "impacts":    inputs["impacts"],
            "mitre":      inputs["mitre_techniques"],
        },
    }


__all__ = ["router", "PROVENANCE_SCHEMA_VERSION"]
