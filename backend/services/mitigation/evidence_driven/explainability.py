"""P0.13 · Phase 3.7 · Recommendation Explainability.

Evidence-chain completeness score for every recommendation.  Never
uses arbitrary weights — a recommendation is 100 % explainable
if every link of the chain

    Evidence → Behavior → Registry → MITRE → Rule → Consumer

carries data that supports the recommendation.  Analysts see a
transparent boolean-per-component breakdown, not a mystery number.

Single implementation, two consumers:
    · baked into every recommendation payload
    · exposed via /api/investigation/recommendations/explainability
      for corpus-wide analytics (filter recs with score < N)
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from services.ida.behavior_registry import build_registry
from services.ida.projections.mitre  import BEHAVIOR_TO_MITRE
from services.mitigation.evidence_driven.attack_posture_normalizer import (
    TECHNIQUE_TO_TACTIC,
)


_COMPONENT_ORDER: tuple = (
    "evidence",
    "behavior",
    "registry",
    "mitre",
    "rule_metadata",
    "consumer_reached",
)


def _behaviors_supporting(rec_mitre: Iterable[str]) -> List[str]:
    """Reverse-lookup: which registered behaviors project into any
    of the recommendation's MITRE techniques?"""
    rec_set = set(rec_mitre or ())
    if not rec_set:
        return []
    hits: List[str] = []
    for btype, tids in BEHAVIOR_TO_MITRE.items():
        if rec_set & set(tids):
            hits.append(btype)
    return sorted(hits)


def compute_explainability(rec:      Dict[str, Any],
                              observed_behaviors: Iterable[str],
                              observed_mitre:     Iterable[str],
                              ) -> Dict[str, Any]:
    """Return ``{"score": int, "components": {...}, "supporting_behaviors": [...]}``.

    Arguments
    ---------
    rec
        The recommendation dict as produced by ``Recommendation.as_dict()``
        (id, mitre, category, priority, evidence, reason, action).
    observed_behaviors
        Behaviors present on the case (``ctx.behaviors``).
    observed_mitre
        MITRE techniques on the case (``ctx.mitre_techniques``).

    All six components are booleans — the score is simply how many
    are true out of six.  No hidden weights.
    """
    reg               = build_registry()
    rec_mitre         = list(rec.get("mitre") or ())
    rec_evidence      = list(rec.get("evidence") or ())
    behaviors_set     = set(observed_behaviors or ())
    observed_mitre_set = set(observed_mitre or ())

    # 1. Evidence — the rule collected at least one evidence line.
    has_evidence = bool(rec_evidence)

    # 2. Behavior — the rec's MITRE overlaps at least one observed
    #    behavior's MITRE projection.  This proves the rec is
    #    supported by an observed behavior, not just a raw MITRE tag.
    supporting_behaviors = [
        b for b in _behaviors_supporting(rec_mitre)
        if b in behaviors_set
    ]
    has_behavior = bool(supporting_behaviors)

    # 3. Registry — every supporting behavior appears in the
    #    Behavior Registry.  This proves the chain is discoverable
    #    from the read-only catalog.
    has_registry = (bool(supporting_behaviors)
                       and all(b in reg for b in supporting_behaviors))

    # 4. MITRE — the rec's techniques resolve to an ATT&CK tactic.
    has_mitre = bool(rec_mitre) and all(
        t in TECHNIQUE_TO_TACTIC for t in rec_mitre)

    # 5. Rule metadata — the rec carries the non-trivial metadata
    #    a downstream renderer / API consumer needs.
    has_rule_metadata = bool(rec.get("id")
                                 and rec.get("category")
                                 and rec.get("priority")
                                 and rec.get("action")
                                 and rec.get("reason"))

    # 6. Consumer reached — at least one supporting behavior
    #    declares recommendation_engine reachability in the registry.
    consumer_reached = any(
        reg.get(b)
        and reg[b].consumer_reach.get("recommendation_engine") is True
        for b in supporting_behaviors)

    components = {
        "evidence":          has_evidence,
        "behavior":          has_behavior,
        "registry":          has_registry,
        "mitre":             has_mitre,
        "rule_metadata":     has_rule_metadata,
        "consumer_reached":  consumer_reached,
    }
    score = int(round(sum(1 for c in components.values() if c)
                          / len(components) * 100))
    return {
        "score":                 score,
        "components":            components,
        "supporting_behaviors":  supporting_behaviors,
    }


def annotate_recommendations(recommendations: List[Dict[str, Any]],
                                 observed_behaviors: Iterable[str],
                                 observed_mitre:     Iterable[str],
                                 ) -> None:
    """In-place: attach an ``explainability`` block to every rec."""
    b = tuple(observed_behaviors or ())
    m = tuple(observed_mitre or ())
    for rec in recommendations:
        rec["explainability"] = compute_explainability(rec, b, m)


__all__ = [
    "compute_explainability",
    "annotate_recommendations",
    "_COMPONENT_ORDER",
]
