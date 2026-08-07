"""UAIE Contract #11 · Registry-Driven Planner  (Rule R28.7)

The Registry-Driven Planner is the deliberate architectural boundary
between orchestration and capability semantics.

    ARCHITECTURAL RULE (locked · never violate)
    ──────────────────────────────────────────
    The orchestrator may ORCHESTRATE, but it must NEVER understand
    capability semantics.  All semantics — what a capability requires,
    produces, improves, consumes, at what cost, with what confidence
    lift — live EXCLUSIVELY in the Capability Registry as contracts.
    The orchestrator asks the registry what is applicable and executes
    the returned plan.  It has no other knowledge of what any
    individual plugin does.

Consequences:
  · Adding a new capability = registering a new contract.
  · Never a modification to the orchestrator, planner, lifecycle,
    QA layer, SSOT projection, or termination audit.
  · The planner sees only ``(CapabilityContract, impl)`` tuples; it
    never inspects the impl.

Selection strategy (deterministic)
──────────────────────────────────
Given an artifact ``A`` and the current graph, the planner returns
the ordered list of ``(contract, impl)`` pairs to execute.  Order is:

    1. Recognizers first  (category = CAT_RECOGNIZER)  · cheapest → dearest
    2. Validators         (category = CAT_VALIDATOR)   · applied via QA
    3. Executors          (category = CAT_EXECUTOR)    · by (cost ASC,
                                                            −priority_hint,
                                                            −total_expected_gain,
                                                            id ASC)
    4. Analyzers          (category = CAT_ANALYZER)
    5. MITRE mappers      (category = CAT_MITRE_MAPPER)
    6. Family classifiers (category = CAT_FAMILY)

Every tie is broken by ``id ASC`` so the plan is bit-for-bit
deterministic — same registry state + same input → same plan.
"""
from __future__ import annotations

from typing import Any, List, Tuple

from .artifact import Artifact
from .contract import (CAT_ANALYZER, CAT_EXECUTOR, CAT_FAMILY,
                         CAT_MITRE_MAPPER, CAT_RECOGNIZER, CAT_REPAIR,
                         CAT_VALIDATOR, CapabilityContract, applicable_contracts,
                         get as _get_impl)


# Category priority (lower = earlier).  Explicit so the ordering is
# reviewable in one place.
_CATEGORY_PRIORITY = {
    CAT_RECOGNIZER:   0,
    CAT_VALIDATOR:    1,
    CAT_EXECUTOR:     2,
    CAT_ANALYZER:     3,
    CAT_MITRE_MAPPER: 4,
    CAT_FAMILY:       5,
    CAT_REPAIR:       6,   # repairs run inside the QA loop, rarely here
}


def _sort_key(c: CapabilityContract) -> tuple:
    """Deterministic sort key for a contract.

    Priority ladder (lower tuple wins):
      1. category order      (recognizers before executors, etc.)
      2. cost ASC            (cheap wins first)
      3. −priority_hint      (advisory tie-break, higher wins)
      4. −total_expected_gain (prefer larger investigation improvement)
      5. id ASC              (final tie-break; always deterministic)
    """
    return (
        _CATEGORY_PRIORITY.get(c.category, 99),
        c.cost,
        -c.priority_hint,
        -c.total_expected_gain(),
        c.id,
    )


def plan_for(artifact: Artifact) -> List[Tuple[CapabilityContract, Any]]:
    """Return the ordered execution plan for ``artifact``.

    The orchestrator calls this function.  It receives back a
    deterministic list of ``(contract, impl)`` tuples in the order
    they should be attempted.  It never inspects the contract fields
    further — the ordering IS the plan.
    """
    contracts = applicable_contracts(artifact.artifact_type)
    ordered = sorted(contracts, key=_sort_key)
    plan: List[Tuple[CapabilityContract, Any]] = []
    for c in ordered:
        pair = _get_impl(c.id)
        if pair is None:
            continue        # impl unregistered (shouldn't happen in practice)
        plan.append(pair)
    return plan


def plan_stats(artifact: Artifact) -> dict:
    """Return a compact stats dict for the audit / opportunity-analysis
    layer.  Non-invasive — safe to call any time.
    """
    contracts = applicable_contracts(artifact.artifact_type)
    by_cat: dict = {}
    total_gain = 0.0
    for c in contracts:
        by_cat[c.category] = by_cat.get(c.category, 0) + 1
        total_gain += c.total_expected_gain()
    return {
        "applicable_count":       len(contracts),
        "by_category":            by_cat,
        "total_expected_gain":    round(total_gain, 4),
    }


__all__ = ["plan_for", "plan_stats"]
