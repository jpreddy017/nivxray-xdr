"""Round 31 · Investigator · Planner + Selector.

Given a Round 30 ``IUEUnderstanding``, deterministically emit the
list of ``PivotAction`` records that should be considered for this
tick.  The Planner does NOT invoke capabilities — the Selector +
Orchestrator do that.
"""
from __future__ import annotations

import hashlib
from typing import List, Set

from services.iue.artifacts import IUEUnderstanding
from services.investigator.models import PivotAction
from services.investigator.capabilities import (
    all_capabilities, get_capability,
)


def _pivot_id(incident_id: str, capability: str, target: str) -> str:
    seed = f"{incident_id}|{capability}|{target}"
    return "pvt_" + hashlib.sha256(seed.encode()).hexdigest()[:20]


def plan_pivots(understanding: IUEUnderstanding,
                    attempted_pivot_ids: Set[str] | None = None,
                   ) -> List[PivotAction]:
    """Deterministic v0 planner.

    * One pivot per unattempted gap in ``understanding.artifacts.gaps``.
    * Pivots are ordered by gap.key (stable) and then by priority.
    * Duplicate pivots (already attempted) are filtered out.
    """
    attempted = attempted_pivot_ids or set()
    ctx = understanding.artifacts.context
    gaps = understanding.artifacts.gaps.gaps
    pivots: List[PivotAction] = []
    for gap in gaps:
        capability = gap.suggested_capability or ""
        if not capability:
            continue
        target_kind = "incident"
        target_value = ctx.incident_id
        pid = _pivot_id(ctx.incident_id, capability, target_value)
        if pid in attempted:
            continue
        # Priority — evidence-facing gaps first, then expansions.
        priority_map = {
            "historical_correlation": 90,
            "mitre_expansion":        70,
            "process_ancestry":       80,
            "identity_pivot":         75,
            "file_reputation":        65,
            "network_pivot":          60,
        }
        priority = priority_map.get(capability, 50)

        pivots.append(PivotAction(
            pivot_id=pid,
            incident_id=ctx.incident_id,
            tenant_id=ctx.tenant_id,
            gap_key=gap.key,
            capability=capability,
            target_kind=target_kind,
            target_value=target_value,
            reason=gap.why_it_matters,
            triggering_evidence=(
                [ctx.canonical_event_id] if ctx.canonical_event_id else []
            ),
            expected_outcome=gap.description,
            priority=priority,
            provenance={
                "gap_id":    gap.gap_id,
                "iue_content_hash": understanding.content_hash,
                "iue_version":      understanding.version,
            },
        ))
    pivots.sort(key=lambda p: (-p.priority, p.gap_key))
    return pivots


# ── Selector ────────────────────────────────────────────────────────

def select_capability(pivot: PivotAction):
    """Return the Capability instance for a pivot, or ``None`` if
    the capability is not registered.  Availability is a property of
    the returned instance — the orchestrator inspects it to decide
    whether to execute or skip honestly.
    """
    return get_capability(pivot.capability)


def known_capability_ids() -> List[str]:
    return sorted(all_capabilities().keys())
