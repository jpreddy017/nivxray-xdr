"""Round 31/32 · Investigator · Planner + Selector.

Given a Round 30 ``IUEUnderstanding``, deterministically emit the
list of ``PivotAction`` records that should be considered for this
tick.  The Planner does NOT invoke capabilities — the Selector +
Orchestrator do that.

Round 32 additions:
  * Multi-capability gap map — a single gap can chain multiple
    capabilities in priority order.
  * Baseline pivots — some capabilities (correlation, mitre_expansion,
    detection_intel, ioc_pivot) always run against every incident to
    give a minimum investigation baseline regardless of IUE gaps.
  * Evidence-sufficiency filter — the selector honestly skips a
    pivot when the capability's requirements are not met, without
    consuming an execution slot.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Set, Tuple

from services.iue.artifacts import IUEUnderstanding
from services.investigator.models import PivotAction
from services.investigator.capabilities import (
    all_capabilities, get_capability,
)


# Gap → ordered list of capabilities to try, highest first.
GAP_CAPABILITY_MAP: Dict[str, Tuple[str, ...]] = {
    "process_lineage.absent":         ("process_ancestry", "commandline_decode",
                                          "lolbas_lookup"),
    "identity_pivot.absent":          ("identity_pivot",),
    "file_reputation.no_artifact":    ("file_reputation",),
    "cross_evidence.no_correlation":  ("correlation", "historical_correlation"),
    "mitre_expansion.signature_only": ("mitre_expansion",),
}


# Baseline capabilities run against every incident.  They provide the
# minimum investigation baseline (detection intel + IOC surface +
# historical presence + correlation) regardless of IUE gaps.
BASELINE_CAPABILITIES: Tuple[str, ...] = (
    "detection_intel",
    "historical_correlation",
    "correlation",
    "mitre_expansion",
    "ioc_pivot",
    "network_pivot",
    "dns_pivot",
)


# Capability priority — deterministic ordering across ticks.
_PRIORITY: Dict[str, int] = {
    "detection_intel":         95,
    "historical_correlation":  90,
    "correlation":             88,
    "process_ancestry":        85,
    "commandline_decode":      82,
    "lolbas_lookup":           80,
    "network_pivot":           78,
    "identity_pivot":          75,
    "dns_pivot":               72,
    "mitre_expansion":         70,
    "ioc_pivot":               65,
    "file_reputation":         60,
}


def _pivot_id(incident_id: str, capability: str, target: str) -> str:
    seed = f"{incident_id}|{capability}|{target}"
    return "pvt_" + hashlib.sha256(seed.encode()).hexdigest()[:20]


def plan_pivots(understanding: IUEUnderstanding,
                    attempted_pivot_ids: Set[str] | None = None,
                   ) -> List[PivotAction]:
    """Deterministic planner (Round 32).

    Emits one PivotAction for every (capability, incident) pair that:
      * belongs to a mapped gap OR to the baseline set,
      * has NOT been attempted in this incident yet.

    Order: priority DESC, then capability id ASC (stable).
    """
    attempted = attempted_pivot_ids or set()
    ctx = understanding.artifacts.context
    incident_id = ctx.incident_id
    caps_to_try: Dict[str, Dict[str, str]] = {}  # cap_id → {reason, gap_key, expected}

    # 1. Gap-driven pivots.
    for gap in understanding.artifacts.gaps.gaps:
        caps = GAP_CAPABILITY_MAP.get(gap.key, ())
        for cap_id in caps:
            if cap_id in caps_to_try:
                continue
            caps_to_try[cap_id] = {
                "reason":            gap.why_it_matters,
                "gap_key":           gap.key,
                "expected_outcome":  gap.description,
            }

    # 2. Baseline pivots — always add if not already present.
    for cap_id in BASELINE_CAPABILITIES:
        if cap_id in caps_to_try:
            continue
        caps_to_try[cap_id] = {
            "reason":           "Baseline investigation pass — establishes the minimum context for this incident.",
            "gap_key":          "baseline",
            "expected_outcome": "Baseline finding recorded regardless of IUE gaps.",
        }

    pivots: List[PivotAction] = []
    for cap_id, meta in caps_to_try.items():
        pid = _pivot_id(incident_id, cap_id, incident_id)
        if pid in attempted:
            continue
        pivots.append(PivotAction(
            pivot_id=pid,
            incident_id=incident_id,
            tenant_id=ctx.tenant_id,
            gap_key=meta["gap_key"],
            capability=cap_id,
            target_kind="incident",
            target_value=incident_id,
            reason=meta["reason"],
            triggering_evidence=(
                [ctx.canonical_event_id] if ctx.canonical_event_id else []
            ),
            expected_outcome=meta["expected_outcome"],
            priority=_PRIORITY.get(cap_id, 50),
            provenance={
                "iue_content_hash": understanding.content_hash,
                "iue_version":      understanding.version,
            },
        ))
    pivots.sort(key=lambda p: (-p.priority, p.capability))
    return pivots


# ── Selector ────────────────────────────────────────────────────────

def select_capability(pivot: PivotAction):
    """Return the Capability instance for a pivot, or ``None`` when
    not registered.  The orchestrator additionally consults
    ``cap.check_evidence`` to decide whether to run or skip
    honestly."""
    return get_capability(pivot.capability)


def known_capability_ids() -> List[str]:
    return sorted(all_capabilities().keys())


def registry_descriptor() -> List[Dict]:
    """Enumerate every registered capability (for introspection APIs)."""
    return [cap.descriptor() for cap in all_capabilities().values()]
