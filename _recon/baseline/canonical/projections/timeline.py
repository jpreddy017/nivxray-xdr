"""project_timeline — canonical evidence timeline.

Builds a deterministic ordered timeline from execution_trace +
reasoning_steps + evidence nodes. Byte_identity.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT


def project_timeline(ssot: AuthoritativeSSOT) -> List[Dict[str, Any]]:
    """Return an ordered timeline: execution_trace steps + evidence nodes.

    Deterministic ordering:
      1. all execution_trace steps in stored order (step_id break-tie)
      2. followed by evidence nodes in stored order

    Elements are minimal descriptors — Phase 4 does not synthesise
    "wall clock" timestamps (P4-FW1: no clock access).
    """
    events: List[Dict[str, Any]] = []
    ordinal = 0

    for step in ssot.execution_trace:
        events.append({
            "ordinal": ordinal,
            "kind": "execution_step",
            "step_id": step.step_id,
            "capability": step.capability,
            "engine": step.engine,
            "status": step.status,
            "notes": step.notes,
        })
        ordinal += 1

    for n in ssot.evidence_graph.nodes:
        events.append({
            "ordinal": ordinal,
            "kind": "evidence_node",
            "node_id": n.id,
            "node_kind": n.kind,
            "label": n.label,
        })
        ordinal += 1

    for r in ssot.reasoning_steps:
        events.append({
            "ordinal": ordinal,
            "kind": "reasoning_step",
            "step_id": r.id,
            "rule": r.rule,
            "rationale": r.rationale,
        })
        ordinal += 1

    return events
