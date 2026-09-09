"""project_verdict — canonical verdict projection.

Purely derived from evidence_graph counts, reasoning_steps, and health.
Numeric + enum-labelled ⇒ byte_identity comparison.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT
from ..ssot.models import VerdictProjection
from ._helpers import (
    command_nodes,
    executed_capabilities,
    health_nodes,
    ioc_nodes,
    mitre_nodes,
    skipped_capabilities,
)


# Deterministic verdict scoring (documented, pure).
# Contribution weights per evidence class; scores clamp to 0..100.
_WEIGHTS = {
    "mitre_technique":  25,
    "ioc":               8,
    "command":           4,
    "reasoning_step":    2,
}
_LABEL_BANDS = [
    (80, "MALICIOUS"),
    (60, "SUSPICIOUS"),
    (30, "LIKELY_BENIGN"),
    (0,  "INCONCLUSIVE"),
]


def _score(ssot: AuthoritativeSSOT) -> int:
    score = 0
    score += min(len(mitre_nodes(ssot)), 4) * _WEIGHTS["mitre_technique"]
    score += min(len(ioc_nodes(ssot)),   8) * _WEIGHTS["ioc"]
    score += min(len(command_nodes(ssot)), 8) * _WEIGHTS["command"]
    score += min(len(ssot.reasoning_steps), 10) * _WEIGHTS["reasoning_step"]
    return max(0, min(score, 100))


def _label(score: int) -> str:
    for threshold, label in _LABEL_BANDS:
        if score >= threshold:
            return label
    return "INCONCLUSIVE"


def _input_completeness(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    hnodes = health_nodes(ssot)
    ok = bool(hnodes and hnodes[0].attrs.get("ok", False))
    completeness = "complete"
    if not hnodes:
        completeness = "unknown"
    elif not ok:
        completeness = "minimal"
    return {
        "level": completeness,
        "health_ok": ok,
        "size_bytes": (hnodes[0].attrs.get("size_bytes") if hnodes else None),
    }


def project_verdict(ssot: AuthoritativeSSOT) -> VerdictProjection:
    """Score + label + contributors + input_completeness.

    P4-FW3-adjacent: `reason` explicitly states "no evidence" when there
    is none — never falls back to generic templates.
    """
    score = _score(ssot)
    label = _label(score)

    contributors: List[Dict[str, Any]] = []
    if mitre_nodes(ssot):
        contributors.append({"class": "mitre_technique",
                             "count": len(mitre_nodes(ssot)),
                             "weight": _WEIGHTS["mitre_technique"]})
    if ioc_nodes(ssot):
        contributors.append({"class": "ioc",
                             "count": len(ioc_nodes(ssot)),
                             "weight": _WEIGHTS["ioc"]})
    if command_nodes(ssot):
        contributors.append({"class": "command",
                             "count": len(command_nodes(ssot)),
                             "weight": _WEIGHTS["command"]})
    if ssot.reasoning_steps:
        contributors.append({"class": "reasoning_step",
                             "count": len(ssot.reasoning_steps),
                             "weight": _WEIGHTS["reasoning_step"]})

    if not contributors:
        reason = "no evidence in canonical SSOT"
    else:
        parts = [f"{c['count']}×{c['class']}" for c in contributors]
        reason = "canonical score derived from " + " + ".join(parts)

    return VerdictProjection(
        label=label,
        confidence=score,
        reason=reason,
        contributors=contributors,
        input_completeness=_input_completeness(ssot),
    )
