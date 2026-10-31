"""Round 31 · Autonomous Investigator · lifecycle state machine (§26).

Allowed transitions.  Every transition is deterministic and driven by
the orchestrator's read of concrete investigation state — never by UI
input, never by an "Auto-Investigate" button (§1, §16).
"""
from __future__ import annotations

from typing import Dict, Tuple

from services.investigator.models import LifecycleState


ALLOWED: Dict[LifecycleState, Tuple[LifecycleState, ...]] = {
    "WAITING_FOR_EVIDENCE":   ("UNDERSTANDING_EVIDENCE", "FAILED"),
    "UNDERSTANDING_EVIDENCE": ("INVESTIGATING", "CONVERGING", "FAILED"),
    "INVESTIGATING":          ("EXPANDING", "CONVERGING",
                                  "WAITING_FOR_CAPABILITY", "FAILED"),
    "EXPANDING":              ("INVESTIGATING", "CONVERGING",
                                  "WAITING_FOR_CAPABILITY", "FAILED"),
    "WAITING_FOR_CAPABILITY": ("INVESTIGATING", "CONVERGING", "FAILED"),
    "CONVERGING":             ("CONVERGED", "REOPENED", "FAILED"),
    "CONVERGED":              ("REOPENED",),
    "REOPENED":               ("UNDERSTANDING_EVIDENCE", "INVESTIGATING"),
    "FAILED":                 ("REOPENED",),
}


def can_transition(src: LifecycleState, dst: LifecycleState) -> bool:
    return dst in ALLOWED.get(src, ())
