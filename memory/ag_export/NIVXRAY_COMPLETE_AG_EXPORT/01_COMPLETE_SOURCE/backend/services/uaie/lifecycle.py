"""UAIE Contract #9 · Artifact Lifecycle State Machine  (Rule R28.5)

Every artifact in an investigation graph moves through a formal
lifecycle.  A `status` field is insufficient — analysts need the
full timeline so any decision the engine made can be replayed and
audited:

    NEW              artifact created (root paste OR capability child)
      │
      ▼
    RECOGNIZED       ≥ 1 recognizer emitted a match
      │
      ▼
    PLANNED          planner ordered applicable capabilities
      │
      ▼
    EXECUTED         all applicable capabilities ran on this artifact
      │
      ▼
    VALIDATED        QA validators passed
      │
      ▼
    REPAIR_PENDING   QA validators failed → repair planner activated
      │
      ▼
    REPAIRED         a repair strategy succeeded (source artifact only)
      │
      ▼
    ANALYZED         ≥ 1 analyzer emitted evidence on this artifact
      │
      ▼
    EVIDENCE_COMPLETE  every applicable analyzer has run
      │
      ▼
    FIXED_POINT      no remaining deterministic transitions (audit clean)
      │
      ▼
    DONE             terminal — this artifact is fully resolved

The state DAG is a strict topological order — each transition
requires the previous state to have been reached.  Terminal branches
(``UNREACHABLE`` after ``REPAIR_PENDING``) short-circuit to DONE.

Every transition emits a ``StateTransition`` record with:
    · timestamp        (float · wall-clock, deterministic per-run)
    · artifact_uri
    · previous_state
    · next_state
    · actor            (which recognizer / capability / validator / repair
                        / audit component drove the transition)
    · reason           (canonical, greppable — e.g. "capability_executed",
                        "validator_passed", "audit_fixed_point")
    · evidence_ids     (evidence emitted as part of this transition,
                        if any)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing      import Dict, List, Set, Tuple


# ══════════════════════════════════════════════════════════════════
# Canonical state names (mirrors qa.STATE_* — kept in sync)
# ══════════════════════════════════════════════════════════════════
LC_NEW               = "NEW"
LC_RECOGNIZED        = "RECOGNIZED"
LC_PLANNED           = "PLANNED"
LC_EXECUTED          = "EXECUTED"
LC_VALIDATED         = "VALIDATED"
LC_REPAIR_PENDING    = "REPAIR_PENDING"
LC_REPAIRED          = "REPAIRED"
LC_UNREACHABLE       = "UNREACHABLE"
LC_ANALYZED          = "ANALYZED"
LC_EVIDENCE_COMPLETE = "EVIDENCE_COMPLETE"
LC_FIXED_POINT       = "FIXED_POINT"
LC_DONE              = "DONE"


# Total order for the "happy-path" backbone.  Terminal branches
# (UNREACHABLE) exit the DAG independently.
LIFECYCLE_ORDER: Tuple[str, ...] = (
    LC_NEW,
    LC_RECOGNIZED,
    LC_PLANNED,
    LC_EXECUTED,
    LC_VALIDATED,
    LC_REPAIR_PENDING,
    LC_REPAIRED,
    LC_ANALYZED,
    LC_EVIDENCE_COMPLETE,
    LC_FIXED_POINT,
    LC_DONE,
)


# Legal transitions.  A ``(prev, next)`` pair is allowed iff:
#   1. It is monotonic in ``LIFECYCLE_ORDER`` (a forward step or leap
#      forward — e.g. ``NEW → RECOGNIZED`` is fine; ``NEW → EXECUTED``
#      is also fine because artifacts without children still visit
#      PLANNED and EXECUTED, but the emitter may collapse micro-steps).
#   2. OR it is a terminal short-circuit to ``UNREACHABLE`` from any
#      of ``VALIDATED`` / ``REPAIR_PENDING`` / ``REPAIRED``.
#   3. OR it is a valid entry into ``FIXED_POINT`` / ``DONE`` from the
#      analyzed set.
_ORDER_INDEX: Dict[str, int] = {s: i for i, s in enumerate(LIFECYCLE_ORDER)}
_TERMINAL_BRANCHES: Set[str] = {LC_UNREACHABLE}


def is_legal_transition(prev: str, nxt: str) -> bool:
    """Whether ``prev → nxt`` is an allowed transition."""
    if nxt == prev:
        return True                                       # idempotent no-op
    if nxt == LC_UNREACHABLE:
        # UNREACHABLE can be reached from any non-terminal state.
        return prev not in (LC_DONE, LC_UNREACHABLE)
    if prev == LC_UNREACHABLE:
        # Only DONE closes an UNREACHABLE artifact.
        return nxt == LC_DONE
    if prev in _ORDER_INDEX and nxt in _ORDER_INDEX:
        return _ORDER_INDEX[nxt] > _ORDER_INDEX[prev]
    return False


@dataclass(frozen=True)
class StateTransition:
    """One immutable step in an artifact's lifecycle."""
    artifact_uri:    str
    previous_state:  str
    next_state:      str
    actor:           str
    reason:          str
    evidence_ids:    List[str] = field(default_factory=list)
    ts:              float     = field(default_factory=lambda: time.time())


class LifecycleRecorder:
    """Central place to move an artifact between lifecycle states.

    Guarantees:
      · every transition is validated by ``is_legal_transition``
      · illegal transitions are rejected silently (never crash the
        loop) but recorded as a ``warning`` so the operator can debug
      · the transition timeline is append-only and immutable per-entry
    """

    def __init__(self) -> None:
        self.transitions: List[StateTransition] = []
        self.warnings:    List[str] = []
        # Latest state per URI — mirror of the orchestrator's states
        # map, kept in sync so callers have one source of truth.
        self._current: Dict[str, str] = {}

    def current(self, uri: str) -> str:
        return self._current.get(uri, "")

    def transition(self, artifact_uri: str, next_state: str, *,
                    actor: str, reason: str,
                    evidence_ids: List[str] | None = None) -> bool:
        """Attempt a state transition.  Returns True if the move was
        legal (and recorded), False if it was rejected."""
        prev = self._current.get(artifact_uri, "")
        if prev == "" and next_state == LC_NEW:
            # Cold entry — always allowed.
            self._current[artifact_uri] = LC_NEW
            self.transitions.append(StateTransition(
                artifact_uri=artifact_uri, previous_state="",
                next_state=LC_NEW, actor=actor, reason=reason,
                evidence_ids=list(evidence_ids or []),
            ))
            return True
        if not is_legal_transition(prev, next_state):
            self.warnings.append(
                f"illegal transition {prev} → {next_state} "
                f"on {artifact_uri} (actor={actor} reason={reason})"
            )
            return False
        self._current[artifact_uri] = next_state
        self.transitions.append(StateTransition(
            artifact_uri=artifact_uri, previous_state=prev,
            next_state=next_state, actor=actor, reason=reason,
            evidence_ids=list(evidence_ids or []),
        ))
        return True

    def all_transitions_for(self, uri: str) -> List[StateTransition]:
        """The full timeline for one artifact — ordered oldest → newest."""
        return [t for t in self.transitions if t.artifact_uri == uri]


__all__ = [
    "LC_NEW", "LC_RECOGNIZED", "LC_PLANNED", "LC_EXECUTED", "LC_VALIDATED",
    "LC_REPAIR_PENDING", "LC_REPAIRED", "LC_UNREACHABLE", "LC_ANALYZED",
    "LC_EVIDENCE_COMPLETE", "LC_FIXED_POINT", "LC_DONE",
    "LIFECYCLE_ORDER", "is_legal_transition",
    "StateTransition", "LifecycleRecorder",
]
