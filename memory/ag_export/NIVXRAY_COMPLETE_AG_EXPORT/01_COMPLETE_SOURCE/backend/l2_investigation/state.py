"""Investigation State Machine · Blueprint §8.1.

State transitions are validated server-side and audit-logged. State is
stored per-case, resumable across sessions, and displayed as a persistent
pill on the Workspace header.

    New → Collecting → Correlating → Reviewing → Completed → Reported
                                              ↓
                                          Reopened → Correlating (loop)

Determinism guarantee: transitions are pure — given a current state and
an action, the next state is a compile-time constant. No wall-clock
inputs, no probabilistic branches.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class InvestigationState(str, Enum):
    """Explicit case state per Blueprint §8.1.

    ``str`` subclass so JSON serialization matches the wire format
    (`"new"`, `"collecting"`, ...) deterministically.
    """

    NEW = "new"
    COLLECTING = "collecting"
    CORRELATING = "correlating"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    REPORTED = "reported"
    REOPENED = "reopened"


# Canonical order (matches Blueprint §8.1 table row order). Used by tests
# to prove the machine has no hidden states.
STATE_ORDER: tuple[InvestigationState, ...] = (
    InvestigationState.NEW,
    InvestigationState.COLLECTING,
    InvestigationState.CORRELATING,
    InvestigationState.REVIEWING,
    InvestigationState.COMPLETED,
    InvestigationState.REPORTED,
    InvestigationState.REOPENED,
)


# Transition table: from → allowed next states.
# Reading Blueprint §8.1 verbatim.
_TRANSITIONS: dict[InvestigationState, frozenset[InvestigationState]] = {
    InvestigationState.NEW: frozenset({InvestigationState.COLLECTING}),
    InvestigationState.COLLECTING: frozenset({InvestigationState.CORRELATING}),
    InvestigationState.CORRELATING: frozenset({InvestigationState.REVIEWING}),
    InvestigationState.REVIEWING: frozenset({InvestigationState.COMPLETED}),
    InvestigationState.COMPLETED: frozenset({InvestigationState.REPORTED}),
    InvestigationState.REPORTED: frozenset({InvestigationState.REOPENED}),
    InvestigationState.REOPENED: frozenset({InvestigationState.CORRELATING}),
}


class InvalidStateTransition(ValueError):
    """Raised when a caller attempts a transition not in the table."""


@dataclass(frozen=True)
class StateTransition:
    """Audit-log entry for a single transition (Blueprint §10)."""

    from_state: InvestigationState
    to_state: InvestigationState
    actor: str  # "system" or an analyst id — never blank
    reason: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "actor": self.actor,
            "reason": self.reason,
        }


@dataclass
class InvestigationStateMachine:
    """Deterministic state machine for a single case.

    Not thread-safe by itself; persistence layer (PR-2) is responsible for
    concurrency control (optimistic locking on case revision).
    """

    case_id: str
    current: InvestigationState = InvestigationState.NEW
    history: list[StateTransition] = field(default_factory=list)

    def allowed_next(self) -> frozenset[InvestigationState]:
        return _TRANSITIONS[self.current]

    def can_transition(self, target: InvestigationState) -> bool:
        return target in _TRANSITIONS[self.current]

    def transition(
        self,
        target: InvestigationState,
        actor: str,
        reason: str = "",
    ) -> StateTransition:
        if not actor:
            raise InvalidStateTransition("actor is required for audit log")
        if not self.can_transition(target):
            raise InvalidStateTransition(
                f"illegal transition {self.current.value} → {target.value}; "
                f"allowed: {sorted(s.value for s in self.allowed_next())}"
            )
        entry = StateTransition(
            from_state=self.current,
            to_state=target,
            actor=actor,
            reason=reason,
        )
        self.history.append(entry)
        self.current = target
        return entry

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "current": self.current.value,
            "history": [h.to_dict() for h in self.history],
        }


def iter_transitions() -> Iterable[tuple[InvestigationState, InvestigationState]]:
    """Enumerate every legal transition. Used by exhaustive tests."""
    for src, dsts in _TRANSITIONS.items():
        for dst in dsts:
            yield src, dst


__all__ = [
    "InvestigationState",
    "InvestigationStateMachine",
    "InvalidStateTransition",
    "StateTransition",
    "STATE_ORDER",
    "iter_transitions",
]
