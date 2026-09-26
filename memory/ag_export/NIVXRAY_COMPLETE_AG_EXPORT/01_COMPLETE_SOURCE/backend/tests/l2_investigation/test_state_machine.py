"""Investigation State Machine · exhaustive tests · Blueprint §8.1."""
from __future__ import annotations

import pytest

from l2_investigation.state import (
    InvalidStateTransition,
    InvestigationState,
    InvestigationStateMachine,
    STATE_ORDER,
    iter_transitions,
)


def test_state_order_matches_blueprint():
    assert [s.value for s in STATE_ORDER] == [
        "new", "collecting", "correlating", "reviewing",
        "completed", "reported", "reopened",
    ]


def test_default_state_is_new():
    m = InvestigationStateMachine(case_id="c1")
    assert m.current is InvestigationState.NEW
    assert m.history == []


def test_full_happy_path():
    m = InvestigationStateMachine(case_id="c1")
    for target in [
        InvestigationState.COLLECTING,
        InvestigationState.CORRELATING,
        InvestigationState.REVIEWING,
        InvestigationState.COMPLETED,
        InvestigationState.REPORTED,
    ]:
        m.transition(target, actor="system")
    assert m.current is InvestigationState.REPORTED
    assert len(m.history) == 5


def test_reopen_loops_back_to_correlating():
    m = InvestigationStateMachine(case_id="c1", current=InvestigationState.REPORTED)
    m.transition(InvestigationState.REOPENED, actor="analyst-42")
    m.transition(InvestigationState.CORRELATING, actor="system")
    assert m.current is InvestigationState.CORRELATING


def test_actor_required():
    m = InvestigationStateMachine(case_id="c1")
    with pytest.raises(InvalidStateTransition):
        m.transition(InvestigationState.COLLECTING, actor="")


@pytest.mark.parametrize("from_state,to_state", list(iter_transitions()))
def test_every_declared_transition_is_legal(from_state, to_state):
    m = InvestigationStateMachine(case_id="c1", current=from_state)
    assert m.can_transition(to_state)
    m.transition(to_state, actor="system")
    assert m.current is to_state


def test_illegal_transitions_raise():
    legal = set(iter_transitions())
    for src in STATE_ORDER:
        for dst in STATE_ORDER:
            if src == dst or (src, dst) in legal:
                continue
            m = InvestigationStateMachine(case_id="c1", current=src)
            with pytest.raises(InvalidStateTransition):
                m.transition(dst, actor="system")


def test_audit_log_entries_serialize():
    m = InvestigationStateMachine(case_id="c1")
    entry = m.transition(InvestigationState.COLLECTING, actor="alice", reason="input received")
    d = entry.to_dict()
    assert d == {
        "from_state": "new",
        "to_state": "collecting",
        "actor": "alice",
        "reason": "input received",
    }


def test_machine_to_dict_shape():
    m = InvestigationStateMachine(case_id="c1")
    m.transition(InvestigationState.COLLECTING, actor="alice")
    d = m.to_dict()
    assert d["case_id"] == "c1"
    assert d["current"] == "collecting"
    assert len(d["history"]) == 1
