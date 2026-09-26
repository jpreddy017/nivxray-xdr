"""§ 12.3 — Every evidence reference must resolve to an ExecNode.

Also covers § 7 — every Behavior must reference ≥ 1 evidence node.
"""
import pytest
from pydantic import ValidationError

from engine.exec_graph import (
    Behavior,
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffect,
    SideEffectVerb,
    TacticKind,
)


def _leaf():
    return ExecNode(kind=NodeKind.decode, confidence=90)


def test_behavior_requires_at_least_one_evidence_node():
    with pytest.raises(ValidationError, match="at least one"):
        Behavior(
            tactic=TacticKind.execution,
            evidence_nodes=(),
            reconstructed="powershell -c 'Start-Process notepad'",
            confidence=90,
        )


def test_behavior_with_valid_evidence_ok():
    b = Behavior(
        tactic=TacticKind.execution,
        evidence_nodes=("n_1",),
        reconstructed="cmd /c echo hi",
        confidence=90,
    )
    assert b.evidence_nodes == ("n_1",)


def test_side_effect_records_node_id_and_verb():
    se = SideEffect(verb=SideEffectVerb.create_process, node_id="n_1", evidence="notepad.exe")
    assert se.verb == SideEffectVerb.create_process
    assert se.node_id == "n_1"


def test_dangling_side_effect_ref_detected_by_graph():
    n = ExecNode(
        kind=NodeKind.process,
        side_effects=(SideEffect(verb=SideEffectVerb.create_process, node_id="n_missing"),),
    )
    g = ExecGraph().add_node(n)
    dangling = g.dangling_refs()
    assert dangling == ["n_missing"]


def test_clean_side_effect_graph_no_dangling():
    n = ExecNode(kind=NodeKind.process)
    # Reference self — legitimate — the ProcessNode is its own evidence.
    n2 = n.model_copy(
        update={"side_effects": (SideEffect(verb=SideEffectVerb.create_process, node_id=n.id),)}
    )
    g = ExecGraph().add_node(n2)
    assert g.dangling_refs() == []
