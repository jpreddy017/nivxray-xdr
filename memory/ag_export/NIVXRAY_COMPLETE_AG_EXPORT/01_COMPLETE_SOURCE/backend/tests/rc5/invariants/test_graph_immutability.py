"""§ 12.1 — ExecNode / ExecGraph are immutable and append-only."""
import pytest
from pydantic import ValidationError

from engine.exec_graph import ExecGraph, ExecNode, NodeKind


def _node(kind=NodeKind.decode, **kw):
    return ExecNode(kind=kind, **kw)


def test_execnode_is_frozen():
    n = _node()
    with pytest.raises(ValidationError):
        n.confidence = 42


def test_execnode_field_assignment_forbidden():
    n = _node(reconstructed="cmd /c echo hi")
    with pytest.raises(ValidationError):
        n.reconstructed = "cmd /c echo bye"


def test_execnode_inputs_tuple_immutable():
    n = _node()
    # tuple attributes cannot be mutated via .append
    with pytest.raises(AttributeError):
        n.inputs.append("x")  # type: ignore[attr-defined]


def test_execgraph_add_node_returns_new_graph():
    g0 = ExecGraph()
    g1 = g0.add_node(_node())
    # original untouched
    assert g0.nodes == ()
    assert len(g1.nodes) == 1


def test_execgraph_is_frozen():
    g = ExecGraph()
    with pytest.raises(ValidationError):
        g.nodes = ()  # type: ignore[misc]


def test_execgraph_add_rejects_unknown_parent():
    g = ExecGraph()
    child = _node(inputs=("n_missing",))
    with pytest.raises(ValueError, match="unknown parent"):
        g.add_node(child)
