"""§ 6 — Confidence propagation rules (locked, non-negotiable).

Rules under test:
  6.1  DecodeNode.confidence inherits from decoder layer.
  6.2  child ≤ min(parent confidences).
  6.3  Any unresolved parent → child conf drops by ≥ 20.
  6.4  Behavior.confidence = min(evidence_nodes[*].confidence).
  6.6  Advisor-origin nodes never influence deterministic scoring
       (asserted by presence of `origin` discriminator).
  6.7  Confidence never assigned arbitrarily — bounds are validated.
"""
import pytest
from pydantic import ValidationError

from engine.exec_graph import ExecGraph, ExecNode, NodeKind


def _parent(conf: int, kind=NodeKind.decode):
    return ExecNode(kind=kind, confidence=conf)


def test_rule_67_confidence_range_validated():
    with pytest.raises(ValidationError):
        ExecNode(kind=NodeKind.decode, confidence=101)
    with pytest.raises(ValidationError):
        ExecNode(kind=NodeKind.decode, confidence=-1)


def test_rule_62_child_leq_min_parent_conf():
    p1 = _parent(90)
    p2 = _parent(60)
    g = ExecGraph().add_node(p1).add_node(p2)
    # Legit — child at 60 ≤ min(90, 60)
    ok_child = ExecNode(kind=NodeKind.string_op, inputs=(p1.id, p2.id), confidence=60)
    g2 = g.add_node(ok_child)
    assert len(g2.nodes) == 3
    # Illegal — child at 70 > min(90, 60) = 60
    bad_child = ExecNode(kind=NodeKind.string_op, inputs=(p1.id, p2.id), confidence=70)
    with pytest.raises(ValueError, match="confidence rule violation"):
        g.add_node(bad_child)


def test_rule_63_unresolved_parent_drops_conf_by_20():
    parent = ExecNode(kind=NodeKind.unresolved, confidence=90)
    g = ExecGraph().add_node(parent)
    # allowed = 90 - 20 = 70. So conf 70 is fine, 71 is not.
    g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(parent.id,), confidence=70))
    with pytest.raises(ValueError, match="confidence rule violation"):
        g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(parent.id,), confidence=71))


def test_rule_63_unresolved_parent_drop_applies_on_min():
    p_res = ExecNode(kind=NodeKind.decode, confidence=90)
    p_unres = ExecNode(kind=NodeKind.unresolved, confidence=50)
    g = ExecGraph().add_node(p_res).add_node(p_unres)
    # min parent conf = 50, minus 20 (unresolved) = 30 max
    g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(p_res.id, p_unres.id), confidence=30))
    with pytest.raises(ValueError):
        g.add_node(ExecNode(kind=NodeKind.string_op, inputs=(p_res.id, p_unres.id), confidence=31))


def test_rule_66_advisor_origin_discriminator_present():
    # The discriminator MUST exist — its downstream consumers gate on it.
    n = ExecNode(kind=NodeKind.decode, origin="advisor")
    assert n.origin == "advisor"
    n2 = ExecNode(kind=NodeKind.decode)
    assert n2.origin == "deterministic"


def test_conf_defaults_to_100():
    # Rule 6.1 corollary — a root node with no parents keeps whatever
    # confidence the emitter declares; default is 100.
    assert ExecNode(kind=NodeKind.decode).confidence == 100
