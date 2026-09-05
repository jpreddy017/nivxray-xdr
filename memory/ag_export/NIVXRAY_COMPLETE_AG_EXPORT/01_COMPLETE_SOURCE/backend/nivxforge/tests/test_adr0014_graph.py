"""ADR-0014 · Slice-A · Evidence Graph primitives regression tests.

Locks the G2 gate contract at the unit level.
"""
from __future__ import annotations

import pytest

from nivxforge.investigation.graph import Edge, EvidenceGraph, Node


def _mk_node(nid: str, kind: str = "artifact", label: str = "x") -> Node:
    return Node(id=nid, kind=kind, label=label, value=None, confidence=1.0, provenance="test")


class TestNodeIdUniqueness:
    def test_add_node_rejects_duplicate_id(self):
        g = EvidenceGraph()
        g.add_node(_mk_node("N-001"))
        with pytest.raises(ValueError):
            g.add_node(_mk_node("N-001"))


class TestEdgeIntegrity:
    def test_dangling_edge_source_rejected(self):
        g = EvidenceGraph()
        g.add_node(_mk_node("N-001"))
        with pytest.raises(ValueError):
            g.add_edge(Edge(source="N-999", target="N-001", kind="produces"))

    def test_dangling_edge_target_rejected(self):
        g = EvidenceGraph()
        g.add_node(_mk_node("N-001"))
        with pytest.raises(ValueError):
            g.add_edge(Edge(source="N-001", target="N-999", kind="produces"))

    def test_valid_edge_added(self):
        g = EvidenceGraph()
        g.add_node(_mk_node("N-001"))
        g.add_node(_mk_node("N-002", kind="ioc", label="1.2.3.4"))
        g.add_edge(Edge(source="N-001", target="N-002", kind="produces"))
        assert len(g.edges) == 1
        assert g.neighbours("N-001") == ["N-002"]


class TestDeterministicSerialize:
    def test_same_content_produces_identical_dict_regardless_of_insertion_order(self):
        g1 = EvidenceGraph()
        g1.add_node(_mk_node("N-001", kind="artifact"))
        g1.add_node(_mk_node("N-002", kind="ioc", label="1.2.3.4"))
        g1.add_node(_mk_node("N-003", kind="lolbin", label="regsvr32"))
        g1.add_edge(Edge(source="N-001", target="N-002", kind="produces"))
        g1.add_edge(Edge(source="N-001", target="N-003", kind="references"))

        g2 = EvidenceGraph()
        # Reverse insertion order
        g2.add_node(_mk_node("N-003", kind="lolbin", label="regsvr32"))
        g2.add_node(_mk_node("N-001", kind="artifact"))
        g2.add_node(_mk_node("N-002", kind="ioc", label="1.2.3.4"))
        g2.add_edge(Edge(source="N-001", target="N-003", kind="references"))
        g2.add_edge(Edge(source="N-001", target="N-002", kind="produces"))

        assert g1.deterministic_serialize() == g2.deterministic_serialize()


class TestNodeKindProjection:
    def test_nodes_by_kind_returns_only_that_kind(self):
        g = EvidenceGraph()
        g.add_node(_mk_node("N-001", kind="artifact"))
        g.add_node(_mk_node("N-002", kind="ioc", label="1.2.3.4"))
        g.add_node(_mk_node("N-003", kind="ioc", label="5.6.7.8"))
        g.add_node(_mk_node("N-004", kind="lolbin", label="regsvr32"))

        iocs = g.nodes_by_kind("ioc")
        assert len(iocs) == 2
        assert {n.id for n in iocs} == {"N-002", "N-003"}
