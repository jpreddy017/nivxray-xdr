"""Unit tests for the Phase 11.3 Correlation Engine · Feb 2026."""
from __future__ import annotations

import json

from engine.evidence_graph import (
    EvidenceGraph, EvidenceNode, EvidenceNodeKind,
)
from engine.correlation_engine import correlate, CorrelationReport


def _build_graph():
    g = EvidenceGraph()
    a = EvidenceNode.build(EvidenceNodeKind.ip,     {"ip": "1.2.3.4"},
                            attrs={"entity_kind": "ipv4", "entity_confidence": 0.95},
                            source_node_ids=("run1:0",))
    b = EvidenceNode.build(EvidenceNodeKind.ip,     {"ip": "9.0.0.0"},
                            attrs={"entity_kind": "software_version", "entity_confidence": 0.75},
                            source_node_ids=("run1:1",))
    c = EvidenceNode.build(EvidenceNodeKind.domain, {"domain": "evil.example"},
                            source_node_ids=("run1:2",))
    d = EvidenceNode.build(EvidenceNodeKind.url,    {"url": "http://evil.example/x.ps1"},
                            source_node_ids=("run1:3",))
    g = g.add_node(a).add_node(b).add_node(c).add_node(d)
    return g


class TestCorrelationEngine:
    def test_shape(self):
        r = correlate(_build_graph())
        assert isinstance(r, CorrelationReport)
        assert r.schema_version == 1
        assert isinstance(r.stats, dict)

    def test_temporal_span_captures_ordered_chain(self):
        r = correlate(_build_graph())
        # All 4 nodes share the "run1" prefix → single span of length 4.
        assert len(r.temporal_spans) == 1
        span = r.temporal_spans[0]
        assert span.length == 4
        assert len(span.node_ids) == 4

    def test_dependency_chain_empty_when_all_roots_unique(self):
        # Every node has a unique source_node_id anchor in _build_graph()
        # so no dependency chain root has >= 2 leaves.
        r = correlate(_build_graph())
        assert r.dependency_chains == ()

    def test_dependency_chain_detected_when_shared_root(self):
        g = EvidenceGraph()
        n1 = EvidenceNode.build(EvidenceNodeKind.ip,     {"ip": "1.2.3.4"},
                                 source_node_ids=("run2:0",))
        n2 = EvidenceNode.build(EvidenceNodeKind.domain, {"domain": "a.example"},
                                 source_node_ids=("run2:0",))
        n3 = EvidenceNode.build(EvidenceNodeKind.url,    {"url": "http://a.example/x"},
                                 source_node_ids=("run2:0",))
        g = g.add_node(n1).add_node(n2).add_node(n3)
        r = correlate(g)
        assert len(r.dependency_chains) == 1
        c = r.dependency_chains[0]
        assert c.root_id == "run2:0"
        assert c.hops == 3

    def test_contradiction_flags_ip_marked_as_version(self):
        r = correlate(_build_graph())
        # Node b was created with EvidenceNodeKind.ip but classifier
        # attrs say it's a software_version → contradiction.
        assert any(
            "software_version" in " ".join(c.reasons) for c in r.contradictions
        ), r.contradictions

    def test_no_verdict_influence(self):
        # Engine must never mutate the input graph.
        g = _build_graph()
        before_nodes = tuple(g.nodes)
        before_edges = tuple(g.edges)
        _ = correlate(g)
        assert tuple(g.nodes) == before_nodes
        assert tuple(g.edges) == before_edges

    def test_determinism_byte_identical(self):
        g = _build_graph()
        a = json.dumps(correlate(g).to_dict(), sort_keys=True)
        b = json.dumps(correlate(g).to_dict(), sort_keys=True)
        assert a == b

    def test_stats_populated(self):
        r = correlate(_build_graph())
        assert r.stats["node_count"] == 4
        assert r.stats["temporal_spans"] == len(r.temporal_spans)
        assert r.stats["contradictions"] == len(r.contradictions)

    def test_empty_graph_yields_empty_report(self):
        r = correlate(EvidenceGraph())
        assert r.temporal_spans == ()
        assert r.dependency_chains == ()
        assert r.contradictions == ()
        assert r.stats["node_count"] == 0
