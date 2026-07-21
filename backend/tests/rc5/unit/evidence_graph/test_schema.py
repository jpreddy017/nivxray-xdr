"""Phase 11.0 — Evidence Knowledge Graph regression suite.

Success criteria (from user-approved plan)
------------------------------------------
* Existing tests remain green.
* Golden Corpus unchanged.
* No analyst-visible behaviour changes.
* Deterministic graph generation.
* Measured performance impact.

This file covers the graph data-model contract. The side-car builder
integration is covered in `test_evidence_graph_sidecar.py`.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from engine.evidence_graph import (
    EVIDENCE_GRAPH_SCHEMA_VERSION,
    EvidenceEdge,
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceNode,
    EvidenceNodeKind,
    compute_edge_id,
    compute_node_id,
)


# ---------------------------------------------------------------------------
# Deterministic IDs
# ---------------------------------------------------------------------------
class TestDeterministicIDs:
    def test_same_key_same_id(self):
        a = compute_node_id(EvidenceNodeKind.domain, {"domain": "evil.example"})
        b = compute_node_id(EvidenceNodeKind.domain, {"domain": "evil.example"})
        assert a == b

    def test_case_folded_for_domains(self):
        a = compute_node_id(EvidenceNodeKind.domain, {"domain": "Evil.Example"})
        b = compute_node_id(EvidenceNodeKind.domain, {"domain": "evil.example"})
        assert a == b

    def test_whitespace_stripped(self):
        a = compute_node_id(EvidenceNodeKind.file, {"path": "  /tmp/x  "})
        b = compute_node_id(EvidenceNodeKind.file, {"path": "/tmp/x"})
        assert a == b

    def test_key_order_irrelevant(self):
        a = compute_node_id(
            EvidenceNodeKind.registry, {"key": "HKLM/Run", "value": "foo"}
        )
        b = compute_node_id(
            EvidenceNodeKind.registry, {"value": "foo", "key": "HKLM/Run"}
        )
        assert a == b

    def test_empty_and_none_treated_as_absent(self):
        a = compute_node_id(EvidenceNodeKind.file, {"path": "/x", "hash": None})
        b = compute_node_id(EvidenceNodeKind.file, {"path": "/x", "hash": ""})
        c = compute_node_id(EvidenceNodeKind.file, {"path": "/x"})
        assert a == b == c

    def test_different_kinds_different_ids(self):
        a = compute_node_id(EvidenceNodeKind.domain, {"domain": "x.com"})
        b = compute_node_id(EvidenceNodeKind.url,    {"domain": "x.com"})
        assert a != b

    def test_id_format(self):
        nid = compute_node_id(EvidenceNodeKind.file, {"path": "/x"})
        assert nid.startswith("eg_")
        assert len(nid) == 19

    def test_edge_id_deterministic(self):
        n1 = compute_node_id(EvidenceNodeKind.process, {"image": "cmd.exe"})
        n2 = compute_node_id(EvidenceNodeKind.file, {"path": "/x"})
        a = compute_edge_id(n1, EvidenceEdgeKind.creates, n2)
        b = compute_edge_id(n1, EvidenceEdgeKind.creates, n2)
        assert a == b
        assert a.startswith("ee_") and len(a) == 19


# ---------------------------------------------------------------------------
# Immutability & schema locking
# ---------------------------------------------------------------------------
class TestImmutability:
    def test_node_is_frozen(self):
        n = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        with pytest.raises(ValidationError):
            n.attrs = {"mutated": True}   # type: ignore[misc]

    def test_edge_is_frozen(self):
        n1 = EvidenceNode.build(EvidenceNodeKind.process, {"image": "p"})
        n2 = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        e = EvidenceEdge.build(n1.id, EvidenceEdgeKind.creates, n2.id)
        with pytest.raises(ValidationError):
            e.attrs = {"mutated": True}   # type: ignore[misc]

    def test_graph_add_node_returns_new(self):
        g0 = EvidenceGraph()
        n = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        g1 = g0.add_node(n)
        assert g0 is not g1
        assert len(g0.nodes) == 0
        assert len(g1.nodes) == 1

    def test_schema_version_locked(self):
        with pytest.raises(ValidationError):
            EvidenceNode(
                id="eg_0000000000000000",
                kind=EvidenceNodeKind.file,
                key={"path": "/x"},
                schema_version=EVIDENCE_GRAPH_SCHEMA_VERSION + 1,
            )

    def test_id_prefix_enforced(self):
        with pytest.raises(ValidationError):
            EvidenceNode(
                id="wrong_prefix",
                kind=EvidenceNodeKind.file,
                key={"path": "/x"},
            )


# ---------------------------------------------------------------------------
# Deduplication & merge semantics
# ---------------------------------------------------------------------------
class TestDedup:
    def test_duplicate_node_no_op(self):
        n = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        g = EvidenceGraph().add_node(n).add_node(n)
        assert len(g.nodes) == 1

    def test_duplicate_key_different_attrs_merges(self):
        n1 = EvidenceNode.build(
            EvidenceNodeKind.file, {"path": "/x"},
            attrs={"size": 100}, source_node_ids=("n_a",),
        )
        n2 = EvidenceNode.build(
            EvidenceNodeKind.file, {"path": "/x"},
            attrs={"hash": "abc"}, source_node_ids=("n_b",),
        )
        g = EvidenceGraph().add_node(n1).add_node(n2)
        assert len(g.nodes) == 1
        merged = g.nodes[0]
        assert merged.attrs == {"size": 100, "hash": "abc"}
        assert merged.source_node_ids == ("n_a", "n_b")

    def test_duplicate_edge_no_op(self):
        n1 = EvidenceNode.build(EvidenceNodeKind.process, {"image": "cmd"})
        n2 = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        e = EvidenceEdge.build(n1.id, EvidenceEdgeKind.creates, n2.id)
        g = EvidenceGraph().add_node(n1).add_node(n2).add_edge(e).add_edge(e)
        assert len(g.edges) == 1

    def test_duplicate_edge_source_union(self):
        n1 = EvidenceNode.build(EvidenceNodeKind.process, {"image": "cmd"})
        n2 = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        e1 = EvidenceEdge.build(
            n1.id, EvidenceEdgeKind.creates, n2.id, source_node_ids=("n_a",),
        )
        e2 = EvidenceEdge.build(
            n1.id, EvidenceEdgeKind.creates, n2.id,
            attrs={"observed_at": 1}, source_node_ids=("n_b",),
        )
        g = EvidenceGraph().add_node(n1).add_node(n2).add_edge(e1).add_edge(e2)
        assert len(g.edges) == 1
        merged = g.edges[0]
        assert merged.source_node_ids == ("n_a", "n_b")
        assert merged.attrs == {"observed_at": 1}


# ---------------------------------------------------------------------------
# Integrity — dangling edges + cycles
# ---------------------------------------------------------------------------
class TestIntegrity:
    def test_dangling_src_rejected(self):
        n = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        g = EvidenceGraph().add_node(n)
        with pytest.raises(ValueError):
            g.add_edge(
                EvidenceEdge.build("eg_" + "0" * 16, EvidenceEdgeKind.creates, n.id)
            )

    def test_dangling_dst_rejected(self):
        n = EvidenceNode.build(EvidenceNodeKind.process, {"image": "p"})
        g = EvidenceGraph().add_node(n)
        with pytest.raises(ValueError):
            g.add_edge(
                EvidenceEdge.build(n.id, EvidenceEdgeKind.creates, "eg_" + "0" * 16)
            )

    def test_well_formed_graph_has_no_errors(self):
        p = EvidenceNode.build(EvidenceNodeKind.process, {"image": "cmd"})
        f = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        g = (
            EvidenceGraph()
            .add_node(p)
            .add_node(f)
            .add_edge(EvidenceEdge.build(p.id, EvidenceEdgeKind.creates, f.id))
        )
        assert g.validate_integrity() == []
        assert not g.has_hard_errors()

    def test_derivation_cycle_detected(self):
        # derivedFrom cycles are illegal.
        a = EvidenceNode.build(EvidenceNodeKind.script, {"sha1": "a" * 40})
        b = EvidenceNode.build(EvidenceNodeKind.script, {"sha1": "b" * 40})
        g = (
            EvidenceGraph()
            .add_node(a)
            .add_node(b)
            .add_edge(EvidenceEdge.build(a.id, EvidenceEdgeKind.derived_from, b.id))
            .add_edge(EvidenceEdge.build(b.id, EvidenceEdgeKind.derived_from, a.id))
        )
        cycles = g.cycles_in_derivation()
        assert cycles, "expected at least one derivation cycle"

    def test_non_strict_cycle_allowed(self):
        # `contacts` cycles are legal (peer-to-peer traffic, etc.).
        d1 = EvidenceNode.build(EvidenceNodeKind.domain, {"domain": "a.com"})
        d2 = EvidenceNode.build(EvidenceNodeKind.domain, {"domain": "b.com"})
        g = (
            EvidenceGraph()
            .add_node(d1)
            .add_node(d2)
            .add_edge(EvidenceEdge.build(d1.id, EvidenceEdgeKind.contacts, d2.id))
            .add_edge(EvidenceEdge.build(d2.id, EvidenceEdgeKind.contacts, d1.id))
        )
        assert g.cycles_in_derivation() == []
        assert not g.has_hard_errors()

    def test_orphan_node_flagged_as_warning(self):
        p = EvidenceNode.build(EvidenceNodeKind.process, {"image": "cmd"})
        f = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        # Add both without connecting them — f is an orphan.
        g = EvidenceGraph().add_node(p).add_node(f)
        # Non-root orphans are reported.
        orphans = g.orphan_nodes()
        assert p.id in orphans
        assert f.id in orphans
        # Warning only — not a hard failure.
        errors = g.validate_integrity()
        assert all(e.startswith("[warn]") for e in errors)
        assert not g.has_hard_errors()

    def test_synthetic_root_process_never_reported_as_orphan(self):
        root = EvidenceNode.build(
            EvidenceNodeKind.process, {"image": "<root>"}, attrs={"synthetic": True},
        )
        g = EvidenceGraph().add_node(root)
        assert g.orphan_nodes() == []
        assert not g.has_hard_errors()


# ---------------------------------------------------------------------------
# Serialization — deterministic round-trip
# ---------------------------------------------------------------------------
class TestSerialization:
    def _sample(self) -> EvidenceGraph:
        p = EvidenceNode.build(EvidenceNodeKind.process, {"image": "powershell.exe"})
        f = EvidenceNode.build(
            EvidenceNodeKind.file, {"path": "C:/temp/x.dll"}, attrs={"size": 42},
        )
        return (
            EvidenceGraph()
            .add_node(p)
            .add_node(f)
            .add_edge(EvidenceEdge.build(p.id, EvidenceEdgeKind.creates, f.id))
        )

    def test_round_trip_dict(self):
        g = self._sample()
        g2 = EvidenceGraph.from_dict(g.to_dict())
        assert g.to_dict() == g2.to_dict()

    def test_round_trip_json(self):
        g = self._sample()
        blob = g.to_json()
        g2 = EvidenceGraph.from_json(blob)
        assert g.to_json() == g2.to_json()

    def test_json_is_deterministic_across_runs(self):
        assert self._sample().to_json() == self._sample().to_json()

    def test_json_shape(self):
        blob = self._sample().to_json()
        data = json.loads(blob)
        assert set(data.keys()) == {"schema_version", "nodes", "edges"}
        assert data["schema_version"] == EVIDENCE_GRAPH_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------
class TestQueryHelpers:
    def test_by_kind_and_edges_by_kind(self):
        p = EvidenceNode.build(EvidenceNodeKind.process, {"image": "cmd"})
        f1 = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/x"})
        f2 = EvidenceNode.build(EvidenceNodeKind.file, {"path": "/y"})
        g = (
            EvidenceGraph()
            .add_node(p).add_node(f1).add_node(f2)
            .add_edge(EvidenceEdge.build(p.id, EvidenceEdgeKind.creates, f1.id))
            .add_edge(EvidenceEdge.build(p.id, EvidenceEdgeKind.writes, f2.id))
        )
        assert len(g.by_kind(EvidenceNodeKind.file)) == 2
        assert len(g.edges_by_kind(EvidenceEdgeKind.creates)) == 1
        assert len(g.outbound(p.id)) == 2
        assert len(g.inbound(f1.id)) == 1
