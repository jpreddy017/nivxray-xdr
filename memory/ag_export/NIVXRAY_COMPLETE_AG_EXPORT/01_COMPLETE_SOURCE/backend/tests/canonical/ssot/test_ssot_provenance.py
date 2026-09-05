"""T2.2 · Provenance envelope MANDATORY (D3-z)."""
import pytest
from canonical.ssot import (
    AuthoritativeSSOT, Provenance, GraphNode, GraphEdge,
    ReasoningStep, Artifact, ExecutionStep, HistoricalItem,
)


PROV = Provenance(engine="test", version="1.0.0", at="phase2")


def test_append_without_provenance_raises():
    s = AuthoritativeSSOT()
    with pytest.raises(ValueError, match="Provenance"):
        s.append("evidence_graph.nodes",
                 GraphNode(id="n1", kind="input", label="x"))


def test_append_with_provenance_argument_succeeds():
    s = AuthoritativeSSOT()
    s.append("evidence_graph.nodes",
             GraphNode(id="n1", kind="input", label="x"),
             provenance=PROV)
    assert s.evidence_graph.nodes[0].provenance is PROV


def test_append_with_entry_carried_provenance_succeeds():
    s = AuthoritativeSSOT()
    node = GraphNode(id="n1", kind="input", label="x", provenance=PROV)
    s.append("evidence_graph.nodes", node)  # no explicit prov arg
    assert s.evidence_graph.nodes[0].provenance is PROV


def test_provenance_required_for_every_bucket():
    s = AuthoritativeSSOT()
    entries = [
        ("evidence_graph.nodes", GraphNode(id="n1", kind="input", label="x")),
        ("evidence_graph.edges", GraphEdge(id="e1", from_node_id="n1", to_node_id="n2", kind="parent_of")),
        ("reasoning_steps", ReasoningStep(id="r1", rule="r", rationale="why")),
        ("artifacts", Artifact(id="a1", kind="blob", label="x")),
        ("execution_trace", ExecutionStep(step_id="s1", capability="DECODER", engine="e", status="planned")),
        ("context.historical", HistoricalItem(kind="prior_case", ref="x")),
    ]
    for bucket, entry in entries:
        with pytest.raises(ValueError, match="Provenance"):
            s.append(bucket, entry)


def test_provenance_envelope_carries_all_required_fields():
    p = Provenance(engine="e", version="1.0", at="phase2",
                   upstream_evidence_ids=["ev.001"])
    assert p.engine and p.version and p.at
    assert p.upstream_evidence_ids == ["ev.001"]


def test_reject_unknown_bucket():
    s = AuthoritativeSSOT()
    with pytest.raises(ValueError, match="not appendable"):
        s.append("nonexistent.bucket", GraphNode(id="n", kind="k", label="x"), PROV)
