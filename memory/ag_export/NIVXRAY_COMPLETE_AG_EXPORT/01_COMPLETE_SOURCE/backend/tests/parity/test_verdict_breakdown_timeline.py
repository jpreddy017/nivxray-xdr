"""P1-02c · Sprint 3 · Confidence Breakdown + Confidence Timeline tests."""
from __future__ import annotations

import pytest

from nivxforge.investigation.graph import EvidenceGraph, Node
from nivxforge.investigation.verdict_engine import compute_verdict


def _make_bits_graph():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="F1", kind="decoded_fragment",
                    label="Encoded PS", confidence=0.9,
                    attrs={"op": "powershell.encoded"}))
    g.add_node(Node(id="F2", kind="decoded_fragment",
                    label="Invoke-Expression", confidence=0.9,
                    value="IEX (New-Object Net.WebClient)",
                    attrs={"op": "iex.inline"}))
    g.add_node(Node(id="L1", kind="lolbin", label="LOLBIN · bitsadmin",
                    value="bitsadmin", confidence=0.9))
    g.add_node(Node(id="U1", kind="ioc", label="URL",
                    value="http://evils.com/a.exe", confidence=0.85,
                    attrs={"ioc_kind": "url"}))
    return g


def test_confidence_breakdown_present_and_ordered():
    v = compute_verdict(_make_bits_graph())
    bd = v.confidence_breakdown
    assert set(bd.keys()) == {"critical", "high", "medium", "low", "context", "mitigating"}
    # Values are ints in [0, 100]
    for cls_name, pct in bd.items():
        assert isinstance(pct, int)
        assert 0 <= pct <= 100
    # For the BITS chain, HIGH must contribute meaningfully.
    assert bd["high"] > 0


def test_confidence_timeline_records_every_positive_step():
    v = compute_verdict(_make_bits_graph())
    tl = v.confidence_timeline
    assert isinstance(tl, list)
    assert len(tl) >= 3
    for step in tl:
        assert set(step.keys()) >= {"stage", "contributor_label", "contributor_kind",
                                     "class", "confidence_pct", "source"}
        assert isinstance(step["stage"], int)
        assert 0 <= step["confidence_pct"] <= 100


def test_timeline_is_monotonically_non_decreasing_for_positives():
    """Every positive-only step must not lower the confidence."""
    v = compute_verdict(_make_bits_graph())
    positives = [s for s in v.confidence_timeline if s["class"] != "mitigating"]
    for i in range(1, len(positives)):
        assert positives[i]["confidence_pct"] >= positives[i-1]["confidence_pct"] - 1


def test_final_confidence_matches_last_timeline_step():
    v = compute_verdict(_make_bits_graph())
    if v.confidence_timeline:
        assert abs(v.confidence_pct - v.confidence_timeline[-1]["confidence_pct"]) <= 1


def test_breakdown_and_timeline_populate_for_empty_evidence():
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    v = compute_verdict(g)
    assert v.confidence_breakdown == {} or all(v == 0 for v in v.confidence_breakdown.values())
    assert v.confidence_timeline == []
