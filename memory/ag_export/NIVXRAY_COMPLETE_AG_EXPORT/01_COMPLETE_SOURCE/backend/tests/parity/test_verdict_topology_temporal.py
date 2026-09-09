"""P1-02c · Sprint 1 · Graph-Aware Scoring + Temporal Correlation tests."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from nivxforge.investigation.graph import EvidenceGraph, Node, Edge
from nivxforge.investigation.topology_signals import (
    graph_topology_signal,
    temporal_correlation_signal,
    attach_topology_and_temporal_signals,
    _longest_chain_depth,
)
from nivxforge.investigation.verdict_engine import compute_verdict


# ────────────────────────── Graph topology ──────────────────────────

def _chain_of(depth: int) -> EvidenceGraph:
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    prev = "A"
    for i in range(depth):
        nid = f"N{i}"
        # rotate kinds to exercise all anchor types
        kind = ("decoded_fragment", "ioc", "lolbin", "behaviour",
                "mitre_technique")[i % 5]
        attrs = {"ioc_kind": "url"} if kind == "ioc" else {}
        g.add_node(Node(id=nid, kind=kind, label=f"step{i}", value=f"v{i}",
                        confidence=0.9, attrs=attrs))
        g.add_edge(Edge(source=prev, target=nid, kind="produces", weight=1.0))
        prev = nid
    return g


def test_longest_chain_depth_is_deterministic():
    g = _chain_of(5)
    d1, p1 = _longest_chain_depth(g)
    d2, p2 = _longest_chain_depth(g)
    assert d1 == d2 == 5
    assert p1 == p2  # deterministic path


def test_topology_signal_none_for_short_chains():
    g = _chain_of(2)
    assert graph_topology_signal(g) is None


def test_topology_signal_high_for_depth_ge_3():
    g = _chain_of(3)
    sig = graph_topology_signal(g)
    assert sig is not None
    assert sig.value == "execution_chain_correlated"
    assert sig.kind == "behaviour"
    assert sig.attrs["chain_depth"] == 3


def test_topology_signal_participates_in_verdict():
    """A 5-stage chain must appear as a HIGH attack-chain contributor."""
    g = _chain_of(5)
    v = compute_verdict(g)
    kinds = {c.kind for c in v.contributors}
    assert "execution_chain_correlated" in kinds
    # HIGH-class attack-chain kind — verdict should be Malicious via attack-chain gate.
    assert v.label == "Malicious"


def test_topology_signal_is_idempotent():
    """Running attach twice must not duplicate the synthetic node."""
    g = _chain_of(4)
    a1 = attach_topology_and_temporal_signals(g)
    a2 = attach_topology_and_temporal_signals(g)
    assert a2 == []
    assert len([n for n in g.nodes if n.id.startswith("SYNTH-CHAIN-")]) == 1


# ────────────────────────── Temporal correlation ─────────────────────

def test_temporal_signal_none_when_no_timestamps():
    g = _chain_of(3)
    assert temporal_correlation_signal(g) is None


def test_temporal_signal_high_for_burst_within_10s():
    t0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    for i in range(3):
        g.add_node(Node(
            id=f"N{i}", kind="behaviour", label=f"beh{i}", value=f"v{i}",
            confidence=0.9,
            attrs={"timestamp": (t0 + timedelta(seconds=i * 3)).isoformat()},
        ))
    sig = temporal_correlation_signal(g)
    assert sig is not None
    assert sig.value == "temporal_burst"
    assert sig.attrs["cluster_size"] == 3
    assert sig.attrs["cluster_span_s"] <= 10


def test_temporal_signal_none_when_events_spread_over_hours():
    t0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    for i in range(3):
        g.add_node(Node(
            id=f"N{i}", kind="behaviour", label=f"beh{i}", value=f"v{i}",
            confidence=0.9,
            attrs={"timestamp": (t0 + timedelta(hours=i)).isoformat()},
        ))
    assert temporal_correlation_signal(g) is None


def test_temporal_signal_participates_in_verdict():
    """A 3-signal 5s burst on execution-relevant nodes → attack-chain HIGH."""
    t0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    for i, (kind, val) in enumerate([
        ("behaviour", "network_beacon"),
        ("lolbin", "powershell"),
        ("ioc", "1.2.3.4"),
    ]):
        attrs = {"timestamp": (t0 + timedelta(seconds=i * 2)).isoformat()}
        if kind == "ioc":
            attrs["ioc_kind"] = "ip"
        g.add_node(Node(id=f"N{i}", kind=kind, label=val, value=val,
                        confidence=0.9, attrs=attrs))
    v = compute_verdict(g)
    assert any(c.kind == "temporal_burst" for c in v.contributors)


# ────────────────────────── Monotonicity ─────────────────────────────

def test_adding_topology_and_temporal_signals_never_lowers_confidence():
    g = _chain_of(3)
    v0 = compute_verdict(g).confidence
    # Add temporal timestamps to N0..N2
    t0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i, n in enumerate(g.nodes):
        if n.id.startswith("N"):
            n.attrs["timestamp"] = (t0 + timedelta(seconds=i * 2)).isoformat()
    v1 = compute_verdict(g).confidence
    assert v1 >= v0 - 1e-9


# ────────────────────────── No-effect on benign inputs ──────────────

def test_topology_temporal_do_not_promote_benign_inputs():
    """Two-node chain with no attack-chain kinds must stay benign."""
    g = EvidenceGraph()
    g.add_node(Node(id="A", kind="artifact", label="input", confidence=1.0))
    g.add_node(Node(id="B", kind="decoded_fragment", label="Layer 0", value="v", confidence=0.9))
    v = compute_verdict(g)
    assert v.label in ("Undetermined", "Informational")
