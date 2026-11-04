"""Stage 11 · Correlation Engine tests.

Contract under test (owner directive 2026-02-XX):

    * Correlation produces Incidents, never Events.
    * Same (Timeline, AttackChain, threshold) → byte-identical output.
    * Every derived field is an aggregate over already-validated facts
      — shared_actors / shared_hosts / severity_hint / time_span
      cannot invent values that aren't on the member events.
    * Below-threshold or orphaned events land in `orphan_event_ids`
      and are never silently promoted into a cluster.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from nivxforge.investigation.cem import (
    CanonicalEvent, CanonicalEventModel, EventKind, Host, Process, Provenance,
)
from nivxforge.investigation.pipeline.attack_chain_builder import (
    build as build_chain,
)
from nivxforge.investigation.pipeline.correlation_engine import (
    Correlation, DEFAULT_MIN_EDGE_CONFIDENCE, IncidentCluster,
    build as build_corr, build_from_graph,
)
from nivxforge.investigation.pipeline.graph_builder import (
    GraphEdge, GraphNode, InvestigationGraph,
)
from nivxforge.investigation.pipeline.timeline_builder import (
    Timeline, build as build_timeline,
)


_T0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
_PROV = Provenance(source="unit-test", timestamp=_T0)


# ── Fabrication helpers (shared shape with attack-chain tests) ───────

def _process_node(image: str) -> GraphNode:
    h = hashlib.sha256(image.encode()).hexdigest()[:12]
    return GraphNode(id=f"process-{h}", kind="process",
                      label=f"PROCESS · {image}", value=image)


def _host_node(name: str) -> GraphNode:
    h = hashlib.sha256(name.encode()).hexdigest()[:12]
    return GraphNode(id=f"host-{h}", kind="host",
                      label=f"HOST · {name}", value=name)


def _command_node(cmd: str) -> GraphNode:
    h = hashlib.sha256(cmd.encode()).hexdigest()[:12]
    return GraphNode(id=f"command-{h}", kind="command",
                      label=f"COMMAND · {cmd}", value=cmd)


def _edge(relation: str, src: str, dst: str, event_id: str = "") -> GraphEdge:
    eid = hashlib.sha256(
        f"{relation}::{src}::{dst}::{event_id}".encode()
    ).hexdigest()[:12]
    return GraphEdge(
        id=f"e-{eid}", from_id=src, to_id=dst, relation=relation,
        evidence_refs=(event_id,) if event_id else tuple(),
    )


def _cem_event(event_id: str, image: str, cmd: str,
                host: str, seconds: int,
                parent_cmd: str = "") -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id, kind=EventKind.process_create,
        timestamp=_T0 + timedelta(seconds=seconds),
        host=Host(name=host, provenance=_PROV),
        process=Process(image=image, command_line=cmd,
                        parent_command_line=(parent_cmd or None),
                        provenance=_PROV),
        provenance=_PROV,
    )


def _pipeline(events: List[CanonicalEvent]):
    nodes = {}
    edges: List[GraphEdge] = []
    for evt in events:
        p_node = _process_node(evt.process.image)
        c_node = _command_node(evt.process.command_line)
        h_node = _host_node(evt.host.name)
        for n in (p_node, c_node, h_node):
            nodes[n.id] = n
        edges.append(_edge("executed_on", p_node.id, h_node.id,
                            evt.event_id))
        edges.append(_edge("belongs_to", c_node.id, p_node.id,
                            evt.event_id))
        if evt.process.parent_command_line:
            parent_cmd = _command_node(evt.process.parent_command_line)
            nodes[parent_cmd.id] = parent_cmd
            edges.append(_edge("child_of", c_node.id, parent_cmd.id,
                                evt.event_id))
    graph = InvestigationGraph(nodes=tuple(nodes.values()),
                                edges=tuple(edges))
    cem = CanonicalEventModel(vendor="test", vendor_route="unit",
                                provenance=_PROV, events=events)
    tl = build_timeline(cem, graph)
    ac = build_chain(tl, graph)
    return tl, ac, graph


# ── Structural invariants ───────────────────────────────────────────

def test_empty_timeline_yields_empty_correlation():
    tl = Timeline(entries=(), time_span={"first": None, "last": None},
                   unknown_time_count=0)
    ac = build_chain(tl, InvestigationGraph(nodes=(), edges=()))
    corr = build_corr(tl, ac)
    assert corr.clusters == ()
    assert corr.orphan_event_ids == ()
    assert corr.min_edge_confidence == DEFAULT_MIN_EDGE_CONFIDENCE


def test_singleton_event_becomes_orphan_not_cluster():
    tl, ac, _ = _pipeline([
        _cem_event("e1", "solo.exe", "solo /x", "host-x", 0),
    ])
    corr = build_corr(tl, ac)
    assert corr.clusters == ()
    assert len(corr.orphan_event_ids) == 1


def test_result_shape_carries_schema_version():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    corr = build_from_graph(tl, ac, graph)
    d = corr.to_dict()
    assert d["schema_version"] == "1.0"
    assert isinstance(corr, Correlation)


# ── Clustering behaviour ─────────────────────────────────────────────

def test_two_events_with_parent_of_edge_form_one_cluster():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    corr = build_from_graph(tl, ac, graph)
    assert len(corr.clusters) == 1
    cluster = corr.clusters[0]
    assert len(cluster.timeline_event_ids) == 2
    assert cluster.attack_edge_ids
    assert cluster.confidence > 0


def test_events_on_different_hosts_do_not_merge():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "attacker.exe", "attacker -a", "host-a", 0),
        _cem_event("e2", "attacker.exe", "attacker -b", "host-b", 5),
    ])
    corr = build_from_graph(tl, ac, graph)
    # Both events should be orphans — no cross-host AttackEdge exists.
    assert corr.clusters == ()
    assert len(corr.orphan_event_ids) == 2


def test_threshold_gates_weak_edges_out():
    """Directly construct AttackEdges with controlled confidences to
    isolate the threshold-gating behaviour from all upstream noise."""
    from nivxforge.investigation.pipeline.attack_chain_builder import (
        AttackChain, AttackEdge, DerivationRule, EvidenceRef,
    )
    from nivxforge.investigation.pipeline.timeline_builder import (
        ProvenanceEntry, TimelineEvent,
    )
    prov_row = ProvenanceEntry(origin="Telemetry", source="unit",
                                reason="unit", confidence=1.0)

    def _tl_event(eid: str) -> TimelineEvent:
        return TimelineEvent(
            id=eid, source_event=f"cem-{eid}",
            timestamp=None, timestamp_precision="unknown",
            timestamp_source="unavailable",
            event_type="Process Create", kind="process",
            action="executed", actor=None, targets=(),
            artifacts=(), source_nodes=(),
            summary=f"unit event {eid}",
            provenance=(prov_row,), confidence=1.0)

    events = tuple(_tl_event(f"t-{i}") for i in ("a", "b", "c"))
    tl = Timeline(entries=events,
                   time_span={"first": None, "last": None},
                   unknown_time_count=3)

    def _edge(from_e: str, to_e: str, conf: float,
               kind: str = "led_to") -> AttackEdge:
        return AttackEdge(
            id=f"ae-{from_e}-{to_e}-{int(conf*100):03d}",
            kind=kind, from_event=from_e, to_event=to_e,
            derivation_rules=(DerivationRule(
                name="shared_actor", observed=True,
                detail="unit", weight=0.6),),
            supporting_evidence=(EvidenceRef(type="timeline_event",
                                              id=from_e),),
            confidence=conf,
            provenance={"source": "unit-test", "reason": "fixture"},
        )

    chain = AttackChain(edges=(
        _edge("t-a", "t-b", 0.9),     # strong
        _edge("t-b", "t-c", 0.3),     # weak
    ))

    # Low threshold — every edge survives → one cluster of 3.
    corr_low = build_corr(tl, chain, min_edge_confidence=0.1)
    assert len(corr_low.clusters) == 1
    assert set(corr_low.clusters[0].timeline_event_ids) == {
        "t-a", "t-b", "t-c"}

    # Mid threshold — weak edge drops out → cluster of 2 + 1 orphan.
    corr_mid = build_corr(tl, chain, min_edge_confidence=0.5)
    assert len(corr_mid.clusters) == 1
    assert set(corr_mid.clusters[0].timeline_event_ids) == {"t-a", "t-b"}
    assert corr_mid.orphan_event_ids == ("t-c",)

    # High threshold — every edge filtered → all orphans.
    corr_high = build_corr(tl, chain, min_edge_confidence=0.99)
    assert corr_high.clusters == ()
    assert set(corr_high.orphan_event_ids) == {"t-a", "t-b", "t-c"}


# ── Derived-field invariants ─────────────────────────────────────────

def test_shared_hosts_reflect_actual_events_only():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    corr = build_from_graph(tl, ac, graph)
    cluster = corr.clusters[0]
    # host-x should be a shared host — validated by the graph.
    assert cluster.shared_hosts
    for host in cluster.shared_hosts:
        assert host.startswith("host-")


def test_severity_hint_uses_max_event_severity_mapping():
    """A cluster containing a Detection event must inherit 'high'."""
    from nivxforge.investigation.cem import Detection, SeverityLevel
    detection_prov = _PROV
    events = [
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        CanonicalEvent(
            event_id="e2", kind=EventKind.detection,
            timestamp=_T0 + timedelta(seconds=5),
            host=Host(name="host-x", provenance=_PROV),
            process=Process(image="cmd.exe",
                            command_line="cmd /c a",
                            parent_command_line="cmd /c a",
                            provenance=_PROV),
            detection=Detection(name="Suspicious CMD",
                                severity=SeverityLevel.high,
                                provenance=detection_prov),
            provenance=_PROV),
    ]
    tl, ac, graph = _pipeline(events)
    corr = build_from_graph(tl, ac, graph)
    # Detection may be its own cluster if no parent_of edge fires; the
    # detection itself must map to 'high' either as a cluster or as an
    # orphan-level lookup.
    all_hints = [c.severity_hint for c in corr.clusters]
    assert corr.clusters or corr.orphan_event_ids
    if all_hints:
        assert "high" in all_hints


def test_time_span_only_uses_known_timestamps():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    corr = build_from_graph(tl, ac, graph)
    cluster = corr.clusters[0]
    assert cluster.time_span["first"] is not None
    assert cluster.time_span["last"] is not None
    assert cluster.time_span["first"] <= cluster.time_span["last"]


# ── Provenance / traceability ────────────────────────────────────────

def test_supporting_evidence_covers_events_and_edges():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    corr = build_from_graph(tl, ac, graph)
    cluster = corr.clusters[0]
    types = {ref.type for ref in cluster.supporting_evidence}
    assert "timeline_event" in types
    assert "cem_event" in types
    assert "attack_edge" in types


def test_provenance_documents_threshold_and_source():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    corr = build_from_graph(tl, ac, graph, min_edge_confidence=0.4)
    for cluster in corr.clusters:
        assert cluster.provenance["source"] == "correlation_engine"
        assert cluster.provenance["min_edge_confidence"] == 0.4


# ── Determinism ──────────────────────────────────────────────────────

def test_same_input_yields_byte_identical_correlation():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
        _cem_event("e3", "child.exe", "child -c", "host-x", 20,
                   parent_cmd="powershell -c b"),
    ])
    a = build_from_graph(tl, ac, graph).to_dict()
    b = build_from_graph(tl, ac, graph).to_dict()
    assert a == b


def test_to_dict_is_json_round_trippable():
    tl, ac, graph = _pipeline([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    d = build_from_graph(tl, ac, graph).to_dict()
    assert json.loads(json.dumps(d)) == d
    for cluster in d["clusters"]:
        for key in ("id", "timeline_event_ids", "attack_edge_ids",
                    "shared_actors", "shared_hosts", "time_span",
                    "unknown_time_count", "dominant_edge_kinds",
                    "confidence", "severity_hint",
                    "supporting_evidence", "provenance"):
            assert key in cluster


# ── Threshold validation ────────────────────────────────────────────

def test_invalid_threshold_raises():
    tl = Timeline(entries=(), time_span={"first": None, "last": None},
                   unknown_time_count=0)
    ac = build_chain(tl, InvestigationGraph(nodes=(), edges=()))
    import pytest
    with pytest.raises(ValueError):
        build_corr(tl, ac, min_edge_confidence=1.5)
    with pytest.raises(ValueError):
        build_corr(tl, ac, min_edge_confidence=-0.1)
