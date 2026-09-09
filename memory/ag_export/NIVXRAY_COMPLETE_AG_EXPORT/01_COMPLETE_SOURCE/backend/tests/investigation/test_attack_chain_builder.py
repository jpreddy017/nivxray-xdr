"""Stage 10 · Attack Chain Builder tests.

Contract under test (owner directives 2026-08-02 · 2026-02-XX):

    * Attack Chain derives causal edges from validated Timeline events
      + InvestigationGraph edges only — it never invents events.
    * Every AttackEdge carries `derivation_rule[]` explaining *why*.
    * Event confidence ≠ Relationship confidence: edge.confidence is
      capped by the weaker endpoint's event confidence, and further
      shrunk if only some rules could be verified.
    * Same (Timeline, Graph) → byte-identical AttackChain.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from nivxforge.investigation.cem import (
    CanonicalEvent, CanonicalEventModel, EventKind, Process, Provenance,
)
from nivxforge.investigation.pipeline.attack_chain_builder import (
    AttackChain, AttackEdge, DerivationRule,
    DEFAULT_LED_TO_WINDOW, build as build_chain,
)
from nivxforge.investigation.pipeline.graph_builder import (
    GraphEdge, GraphNode, InvestigationGraph,
)
from nivxforge.investigation.pipeline.timeline_builder import (
    build as build_timeline,
)


# ── Test helpers ─────────────────────────────────────────────────────

_T0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
_PROV = Provenance(source="unit-test", timestamp=_T0)


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
    from nivxforge.investigation.cem import Host
    return CanonicalEvent(
        event_id=event_id, kind=EventKind.process_create,
        timestamp=_T0 + timedelta(seconds=seconds),
        host=Host(name=host, provenance=_PROV),
        process=Process(image=image, command_line=cmd,
                        parent_command_line=(parent_cmd or None),
                        provenance=_PROV),
        provenance=_PROV,
    )


def _fabricate(events: List[CanonicalEvent],
                extra_nodes: Tuple[GraphNode, ...] = (),
                extra_edges: Tuple[GraphEdge, ...] = ()):
    """Build (Timeline, InvestigationGraph) from a hand-crafted CEM.
    Adds a process node, command node, host node, and executed_on
    edge per event so `_actor_host` resolves as it does in production."""
    nodes = {n.id: n for n in extra_nodes}
    edges: List[GraphEdge] = list(extra_edges)

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
    return tl, graph


# ── Structural invariants ───────────────────────────────────────────

def test_empty_timeline_yields_empty_chain():
    from nivxforge.investigation.pipeline.timeline_builder import Timeline
    tl = Timeline(entries=(), time_span={"first": None, "last": None},
                   unknown_time_count=0)
    graph = InvestigationGraph(nodes=(), edges=())
    ac = build_chain(tl, graph)
    assert ac.edges == ()
    assert ac.edge_kinds == {}


def test_result_shape():
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    ac = build_chain(tl, graph)
    assert isinstance(ac, AttackChain)
    for e in ac.edges:
        assert isinstance(e, AttackEdge)
        assert e.derivation_rules
        assert all(isinstance(r, DerivationRule)
                   for r in e.derivation_rules)


# ── parent_of edge (strongest) ───────────────────────────────────────

def test_parent_of_fires_when_graph_has_child_of_edge():
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    ac = build_chain(tl, graph)
    kinds = {e.kind for e in ac.edges}
    assert "parent_of" in kinds
    edge = next(e for e in ac.edges if e.kind == "parent_of")
    # The graph_child_of_edge rule must be present and fired
    rule_names = {r.name for r in edge.derivation_rules
                   if r.observed is True}
    assert "graph_child_of_edge" in rule_names


def test_parent_of_carries_ordered_and_host_rules():
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    ac = build_chain(tl, graph)
    edge = next(e for e in ac.edges if e.kind == "parent_of")
    names = {r.name for r in edge.derivation_rules}
    assert {"graph_child_of_edge", "shared_host",
            "time_ordered"}.issubset(names)


# ── led_to edge ─────────────────────────────────────────────────────

def test_led_to_fires_for_same_actor_same_host_within_30s():
    tl, graph = _fabricate([
        _cem_event("e1", "attacker.exe", "attacker -a", "host-x", 0),
        _cem_event("e2", "attacker.exe", "attacker -b", "host-x", 10),
    ])
    ac = build_chain(tl, graph)
    assert any(e.kind == "led_to" for e in ac.edges)
    edge = next(e for e in ac.edges if e.kind == "led_to")
    fired = {r.name for r in edge.derivation_rules
              if r.observed is True}
    assert {"shared_actor", "shared_host",
            "within_30_seconds"}.issubset(fired)


def test_led_to_does_not_fire_across_different_hosts():
    tl, graph = _fabricate([
        _cem_event("e1", "attacker.exe", "attacker -a", "host-a", 0),
        _cem_event("e2", "attacker.exe", "attacker -b", "host-b", 5),
    ])
    ac = build_chain(tl, graph)
    for e in ac.edges:
        assert e.kind != "led_to"


def test_led_to_does_not_fire_outside_time_window():
    beyond = int(DEFAULT_LED_TO_WINDOW.total_seconds()) + 5
    tl, graph = _fabricate([
        _cem_event("e1", "attacker.exe", "attacker -a", "host-x", 0),
        _cem_event("e2", "attacker.exe", "attacker -b", "host-x", beyond),
    ])
    ac = build_chain(tl, graph)
    for e in ac.edges:
        assert e.kind != "led_to"


def test_led_to_dropped_when_timestamps_unknown():
    """No timestamps → within_30_seconds is unknown → led_to must
    not be emitted (renderer contract: no guessed edges)."""
    from nivxforge.investigation.cem import Host
    events = [
        CanonicalEvent(
            event_id="e1", kind=EventKind.process_create,
            host=Host(name="host-x", provenance=_PROV),
            process=Process(image="a.exe", command_line="a -x",
                            provenance=_PROV),
            provenance=_PROV),
        CanonicalEvent(
            event_id="e2", kind=EventKind.process_create,
            host=Host(name="host-x", provenance=_PROV),
            process=Process(image="a.exe", command_line="a -y",
                            provenance=_PROV),
            provenance=_PROV),
    ]
    tl, graph = _fabricate(events)
    ac = build_chain(tl, graph)
    for e in ac.edges:
        assert e.kind != "led_to"


# ── same_context edge (weakest) ─────────────────────────────────────

def test_same_context_fires_across_process_tree():
    """cmd → powershell (parent-child in graph) with a different
    actor beyond the 30 s window: no parent_of (would fire since
    graph_child_of_edge fires), so we choose events where actors
    differ AND no direct child_of exists to isolate same_context."""
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        # parent-child in graph but 90 s apart → parent_of still
        # fires because parent_of ignores time window.
        # To isolate same_context we need TWO events that share host
        # + tree but NOT a direct child_of. Add a third node:
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
        _cem_event("e3", "child.exe", "child -c", "host-x", 20,
                   parent_cmd="powershell -c b"),
    ])
    ac = build_chain(tl, graph)
    kinds = [e.kind for e in ac.edges]
    # e1→e3 has NO direct child_of (grandchild), same host, same
    # tree, within 5 minutes → must be same_context.
    e1_to_e3 = [e for e in ac.edges
                 if e.from_event == tl.entries[0].id
                 and e.to_event == tl.entries[2].id]
    assert e1_to_e3, f"expected e1→e3 edge; got {kinds}"
    assert e1_to_e3[0].kind == "same_context"


# ── Confidence contract ──────────────────────────────────────────────

def test_edge_confidence_never_exceeds_endpoint_event_confidence():
    """RELATIONSHIP confidence is capped by the weaker EVENT confidence.
    Owner directive 2026-02-XX: event confidence ≠ edge confidence."""
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    ac = build_chain(tl, graph)
    for edge in ac.edges:
        from_evt = next(e for e in tl.entries if e.id == edge.from_event)
        to_evt = next(e for e in tl.entries if e.id == edge.to_event)
        cap = min(from_evt.confidence, to_evt.confidence)
        assert edge.confidence <= cap + 1e-9, (
            f"{edge.kind} confidence {edge.confidence} > cap {cap}")


def test_edge_confidence_is_zero_when_no_rules_fired():
    """No rule should ever fire an edge with 0/0 confidence — verify
    the divide-by-zero guard produces a clean 0.0 without exception."""
    from nivxforge.investigation.pipeline.attack_chain_builder import (
        _confidence,
    )
    assert _confidence((), 1.0) == 0.0


# ── Determinism ──────────────────────────────────────────────────────

def test_same_timeline_and_graph_yield_byte_identical_chain():
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    a = build_chain(tl, graph).to_dict()
    b = build_chain(tl, graph).to_dict()
    assert a == b


def test_edge_ids_reference_existing_timeline_events():
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    ac = build_chain(tl, graph)
    ids = {e.id for e in tl.entries}
    for edge in ac.edges:
        assert edge.from_event in ids
        assert edge.to_event in ids


# ── Derivation rule provenance (owner directive) ────────────────────

def test_every_edge_has_at_least_one_fired_rule():
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    ac = build_chain(tl, graph)
    for edge in ac.edges:
        fired = [r for r in edge.derivation_rules if r.observed is True]
        assert fired, f"edge {edge.kind} has no fired rule"


def test_derivation_rules_carry_deterministic_detail_strings():
    """The `detail` string is meant to be shown to analysts. It must
    be deterministic (no timestamps captured at runtime, no random)."""
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    a = build_chain(tl, graph)
    b = build_chain(tl, graph)
    a_details = [(r.name, r.detail) for e in a.edges
                  for r in e.derivation_rules]
    b_details = [(r.name, r.detail) for e in b.edges
                  for r in e.derivation_rules]
    assert a_details == b_details


def test_to_dict_is_json_round_trippable():
    import json
    tl, graph = _fabricate([
        _cem_event("e1", "cmd.exe", "cmd /c a", "host-x", 0),
        _cem_event("e2", "powershell.exe", "powershell -c b",
                   "host-x", 5, parent_cmd="cmd /c a"),
    ])
    d = build_chain(tl, graph).to_dict()
    assert json.loads(json.dumps(d)) == d
    for e in d["edges"]:
        for key in ("id", "kind", "from_event", "to_event",
                    "derivation_rules", "confidence", "provenance"):
            assert key in e
