"""Stage 11 · Correlation Engine.

Deterministic clustering over `AttackChain` edges + `TimelineEvent`s.
Produces `IncidentCluster`s — groupings of already-validated timeline
events connected by AttackEdges above a confidence threshold.

Architectural contract (owner directive 2026-02-XX):

    Correlation produces **Incidents, not Events**.

    * The Correlation Engine never emits a new event, never invents a
      relationship, and never contradicts anything the Timeline or
      Attack Chain already asserted.
    * A cluster is the set of TimelineEvents reachable through the
      subgraph of AttackEdges whose confidence ≥ `min_edge_confidence`.
    * Every derived field on the cluster (shared_actors, shared_hosts,
      time_span, severity_hint) is computed by intersecting or
      aggregating validated facts already carried on its member events.
    * Same (Timeline, AttackChain) + same threshold → byte-identical
      Correlation.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .attack_chain_builder import AttackChain, AttackEdge, EvidenceRef
from .timeline_builder import Timeline, TimelineEvent


SCHEMA_VERSION = "1.0"

# Default minimum RELATIONSHIP confidence for an edge to enter the
# clustering graph. Conservative to keep noisy `same_context` edges
# from over-clustering; may be tuned once real telemetry lands.
DEFAULT_MIN_EDGE_CONFIDENCE = 0.5


# ── Data classes ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class IncidentCluster:
    """A connected group of TimelineEvents joined by AttackEdges above
    the confidence threshold. Downstream (narrative, UI) consumes this
    unchanged."""

    id: str
    timeline_event_ids: Tuple[str, ...]
    attack_edge_ids: Tuple[str, ...]
    shared_actors: Tuple[str, ...]        # graph node ids common to ≥2 events
    shared_hosts: Tuple[str, ...]         # graph node ids
    time_span: Dict[str, Optional[str]]   # {"first": iso|None, "last": iso|None}
    unknown_time_count: int
    dominant_edge_kinds: Dict[str, int]   # per-kind edge count in cluster
    confidence: float                     # min edge confidence in cluster
    severity_hint: str                    # informational|low|medium|high|critical
    supporting_evidence: Tuple[EvidenceRef, ...]
    provenance: Dict[str, Any]            # {source, reason, threshold}


@dataclass(frozen=True)
class Correlation:
    """Full correlation result over a Timeline + AttackChain."""

    clusters: Tuple[IncidentCluster, ...]
    orphan_event_ids: Tuple[str, ...]     # TimelineEvent ids with no edge
    min_edge_confidence: float
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "min_edge_confidence": self.min_edge_confidence,
            "cluster_count": len(self.clusters),
            "orphan_event_count": len(self.orphan_event_ids),
            "orphan_event_ids": list(self.orphan_event_ids),
            "clusters": [
                {
                    "id": c.id,
                    "timeline_event_ids": list(c.timeline_event_ids),
                    "attack_edge_ids": list(c.attack_edge_ids),
                    "shared_actors": list(c.shared_actors),
                    "shared_hosts": list(c.shared_hosts),
                    "time_span": dict(c.time_span),
                    "unknown_time_count": c.unknown_time_count,
                    "dominant_edge_kinds": dict(c.dominant_edge_kinds),
                    "confidence": c.confidence,
                    "severity_hint": c.severity_hint,
                    "supporting_evidence": [
                        {"type": e.type, "id": e.id}
                        for e in c.supporting_evidence
                    ],
                    "provenance": dict(c.provenance),
                }
                for c in self.clusters
            ],
        }


# ── Internals ────────────────────────────────────────────────────────

def _hash_id(*parts: str) -> str:
    h = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"ic-{h}"


def _connected_components(
    events: List[TimelineEvent],
    edges: List[AttackEdge],
) -> List[List[str]]:
    """Union-Find over the TimelineEvent id graph implied by edges.

    Deterministic: node ids are processed in sorted order, and every
    component is returned as a sorted list. Same input → same output
    partition regardless of edge iteration order.
    """
    parent: Dict[str, str] = {e.id: e.id for e in events}

    def _find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: str, b: str) -> None:
        ra, rb = _find(a), _find(b)
        if ra == rb:
            return
        # Deterministic: attach the lexicographically-larger root
        # under the smaller one.
        if ra < rb:
            parent[rb] = ra
        else:
            parent[ra] = rb

    for edge in edges:
        if edge.from_event in parent and edge.to_event in parent:
            _union(edge.from_event, edge.to_event)

    groups: Dict[str, List[str]] = {}
    for eid in sorted(parent):
        root = _find(eid)
        groups.setdefault(root, []).append(eid)

    # Return components sorted by first member for stable output.
    return sorted(groups.values(), key=lambda comp: comp[0])


_EVENT_TYPE_SEVERITY: Dict[str, str] = {
    # High-signal event types get a stronger default hint. This is a
    # deterministic lookup — no inference beyond the CEM event kind.
    "Detection":      "high",
    "Alert":          "high",
    "Auth Failure":   "medium",
    "Service Install": "medium",
    "Scheduled Task":  "medium",
    "Registry Write":  "low",
    "Registry Delete": "low",
    "Network Connect": "low",
    "DNS Query":       "informational",
    "Process Create":  "informational",
    "Process Terminate": "informational",
    "File Create":     "informational",
    "File Modify":     "informational",
    "File Delete":     "informational",
    "Auth Success":    "informational",
    "Generic":         "informational",
}

_SEVERITY_ORDER = [
    "informational", "low", "medium", "high", "critical",
]


def _severity_hint(events: List[TimelineEvent]) -> str:
    """Cluster severity = max severity across its member event types.

    This is a deterministic aggregate over an already-mapped lookup —
    no free-form inference. Returns "informational" for an empty set."""
    best = "informational"
    for evt in events:
        s = _EVENT_TYPE_SEVERITY.get(evt.event_type, "informational")
        if _SEVERITY_ORDER.index(s) > _SEVERITY_ORDER.index(best):
            best = s
    return best


def _cluster_supporting_evidence(
    events: List[TimelineEvent],
    edges: List[AttackEdge],
) -> Tuple[EvidenceRef, ...]:
    """Aggregate & deduplicate every AttackEdge's supporting_evidence."""
    refs: List[EvidenceRef] = []
    seen: Set[Tuple[str, str]] = set()

    def _push(ref: EvidenceRef) -> None:
        key = (ref.type, ref.id)
        if key not in seen:
            seen.add(key)
            refs.append(ref)

    for evt in events:
        _push(EvidenceRef(type="timeline_event", id=evt.id))
        _push(EvidenceRef(type="cem_event", id=evt.source_event))
    for edge in edges:
        _push(EvidenceRef(type="attack_edge", id=edge.id))
        for ref in edge.supporting_evidence:
            _push(ref)

    # Sort for byte-stable output.
    refs.sort(key=lambda r: (r.type, r.id))
    return tuple(refs)


def _shared_ids(events: List[TimelineEvent],
                 attr: str) -> Tuple[str, ...]:
    """Return node ids that appear on ≥ 2 events under the given attr.
    Sorted for determinism."""
    counter: Dict[str, int] = {}
    for evt in events:
        val = getattr(evt, attr, None)
        if val:
            counter[val] = counter.get(val, 0) + 1
    return tuple(sorted(nid for nid, c in counter.items() if c >= 2))


def _shared_hosts(events: List[TimelineEvent],
                   host_by_actor: Dict[str, str]) -> Tuple[str, ...]:
    """Hosts observed on ≥ 2 events, resolved from each event's actor."""
    counter: Dict[str, int] = {}
    for evt in events:
        host = host_by_actor.get(evt.actor or "", "")
        if host:
            counter[host] = counter.get(host, 0) + 1
    return tuple(sorted(nid for nid, c in counter.items() if c >= 2))


def _time_span(events: List[TimelineEvent]) -> Dict[str, Optional[str]]:
    known = [e.timestamp for e in events if e.timestamp is not None]
    known.sort()
    return {
        "first": known[0].isoformat() if known else None,
        "last": known[-1].isoformat() if known else None,
    }


# ── Public API ───────────────────────────────────────────────────────

def build(
    timeline: Timeline,
    chain: AttackChain,
    *,
    min_edge_confidence: float = DEFAULT_MIN_EDGE_CONFIDENCE,
    host_by_actor: Optional[Dict[str, str]] = None,
) -> Correlation:
    """Cluster the Timeline into IncidentClusters.

    `host_by_actor` maps `TimelineEvent.actor` → host graph-node id,
    if callers have already resolved it. Passing this in keeps the
    Correlation Engine free of graph knowledge — it only reads the
    Timeline + AttackChain contract objects.
    """
    if not (0.0 <= min_edge_confidence <= 1.0):
        raise ValueError("min_edge_confidence must be in [0, 1]")

    events_by_id = {e.id: e for e in timeline.entries}
    strong_edges = [
        e for e in chain.edges if e.confidence >= min_edge_confidence
    ]

    components = _connected_components(
        list(timeline.entries), strong_edges)

    edges_by_from: Dict[str, List[AttackEdge]] = {}
    for edge in strong_edges:
        edges_by_from.setdefault(edge.from_event, []).append(edge)
    edges_by_to: Dict[str, List[AttackEdge]] = {}
    for edge in strong_edges:
        edges_by_to.setdefault(edge.to_event, []).append(edge)

    clusters: List[IncidentCluster] = []
    orphans: List[str] = []
    host_lookup = host_by_actor or {}

    for component in components:
        if len(component) <= 1:
            # A singleton with no strong edges is an orphan — a
            # TimelineEvent the Correlation Engine could not tie to
            # anything else with sufficient confidence.
            orphans.extend(component)
            continue

        cluster_events = [events_by_id[eid] for eid in component]
        # Edges entirely inside the component.
        cluster_edges = [
            edge for edge in strong_edges
            if edge.from_event in component and edge.to_event in component
        ]
        cluster_edges.sort(key=lambda e: e.id)

        kinds_counter: Dict[str, int] = {}
        for edge in cluster_edges:
            kinds_counter[edge.kind] = kinds_counter.get(edge.kind, 0) + 1

        min_conf = min((e.confidence for e in cluster_edges),
                       default=1.0)
        unknown_ts = sum(1 for e in cluster_events if e.timestamp is None)

        cluster_id = _hash_id(*component)

        clusters.append(IncidentCluster(
            id=cluster_id,
            timeline_event_ids=tuple(component),
            attack_edge_ids=tuple(e.id for e in cluster_edges),
            shared_actors=_shared_ids(cluster_events, "actor"),
            shared_hosts=_shared_hosts(cluster_events, host_lookup),
            time_span=_time_span(cluster_events),
            unknown_time_count=unknown_ts,
            dominant_edge_kinds=kinds_counter,
            confidence=min_conf,
            severity_hint=_severity_hint(cluster_events),
            supporting_evidence=_cluster_supporting_evidence(
                cluster_events, cluster_edges),
            provenance={
                "source": "correlation_engine",
                "reason": ("connected-components over AttackEdges "
                           f"≥ {min_edge_confidence}"),
                "min_edge_confidence": min_edge_confidence,
            },
        ))

    clusters.sort(key=lambda c: c.id)
    return Correlation(
        clusters=tuple(clusters),
        orphan_event_ids=tuple(sorted(orphans)),
        min_edge_confidence=min_edge_confidence,
    )


def build_from_graph(
    timeline: Timeline,
    chain: AttackChain,
    graph,
    *,
    min_edge_confidence: float = DEFAULT_MIN_EDGE_CONFIDENCE,
) -> Correlation:
    """Convenience wrapper — resolves `host_by_actor` from the graph.

    The core `build()` is deliberately graph-agnostic; this wrapper
    is what routers / orchestrators call in production.
    """
    host_by_actor: Dict[str, str] = {}
    for evt in timeline.entries:
        if not evt.actor:
            continue
        for edge in graph.edges_from(evt.actor):
            if (edge.relation == "executed_on"
                    and evt.source_event in edge.evidence_refs):
                host_by_actor[evt.actor] = edge.to_id
                break
        else:
            # Fallback: single deterministic host if only one exists.
            hosts = {edge.to_id for edge in graph.edges_from(evt.actor)
                     if edge.relation == "executed_on"}
            if len(hosts) == 1:
                host_by_actor[evt.actor] = next(iter(hosts))
    return build(timeline, chain,
                 min_edge_confidence=min_edge_confidence,
                 host_by_actor=host_by_actor)


__all__ = [
    "SCHEMA_VERSION",
    "IncidentCluster", "Correlation",
    "DEFAULT_MIN_EDGE_CONFIDENCE",
    "build", "build_from_graph",
]
