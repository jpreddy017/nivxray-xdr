"""Stage 9 · Timeline Builder.

Deterministic chronological renderer over the validated Investigation
Graph. Consumes CEMv1 + InvestigationGraph and emits a `Timeline` — an
ordered sequence of `TimelineEntry` objects.

Architectural contract (2026-08-02 · owner directive):
    Timeline is a **renderer** over validated evidence, not an
    inference engine.
        • Timeline may sort, group, annotate, and link evidence.
        • Timeline MUST NOT invent, guess, or synthesise events that
          are absent from the Investigation Graph.

Concretely:
    • Every entry references a CEM event_id that exists in the
      supplied CanonicalEventModel.
    • Every actor / target references a GraphNode id that exists
      in the supplied InvestigationGraph — never a phantom id.
    • Action verbs are derived 1:1 from `EventKind`; no free-form
      language generation happens here.
    • Same (CEM + Graph) → byte-identical Timeline.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from nivxforge.investigation.cem import (
    CanonicalEvent, CanonicalEventModel, EventKind,
)
from .graph_builder import GraphNode, InvestigationGraph


# ── Verb map (deterministic; no inference) ───────────────────────────

_VERB_BY_KIND: Dict[EventKind, str] = {
    EventKind.process_create: "executed",
    EventKind.process_terminate: "terminated",
    EventKind.file_create: "created",
    EventKind.file_modify: "modified",
    EventKind.file_delete: "deleted",
    EventKind.registry_write: "wrote",
    EventKind.registry_delete: "removed",
    EventKind.network_connect: "connected-to",
    EventKind.dns_query: "resolved",
    EventKind.auth_success: "authenticated",
    EventKind.auth_failure: "auth-failed",
    EventKind.service_install: "installed-service",
    EventKind.task_scheduled: "scheduled-task",
    EventKind.alert: "alerted",
    EventKind.detection: "detected",
    EventKind.generic: "observed",
}

# Human-facing canonical event type. Same 1-to-1 with EventKind — this
# is a label, not inference. Downstream stages MUST read `event_type`
# rather than reparsing the verb.
_EVENT_TYPE_BY_KIND: Dict[EventKind, str] = {
    EventKind.process_create: "Process Create",
    EventKind.process_terminate: "Process Terminate",
    EventKind.file_create: "File Create",
    EventKind.file_modify: "File Modify",
    EventKind.file_delete: "File Delete",
    EventKind.registry_write: "Registry Write",
    EventKind.registry_delete: "Registry Delete",
    EventKind.network_connect: "Network Connect",
    EventKind.dns_query: "DNS Query",
    EventKind.auth_success: "Auth Success",
    EventKind.auth_failure: "Auth Failure",
    EventKind.service_install: "Service Install",
    EventKind.task_scheduled: "Scheduled Task",
    EventKind.alert: "Alert",
    EventKind.detection: "Detection",
    EventKind.generic: "Generic",
}

_KIND_TO_TL_KIND: Dict[EventKind, str] = {
    EventKind.process_create: "process",
    EventKind.process_terminate: "process",
    EventKind.file_create: "file",
    EventKind.file_modify: "file",
    EventKind.file_delete: "file",
    EventKind.registry_write: "registry",
    EventKind.registry_delete: "registry",
    EventKind.network_connect: "network",
    EventKind.dns_query: "dns",
    EventKind.auth_success: "auth",
    EventKind.auth_failure: "auth",
    EventKind.service_install: "service",
    EventKind.task_scheduled: "task",
    EventKind.alert: "alert",
    EventKind.detection: "detection",
    EventKind.generic: "generic",
}

# Timestamp source labels — where the timestamp came from. When absent,
# the reason is explicit so downstream (Correlation) can decide whether
# to backfill from neighbouring events.
_TS_SOURCE_PRESENT = "CEM.event.timestamp"
_TS_SOURCE_ABSENT  = "unavailable"

# Origin of a timeline entry — grounding for the "why does this exist?"
# question the owner asked for on 2026-02-XX.
_ORIGIN_TELEMETRY = "Telemetry"     # CEM event field directly named the node
_ORIGIN_DECODED   = "Decoded"       # node reached via a graph edge that
                                     # graph_builder created from decoded /
                                     # extracted IOC evidence
_ORIGIN_DERIVED   = "Derived"       # actor-only entries with no target

SCHEMA_VERSION = "1.0"


# ── Data classes ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProvenanceEntry:
    """One row of provenance. A TimelineEvent may carry several — e.g.
    one for the CEM event, one for the graph edge that annotated an
    artifact, etc."""

    origin: str                        # Telemetry | Decoded | Derived
    source: str                        # CEM.event.timestamp / graph.edge:has_ioc / ...
    reason: str                        # short deterministic string
    confidence: float


@dataclass(frozen=True)
class TimelineEvent:
    """Canonical Timeline Event Model.

    Consumed unchanged by Attack Chain and Correlation (see
    ROADMAP.md · Phase 2). Every field is grounded in either the CEM
    event or the Investigation Graph — no inference lives here.
    """

    # Identity
    id: str                            # deterministic hash id
    source_event: str                  # CEM event_id (foreign key back to CEM)

    # Temporal
    timestamp: Optional[datetime]
    timestamp_precision: str           # "exact" | "unknown"
    timestamp_source: str              # e.g. "CEM.event.timestamp"

    # Semantics (never inferred — map derived from EventKind)
    event_type: str                    # "Process Create", "DNS Query", ...
    kind: str                          # process | file | registry | ...
    action: str                        # verb — 1:1 with EventKind

    # Subjects / objects — all validated GraphNode ids
    actor: Optional[str]               # actor GraphNode id
    targets: Tuple[str, ...]           # direct objects of the action
    artifacts: Tuple[str, ...]         # IOCs / evidence linked via edges
    source_nodes: Tuple[str, ...]      # every graph node id referenced

    # Presentation + provenance
    summary: str                       # deterministic string, no NLG
    provenance: Tuple[ProvenanceEntry, ...]
    confidence: float                  # min confidence across provenance


# Legacy alias — kept so external code that imported the old name
# during Timeline v0 keeps compiling. Same identity as TimelineEvent.
TimelineEntry = TimelineEvent


@dataclass(frozen=True)
class Timeline:
    """Chronologically ordered projection of the Investigation Graph."""

    entries: Tuple[TimelineEvent, ...]
    time_span: Dict[str, Optional[str]]  # {"first": iso|None, "last": iso|None}
    unknown_time_count: int
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "entries": [
                {
                    "id": e.id,
                    "source_event": e.source_event,
                    "timestamp": (
                        e.timestamp.isoformat() if e.timestamp else None
                    ),
                    "timestamp_precision": e.timestamp_precision,
                    "timestamp_source": e.timestamp_source,
                    "event_type": e.event_type,
                    "kind": e.kind,
                    "action": e.action,
                    "actor": e.actor,
                    "targets": list(e.targets),
                    "artifacts": list(e.artifacts),
                    "source_nodes": list(e.source_nodes),
                    "summary": e.summary,
                    "provenance": [
                        {
                            "origin": p.origin,
                            "source": p.source,
                            "reason": p.reason,
                            "confidence": p.confidence,
                        }
                        for p in e.provenance
                    ],
                    "confidence": e.confidence,
                }
                for e in self.entries
            ],
            "time_span": dict(self.time_span),
            "unknown_time_count": self.unknown_time_count,
            "entry_count": len(self.entries),
        }


# ── Internals ────────────────────────────────────────────────────────

def _hash_id(*parts: str) -> str:
    h = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"t-{h}"


def _canonicalise(kind: str, value: str) -> str:
    if kind in ("hash", "ip", "domain", "url", "dns", "host", "user"):
        return value.strip().lower()
    return value.strip()[:200]


def _find_node(graph: InvestigationGraph, kind: str,
                canonical_value: str) -> Optional[GraphNode]:
    # graph_builder builds ids as f"{kind}-{sha256(value)[:12]}"; the
    # kind is a *prefix*, not part of the hashed material. Match the
    # exact convention so we never fabricate a phantom id.
    h = hashlib.sha256(canonical_value.encode("utf-8")).hexdigest()[:12]
    return graph.node(f"{kind}-{h}")


def _resolve_actor(event: CanonicalEvent,
                    graph: InvestigationGraph) -> Optional[str]:
    """Actor priority: process → user → host. Never invented — must
    correspond to an existing node in the graph."""
    if event.process and event.process.image:
        n = _find_node(graph, "process",
                       _canonicalise("process", event.process.image))
        if n:
            return n.id
    if event.user and event.user.name:
        n = _find_node(graph, "user",
                       _canonicalise("user", event.user.name))
        if n:
            return n.id
    if event.host and (event.host.name or event.host.fqdn or event.host.ip):
        n = _find_node(graph, "host", _canonicalise(
            "host",
            event.host.name or event.host.fqdn or event.host.ip or ""))
        if n:
            return n.id
    return None


def _resolve_targets_and_artifacts(
    event: CanonicalEvent,
    graph: InvestigationGraph,
) -> Tuple[List[str], List[str]]:
    """Return (targets, artifacts) — both are validated GraphNode ids.

    * **targets** — direct objects of the action, named explicitly by
      a CEM event field (command from process_create, file from
      file_*, registry from registry_*, network URL/IP from
      network_connect, dns.query from dns_query, detection.name).

    * **artifacts** — IOC / evidence nodes reached only via a graph
      edge that graph_builder created from decoded content or IOC
      extraction (e.g. a URL discovered inside a decoded command).

    The split lets Attack Chain reason about causal *targets* while
    still surfacing supporting *artifacts* for the analyst.
    """
    targets: List[str] = []
    artifacts: List[str] = []
    seen: set = set()

    def _push(dst: List[str], nid: Optional[str]) -> None:
        if nid and nid not in seen and graph.node(nid):
            seen.add(nid)
            dst.append(nid)

    cmd_node_id: Optional[str] = None
    if event.process and event.process.command_line:
        cmd_node_id = _maybe_id(graph, "command",
                                 _canonicalise("command",
                                                event.process.command_line))
        _push(targets, cmd_node_id)

    if event.file and event.file.path:
        _push(targets, _maybe_id(graph, "file",
                         _canonicalise("file", event.file.path)))
        if event.file.hash_sha256:
            _push(targets, _maybe_id(graph, "hash",
                             _canonicalise("hash", event.file.hash_sha256)))

    if event.registry and event.registry.key:
        _push(targets, _maybe_id(graph, "registry",
                         _canonicalise("registry", event.registry.key)))

    if event.network:
        if event.network.url:
            _push(targets, _maybe_id(graph, "url",
                             _canonicalise("url", event.network.url)))
        if event.network.domain:
            _push(targets, _maybe_id(graph, "url",
                             _canonicalise("url", event.network.domain)))
        if event.network.dst_ip:
            _push(targets, _maybe_id(graph, "ip",
                             _canonicalise("ip", event.network.dst_ip)))

    if event.dns and event.dns.query:
        _push(targets, _maybe_id(graph, "dns",
                         _canonicalise("dns", event.dns.query)))

    if event.detection and event.detection.name:
        _push(targets, _maybe_id(graph, "detection",
                         _canonicalise("detection", event.detection.name)))

    # Artifacts — semantic-target edges from the command node that
    # graph_builder tagged with this event_id. These represent evidence
    # the decoder / IOC extractor uncovered *inside* the event payload.
    _ARTIFACT_RELATIONS = {
        "has_ioc", "touched", "connected_to", "resolved_to",
        "decoded_to", "flagged",
    }
    if cmd_node_id:
        outgoing = sorted(graph.edges_from(cmd_node_id), key=lambda e: e.id)
        for edge in outgoing:
            if edge.relation not in _ARTIFACT_RELATIONS:
                continue
            if event.event_id not in edge.evidence_refs:
                continue
            _push(artifacts, edge.to_id)

    return targets, artifacts


def _maybe_id(graph: InvestigationGraph, kind: str,
               canonical_value: str) -> Optional[str]:
    n = _find_node(graph, kind, canonical_value)
    return n.id if n else None


def _label(graph: InvestigationGraph, node_id: Optional[str]) -> str:
    if not node_id:
        return ""
    n = graph.node(node_id)
    return n.label if n else ""


def _summary(action: str, actor_label: str,
              target_labels: List[str]) -> str:
    """Deterministic string. No NLG, no free-form generation."""
    subject = actor_label or "actor"
    if not target_labels:
        return f"{subject} {action}"
    if len(target_labels) == 1:
        return f"{subject} {action} {target_labels[0]}"
    head = ", ".join(target_labels[:2])
    if len(target_labels) > 2:
        head += f" (+{len(target_labels) - 2})"
    return f"{subject} {action} {head}"


# ── Builder ──────────────────────────────────────────────────────────

def _classify_origin(event: CanonicalEvent,
                      targets: List[str],
                      artifacts: List[str]) -> str:
    """Deterministic origin classification — no inference.

        * Telemetry — the CEM event named at least one target.
        * Decoded   — only artifacts survived (targets empty but
                      graph_builder linked IOCs via edges).
        * Derived   — actor-only entry (no target, no artifact).
    """
    if targets:
        return _ORIGIN_TELEMETRY
    if artifacts:
        return _ORIGIN_DECODED
    return _ORIGIN_DERIVED


def _reason(event_type: str, origin: str) -> str:
    """Short deterministic reason string. Not NLG — just a canonical
    label of *why this row is on the timeline*."""
    if origin == _ORIGIN_TELEMETRY:
        return f"Canonical {event_type} event from CEM"
    if origin == _ORIGIN_DECODED:
        return f"IOC/artifact linked from {event_type} via graph edge"
    return f"{event_type} event with no downstream anchor"


def build(cem: CanonicalEventModel,
           graph: InvestigationGraph) -> Timeline:
    """Render the Investigation Graph chronologically.

    Every entry emitted is grounded in one CEM event and links only
    to nodes that already exist in the supplied Investigation Graph.
    """
    entries: List[TimelineEvent] = []

    for evt in cem.events:
        kind = _KIND_TO_TL_KIND.get(evt.kind, "generic")
        action = _VERB_BY_KIND.get(evt.kind, "observed")
        event_type = _EVENT_TYPE_BY_KIND.get(evt.kind, "Generic")

        actor_id = _resolve_actor(evt, graph)
        targets, artifacts = _resolve_targets_and_artifacts(evt, graph)
        # An actor is never its own target/artifact.
        if actor_id:
            targets = [t for t in targets if t != actor_id]
            artifacts = [a for a in artifacts if a != actor_id]

        # Renderer contract: an entry needs at least one graph anchor.
        if not actor_id and not targets and not artifacts:
            continue

        actor_label = _label(graph, actor_id)
        target_labels = [_label(graph, t) for t in targets]
        target_labels = [t for t in target_labels if t]

        precision = "exact" if evt.timestamp is not None else "unknown"
        ts_source = (_TS_SOURCE_PRESENT if evt.timestamp is not None
                     else _TS_SOURCE_ABSENT)
        origin = _classify_origin(evt, targets, artifacts)
        reason = _reason(event_type, origin)

        eid = _hash_id(evt.event_id, kind, action,
                       actor_id or "-", "|".join(targets),
                       "|".join(artifacts))

        source_nodes: List[str] = []
        if actor_id:
            source_nodes.append(actor_id)
        for nid in targets + artifacts:
            if nid not in source_nodes:
                source_nodes.append(nid)

        # Provenance rows — one per grounding fact. Consumers
        # (Attack Chain, Correlation) can trace every claim back to
        # either the CEM event or a specific graph edge.
        prov_rows: List[ProvenanceEntry] = [
            ProvenanceEntry(
                origin=_ORIGIN_TELEMETRY,
                source=f"CEM.event[{evt.event_id}]",
                reason=reason,
                confidence=(evt.provenance.confidence
                            if evt.provenance else 1.0),
            )
        ]
        if artifacts:
            prov_rows.append(ProvenanceEntry(
                origin=_ORIGIN_DECODED,
                source="graph.edges[has_ioc|decoded_to|touched|"
                       "connected_to|resolved_to|flagged]",
                reason=f"{len(artifacts)} artifact(s) linked via graph",
                confidence=1.0,
            ))
        min_confidence = min(p.confidence for p in prov_rows)

        entries.append(TimelineEvent(
            id=eid,
            source_event=evt.event_id,
            timestamp=evt.timestamp,
            timestamp_precision=precision,
            timestamp_source=ts_source,
            event_type=event_type,
            kind=kind,
            action=action,
            actor=actor_id,
            targets=tuple(targets),
            artifacts=tuple(artifacts),
            source_nodes=tuple(source_nodes),
            summary=_summary(action, actor_label, target_labels),
            provenance=tuple(prov_rows),
            confidence=min_confidence,
        ))

    # Deterministic sort: (timestamp asc, event_id, kind, id).
    def _sort_key(e: TimelineEvent) -> Tuple[Any, ...]:
        ts_key = (
            e.timestamp.timestamp()
            if e.timestamp is not None
            else float("inf")
        )
        return (ts_key, e.source_event, e.kind, e.id)

    entries.sort(key=_sort_key)

    # De-dup identical entries (same source_event + kind + action +
    # actor + targets + artifacts). First-seen wins post-sort.
    deduped: List[TimelineEvent] = []
    seen_keys: set = set()
    for e in entries:
        key = (e.source_event, e.kind, e.action, e.actor,
               e.targets, e.artifacts)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(e)

    known = [e for e in deduped if e.timestamp is not None]
    span = {
        "first": known[0].timestamp.isoformat() if known else None,
        "last": known[-1].timestamp.isoformat() if known else None,
    }
    unknown = sum(1 for e in deduped if e.timestamp is None)

    return Timeline(
        entries=tuple(deduped),
        time_span=span,
        unknown_time_count=unknown,
    )


__all__ = [
    "SCHEMA_VERSION",
    "TimelineEvent", "TimelineEntry", "Timeline",
    "ProvenanceEntry", "build",
]
