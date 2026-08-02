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


# ── Data classes ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class TimelineEntry:
    """One chronologically-anchored view over validated evidence."""

    entry_id: str
    event_id: str
    kind: str                       # process | file | registry | ...
    action: str                     # verb from EventKind (never inferred)
    timestamp: Optional[datetime]   # None ⇢ correlated / unknown time
    timestamp_precision: str        # "exact" | "unknown"
    actor_node_id: Optional[str]
    target_node_ids: Tuple[str, ...]
    summary: str                    # deterministic string, no NLG
    evidence_refs: Tuple[str, ...]  # graph node ids + event ids
    provenance: Dict[str, Any]      # vendor / vendor_route / confidence


@dataclass(frozen=True)
class Timeline:
    """Chronologically ordered projection of the Investigation Graph."""

    entries: Tuple[TimelineEntry, ...]
    time_span: Dict[str, Optional[str]]  # {"first": iso|None, "last": iso|None}
    unknown_time_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entries": [
                {
                    "entry_id": e.entry_id,
                    "event_id": e.event_id,
                    "kind": e.kind,
                    "action": e.action,
                    "timestamp": (
                        e.timestamp.isoformat() if e.timestamp else None
                    ),
                    "timestamp_precision": e.timestamp_precision,
                    "actor_node_id": e.actor_node_id,
                    "target_node_ids": list(e.target_node_ids),
                    "summary": e.summary,
                    "evidence_refs": list(e.evidence_refs),
                    "provenance": dict(e.provenance),
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


def _resolve_targets(event: CanonicalEvent,
                      graph: InvestigationGraph) -> List[str]:
    """Targets are validated graph node ids only. Order is deterministic.

    Two sources feed this list:
        1. Direct fields on the CEM event (file / registry / network / dns
           / detection / decoded command).
        2. Existing graph edges from the event's command node that were
           already materialised by graph_builder (e.g. `has_ioc` from a
           command to URL/IP/DNS/hash nodes when they share an event_id).

    Neither source invents evidence — (1) is grounded in the CEM event,
    (2) is grounded in graph edges already validated by graph_builder.
    """
    out: List[str] = []
    seen: set = set()

    def _push(nid: Optional[str]) -> None:
        if nid and nid not in seen and graph.node(nid):
            seen.add(nid)
            out.append(nid)

    cmd_node_id: Optional[str] = None
    # process_create emits the child command as target (its image is actor)
    if event.process and event.process.command_line:
        cmd_node_id = _maybe_id(graph, "command",
                                 _canonicalise("command",
                                                event.process.command_line))
        _push(cmd_node_id)

    if event.file and event.file.path:
        _push(_maybe_id(graph, "file",
                         _canonicalise("file", event.file.path)))
        if event.file.hash_sha256:
            _push(_maybe_id(graph, "hash",
                             _canonicalise("hash", event.file.hash_sha256)))

    if event.registry and event.registry.key:
        _push(_maybe_id(graph, "registry",
                         _canonicalise("registry", event.registry.key)))

    if event.network:
        if event.network.url:
            _push(_maybe_id(graph, "url",
                             _canonicalise("url", event.network.url)))
        if event.network.domain:
            _push(_maybe_id(graph, "url",
                             _canonicalise("url", event.network.domain)))
        if event.network.dst_ip:
            _push(_maybe_id(graph, "ip",
                             _canonicalise("ip", event.network.dst_ip)))

    if event.dns and event.dns.query:
        _push(_maybe_id(graph, "dns",
                         _canonicalise("dns", event.dns.query)))

    if event.detection and event.detection.name:
        _push(_maybe_id(graph, "detection",
                         _canonicalise("detection", event.detection.name)))

    # Annotate with graph edges already produced by graph_builder that
    # share this event_id. Only *semantic-target* relations count — we
    # skip structural back-edges (`belongs_to`, `ran_by`, `child_of`,
    # `executed_on`) which are already reflected in actor resolution.
    _TARGET_RELATIONS = {
        "has_ioc", "touched", "connected_to", "resolved_to",
        "decoded_to", "flagged",
    }
    if cmd_node_id:
        outgoing = sorted(graph.edges_from(cmd_node_id), key=lambda e: e.id)
        for edge in outgoing:
            if edge.relation not in _TARGET_RELATIONS:
                continue
            if event.event_id in edge.evidence_refs:
                _push(edge.to_id)

    return out


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

def build(cem: CanonicalEventModel,
           graph: InvestigationGraph) -> Timeline:
    """Render the Investigation Graph chronologically.

    Every entry emitted is grounded in one CEM event and links only
    to nodes that already exist in the supplied Investigation Graph.
    """
    entries: List[TimelineEntry] = []

    for evt in cem.events:
        kind = _KIND_TO_TL_KIND.get(evt.kind, "generic")
        action = _VERB_BY_KIND.get(evt.kind, "observed")

        actor_id = _resolve_actor(evt, graph)
        targets = _resolve_targets(evt, graph)
        # An actor is never its own target.
        if actor_id and actor_id in targets:
            targets = [t for t in targets if t != actor_id]

        # Renderer contract: an entry needs at least one graph anchor.
        # If neither actor nor targets exist in the graph, skip — never
        # invent phantom relations just to keep the entry.
        if not actor_id and not targets:
            continue

        actor_label = _label(graph, actor_id)
        target_labels = [_label(graph, t) for t in targets]
        target_labels = [t for t in target_labels if t]

        precision = "exact" if evt.timestamp is not None else "unknown"
        eid = _hash_id(evt.event_id, kind, action,
                       actor_id or "-", "|".join(targets))

        evidence_refs: List[str] = [evt.event_id]
        if actor_id:
            evidence_refs.append(actor_id)
        for tid in targets:
            if tid not in evidence_refs:
                evidence_refs.append(tid)

        entries.append(TimelineEntry(
            entry_id=eid,
            event_id=evt.event_id,
            kind=kind,
            action=action,
            timestamp=evt.timestamp,
            timestamp_precision=precision,
            actor_node_id=actor_id,
            target_node_ids=tuple(targets),
            summary=_summary(action, actor_label, target_labels),
            evidence_refs=tuple(evidence_refs),
            provenance={
                "vendor": cem.vendor,
                "vendor_route": cem.vendor_route,
                "source": "timeline_builder",
                "confidence": evt.provenance.confidence
                if evt.provenance else 1.0,
            },
        ))

    # Deterministic sort: (timestamp asc, event_id, kind, entry_id).
    # Unknown-time entries sort to the end preserving insertion stability
    # via event_id as a tie-breaker.
    def _sort_key(e: TimelineEntry) -> Tuple[Any, ...]:
        ts_key = (
            e.timestamp.timestamp()
            if e.timestamp is not None
            else float("inf")
        )
        return (ts_key, e.event_id, e.kind, e.entry_id)

    entries.sort(key=_sort_key)

    # De-duplicate identical entries (same event_id + kind + action +
    # actor + targets) which may occur when a CEM event is mirrored by
    # multiple adapters. First-seen wins (post-sort → earliest ts).
    deduped: List[TimelineEntry] = []
    seen_keys: set = set()
    for e in entries:
        key = (e.event_id, e.kind, e.action, e.actor_node_id,
               e.target_node_ids)
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
    "TimelineEntry", "Timeline", "build",
]
