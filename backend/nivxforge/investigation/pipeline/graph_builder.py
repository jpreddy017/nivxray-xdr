"""Stage 8 · Investigation Graph Builder.

Consumes CEMv1 + EvidenceBundle and produces the immutable
`InvestigationGraph` — a directed multigraph where every downstream
stage (Correlation, Timeline, Attack Chain, Hypothesis, Root Cause,
Narrative) must consume ONLY this graph, per Addendum B invariant.

Node taxonomy (Contract #3):
    Host · User · Process · Command · DecodedPayload · Registry
    · Service · ScheduledTask · File · Hash · URL · IP · DNS
    · Certificate · Network · Alert · Detection · ATT&CK
    · ThreatFamily · Recommendation · Finding · Hypothesis
    · TimelineEvent

Edge relations (subset used in Phase 1):
    executed_on · ran_by · child_of · touched · connected_to
    · resolved_to · flagged · decoded_to · has_ioc · observed_at
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from nivxforge.investigation.cem import CanonicalEventModel
from .evidence_extraction import EvidenceBundle, EvidenceItem


NODE_KINDS = {
    "host", "user", "process", "command", "decoded_payload",
    "registry", "service", "scheduled_task", "file", "hash",
    "url", "ip", "dns", "certificate", "network", "alert",
    "detection", "attck", "threat_family", "recommendation",
    "finding", "hypothesis", "timeline_event",
}

EDGE_RELATIONS = {
    "executed_on", "ran_by", "child_of", "touched", "connected_to",
    "resolved_to", "flagged", "decoded_to", "has_ioc", "observed_at",
    "belongs_to",
}


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    value: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    evidence_refs: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GraphEdge:
    id: str
    from_id: str
    to_id: str
    relation: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: Tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 1.0


@dataclass
class InvestigationGraph:
    """Directed multigraph. Read-only from downstream stages."""
    nodes: Tuple[GraphNode, ...]
    edges: Tuple[GraphEdge, ...]
    _by_id: Dict[str, GraphNode] = field(default_factory=dict)
    _by_kind: Dict[str, List[GraphNode]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._by_id = {n.id: n for n in self.nodes}
        by_kind: Dict[str, List[GraphNode]] = {}
        for n in self.nodes:
            by_kind.setdefault(n.kind, []).append(n)
        self._by_kind = by_kind

    def node(self, node_id: str) -> Optional[GraphNode]:
        return self._by_id.get(node_id)

    def nodes_of(self, kind: str) -> List[GraphNode]:
        return list(self._by_kind.get(kind, []))

    def edges_from(self, node_id: str) -> List[GraphEdge]:
        return [e for e in self.edges if e.from_id == node_id]

    def edges_to(self, node_id: str) -> List[GraphEdge]:
        return [e for e in self.edges if e.to_id == node_id]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.id, "kind": n.kind, "label": n.label,
                    "value": n.value, "attrs": n.attrs,
                    "confidence": n.confidence,
                    "evidence_refs": list(n.evidence_refs),
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "id": e.id, "from": e.from_id, "to": e.to_id,
                    "relation": e.relation, "attrs": e.attrs,
                    "confidence": e.confidence,
                    "evidence_refs": list(e.evidence_refs),
                }
                for e in self.edges
            ],
        }


# ── Builder ──────────────────────────────────────────────────────────

_KIND_TO_NODE_KIND = {
    "host": "host", "user": "user", "process": "process",
    "command": "command", "file": "file", "hash": "hash",
    "url": "url", "ip": "ip", "domain": "url", "dns": "dns",
    "registry": "registry", "detection": "detection",
    "decoded_payload": "decoded_payload",
}


def _hash_id(prefix: str, *parts: str) -> str:
    h = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{h}"


def build(cem: CanonicalEventModel,
          evidence: EvidenceBundle) -> InvestigationGraph:
    """Build immutable Investigation Graph from CEM + evidence."""
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    # Evidence items → nodes (canonical identity)
    ev_to_node: Dict[Tuple[str, str], str] = {}
    for ev in evidence.items:
        node_kind = _KIND_TO_NODE_KIND.get(ev.kind)
        if node_kind is None:
            continue
        canonical_value = _canonicalise(ev.kind, ev.value)
        nid = _hash_id(node_kind, canonical_value)
        if nid not in nodes:
            nodes[nid] = GraphNode(
                id=nid,
                kind=node_kind,
                label=_label_for(node_kind, ev),
                value=ev.value,
                attrs=dict(ev.attrs),
                confidence=ev.confidence,
                evidence_refs=tuple(ev.event_ids),
                provenance={"vendor": cem.vendor,
                             "vendor_route": cem.vendor_route},
            )
        ev_to_node[(ev.kind, canonical_value)] = nid

    # Timeline / observed_at edges: process → host, command → process,
    # network → process, etc.
    for evt in cem.events:
        host_id = None
        if evt.host and (evt.host.name or evt.host.fqdn or evt.host.ip):
            host_id = _hash_id("host", _canonicalise("host",
                evt.host.name or evt.host.fqdn or evt.host.ip or ""))
        user_id = None
        if evt.user and evt.user.name:
            user_id = _hash_id("user", _canonicalise("user", evt.user.name))
        proc_id = None
        if evt.process and evt.process.image:
            proc_id = _hash_id("process",
                _canonicalise("process", evt.process.image))
        cmd_id = None
        if evt.process and evt.process.command_line:
            cmd_id = _hash_id("command",
                _canonicalise("command", evt.process.command_line))
        parent_cmd_id = None
        if evt.parent_process and evt.parent_process.command_line:
            parent_cmd_id = _hash_id("command",
                _canonicalise("command",
                              evt.parent_process.command_line))

        if proc_id and host_id and proc_id in nodes and host_id in nodes:
            edges.append(_edge("executed_on", proc_id, host_id, evt.event_id))
        if cmd_id and proc_id and cmd_id in nodes and proc_id in nodes:
            edges.append(_edge("belongs_to", cmd_id, proc_id, evt.event_id))
        if proc_id and user_id and proc_id in nodes and user_id in nodes:
            edges.append(_edge("ran_by", proc_id, user_id, evt.event_id))
        if parent_cmd_id and cmd_id and parent_cmd_id in nodes and cmd_id in nodes:
            edges.append(_edge("child_of", cmd_id, parent_cmd_id, evt.event_id))

        # File touched
        if evt.file and evt.file.path:
            fid = _hash_id("file",
                _canonicalise("file", evt.file.path))
            if fid in nodes and proc_id and proc_id in nodes:
                edges.append(_edge("touched", proc_id, fid, evt.event_id))
        # Network
        if evt.network:
            if evt.network.url:
                uid = _hash_id("url",
                    _canonicalise("url", evt.network.url))
                if uid in nodes and proc_id and proc_id in nodes:
                    edges.append(_edge("connected_to", proc_id, uid,
                                        evt.event_id))
            elif evt.network.dst_ip:
                ipid = _hash_id("ip",
                    _canonicalise("ip", evt.network.dst_ip))
                if ipid in nodes and proc_id and proc_id in nodes:
                    edges.append(_edge("connected_to", proc_id, ipid,
                                        evt.event_id))
            if evt.network.domain:
                did = _hash_id("url",
                    _canonicalise("url", evt.network.domain))
                if did in nodes and proc_id and proc_id in nodes:
                    edges.append(_edge("resolved_to", proc_id, did,
                                        evt.event_id))
        # DNS
        if evt.dns and evt.dns.query:
            dnsid = _hash_id("dns",
                _canonicalise("dns", evt.dns.query))
            if dnsid in nodes and proc_id and proc_id in nodes:
                edges.append(_edge("resolved_to", proc_id, dnsid,
                                    evt.event_id))
        # Detection
        if evt.detection and evt.detection.name:
            det_id = _hash_id("detection",
                _canonicalise("detection", evt.detection.name))
            if det_id in nodes and proc_id and proc_id in nodes:
                edges.append(_edge("flagged", det_id, proc_id, evt.event_id))
            if det_id in nodes and host_id and host_id in nodes:
                edges.append(_edge("flagged", det_id, host_id, evt.event_id))

    # Decoded payload edges: parent_event → decoded_payload
    for ev in evidence.items:
        if ev.kind != "decoded_payload":
            continue
        dp_id = _hash_id("decoded_payload",
            _canonicalise("decoded_payload", ev.value))
        for eid in ev.event_ids:
            # find command node associated with same event
            cmd_hits = [n for n in nodes.values()
                         if n.kind == "command" and eid in n.evidence_refs]
            for cmd in cmd_hits:
                edges.append(_edge("decoded_to", cmd.id, dp_id, eid))

    # Hash → process/file linkage
    for ev in evidence.items:
        if ev.kind != "hash":
            continue
        h_id = _hash_id("hash", _canonicalise("hash", ev.value))
        for eid in ev.event_ids:
            for n in nodes.values():
                if n.kind in ("process", "file") and eid in n.evidence_refs:
                    edges.append(_edge("has_ioc", n.id, h_id, eid))

    # De-duplicate edges by (relation, from, to, event)
    edges = _dedup_edges(edges)

    return InvestigationGraph(
        nodes=tuple(nodes.values()),
        edges=tuple(edges),
    )


def _canonicalise(kind: str, value: str) -> str:
    if kind in ("hash", "ip", "domain", "url", "dns", "host", "user"):
        return value.strip().lower()
    return value.strip()[:200]


def _label_for(kind: str, ev: EvidenceItem) -> str:
    v = ev.value
    if len(v) > 80:
        v = v[:77] + "…"
    return f"{kind.upper()} · {v}"


def _edge(relation: str, from_id: str, to_id: str,
          event_id: Optional[str]) -> GraphEdge:
    eid = _hash_id("e", relation, from_id, to_id, event_id or "")
    return GraphEdge(
        id=eid,
        from_id=from_id,
        to_id=to_id,
        relation=relation,
        evidence_refs=tuple([event_id]) if event_id else tuple(),
    )


def _dedup_edges(edges: List[GraphEdge]) -> List[GraphEdge]:
    seen: Dict[str, GraphEdge] = {}
    for e in edges:
        key = f"{e.relation}::{e.from_id}::{e.to_id}"
        prev = seen.get(key)
        if prev is None:
            seen[key] = e
        else:
            merged_refs = tuple(sorted(set(prev.evidence_refs)
                                        | set(e.evidence_refs)))
            seen[key] = GraphEdge(
                id=prev.id, from_id=prev.from_id, to_id=prev.to_id,
                relation=prev.relation, attrs=prev.attrs,
                evidence_refs=merged_refs,
                confidence=max(prev.confidence, e.confidence),
            )
    return list(seen.values())


__all__ = [
    "NODE_KINDS", "EDGE_RELATIONS",
    "GraphNode", "GraphEdge", "InvestigationGraph", "build",
]
