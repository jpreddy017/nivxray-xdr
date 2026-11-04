"""v2/investigation/ikg.py · Investigation Knowledge Graph — SSOT.

The Investigation Knowledge Graph (IKG) is the single source of truth for
every view in the NivXRay Enterprise Investigation Workspace. Every view —
Summary, Trajectory, Process Tree, Attack Story, Evidence Graph, Verdict,
ATT&CK, Threat Intelligence, Reports, Explainability — is a *projection*
or *traversal* of the same IKG. Nothing calculates its own truth.

Node model:
    process      · a process observed on the device
    file         · a file created / modified / deleted
    registry     · a registry key / value
    network      · a network endpoint / connection
    module       · a loaded DLL / driver
    service      · a Windows service
    task         · a scheduled task
    event        · a raw telemetry event (frame)
    technique    · a MITRE ATT&CK technique reference
    tactic       · a MITRE ATT&CK tactic reference
    verdict      · an aggregate verdict (event / process / chain / device / incident)
    device       · the device under investigation
    incident     · the incident this case represents

Edge model (verbs):
    created         a process created a file
    modified        a process modified a file / registry key
    deleted         a process deleted a file / registry key
    contacted       a process contacted a network endpoint
    loaded          a process loaded a module
    installed       a process installed a service / task
    spawned         a process spawned a child process (parent → child)
    executed_by     an event was executed by a process
    maps_to         a technique / event maps to a MITRE technique
    covers          a technique is under a tactic
    contributes_to  an event / process contributes to a verdict
    rollup_of       a verdict rolls up other verdicts (parent → child layer)
    hosted_on       everything ultimately anchors to the device
    part_of         the device is part of the incident
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


VALID_NODE_TYPES: frozenset[str] = frozenset({
    "process", "file", "registry", "network", "module", "service", "task",
    "event", "technique", "tactic", "verdict", "device", "incident",
})

VALID_EDGE_TYPES: frozenset[str] = frozenset({
    "created", "modified", "deleted", "contacted", "loaded", "installed",
    "spawned", "executed_by", "maps_to", "covers", "contributes_to",
    "rollup_of", "hosted_on", "part_of",
})


@dataclass
class Node:
    id: str                       # stable IID (content-addressed where possible)
    type: str                     # one of VALID_NODE_TYPES
    label: str                    # human-friendly display label
    attrs: dict[str, Any] = field(default_factory=dict)   # type-specific attributes

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "label": self.label,
                "attrs": self.attrs}


@dataclass
class Edge:
    source: str                   # source node id
    target: str                   # target node id
    type: str                     # one of VALID_EDGE_TYPES
    attrs: dict[str, Any] = field(default_factory=dict)   # timestamp, count, etc.

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target,
                "type": self.type, "attrs": self.attrs}


@dataclass
class InvestigationKnowledgeGraph:
    """The IKG for a single case. Ordered, deterministic, deduplicated."""
    case_id: str
    nodes: dict[str, Node] = field(default_factory=dict)   # id → Node
    edges: list[Edge] = field(default_factory=list)
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set)

    # ─── Mutators ──────────────────────────────────────────────────

    def add_node(self, node: Node) -> Node:
        """Insert or upsert a node. Merges attrs on collision."""
        if node.type not in VALID_NODE_TYPES:
            raise ValueError(f"invalid node type: {node.type}")
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # Merge — new attrs override, existing preserved otherwise.
        merged = {**existing.attrs, **node.attrs}
        self.nodes[node.id] = Node(
            id=node.id, type=existing.type,
            label=node.label or existing.label, attrs=merged,
        )
        return self.nodes[node.id]

    def add_edge(self, source: str, target: str, edge_type: str,
                 attrs: dict[str, Any] | None = None) -> Edge | None:
        """Insert an edge if both endpoints exist. Deduped by (src, tgt, type)."""
        if edge_type not in VALID_EDGE_TYPES:
            raise ValueError(f"invalid edge type: {edge_type}")
        if source not in self.nodes or target not in self.nodes:
            return None
        key = (source, target, edge_type)
        if key in self._edge_keys:
            return None
        edge = Edge(source=source, target=target, type=edge_type,
                    attrs=attrs or {})
        self.edges.append(edge)
        self._edge_keys.add(key)
        return edge

    # ─── Queries ──────────────────────────────────────────────────

    def by_type(self, node_type: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.type == node_type]

    def out_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        return [e for e in self.edges
                if e.source == node_id and (edge_type is None or e.type == edge_type)]

    def in_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        return [e for e in self.edges
                if e.target == node_id and (edge_type is None or e.type == edge_type)]

    def neighbors(self, node_id: str, direction: str = "out") -> list[Node]:
        edges = self.out_edges(node_id) if direction == "out" else self.in_edges(node_id)
        seen: set[str] = set()
        out: list[Node] = []
        for e in edges:
            other = e.target if direction == "out" else e.source
            if other in seen:
                continue
            seen.add(other)
            n = self.nodes.get(other)
            if n:
                out.append(n)
        return out

    # ─── Stats ────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for n in self.nodes.values():
            type_counts[n.type] = type_counts.get(n.type, 0) + 1
        edge_counts: dict[str, int] = {}
        for e in self.edges:
            edge_counts[e.type] = edge_counts.get(e.type, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_node_type": type_counts,
            "by_edge_type": edge_counts,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "nodes":   [n.to_dict() for n in self.nodes.values()],
            "edges":   [e.to_dict() for e in self.edges],
            "stats":   self.stats(),
        }
