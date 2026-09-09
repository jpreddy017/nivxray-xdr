"""ADR-0014 · Evidence Graph primitives.

Nodes and typed edges. The graph IS the investigation (§1.1 principle 2).

Design constraints:
    - Node ids MUST be unique within a CIO.
    - Every edge MUST reference existing nodes (no dangling edges).
    - Edge kinds are restricted to the enum below (§2 of ADR-0014).
    - Serialization is deterministic (nodes sorted by id, edges by
      (source, kind, target)) so that identical inputs produce
      byte-identical graphs.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


# ─── Typed enums (ADR-0014 §2) ──────────────────────────────────────────

NodeKind = Literal[
    "artifact",           # the raw input under investigation
    "decoded_fragment",   # one recovered layer
    "ioc",                # ip / domain / url / hash / email
    "mitre_technique",    # ATT&CK id
    "lolbin",             # living-off-the-land binary
    "family_match",       # threat family / labelled tradecraft
    "behaviour",          # observed behaviour (e.g. "signed-binary proxy")
    "reasoning_step",     # ReasoningStep record (Slice-B populates)
    "verdict",            # final verdict node (single per CIO)
]

EdgeKind = Literal[
    "produces",           # decoder produces fragment / fragment produces IOC
    "contributes_to",     # evidence contributes to verdict / assessment
    "contradicts",        # evidence contradicts another node
    "supports",           # evidence supports another node
    "derived_from",       # child fragment derived from parent
    "references",         # cross-reference (e.g. behaviour references mitre_technique)
    "escalates_to",       # confidence/severity escalation link
]


# ─── Node ───────────────────────────────────────────────────────────────

class Node(BaseModel):
    """A single node in the Evidence Graph."""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique node id within the CIO, e.g. 'N-001'.")
    kind: NodeKind
    label: str = Field(..., description="Analyst-facing label (short, humanised).")
    value: Optional[str] = Field(default=None, description="Canonical value (IOC value, technique id, LOLBIN name, etc).")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Node confidence 0..1.")
    provenance: str = Field(default="", description="Producer tag (e.g. 'decoder:base64', 'extractor:ioc', 'rule:command_analyzer').")
    attrs: Dict[str, Any] = Field(default_factory=dict, description="Kind-specific attributes (kept small).")


# ─── Edge ───────────────────────────────────────────────────────────────

class Edge(BaseModel):
    """A directed, typed edge in the Evidence Graph."""
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., description="Source node id.")
    target: str = Field(..., description="Target node id.")
    kind: EdgeKind
    weight: float = Field(default=1.0, ge=0.0, le=1.0, description="Edge weight 0..1 (contribution strength).")


# ─── EvidenceGraph ──────────────────────────────────────────────────────

class EvidenceGraph(BaseModel):
    """The Evidence Graph — nodes + typed edges = the investigation."""
    model_config = ConfigDict(extra="forbid")

    nodes: List[Node] = Field(default_factory=list)
    edges: List[Edge] = Field(default_factory=list)

    # ── deterministic construction helpers ────────────────────────────

    def add_node(self, node: Node) -> Node:
        """Add a node; raises ValueError if id already exists."""
        if any(n.id == node.id for n in self.nodes):
            raise ValueError(f"Node id already exists: {node.id}")
        self.nodes.append(node)
        return node

    def add_edge(self, edge: Edge) -> Edge:
        """Add an edge; raises ValueError if endpoints do not exist."""
        ids = {n.id for n in self.nodes}
        if edge.source not in ids:
            raise ValueError(f"Dangling edge source: {edge.source}")
        if edge.target not in ids:
            raise ValueError(f"Dangling edge target: {edge.target}")
        self.edges.append(edge)
        return edge

    # ── read-only projections ─────────────────────────────────────────

    def nodes_by_kind(self, kind: NodeKind) -> List[Node]:
        return [n for n in self.nodes if n.kind == kind]

    def neighbours(self, node_id: str) -> List[str]:
        """All node ids reachable from `node_id` via any outgoing edge."""
        return [e.target for e in self.edges if e.source == node_id]

    def deterministic_serialize(self) -> Dict[str, Any]:
        """Return a dict with nodes sorted by id, edges sorted by (source, kind, target).

        Used by tests to assert byte-identical serialization for identical
        inputs (ADR-0014 §7.1 G2 gate).
        """
        nodes = sorted(self.nodes, key=lambda n: n.id)
        edges = sorted(self.edges, key=lambda e: (e.source, e.kind, e.target))
        return {
            "nodes": [n.model_dump(mode="json") for n in nodes],
            "edges": [e.model_dump(mode="json") for e in edges],
        }
