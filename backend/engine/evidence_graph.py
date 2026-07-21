"""RC5 · Phase 11.0 — Evidence Knowledge Graph (infrastructure only).

Status
------
**Side-car** data structure. Does NOT influence verdicts, MITRE mapping, or
analyst-visible output. `ExecGraph` remains the sole verdict-driving artifact.

Scope (Phase 11.0)
------------------
* Node model with 18 reserved kinds (see `EvidenceNodeKind`).
* Edge model with 19 reserved verbs (see `EvidenceEdgeKind`).
* Deterministic content-addressed IDs (`sha256(kind|canonical_key)[:16]`).
* Immutable, append-only graph container (mirrors `ExecGraph`'s discipline).
* JSON round-trip serialization.
* Graph-integrity validation (dangling edge references, cycle detection on
  the strict `dependsOn` / `derivedFrom` sub-graph).

Explicitly NOT in Phase 11.0
----------------------------
Correlation Engine · Negative Evidence · Dimensional Confidence · Rule
Dependency Engine · Verdict migration · Explainability migration. These
belong to Phases 11.3 – 11.6 and are only unlocked once the graph itself
is stable and complete (see `/app/memory/RC5_EVIDENCE_GRAPH_ROADMAP.md`).

Design principles
-----------------
1. **Deterministic**: identical input → identical node IDs → identical graph.
2. **Immutable**: `add_node` / `add_edge` return a *new* graph.
3. **Auditable**: every node carries `source_node_ids` linking it back to
   the `ExecNode`(s) that produced it. Zero orphans allowed post-build.
4. **Side-car**: schema evolves independently of `ExecGraph.SCHEMA_VERSION`.
"""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Schema version — independent of ExecGraph.SCHEMA_VERSION. Bump only on
# node-kind / edge-kind additions.
# ---------------------------------------------------------------------------
EVIDENCE_GRAPH_SCHEMA_VERSION: int = 1


# ---------------------------------------------------------------------------
# Node kinds — the 18 reserved entities from the roadmap.
# ---------------------------------------------------------------------------
class EvidenceNodeKind(str, Enum):
    process   = "Process"
    command   = "Command"
    script    = "Script"
    file      = "File"
    registry  = "Registry"
    network   = "Network"
    url       = "URL"
    ip        = "IP"
    domain    = "Domain"
    user      = "User"
    cred      = "Credential"
    token     = "Token"
    service   = "Service"
    task      = "Task"
    cert      = "Certificate"
    com       = "COM"
    pipe      = "Pipe"
    memobj    = "MemObj"


# ---------------------------------------------------------------------------
# Edge kinds — the 19 reserved relationships from the roadmap.
# ---------------------------------------------------------------------------
class EvidenceEdgeKind(str, Enum):
    executes      = "executes"
    creates       = "creates"
    reads         = "reads"
    writes        = "writes"
    downloads     = "downloads"
    uploads       = "uploads"
    injects       = "injects"
    spawns        = "spawns"
    contacts      = "contacts"
    persists      = "persists"
    uses          = "uses"
    loads         = "loads"
    reflects      = "reflects"
    encodes       = "encodes"
    decodes       = "decodes"
    decrypts      = "decrypts"
    depends_on    = "dependsOn"
    derived_from  = "derivedFrom"
    observed_via  = "observedVia"


# ---------------------------------------------------------------------------
# Canonical key computation (deterministic ID input).
# ---------------------------------------------------------------------------
def _canonical_key(kind: EvidenceNodeKind, key: Dict[str, Any]) -> str:
    """Produce a stable canonical string from a node's identifying key.

    Rules:
        * Keys sorted alphabetically.
        * Values coerced to string; whitespace stripped; case-folded for
          the fields we know are case-insensitive (domain, url-scheme, etc).
        * `None`, `""`, and missing keys are all treated as absent.
    """
    _CASEFOLD = {"domain", "host", "scheme", "extension"}
    clean: Dict[str, str] = {}
    for k in sorted(key.keys()):
        v = key[k]
        if v is None:
            continue
        s = str(v).strip()
        if s == "":
            continue
        if k in _CASEFOLD:
            s = s.casefold()
        clean[k] = s
    return kind.value + "|" + json.dumps(clean, sort_keys=True, separators=(",", ":"))


def compute_node_id(kind: EvidenceNodeKind, key: Dict[str, Any]) -> str:
    """Deterministic 16-hex-char content-addressed ID."""
    canon = _canonical_key(kind, key)
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]
    return f"eg_{digest}"


# ---------------------------------------------------------------------------
# EvidenceNode
# ---------------------------------------------------------------------------
class EvidenceNode(BaseModel):
    """A single entity observed in the reconstructed execution.

    Immutable. Never mutated post-construction. Content-addressed by
    `(kind, key)` so identical entities across the pipeline collapse to
    the same node — the graph is naturally deduplicated.

    Fields
    ------
    id
        Deterministic. Never manually set; always derived from
        `compute_node_id(kind, key)`.
    kind
        One of `EvidenceNodeKind` — 18 reserved values.
    key
        The identity-defining dict. Two nodes with the same
        `(kind, key)` MUST collapse to the same `id`.
        Kept small: for a `File`, `{"path": "C:/temp/x.dll"}`; for a
        `Domain`, `{"domain": "evil.example"}`.
    attrs
        Non-identity metadata (size, hash, hits, first_seen). Free-form
        but must be JSON-serialisable.
    source_node_ids
        `ExecNode.id` values that produced or observed this evidence.
        Zero-length only allowed for synthetic / root nodes — flagged by
        `validate_integrity()` if used incorrectly.
    schema_version
        Locked to `EVIDENCE_GRAPH_SCHEMA_VERSION`.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    kind: EvidenceNodeKind
    key: Dict[str, Any]
    attrs: Dict[str, Any] = Field(default_factory=dict)
    source_node_ids: Tuple[str, ...] = ()
    schema_version: int = EVIDENCE_GRAPH_SCHEMA_VERSION

    @field_validator("schema_version")
    @classmethod
    def _lock_schema(cls, v: int) -> int:
        if v != EVIDENCE_GRAPH_SCHEMA_VERSION:
            raise ValueError(
                f"EvidenceNode.schema_version {v} != "
                f"EVIDENCE_GRAPH_SCHEMA_VERSION {EVIDENCE_GRAPH_SCHEMA_VERSION}"
            )
        return v

    @field_validator("id")
    @classmethod
    def _id_prefix(cls, v: str) -> str:
        if not v.startswith("eg_") or len(v) != 19:
            raise ValueError(
                f"EvidenceNode.id must be 'eg_' + 16 hex chars, got {v!r}"
            )
        return v

    @classmethod
    def build(
        cls,
        kind: EvidenceNodeKind,
        key: Dict[str, Any],
        attrs: Optional[Dict[str, Any]] = None,
        source_node_ids: Tuple[str, ...] = (),
    ) -> "EvidenceNode":
        """Construct with a deterministic ID. Preferred over calling
        the constructor directly with a hand-crafted `id`."""
        return cls(
            id=compute_node_id(kind, key),
            kind=kind,
            key=dict(key),
            attrs=dict(attrs or {}),
            source_node_ids=tuple(source_node_ids),
        )


# ---------------------------------------------------------------------------
# EvidenceEdge
# ---------------------------------------------------------------------------
def compute_edge_id(src_id: str, kind: EvidenceEdgeKind, dst_id: str) -> str:
    """Deterministic edge ID from `(src, kind, dst)`."""
    canon = f"{src_id}|{kind.value}|{dst_id}"
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]
    return f"ee_{digest}"


class EvidenceEdge(BaseModel):
    """A directed, typed relationship between two `EvidenceNode`s.

    Immutable. Content-addressed by `(src, kind, dst)` so duplicate edges
    across the pipeline collapse to a single entry.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    src: str
    dst: str
    kind: EvidenceEdgeKind
    attrs: Dict[str, Any] = Field(default_factory=dict)
    source_node_ids: Tuple[str, ...] = ()
    schema_version: int = EVIDENCE_GRAPH_SCHEMA_VERSION

    @field_validator("schema_version")
    @classmethod
    def _lock_schema(cls, v: int) -> int:
        if v != EVIDENCE_GRAPH_SCHEMA_VERSION:
            raise ValueError(
                f"EvidenceEdge.schema_version {v} != "
                f"EVIDENCE_GRAPH_SCHEMA_VERSION {EVIDENCE_GRAPH_SCHEMA_VERSION}"
            )
        return v

    @field_validator("id")
    @classmethod
    def _id_prefix(cls, v: str) -> str:
        if not v.startswith("ee_") or len(v) != 19:
            raise ValueError(
                f"EvidenceEdge.id must be 'ee_' + 16 hex chars, got {v!r}"
            )
        return v

    @classmethod
    def build(
        cls,
        src_id: str,
        kind: EvidenceEdgeKind,
        dst_id: str,
        attrs: Optional[Dict[str, Any]] = None,
        source_node_ids: Tuple[str, ...] = (),
    ) -> "EvidenceEdge":
        return cls(
            id=compute_edge_id(src_id, kind, dst_id),
            src=src_id,
            dst=dst_id,
            kind=kind,
            attrs=dict(attrs or {}),
            source_node_ids=tuple(source_node_ids),
        )


# ---------------------------------------------------------------------------
# EvidenceGraph — immutable, append-only container.
# ---------------------------------------------------------------------------
class EvidenceGraph(BaseModel):
    """Immutable, deduplicated evidence graph.

    Nodes and edges are kept in insertion order and deduplicated by their
    deterministic IDs. Adding a duplicate is a no-op that returns the
    existing graph — this makes side-car construction from multiple
    detectors safe.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: Tuple[EvidenceNode, ...] = ()
    edges: Tuple[EvidenceEdge, ...] = ()
    schema_version: int = EVIDENCE_GRAPH_SCHEMA_VERSION

    # ------------------------------------------------------------------
    # Mutation-by-copy helpers
    # ------------------------------------------------------------------
    def add_node(self, node: EvidenceNode) -> "EvidenceGraph":
        """Return a graph with `node` merged in. Duplicate ID → no-op.

        Duplicate `(kind, key)` with different `attrs` MERGES `attrs` and
        UNIONs `source_node_ids`. This lets multiple detectors contribute
        observations about the same entity without race conditions.
        """
        existing = self._by_id(node.id)
        if existing is not None:
            if existing == node:
                return self
            merged_attrs = {**existing.attrs, **node.attrs}
            merged_sources = tuple(
                dict.fromkeys(existing.source_node_ids + node.source_node_ids)
            )
            merged = EvidenceNode(
                id=existing.id,
                kind=existing.kind,
                key=existing.key,
                attrs=merged_attrs,
                source_node_ids=merged_sources,
            )
            new_nodes = tuple(merged if n.id == existing.id else n for n in self.nodes)
            return EvidenceGraph(
                nodes=new_nodes, edges=self.edges, schema_version=self.schema_version
            )
        return EvidenceGraph(
            nodes=self.nodes + (node,),
            edges=self.edges,
            schema_version=self.schema_version,
        )

    def add_edge(self, edge: EvidenceEdge) -> "EvidenceGraph":
        """Return a graph with `edge` added. Duplicate ID → merge.

        Both endpoints MUST already exist in the graph — a dangling edge
        raises `ValueError`. This preserves the invariant checked by
        `validate_integrity()`.
        """
        if self._by_id(edge.src) is None:
            raise ValueError(
                f"add_edge: src node {edge.src!r} not present in graph"
            )
        if self._by_id(edge.dst) is None:
            raise ValueError(
                f"add_edge: dst node {edge.dst!r} not present in graph"
            )
        existing = self._edge_by_id(edge.id)
        if existing is not None:
            if existing == edge:
                return self
            merged_attrs = {**existing.attrs, **edge.attrs}
            merged_sources = tuple(
                dict.fromkeys(existing.source_node_ids + edge.source_node_ids)
            )
            merged = EvidenceEdge(
                id=existing.id,
                src=existing.src,
                dst=existing.dst,
                kind=existing.kind,
                attrs=merged_attrs,
                source_node_ids=merged_sources,
            )
            new_edges = tuple(merged if e.id == existing.id else e for e in self.edges)
            return EvidenceGraph(
                nodes=self.nodes, edges=new_edges, schema_version=self.schema_version
            )
        return EvidenceGraph(
            nodes=self.nodes,
            edges=self.edges + (edge,),
            schema_version=self.schema_version,
        )

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    def _by_id(self, node_id: str) -> Optional[EvidenceNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def _edge_by_id(self, edge_id: str) -> Optional[EvidenceEdge]:
        for e in self.edges:
            if e.id == edge_id:
                return e
        return None

    def find_node(self, node_id: str) -> Optional[EvidenceNode]:
        return self._by_id(node_id)

    def find_edge(self, edge_id: str) -> Optional[EvidenceEdge]:
        return self._edge_by_id(edge_id)

    def by_kind(self, kind: EvidenceNodeKind) -> List[EvidenceNode]:
        return [n for n in self.nodes if n.kind == kind]

    def edges_by_kind(self, kind: EvidenceEdgeKind) -> List[EvidenceEdge]:
        return [e for e in self.edges if e.kind == kind]

    def outbound(self, node_id: str) -> List[EvidenceEdge]:
        return [e for e in self.edges if e.src == node_id]

    def inbound(self, node_id: str) -> List[EvidenceEdge]:
        return [e for e in self.edges if e.dst == node_id]

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------
    def dangling_edges(self) -> List[str]:
        """Edge IDs whose src or dst does not resolve. Should always be empty
        (constructor prevents dangling), but exposed for CI verification."""
        known = {n.id for n in self.nodes}
        return [e.id for e in self.edges if e.src not in known or e.dst not in known]

    def cycles_in_derivation(self) -> List[List[str]]:
        """Return any cycles on the `dependsOn` + `derivedFrom` sub-graph.

        These two edge kinds MUST form a DAG — a cycle indicates a
        detector bug (something derived from itself). Other edge kinds
        (e.g. `contacts`, `executes`) are legitimately cyclic and are
        excluded from this check.
        """
        strict = {
            EvidenceEdgeKind.depends_on,
            EvidenceEdgeKind.derived_from,
        }
        adj: Dict[str, List[str]] = {n.id: [] for n in self.nodes}
        for e in self.edges:
            if e.kind in strict:
                adj[e.src].append(e.dst)

        WHITE, GREY, BLACK = 0, 1, 2
        color: Dict[str, int] = {n.id: WHITE for n in self.nodes}
        stack: List[str] = []
        cycles: List[List[str]] = []

        def _dfs(u: str) -> None:
            color[u] = GREY
            stack.append(u)
            for v in adj[u]:
                if color[v] == GREY:
                    idx = stack.index(v)
                    cycles.append(stack[idx:] + [v])
                elif color[v] == WHITE:
                    _dfs(v)
            stack.pop()
            color[u] = BLACK

        for nid in adj:
            if color[nid] == WHITE:
                _dfs(nid)
        return cycles

    def orphan_nodes(self) -> List[str]:
        """Node IDs with zero inbound and zero outbound edges.

        Orphans are allowed in Phase 11.0 because the graph is built
        incrementally — some detectors may register an entity before
        any relationship is known. `validate_integrity()` records them
        as `warning` only (returned in the error list with the
        `[warn]` prefix) so CI can track drift without failing.

        The synthetic `<root>` process is always excluded — it exists to
        anchor downstream evidence and is expected to sit alone when the
        ExecGraph is empty.
        """
        referenced: set[str] = set()
        for e in self.edges:
            referenced.add(e.src)
            referenced.add(e.dst)
        orphans: List[str] = []
        for n in self.nodes:
            if n.id in referenced:
                continue
            if n.kind == EvidenceNodeKind.process and n.key.get("image") == "<root>":
                continue
            orphans.append(n.id)
        return orphans

    def validate_integrity(self) -> List[str]:
        """Return a list of human-readable integrity errors. Empty list
        means the graph is well-formed. `[warn]` entries are advisory
        and do not fail CI on their own."""
        errors: List[str] = []
        for eid in self.dangling_edges():
            errors.append(f"dangling edge {eid}")
        for cyc in self.cycles_in_derivation():
            errors.append(
                "derivation cycle: " + " -> ".join(cyc)
            )
        # Verify content-addressing was respected — no hand-crafted IDs.
        for n in self.nodes:
            expected = compute_node_id(n.kind, n.key)
            if n.id != expected:
                errors.append(
                    f"node {n.id} does not match content-addressed id {expected}"
                )
        for e in self.edges:
            expected = compute_edge_id(e.src, e.kind, e.dst)
            if e.id != expected:
                errors.append(
                    f"edge {e.id} does not match content-addressed id {expected}"
                )
        # Orphans are warnings, not hard errors.
        for oid in self.orphan_nodes():
            errors.append(f"[warn] orphan node {oid}")
        return errors

    def has_hard_errors(self) -> bool:
        """True if `validate_integrity()` returned any non-warning entry."""
        return any(not e.startswith("[warn]") for e in self.validate_integrity())

    # ------------------------------------------------------------------
    # Serialization — deterministic JSON round-trip.
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "nodes": [n.model_dump(mode="json") for n in self.nodes],
            "edges": [e.model_dump(mode="json") for e in self.edges],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceGraph":
        return cls(
            schema_version=data.get("schema_version", EVIDENCE_GRAPH_SCHEMA_VERSION),
            nodes=tuple(EvidenceNode(**n) for n in data.get("nodes", [])),
            edges=tuple(EvidenceEdge(**e) for e in data.get("edges", [])),
        )

    @classmethod
    def from_json(cls, blob: str) -> "EvidenceGraph":
        return cls.from_dict(json.loads(blob))


# ---------------------------------------------------------------------------
# Public exports.
# ---------------------------------------------------------------------------
__all__ = [
    "EVIDENCE_GRAPH_SCHEMA_VERSION",
    "EvidenceNodeKind",
    "EvidenceEdgeKind",
    "EvidenceNode",
    "EvidenceEdge",
    "EvidenceGraph",
    "compute_node_id",
    "compute_edge_id",
]
