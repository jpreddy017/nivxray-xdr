"""Phase 11.3 · Correlation Engine — Feb 2026.

Observational side-car analysis over an already-built EvidenceGraph.
Zero verdict / scoring influence: the engine only DESCRIBES relationships
between existing evidence nodes. It NEVER adds nodes to the graph and
NEVER mutates the ExecGraph or the analyst-facing verdict.

Three deterministic reasoners live here:

    1. TemporalReasoner        — orders evidence nodes by their originating
                                 ExecGraph position and reports the chain.
    2. DependencyChainReasoner — walks explicit ``derives_from`` / observed
                                 source_node_ids to surface multi-step
                                 attack chains.
    3. ContradictionReasoner   — flags evidence that structurally
                                 contradicts other evidence in the same
                                 graph (e.g. a node classified both as
                                 ``ipv4`` and as ``software_version``).

Determinism: given the same EvidenceGraph, calling ``correlate(g)`` twice
returns byte-identical output. This is enforced by a unit test in
``test_correlation_engine.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Tuple

from engine.evidence_graph import EvidenceGraph, EvidenceNode


# ─── Public payloads (immutable) ─────────────────────────────────────
@dataclass(frozen=True)
class TemporalSpan:
    """A single temporally-ordered chain fragment."""
    node_ids: Tuple[str, ...]
    length: int
    kind_sequence: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "node_ids":      list(self.node_ids),
            "length":        self.length,
            "kind_sequence": list(self.kind_sequence),
        }


@dataclass(frozen=True)
class DependencyChain:
    """A rooted derives_from chain leading up to a leaf artefact."""
    root_id: str
    leaves: Tuple[str, ...]
    hops: int

    def to_dict(self) -> dict:
        return {"root_id": self.root_id, "leaves": list(self.leaves), "hops": self.hops}


@dataclass(frozen=True)
class Contradiction:
    """Two evidence facts about the SAME artefact that structurally clash."""
    node_id: str
    kind: str
    reasons: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {"node_id": self.node_id, "kind": self.kind, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class CorrelationReport:
    """Aggregate side-car output. ``to_dict()`` yields JSON-safe dict."""
    schema_version: int = 1
    temporal_spans: Tuple[TemporalSpan, ...] = ()
    dependency_chains: Tuple[DependencyChain, ...] = ()
    contradictions: Tuple[Contradiction, ...] = ()
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema_version":    self.schema_version,
            "temporal_spans":    [s.to_dict() for s in self.temporal_spans],
            "dependency_chains": [c.to_dict() for c in self.dependency_chains],
            "contradictions":    [x.to_dict() for x in self.contradictions],
            "stats":             dict(self.stats),
        }


# ─── Reasoners ───────────────────────────────────────────────────────
def _temporal_spans(graph: EvidenceGraph) -> Tuple[TemporalSpan, ...]:
    """Group nodes into contiguous chains ordered by first ``source_node_ids``.

    The ExecGraph produces monotonically-increasing node IDs, so the first
    entry in ``source_node_ids`` is a stable temporal anchor. Nodes with
    no sources are dropped from spans (they cannot be temporally located).
    """
    ordered = []
    for n in graph.nodes:
        if not n.source_node_ids:
            continue
        anchor = n.source_node_ids[0]
        ordered.append((anchor, n))
    ordered.sort(key=lambda t: (t[0], t[1].id))

    spans: List[TemporalSpan] = []
    if not ordered:
        return ()

    # Cluster into spans by shared prefix of the anchor id — this
    # captures the "same run" grouping deterministically.
    current: List[EvidenceNode] = []
    current_prefix: str | None = None
    def _prefix(anchor: str) -> str:
        return anchor.split(":", 1)[0] if ":" in anchor else anchor

    for anchor, node in ordered:
        p = _prefix(anchor)
        if current_prefix is None or p == current_prefix:
            current.append(node); current_prefix = p
        else:
            if len(current) >= 2:
                spans.append(TemporalSpan(
                    node_ids=tuple(x.id for x in current),
                    length=len(current),
                    kind_sequence=tuple(str(x.kind.value) if hasattr(x.kind, "value") else str(x.kind) for x in current),
                ))
            current = [node]; current_prefix = p
    if len(current) >= 2:
        spans.append(TemporalSpan(
            node_ids=tuple(x.id for x in current),
            length=len(current),
            kind_sequence=tuple(str(x.kind.value) if hasattr(x.kind, "value") else str(x.kind) for x in current),
        ))
    return tuple(spans)


def _dependency_chains(graph: EvidenceGraph) -> Tuple[DependencyChain, ...]:
    """Group leaves that all point back to a common root via source_node_ids."""
    roots: Dict[str, List[str]] = {}
    for n in graph.nodes:
        if not n.source_node_ids:
            continue
        root = n.source_node_ids[0]
        roots.setdefault(root, []).append(n.id)

    chains: List[DependencyChain] = []
    for root, leaves in sorted(roots.items()):
        if len(leaves) >= 2:
            chains.append(DependencyChain(
                root_id=root,
                leaves=tuple(sorted(leaves)),
                hops=len(leaves),
            ))
    return tuple(chains)


def _contradictions(graph: EvidenceGraph) -> Tuple[Contradiction, ...]:
    """Detect structurally impossible attribute pairs on the same node.

    Example: an IP evidence node whose entity-classifier attrs say the
    token is both a ``software_version`` AND a private-loopback IPv4.
    """
    out: List[Contradiction] = []
    for n in graph.nodes:
        reasons: List[str] = []
        attrs = n.attrs or {}

        kind = attrs.get("entity_kind")
        # Contradiction #1 — evidence node is stored as EvidenceNodeKind.ip
        # but the classifier explicitly says it is NOT an IPv4.
        if str(n.kind).endswith(".ip") or getattr(n.kind, "value", None) == "ip":
            if kind and kind not in ("ipv4", None):
                reasons.append(
                    f"routed to IP bucket yet classifier says '{kind}'"
                )

        # Contradiction #2 — two mutually-exclusive classifier verdicts
        # merged onto the same node via graph.add_node().
        other_kind = attrs.get("entity_kind_alt")
        if kind and other_kind and kind != other_kind:
            reasons.append(f"dual classification: {kind!r} vs {other_kind!r}")

        if reasons:
            out.append(Contradiction(
                node_id=n.id,
                kind=(getattr(n.kind, "value", None) or str(n.kind)),
                reasons=tuple(reasons),
            ))
    return tuple(out)


# ─── Public entry point ──────────────────────────────────────────────
def correlate(graph: EvidenceGraph) -> CorrelationReport:
    """Run all reasoners over ``graph`` and return the aggregate report.

    Pure function — no I/O, no globals, no verdict/scoring side-effects.
    Feed it a graph, get a JSON-serialisable report back.
    """
    temporal   = _temporal_spans(graph)
    chains     = _dependency_chains(graph)
    contras    = _contradictions(graph)
    stats = {
        "node_count":         len(graph.nodes),
        "edge_count":         len(graph.edges),
        "temporal_spans":     len(temporal),
        "dependency_chains":  len(chains),
        "contradictions":     len(contras),
    }
    return CorrelationReport(
        temporal_spans=temporal,
        dependency_chains=chains,
        contradictions=contras,
        stats=stats,
    )


__all__ = [
    "TemporalSpan",
    "DependencyChain",
    "Contradiction",
    "CorrelationReport",
    "correlate",
]
