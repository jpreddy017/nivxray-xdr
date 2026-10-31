"""R28.9 · Provenance Graph API — the "truth graph" of every
investigation.

Pure DERIVATION.  Consumes ``OrchestratorResult`` (which already
tracks parent_uri, discovered_by, ledger, evidence links) and emits
a structured graph with topology + chains ready for:

    · Explainability   ("this IOC originated from this exact chain")
    · Debugging        (diff two runs at graph-topology level)
    · Regression       (assert graph equivalence across releases)
    · Analyst UI       (Incident Graph · Attack Story lineage)

DESIGN INVARIANT — this file writes ZERO new state.  Every field of
every node / edge / chain must be derivable from what the
orchestrator already records.  If a field cannot be derived, the
missing tracking belongs in the orchestrator, not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════
# Graph primitives
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class ProvenanceNode:
    """A single artifact + its situational metadata inside the graph.

    Every field is derived from ``Artifact`` + ``Ledger`` — see
    ``build_provenance_graph`` below."""
    uri:            str
    artifact_type:  str
    depth:          int
    size:           int
    discovered_by:  str
    state:          Optional[str]     = None
    is_root:        bool              = False
    is_terminal:    bool              = False
    confidence:     Optional[float]   = None
    meta:           Dict[str, Any]    = field(default_factory=dict)


@dataclass(frozen=True)
class ProvenanceEdge:
    """A directed edge parent → child.

    ``via_capability`` names the Capability whose ``child_artifacts``
    list included this child.  ``evidence_ids`` links to every piece
    of ``Evidence`` produced by that capability execution — so an
    edge answers "*why* was this child created?"."""
    parent_uri:      str
    child_uri:       str
    via_capability:  str
    evidence_ids:    List[str]        = field(default_factory=list)
    confidence:      Optional[float]  = None


@dataclass(frozen=True)
class ProvenanceChain:
    """A root → terminal path through the graph.

    Used by Attack Story rendering ("root → PowerShell → gzip → XOR
    loop → shellcode → IOC 149.28.81.19") and by the analyst-visible
    "why this IOC" explanation."""
    node_uris:      List[str]         = field(default_factory=list)
    capabilities:   List[str]         = field(default_factory=list)
    terminal_kind:  Optional[str]     = None
    length:         int               = 0


@dataclass(frozen=True)
class ProvenanceGraph:
    """The complete provenance graph for one investigation.

    Equality-comparable by ``topology_signature()`` — see the
    regression harness ``assert_graphs_equivalent`` at the bottom of
    this module.
    """
    nodes:   List[ProvenanceNode]     = field(default_factory=list)
    edges:   List[ProvenanceEdge]     = field(default_factory=list)
    chains:  List[ProvenanceChain]    = field(default_factory=list)

    def topology_signature(self) -> Dict[str, Any]:
        """Return a stable, order-independent structural fingerprint.

        Two investigations with the same topology but different URIs
        (URIs are content-hashed and can drift between runs even for
        equivalent artifacts) still compare equal via this signature."""
        # Nodes signed by (type, depth, discovered_by) so URI churn
        # doesn't cause false negatives.
        node_sig = sorted(
            (n.artifact_type, n.depth, n.discovered_by,
             n.is_root, n.is_terminal)
            for n in self.nodes
        )
        # Edges signed by (parent_type, child_type, via_capability).
        uri_to_type = {n.uri: n.artifact_type for n in self.nodes}
        edge_sig = sorted(
            (uri_to_type.get(e.parent_uri, "?"),
             uri_to_type.get(e.child_uri,  "?"),
             e.via_capability)
            for e in self.edges
        )
        chain_sig = sorted(
            tuple(c.capabilities) + (c.terminal_kind or "",)
            for c in self.chains
        )
        return {
            "node_count":   len(self.nodes),
            "edge_count":   len(self.edges),
            "chain_count":  len(self.chains),
            "nodes":        node_sig,
            "edges":        edge_sig,
            "chains":       chain_sig,
        }


# ══════════════════════════════════════════════════════════════════
# Builder
# ══════════════════════════════════════════════════════════════════
def build_provenance_graph(orchestrator_result) -> ProvenanceGraph:
    """Derive a ``ProvenanceGraph`` from an ``OrchestratorResult``.

    Pure function — no side effects.  All information comes from
    ``result.artifacts``, ``result.states``, ``result.ledger`` and
    ``result.evidence`` — fields the orchestrator already populates
    for every run.
    """
    artifacts   = getattr(orchestrator_result, "artifacts",  {}) or {}
    states      = getattr(orchestrator_result, "states",     {}) or {}
    ledger      = getattr(orchestrator_result, "ledger",     None)
    evidence    = getattr(orchestrator_result, "evidence",   []) or []
    termcert    = getattr(orchestrator_result,
                            "termination_certificate", None)
    terminal_uris = set()
    if termcert is not None:
        terminal_uris.update(getattr(termcert, "terminal_uris", []) or [])

    # ── Nodes ────────────────────────────────────────────────────
    # Root = the artifact with parent_uri None AND depth 0.  Multiple
    # roots are legitimate (adapters may emit several primary
    # artifacts) — flag them all.
    ev_by_uri: Dict[str, List[Any]] = {}
    for e in evidence:
        uri = getattr(e, "artifact_uri", None)
        if uri:
            ev_by_uri.setdefault(uri, []).append(e)

    nodes: List[ProvenanceNode] = []
    for uri, a in artifacts.items():
        ev_list = ev_by_uri.get(uri, [])
        best_conf = max((getattr(e, "confidence", 0.0) or 0.0
                           for e in ev_list),
                          default=None)
        nodes.append(ProvenanceNode(
            uri            = uri,
            artifact_type  = getattr(a, "artifact_type", "unknown"),
            depth          = getattr(a, "depth", 0),
            size           = getattr(a, "size", 0),
            discovered_by  = getattr(a, "discovered_by", "unknown"),
            state          = states.get(uri),
            is_root        = (getattr(a, "parent_uri", None) is None),
            is_terminal    = uri in terminal_uris,
            confidence     = best_conf,
            meta           = dict(getattr(a, "meta", {}) or {}),
        ))

    # ── Edges  (from ledger + parent links) ──────────────────────
    # Ledger has action=='enqueue' entries recording (parent_uri,
    # child_uri, actor).  When ledger tracking is unavailable we
    # fall back to parent_uri-only edges keyed by discovered_by.
    edges: List[ProvenanceEdge] = []
    seen = set()

    entries = list(getattr(ledger, "entries", []) or []) if ledger else []
    for ent in entries:
        action = getattr(ent, "action", "")
        actor  = getattr(ent, "actor",  "")
        parent = getattr(ent, "artifact_uri", None)
        # ledger.append(child_uris=[...]) — capability execution edges.
        child_uris = getattr(ent, "children_uris", None) or \
                      getattr(ent, "child_uris", None) or []
        if not child_uris:
            continue
        conf = getattr(ent, "confidence", None)
        ev_ids = list(getattr(ent, "evidence_ids", []) or [])
        for c in child_uris:
            key = (parent, c, actor)
            if key in seen:
                continue
            seen.add(key)
            edges.append(ProvenanceEdge(
                parent_uri      = parent or "",
                child_uri       = c,
                via_capability  = actor or "unknown",
                evidence_ids    = ev_ids,
                confidence      = conf,
            ))

    # Fallback — cover children whose lineage wasn't in the ledger
    # (defensive; the orchestrator normally records everything).
    for uri, a in artifacts.items():
        parent = getattr(a, "parent_uri", None)
        if not parent:
            continue
        key = (parent, uri, getattr(a, "discovered_by", "unknown"))
        if key in seen:
            continue
        seen.add(key)
        edges.append(ProvenanceEdge(
            parent_uri     = parent,
            child_uri      = uri,
            via_capability = getattr(a, "discovered_by", "unknown"),
        ))

    # ── Chains — every root → terminal path ─────────────────────
    child_index: Dict[str, List[ProvenanceEdge]] = {}
    for e in edges:
        child_index.setdefault(e.parent_uri, []).append(e)
    uri_to_node = {n.uri: n for n in nodes}
    chains: List[ProvenanceChain] = []
    roots = [n for n in nodes if n.is_root]

    def _walk(uri: str, path_uris: List[str],
                 path_caps: List[str], seen_on_path: set) -> None:
        outs = child_index.get(uri, [])
        # Terminal reached — either explicitly flagged terminal or a
        # leaf (no outgoing edges).
        node = uri_to_node.get(uri)
        if not outs:
            if node is not None:
                chains.append(ProvenanceChain(
                    node_uris      = list(path_uris),
                    capabilities   = list(path_caps),
                    terminal_kind  = node.artifact_type,
                    length         = len(path_uris),
                ))
            return
        for edge in outs:
            if edge.child_uri in seen_on_path:  # cycle guard
                continue
            seen_on_path.add(edge.child_uri)
            _walk(edge.child_uri,
                    path_uris + [edge.child_uri],
                    path_caps + [edge.via_capability],
                    seen_on_path)
            seen_on_path.discard(edge.child_uri)

    for root in roots:
        _walk(root.uri, [root.uri], [], {root.uri})

    return ProvenanceGraph(nodes=nodes, edges=edges, chains=chains)


# ══════════════════════════════════════════════════════════════════
# Regression harness — behavioural-equivalence gate
# ══════════════════════════════════════════════════════════════════
def assert_graphs_equivalent(expected: ProvenanceGraph,
                                 actual:   ProvenanceGraph,
                                 *, msg: str = "") -> None:
    """Fail the caller (raise AssertionError) if two graphs differ
    at the topology level.

    Ignores URIs (content-hashed, may drift) and evidence IDs (also
    hashed).  Compares:
        · node counts + (type, depth, discovered_by) tuples
        · edge counts + (parent_type, child_type, capability) tuples
        · chain counts + capability sequences + terminal kinds

    Used by Phase-A migration regression tests to prove legacy →
    UAIE capability migrations preserve behaviour.
    """
    exp = expected.topology_signature()
    got = actual.topology_signature()
    if exp == got:
        return
    diff_lines = []
    for k in ("node_count", "edge_count", "chain_count"):
        if exp[k] != got[k]:
            diff_lines.append(f"  {k}: expected={exp[k]}  actual={got[k]}")
    if exp["nodes"] != got["nodes"]:
        missing = set(map(tuple, exp["nodes"])) - set(map(tuple, got["nodes"]))
        extra   = set(map(tuple, got["nodes"])) - set(map(tuple, exp["nodes"]))
        if missing:
            diff_lines.append(f"  missing nodes: {sorted(missing)}")
        if extra:
            diff_lines.append(f"  extra nodes:   {sorted(extra)}")
    if exp["edges"] != got["edges"]:
        missing = set(map(tuple, exp["edges"])) - set(map(tuple, got["edges"]))
        extra   = set(map(tuple, got["edges"])) - set(map(tuple, exp["edges"]))
        if missing:
            diff_lines.append(f"  missing edges: {sorted(missing)}")
        if extra:
            diff_lines.append(f"  extra edges:   {sorted(extra)}")
    header = f"Provenance graphs differ{': ' + msg if msg else ''}"
    raise AssertionError(header + "\n" + "\n".join(diff_lines))


__all__ = [
    "ProvenanceNode", "ProvenanceEdge", "ProvenanceChain",
    "ProvenanceGraph", "build_provenance_graph",
    "assert_graphs_equivalent",
]
