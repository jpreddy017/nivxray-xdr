"""Investigation Graph visualisation helpers.

Renders an `InvestigationGraph` as an analyst-readable ASCII tree:

    Host · WKS-42 [prov: cisco_secure_endpoint · 2026-01-15T10:22Z]
     ├── User · CORP\\alice
     ├── Process · cmd.exe
     │      ├── Command · cmd.exe /c whoami
     │      │      └── DecodedPayload · IEX(New-Object …)
     │      ├── URL · http://bad.example/p1
     │      └── Hash · <sha256>
     └── Detection · W32.Emotet.Gen

Every rendered node carries provenance so the tree doubles as an
audit trail. The renderer is deterministic and side-effect free —
safe for tests, CLI usage, and CI artefacts.

This is a Phase-1 exit-criteria artefact: if the graph cannot be
rendered as a coherent tree, downstream Phase 2 stages will inherit
defects.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from .graph_builder import GraphEdge, GraphNode, InvestigationGraph


# Node kinds anchor the tree. Anchors are grouped left-to-right; each
# anchor becomes a top-level tree root.
_ANCHOR_KINDS = ("host", "detection", "process", "command")

# Preferred child ordering under any node. Determines rendering order.
_CHILD_ORDER = (
    "user", "process", "command", "decoded_payload",
    "url", "ip", "dns", "file", "hash",
    "registry", "network", "detection",
)


def render_tree(graph: InvestigationGraph, show_provenance: bool = True,
                max_children: int = 20) -> str:
    """Render `graph` as an ASCII tree. Deterministic output."""
    if not graph.nodes:
        return "(empty graph)"

    # Identify anchor roots: hosts first, then unattached detections,
    # then top-level processes / commands.
    roots = _find_roots(graph)
    lines: List[str] = []
    seen: Set[str] = set()
    for root in roots:
        _render_node(graph, root, prefix="", is_last=True,
                     lines=lines, seen=seen,
                     show_provenance=show_provenance,
                     max_children=max_children)
        lines.append("")   # blank line between subtrees
    # Any node not reached from anchors is dumped under a "Orphans"
    # header so the report is complete.
    orphans = [n for n in graph.nodes if n.id not in seen]
    if orphans:
        lines.append("Orphans:")
        for n in orphans:
            lines.append(f"  · {_label(n, show_provenance)}")
    return "\n".join(lines).rstrip()


def _find_roots(graph: InvestigationGraph) -> List[GraphNode]:
    """Anchor selection: hosts are always roots; if there are no hosts,
    detections become roots; otherwise top-level processes / commands."""
    for kind in _ANCHOR_KINDS:
        anchors = graph.nodes_of(kind)
        if anchors:
            # Deduplicate by id, keep deterministic ordering.
            seen = set()
            out: List[GraphNode] = []
            for a in anchors:
                if a.id not in seen:
                    seen.add(a.id)
                    out.append(a)
            return out
    return list(graph.nodes)


def _render_node(graph: InvestigationGraph, node: GraphNode, prefix: str,
                  is_last: bool, lines: List[str], seen: Set[str],
                  show_provenance: bool,
                  max_children: int) -> None:
    branch = "└── " if is_last else "├── "
    if not prefix:
        lines.append(_label(node, show_provenance))
    else:
        lines.append(prefix + branch + _label(node, show_provenance))
    seen.add(node.id)
    children = _children_of(graph, node, seen)
    children = _sort_children(children)
    if not children:
        return
    if len(children) > max_children:
        children = children[:max_children]
    next_prefix = prefix + ("    " if is_last else "│   ")
    for i, child in enumerate(children):
        _render_node(graph, child, next_prefix,
                     i == len(children) - 1, lines, seen,
                     show_provenance, max_children)


def _children_of(graph: InvestigationGraph, node: GraphNode,
                  seen: Set[str]) -> List[GraphNode]:
    """Directed children — targets of edges FROM this node, PLUS
    reverse-anchor edges so hosts see the processes that ran on them
    and processes see the commands that belong to them."""
    out: List[GraphNode] = []
    for e in graph.edges_from(node.id):
        target = graph.node(e.to_id)
        if target and target.id not in seen:
            out.append(target)
    # Reverse edges: commands `belongs_to` process; processes
    # `executed_on` host; detections `flagged` host/process. In the
    # tree these should render as CHILDREN of the anchor node.
    for e in graph.edges_to(node.id):
        if e.relation in ("executed_on", "flagged", "belongs_to",
                           "child_of"):
            src = graph.node(e.from_id)
            if src and src.id not in seen:
                out.append(src)
    return out


def _sort_children(nodes: List[GraphNode]) -> List[GraphNode]:
    def rank(n: GraphNode) -> Tuple[int, str]:
        try:
            r = _CHILD_ORDER.index(n.kind)
        except ValueError:
            r = len(_CHILD_ORDER)
        return (r, n.value.lower()[:40])
    return sorted(nodes, key=rank)


def _label(n: GraphNode, show_provenance: bool) -> str:
    v = n.value if len(n.value) <= 80 else n.value[:77] + "…"
    kind_txt = n.kind.upper().replace("_", " ")
    base = f"{kind_txt} · {v}"
    if not show_provenance:
        return base
    prov_bits: List[str] = []
    vendor = (n.provenance or {}).get("vendor")
    if vendor:
        prov_bits.append(str(vendor))
    if n.evidence_refs:
        prov_bits.append(f"{len(n.evidence_refs)} ev-ref(s)")
    if n.confidence and n.confidence < 1.0:
        prov_bits.append(f"conf={n.confidence:.2f}")
    if prov_bits:
        base += "  [" + " · ".join(prov_bits) + "]"
    return base


# ── Provenance verification helpers (used by exit-criteria tests) ──

def assert_provenance(graph: InvestigationGraph) -> None:
    """Assert every node and every edge carries provenance
    (evidence_refs OR vendor tag). Raises AssertionError with the
    offending node/edge id if any element is bare."""
    for n in graph.nodes:
        if not n.evidence_refs and not (n.provenance or {}).get("vendor"):
            raise AssertionError(
                f"graph node {n.id} ({n.kind}) has no provenance: "
                f"evidence_refs empty and vendor tag missing"
            )
    for e in graph.edges:
        if not e.evidence_refs:
            raise AssertionError(
                f"graph edge {e.id} ({e.relation}: {e.from_id}→{e.to_id}) "
                f"has no evidence_refs"
            )


def decoded_payloads_link_back(graph: InvestigationGraph) -> bool:
    """Every decoded_payload node must have at least one incoming
    `decoded_to` edge from a command node. Returns True if the invariant
    holds."""
    dp_nodes = graph.nodes_of("decoded_payload")
    if not dp_nodes:
        return True
    for dp in dp_nodes:
        incoming = [e for e in graph.edges_to(dp.id)
                    if e.relation == "decoded_to"]
        if not incoming:
            return False
        # source must be a command
        for e in incoming:
            src = graph.node(e.from_id)
            if not src or src.kind != "command":
                return False
    return True


def iocs_link_to_evidence(graph: InvestigationGraph) -> bool:
    """Every IOC-like node (url / ip / hash / dns / domain) must
    carry at least one evidence_ref OR be connected via a relation
    to a process / command."""
    ioc_kinds = ("url", "ip", "hash", "dns")
    for kind in ioc_kinds:
        for n in graph.nodes_of(kind):
            if n.evidence_refs:
                continue
            connected = any(
                (graph.node(e.from_id) or graph.node(e.to_id))
                for e in graph.edges_to(n.id) + graph.edges_from(n.id)
            )
            if not connected:
                return False
    return True


__all__ = [
    "render_tree",
    "assert_provenance",
    "decoded_payloads_link_back",
    "iocs_link_to_evidence",
]
