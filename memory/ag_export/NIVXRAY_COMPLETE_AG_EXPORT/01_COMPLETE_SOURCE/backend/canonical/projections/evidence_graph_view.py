"""project_evidence_graph_view — canonical evidence-graph rendering.

Read-only rendering of the evidence graph with derived indices.
Pure fn; byte_identity.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT


def project_evidence_graph_view(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Return an evidence-graph view with per-kind counts + adjacency.

    Shape:
      {
        "node_count": N, "edge_count": M,
        "kinds": {"ioc": k1, "mitre_technique": k2, ...},
        "adjacency": { node_id: [neighbour_id, ...], ... }
      }
    """
    kinds: Dict[str, int] = {}
    for n in ssot.evidence_graph.nodes:
        kinds[n.kind] = kinds.get(n.kind, 0) + 1

    adjacency: Dict[str, List[str]] = {}
    for e in ssot.evidence_graph.edges:
        adjacency.setdefault(e.from_node_id, []).append(e.to_node_id)
    # Deterministic ordering.
    for k in adjacency:
        adjacency[k] = sorted(adjacency[k])

    return {
        "schema": "canonical.projection.evidence_graph_view/1.0.0-phase4",
        "node_count": len(ssot.evidence_graph.nodes),
        "edge_count": len(ssot.evidence_graph.edges),
        "kinds": dict(sorted(kinds.items())),
        "adjacency": dict(sorted(adjacency.items())),
    }
