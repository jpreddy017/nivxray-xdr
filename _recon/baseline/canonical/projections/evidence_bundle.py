"""project_evidence_bundle — canonical EvidenceBundle shape (SSOT-E).

Backwards-compat projection into the L4 analyst workspace's evidence
bundle format. Pure fn.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..ssot import AuthoritativeSSOT


def project_evidence_bundle(ssot: AuthoritativeSSOT) -> Dict[str, Any]:
    """Return the canonical evidence bundle.

    Shape: mirrors the L4 workspace expectation but is populated from
    the authoritative SSOT ONLY.
    """
    nodes: List[Dict[str, Any]] = []
    for n in ssot.evidence_graph.nodes:
        nodes.append({
            "id": n.id,
            "kind": n.kind,
            "label": n.label,
            "attrs": dict(n.attrs),
            "provenance": _prov_dict(n.provenance),
        })

    edges: List[Dict[str, Any]] = []
    for e in ssot.evidence_graph.edges:
        edges.append({
            "id": e.id,
            "from": e.from_node_id,
            "to": e.to_node_id,
            "kind": e.kind,
            "attrs": dict(e.attrs),
            "provenance": _prov_dict(e.provenance),
        })

    reasoning: List[Dict[str, Any]] = []
    for r in ssot.reasoning_steps:
        reasoning.append({
            "id": r.id,
            "rule": r.rule,
            "rationale": r.rationale,
            "input_evidence_ids": list(r.input_evidence_ids),
            "output_evidence_ids": list(r.output_evidence_ids),
            "provenance": _prov_dict(r.provenance),
        })

    artifacts: List[Dict[str, Any]] = []
    for a in ssot.artifacts:
        artifacts.append({
            "id": a.id,
            "kind": a.kind,
            "label": a.label,
            "parent_evidence_id": a.parent_evidence_id,
            "investigation_ref": a.investigation_ref,
            "attrs": dict(a.attrs),
            "provenance": _prov_dict(a.provenance),
        })

    return {
        "schema": "canonical.projection.evidence_bundle/1.0.0-phase4",
        "ssot_id": ssot.id,
        "fingerprint": ssot.fingerprint(),
        "nodes": nodes,
        "edges": edges,
        "reasoning_steps": reasoning,
        "artifacts": artifacts,
    }


def _prov_dict(p) -> Any:
    if p is None:
        return None
    return {
        "engine": p.engine,
        "version": p.version,
        "at": p.at,
        "upstream_evidence_ids": list(p.upstream_evidence_ids),
    }
