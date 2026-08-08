"""``/api/uaie/catalog`` — read-only Capability Catalog endpoint.

Phase A · exposes the machine-readable catalog collected by
``services.uaie.migration_gate.build_capability_catalog`` as a
relationship-rich REST resource.  Follows the user directive
(2026-02-04): "expose relationships, not just a flat list, so
consumers can derive dependency graphs / planner visualisation /
capability explorer / missing-plugin validation from ONE source
of truth."

No UI is wired to this endpoint yet — that is postponed until
after Slice 6 + Architecture Freeze per user directive.  The
endpoint itself is a stable public contract.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from fastapi import APIRouter

from services.uaie.migration_gate import build_capability_catalog

router = APIRouter(prefix="/uaie", tags=["uaie"])


def _build_dependency_graph(catalog: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Derive the ``produces → requires`` dependency graph from the
    catalog.  Every edge ``(cap_a, cap_b)`` means: ``cap_a`` produces
    an artifact type that ``cap_b`` requires.  This is the exact
    graph planner-optimisation, visualisation, and CI dependency
    validation consumers will read."""
    produces_of: Dict[str, Set[str]] = {}
    requires_of: Dict[str, Set[str]] = {}
    for cap_id, meta in catalog.items():
        produces_of[cap_id] = set(meta.get("produces") or [])
        requires_of[cap_id] = set(meta.get("requires") or [])

    # Build edges A → B iff A.produces ∩ B.requires  is non-empty
    edges: List[Dict[str, Any]] = []
    for a, a_prod in produces_of.items():
        if not a_prod:
            continue
        for b, b_req in requires_of.items():
            if a == b:
                continue
            shared = a_prod & b_req
            if shared:
                edges.append({
                    "from": a, "to": b,
                    "via_artifact_types": sorted(shared),
                })

    # Compute "orphans" — capabilities whose requires can never be
    # satisfied by anything else in the catalog (helpful for planner
    # sanity checks).  Wildcards ``*`` are always considered satisfiable.
    all_produced_types: Set[str] = set()
    for s in produces_of.values():
        all_produced_types |= s
    orphans: List[Dict[str, Any]] = []
    for cap_id, reqs in requires_of.items():
        if not reqs:
            continue
        if "*" in reqs:
            continue
        unsatisfied = sorted(reqs - all_produced_types)
        # Some inputs (``text``, ``bytes``, ``powershell``) come from
        # the root paste, not from another capability — treat these
        # as external roots and record them separately.
        if unsatisfied:
            orphans.append({"capability": cap_id,
                              "unsatisfied_requires": unsatisfied})
    return {
        "edges":   edges,
        "orphans": orphans,
    }


@router.get("/catalog")
def get_capability_catalog() -> Dict[str, Any]:
    """Return the full capability catalog + derived dependency graph.

    Response schema (STABLE — API consumers rely on this shape):

    ```
    {
      "count": int,
      "capabilities": {
        "<capability_id>": {
          "id":                str,
          "version":           str,
          "category":          str,
          "requires":          [str, ...],
          "optional_requires": [str, ...],
          "produces":          [str, ...],
          "consumes":          [str, ...],
          "improves":          [str, ...],
          "deterministic":     bool,
          "cost":              int,
          "priority_hint":     int,
          "description":       str,
          "contract_registered": bool
        },
        ...
      },
      "graph": {
        "edges":   [{"from": str, "to": str,
                       "via_artifact_types": [str, ...]}, ...],
        "orphans": [{"capability": str,
                       "unsatisfied_requires": [str, ...]}, ...]
      }
    }
    ```
    """
    catalog = build_capability_catalog()
    return {
        "count":        len(catalog),
        "capabilities": catalog,
        "graph":        _build_dependency_graph(catalog),
    }
