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

from fastapi import APIRouter, Response

from services.uaie.migration_gate import build_capability_catalog

router = APIRouter(prefix="/uaie", tags=["uaie"])


# ── Response schema version ────────────────────────────────────────
# Reserved now (per user directive, 2026-02-04) — bumping this is
# how the endpoint signals a breaking shape change to consumers.
# Additive fields do NOT bump the version.
CATALOG_SCHEMA_VERSION = 1


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
        "schema_version": CATALOG_SCHEMA_VERSION,
        "count":        len(catalog),
        "capabilities": catalog,
        "graph":        _build_dependency_graph(catalog),
    }


@router.get("/catalog.dot", response_class=Response)
def get_capability_catalog_dot() -> Response:
    """Return the capability dependency graph in Graphviz DOT format.

    Explicitly a **developer artifact** — no UI is wired to this
    route.  Analysts / contributors can paste the output into any
    Graphviz viewer (``dot -Tpng``, https://dreampuf.github.io/GraphvizOnline/,
    …) to get an instant visual dependency map of the UAIE registry.
    Zero engineering cost on our side — the edges are already derived
    from ``build_capability_catalog``.
    """
    catalog = build_capability_catalog()
    graph = _build_dependency_graph(catalog)
    lines: List[str] = [
        "digraph nvx_capability_catalog {",
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fillcolor="#0f172a", '
        'fontcolor="#e2e8f0", color="#334155", fontname="JetBrains Mono"];',
        '  edge [color="#67e8f9", fontcolor="#94a3b8", '
        'fontname="JetBrains Mono", fontsize=10];',
        '  bgcolor="#020617";',
    ]
    for cap_id, meta in catalog.items():
        label = cap_id.replace('"', '\\"')
        subtitle = meta.get("category") or ("legacy"
                    if not meta.get("contract_registered") else "")
        if subtitle:
            label = f"{label}\\n[{subtitle}]"
        lines.append(f'  "{cap_id}" [label="{label}"];')
    for e in graph["edges"]:
        via = ",".join(e["via_artifact_types"])
        lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{via}"];')
    lines.append("}")
    return Response(content="\n".join(lines) + "\n",
                     media_type="text/vnd.graphviz")
