"""Round 36 · Three deterministic projections over the same evidence
SSOT that answers the three canonical investigation questions:

    ┌───────────────────────────────────────────────────────────┐
    │  MITRE CHAIN   →  What attack behaviour was evidenced,    │
    │                    and how did the attack progress?        │
    │  PROCESS TREE  →  What process executed what?              │
    │  ACTIVITY GRAPH→  What entities/events are related?        │
    └───────────────────────────────────────────────────────────┘

All three projections consume the same nodes[]/edges[] produced by
:func:`AttackGraphService.compose`.  Nothing is fabricated; nothing
is duplicated.  Same inputs → byte-identical output.

Owner rules preserved:
  • Non-fabrication (§11) — every projection reads from the governed
    node/edge SSOT.  If evidence is missing, the projection returns
    an empty section rather than inventing content.
  • Four-state grammar (OBSERVED / SUPPORTED / POSSIBLE / NOT_OBSERVED)
    is carried through faithfully.
  • Deterministic ordering — projections sort by stable identifiers so
    the same inputs always produce the same layout.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────
# 1 · MITRE CHAIN PROJECTION
# ─────────────────────────────────────────────────────────────────────

def _find_adjacent(edges: List[Dict[str, Any]],
                     dst: str, rel: Optional[str] = None) -> List[Dict[str, Any]]:
    return [e for e in edges
              if e["dst"] == dst
              and e["state"] != "NOT_OBSERVED"
              and (rel is None or e["rel"] == rel)]


def _walk_incoming(edges: List[Dict[str, Any]],
                        nodes_by_id: Dict[str, Dict[str, Any]],
                        start: str, target_kinds: set,
                        max_depth: int = 6) -> List[Dict[str, Any]]:
    """Reverse-walk edges toward evidence origin nodes.

    Returns the earliest ancestor nodes matching ``target_kinds`` that
    can reach ``start`` through non-NOT_OBSERVED edges.
    """
    hits: List[Dict[str, Any]] = []
    seen = {start}
    frontier = [start]
    depth = 0
    while frontier and depth < max_depth:
        nxt: List[str] = []
        for cur in frontier:
            for e in edges:
                if e["dst"] != cur or e["state"] == "NOT_OBSERVED":
                    continue
                src = e["src"]
                if src in seen:
                    continue
                seen.add(src)
                if nodes_by_id.get(src, {}).get("kind") in target_kinds:
                    hits.append(nodes_by_id[src])
                nxt.append(src)
        frontier = nxt
        depth += 1
    return hits


def project_mitre_chain(nodes: List[Dict[str, Any]],
                             edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """MITRE Chain projection.

    Groups every OBSERVED / SUPPORTED technique node under its parent
    ATT&CK stage(s) and attaches the evidence that supports it.  Only
    stages that have at least one evidenced technique are surfaced.
    """
    nodes_by_id = {n["id"]: n for n in nodes}

    stages = [n for n in nodes if n["kind"] == "stage"]
    techniques = [n for n in nodes if n["kind"] == "technique"]

    # Technique → parent stages via BELONGS_TO edges (SSOT).
    stages_for_tech: Dict[str, List[str]] = {}
    for e in edges:
        if e["rel"] == "BELONGS_TO" and e["state"] != "NOT_OBSERVED":
            src_kind = nodes_by_id.get(e["src"], {}).get("kind")
            dst_kind = nodes_by_id.get(e["dst"], {}).get("kind")
            if src_kind == "technique" and dst_kind == "stage":
                stages_for_tech.setdefault(e["src"], []).append(e["dst"])

    # Evidence bundle for each technique — reverse-walk to find the
    # detection / commandline / process / event / finding that
    # actually caused this mapping.
    def _evidence_for_tech(tech_id: str) -> Dict[str, Any]:
        detection = _walk_incoming(edges, nodes_by_id, tech_id, {"detection"})
        match     = _walk_incoming(edges, nodes_by_id, tech_id, {"match"})
        cli       = _walk_incoming(edges, nodes_by_id, tech_id, {"commandline"})
        procs     = _walk_incoming(edges, nodes_by_id, tech_id, {"process"})
        events    = _walk_incoming(edges, nodes_by_id, tech_id,
                                        {"event", "signature", "event_id"})
        findings  = _walk_incoming(edges, nodes_by_id, tech_id,
                                        {"finding", "capability"})
        # evidence_refs from every edge that led here.
        refs: List[str] = []
        for e in edges:
            if e["dst"] == tech_id and e["state"] != "NOT_OBSERVED":
                refs.extend(e.get("evidence_refs") or [])
        return {
            "detection_rules": [{"id": d["id"], "label": d["label"],
                                        "state": d["state"]}
                                       for d in detection],
            "correlation_matches": [{"id": m["id"], "label": m["label"],
                                             "state": m["state"]}
                                             for m in match],
            "commands": [{"id": c["id"], "label": c["label"],
                              "full": (c.get("attrs") or {}).get("full")}
                              for c in cli],
            "processes": [{"id": p["id"], "label": p["label"],
                                "role": (p.get("attrs") or {}).get("role"),
                                "host": (p.get("attrs") or {}).get("host")}
                                for p in procs],
            "events": [{"id": ev["id"], "label": ev["label"],
                              "kind": ev["kind"]} for ev in events],
            "findings": [{"id": f["id"], "label": f["label"],
                              "kind": f["kind"], "state": f["state"]}
                              for f in findings],
            "evidence_refs": sorted({r for r in refs if r}),
        }

    # Group techniques under stages (sorted by kill-chain order — nodes
    # already carry an "order" attr in attack_cycle.STAGES).
    stage_map: Dict[str, Dict[str, Any]] = {}
    for s in stages:
        stage_map[s["id"]] = {
            "id":     s["id"],
            "name":   s["label"],
            "state":  s["state"],
            "order":  (s.get("attrs") or {}).get("order", 99),
            "techniques": [],
        }

    orphan_techniques: List[Dict[str, Any]] = []
    for t in techniques:
        parent_stages = stages_for_tech.get(t["id"], [])
        tech_entry = {
            "id":     t["id"],
            "tid":    (t.get("attrs") or {}).get("tid") or t["label"],
            "name":   (t.get("attrs") or {}).get("name") or t["label"],
            "state":  t["state"],
            "tactic_id":   (t.get("attrs") or {}).get("tactic_id"),
            "source": (t.get("attrs") or {}).get("source"),
            "evidence": _evidence_for_tech(t["id"]),
        }
        if not parent_stages:
            orphan_techniques.append(tech_entry)
            continue
        for sid in parent_stages:
            if sid in stage_map:
                stage_map[sid]["techniques"].append(tech_entry)

    # Keep only stages that have at least one evidenced technique — the
    # MITRE Chain view must never surface NOT_OBSERVED tactics as if
    # they had happened.
    evidenced_states = {"OBSERVED", "SUPPORTED", "POSSIBLE"}
    stages_out = [s for s in stage_map.values()
                    if any(tt["state"] in evidenced_states
                              for tt in s["techniques"])]
    stages_out.sort(key=lambda s: (s["order"], s["name"]))

    # Deterministic technique ordering within each stage.
    for s in stages_out:
        s["techniques"].sort(key=lambda t: (t["state"] != "OBSERVED",
                                                        t["tid"], t["id"]))

    total_techniques = sum(len(s["techniques"]) for s in stages_out)
    observed_techniques = sum(1 for s in stages_out
                                     for t in s["techniques"]
                                     if t["state"] == "OBSERVED")
    return {
        "stages":              stages_out,
        "orphan_techniques":   sorted(orphan_techniques,
                                              key=lambda t: t["tid"]),
        "totals": {
            "stages_shown":        len(stages_out),
            "techniques_total":    total_techniques,
            "techniques_observed": observed_techniques,
        },
    }


# ─────────────────────────────────────────────────────────────────────
# 2 · PROCESS TREE PROJECTION
# ─────────────────────────────────────────────────────────────────────

def project_process_tree(nodes: List[Dict[str, Any]],
                              edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Process Tree projection — pure parent → child ancestry.

    Uses only ``SPAWNED`` edges between ``process`` nodes.  Every leaf
    exposes commandline / host / user attributes when the underlying
    canonical evidence carries them.
    """
    procs = [n for n in nodes if n["kind"] == "process"]
    procs_by_id = {p["id"]: p for p in procs}

    # Adjacency: parent → children via SPAWNED.
    children: Dict[str, List[str]] = {}
    incoming: Dict[str, int] = {p["id"]: 0 for p in procs}
    for e in edges:
        if (e["rel"] == "SPAWNED"
                and e["state"] != "NOT_OBSERVED"
                and e["src"] in procs_by_id
                and e["dst"] in procs_by_id):
            children.setdefault(e["src"], []).append(e["dst"])
            incoming[e["dst"]] = incoming.get(e["dst"], 0) + 1

    # Commandline attached to a process via EXECUTED edges.
    cli_for_proc: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges:
        if e["rel"] == "EXECUTED" and e["state"] != "NOT_OBSERVED":
            src_kind = next((n["kind"] for n in nodes if n["id"] == e["src"]), None)
            dst_kind = next((n["kind"] for n in nodes if n["id"] == e["dst"]), None)
            if src_kind == "process" and dst_kind == "commandline":
                cli_node = next(n for n in nodes if n["id"] == e["dst"])
                cli_for_proc.setdefault(e["src"], []).append({
                    "id": cli_node["id"],
                    "label": cli_node["label"],
                    "full":  (cli_node.get("attrs") or {}).get("full")})

    def _to_entry(pid: str) -> Dict[str, Any]:
        p = procs_by_id[pid]
        a = p.get("attrs") or {}
        return {
            "id":         p["id"],
            "name":       p["label"],
            "state":      p["state"],
            "role":       a.get("role"),
            "host":       a.get("host"),
            "commandlines": cli_for_proc.get(pid, []),
            "children":   sorted([_to_entry(c) for c in children.get(pid, [])],
                                    key=lambda x: (x["name"], x["id"])),
        }

    roots = [_to_entry(p["id"]) for p in procs
                if incoming.get(p["id"], 0) == 0]
    roots.sort(key=lambda x: (x["name"], x["id"]))
    total_nodes = len(procs)
    return {
        "roots":      roots,
        "totals":     {"processes": total_nodes,
                            "roots":     len(roots)},
    }


# ─────────────────────────────────────────────────────────────────────
# 3 · ACTIVITY GRAPH PROJECTION
# ─────────────────────────────────────────────────────────────────────

_ACTIVITY_ALLOWED_KINDS = {
    "incident", "host", "user", "ip", "hash", "event", "event_id",
    "signature", "process", "commandline", "file", "domain",
}
# Round 36 · Deliberately excluded from the Activity Graph:
#   • `capability`  → NivXRay tools, not evidence entities.  They
#                     belong on the Evidence Inspector as investigation
#                     actions, not as first-class graph nodes.
#   • `finding`     → derived conclusions, surfaced as annotations /
#                     inspector cards rather than graph boxes.
#   • `stage` / `technique` / `detection` / `match` / `gap` →
#                     MITRE-model concepts, live in the MITRE Chain
#                     view exclusively.

def project_activity_graph(nodes: List[Dict[str, Any]],
                                edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Activity Graph projection.

    The entity/evidence relationship graph — with MITRE stages,
    techniques, detections, matches and gaps intentionally *excluded*.
    This is the view for "what interacted with what?" — MITRE mapping
    stays in the MITRE Chain view where it belongs.
    """
    kept_ids = {n["id"] for n in nodes
                    if n["kind"] in _ACTIVITY_ALLOWED_KINDS}
    kept_nodes = [n for n in nodes if n["id"] in kept_ids]
    kept_edges = [e for e in edges
                    if e["src"] in kept_ids and e["dst"] in kept_ids
                       and e["state"] != "NOT_OBSERVED"]
    return {
        "nodes":  kept_nodes,
        "edges":  kept_edges,
        "totals": {
            "nodes": len(kept_nodes),
            "edges": len(kept_edges),
        },
    }
