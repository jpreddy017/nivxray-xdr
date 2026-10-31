"""Convert canonical nested-JSON ProcessTree ↔ flat edge list ↔ ASCII tree.

Nested-JSON is the CANONICAL internal format. The other two are:
  - Flat edge list  → compact, easy for tabular ingestion
  - ASCII tree      → human-friendly for training prompts / analyst review
"""
from __future__ import annotations
from typing import Dict, List, Any

from training.schema import ProcessTree, ProcessNode, SocRationale, ProcessEvidence


# --- Nested JSON  →  Flat edge list ------------------------------------- #
def to_edge_list(tree: ProcessTree) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, str]] = []

    def walk(n: ProcessNode, parent_id: str | None = None):
        d = n.model_dump()
        d.pop("children", None)
        d["parent_node_id"] = parent_id
        nodes.append(d)
        if parent_id:
            edges.append({"parent": parent_id, "child": n.node_id})
        for c in n.children:
            walk(c, n.node_id)

    walk(tree.root, None)
    return {
        "tree_id": tree.tree_id,
        "platform": tree.platform,
        "evidence_source": tree.evidence_source,
        "nodes": nodes,
        "edges": edges,
        "rationale": tree.rationale.model_dump(),
        "warnings": tree.warnings,
    }


# --- Flat edge list  →  Nested JSON ------------------------------------- #
def edge_list_to_tree(data: Dict[str, Any]) -> ProcessTree:
    by_id: Dict[str, ProcessNode] = {}
    for nd in data["nodes"]:
        nd = dict(nd)
        nd["children"] = []
        ev = nd.pop("evidence", None)
        if ev:
            nd["evidence"] = ProcessEvidence(**ev)
        by_id[nd["node_id"]] = ProcessNode(**nd)

    child_ids = {e["child"] for e in data.get("edges", [])}
    root_id = next((nid for nid in by_id if nid not in child_ids), None)
    if root_id is None and by_id:
        root_id = next(iter(by_id))

    for e in data.get("edges", []):
        parent = by_id.get(e["parent"])
        child = by_id.get(e["child"])
        if parent and child:
            parent.children.append(child)

    rationale = SocRationale(**(data.get("rationale") or {}))
    return ProcessTree(
        tree_id=data.get("tree_id"),
        platform=data.get("platform", "windows"),
        root=by_id[root_id] if root_id else ProcessNode(process="(empty)"),
        rationale=rationale,
        evidence_source=data.get("evidence_source", "decoded"),
        warnings=data.get("warnings", []),
    )


# --- Nested JSON  →  ASCII tree ----------------------------------------- #
def to_ascii_tree(tree: ProcessTree, max_cmd_len: int = 100) -> str:
    lines: List[str] = []
    lines.append(f"[{tree.platform.upper()}] tree_id={tree.tree_id} · source={tree.evidence_source}")
    lines.append(f"verdict : {tree.rationale.verdict}  ({tree.rationale.severity})")
    if tree.rationale.mitre_ids:
        lines.append(f"MITRE   : {', '.join(tree.rationale.mitre_ids)}")
    if tree.rationale.lolbins:
        lines.append(f"LOLBins : {', '.join(tree.rationale.lolbins)}")
    lines.append("")

    def walk(n: ProcessNode, prefix: str, is_last: bool):
        connector = "└─ " if is_last else "├─ "
        mitre = f"  [{','.join(n.mitre_ids)}]" if n.mitre_ids else ""
        inf = "  (inferred)" if n.evidence.inferred else ""
        lines.append(f"{prefix}{connector}{n.process}{mitre}{inf}")
        indent = prefix + ("   " if is_last else "│  ")
        if n.command_line:
            cmd = n.command_line.replace("\n", " ")
            if len(cmd) > max_cmd_len:
                cmd = cmd[:max_cmd_len - 3] + "..."
            lines.append(f"{indent}  cmd : {cmd}")
        if n.action:
            lines.append(f"{indent}  → {n.action}")
        for i, c in enumerate(n.children):
            walk(c, indent, i == len(n.children) - 1)

    walk(tree.root, "", True)
    if tree.rationale.analyst_summary:
        lines.append("")
        lines.append("SUMMARY:")
        lines.append(f"  {tree.rationale.analyst_summary}")
    return "\n".join(lines)
