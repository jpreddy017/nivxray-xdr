"""v2/routers/irg.py · Investigation Relationship Graph endpoint.

GET /api/v2/cases/{case_id}/irg
    - Loads shadow observations for the case.
    - Runs the IRG enricher (v2/shadow/irg.py) — canonical relationship model.
    - Aggregates frames into { nodes, edges } suitable for graph rendering.

Read-only. Flag-gated on TRAJECTORY_ENGINE (same gate — same data source).
"""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.trajectory import build_from_observations
from v2.shadow.irg import enrich as irg_enrich

router = APIRouter(prefix="/v2/cases", tags=["v2-irg"])


@router.get("/{case_id}/irg")
async def investigation_graph(case_id: str, limit: int = 500,
                              _: dict = Depends(require_admin)) -> dict[str, Any]:
    if not get_flag("TRAJECTORY_ENGINE").observable():
        raise HTTPException(status_code=503, detail="trajectory engine disabled")

    frames = await build_from_observations(_db, case_id=case_id,
                                           limit=max(1, min(limit, 5000)))
    frame_dicts = [f.to_dict() for f in frames]
    frame_dicts = irg_enrich(frame_dicts)

    # ── Aggregate to nodes + edges ─────────────────────────────────
    nodes: dict[str, dict] = {}
    edges_seen: set[tuple[str, str, str]] = set()
    edges: list[dict] = []

    def _node(iid: str, ntype: str, name: str) -> dict:
        n = nodes.get(iid)
        if n is None:
            n = {
                "iid":       iid,
                "type":      ntype,
                "name":      name,
                "event_count": 0,
                "malicious": False,
                "first_seen": None,
                "last_seen":  None,
                "mitre":     [],
                "depth":     0,
                "parent_iid": None,
            }
            nodes[iid] = n
        return n

    for f in frame_dicts:
        ent    = f.get("entity") or {}
        parent = f.get("parent") or {}
        rel    = f.get("relationship") or {}
        execn  = f.get("execution") or {}
        ent_iid = ent.get("iid")
        if not ent_iid:
            continue
        n = _node(ent_iid, ent.get("type") or "process", ent.get("name") or ent_iid)
        n["event_count"] += 1
        # Verdict
        if (f.get("verdict") or "").lower() == "malicious":
            n["malicious"] = True
        # Time bounds
        ts = f.get("ts")
        if ts is not None:
            n["first_seen"] = ts if n["first_seen"] is None else min(n["first_seen"], ts) if isinstance(ts, (int, float)) else n["first_seen"]
            n["last_seen"]  = ts if n["last_seen"]  is None else max(n["last_seen"],  ts) if isinstance(ts, (int, float)) else n["last_seen"]
            if n["first_seen"] is None or (isinstance(ts, str) and (n["first_seen"] is None or ts < n["first_seen"])):
                n["first_seen"] = ts
            if isinstance(ts, str) and (n["last_seen"] is None or ts > n["last_seen"]):
                n["last_seen"] = ts
        # MITRE
        for m in (f.get("mitre") or []):
            if m and m not in n["mitre"]:
                n["mitre"].append(m)
        # Depth + parent
        depth = execn.get("depth")
        if isinstance(depth, int) and depth > n["depth"]:
            n["depth"] = depth
        parent_iid = parent.get("iid")
        if parent_iid and n["parent_iid"] is None:
            n["parent_iid"] = parent_iid
        # Edge
        if parent_iid and ent_iid and parent_iid != ent_iid:
            rel_type = rel.get("type") or "SPAWNED"
            key = (parent_iid, ent_iid, rel_type)
            if key not in edges_seen:
                edges_seen.add(key)
                edges.append({
                    "source":   parent_iid,
                    "target":   ent_iid,
                    "type":     rel_type,
                    "count":    1,
                })
            else:
                for e in edges:
                    if e["source"] == parent_iid and e["target"] == ent_iid and e["type"] == rel_type:
                        e["count"] += 1
                        break

    # Ensure parent nodes referenced by edges also exist as nodes.
    for e in edges:
        if e["source"] not in nodes:
            _node(e["source"], "process", e["source"].replace("ent_process_", ""))

    return {
        "ok": True,
        "case_id": case_id,
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
