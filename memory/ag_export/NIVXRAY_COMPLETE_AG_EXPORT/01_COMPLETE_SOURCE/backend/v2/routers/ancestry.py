"""v2/routers/ancestry.py · Process Ancestry endpoint (R1.2).

GET /api/v2/cases/{case_id}/ancestry/process/{process_iid}
    Returns the parent-→-child spawn graph rooted at the given process,
    plus every event attributed to each node in the graph.

Same source of truth as the Device Trajectory + R4 Report — reuses
`v2.trajectory.build_from_observations`. Zero RC5 imports.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Any
from fastapi import APIRouter, Depends, HTTPException

from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.trajectory.device import build_from_observations
from v2.shadow.irg import enrich as irg_enrich

router = APIRouter(prefix="/v2/cases", tags=["v2-ancestry"])


def _guard() -> None:
    if not get_flag("TRAJECTORY_ENGINE").observable():
        raise HTTPException(status_code=503, detail="trajectory engine disabled")


def _process_key(frame) -> str:
    """Same collapsing rule the frontend + report builder use — group by
    readable binary name so N events from the same binary land on one
    ancestry node instead of exploding into N synthetic proc_shadow rows."""
    import re
    lbl = getattr(frame, "label", "") or getattr(frame, "action", "") or ""
    m = re.search(r"([A-Za-z0-9_.-]+\.(?:exe|dll|msi|ps1|bat|cmd|sys|com))",
                  lbl, re.IGNORECASE)
    if m:
        return f"bin:{m.group(1).lower()}"
    proc = getattr(frame, "process", None)
    parent = getattr(frame, "parent", None)
    if proc and getattr(proc, "iid", None):
        return proc.iid
    if parent and getattr(parent, "iid", None):
        return parent.iid
    return f"sys:{getattr(frame, 'lane', 'unknown')}"


@router.get("/{case_id}/ancestry/process/{process_iid}")
async def process_ancestry(
    case_id: str, process_iid: str,
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Compute the ancestry subgraph rooted at `process_iid`.

    Nodes are keyed by the same collapsing rule the trajectory UI uses,
    so `bin:cmd.exe` is one node even if it fired 15 events. Edges are
    directed parent → child using the frame's parent.iid link.
    """
    _guard()
    frames = await build_from_observations(_db, case_id=case_id, limit=5000)
    if not frames:
        raise HTTPException(status_code=404, detail=f"no frames for case {case_id}")

    # Enrich frames with the canonical IRG schema so Device Trajectory,
    # IRG Workspace, and Process Ancestry all consume the same
    # entity.iid / parent.iid / root.iid model. Zero drift.
    frame_dicts = [f.to_dict() for f in frames]
    frame_dicts = irg_enrich(frame_dicts)
    irg_by_frame = { fd.get("frame_iid") or fd.get("id"): fd for fd in frame_dicts }

    def _irg(f):
        fid = getattr(f, "frame_iid", None) or getattr(f, "id", None)
        return irg_by_frame.get(fid, {}) if fid else {}

    # Build key → frames map + edges (parent-key → set(child-key)) using
    # the IRG-derived parent.iid. Fall back to the legacy heuristic only
    # when IRG has no parent for a frame (shouldn't happen — irg.py
    # always injects one).
    frames_by_key: dict[str, list] = defaultdict(list)
    edges: dict[str, set[str]] = defaultdict(set)
    reverse_edges: dict[str, set[str]] = defaultdict(set)

    # First pass — map each frame to its canonical key.
    key_by_entity_iid: dict[str, str] = {}
    for f in frames:
        k = _process_key(f)
        frames_by_key[k].append(f)
        irg = _irg(f)
        ent_iid = (irg.get("entity") or {}).get("iid")
        if ent_iid and ent_iid not in key_by_entity_iid:
            key_by_entity_iid[ent_iid] = k

    # Second pass — resolve edges via IRG parent.iid.
    for f in frames:
        k = _process_key(f)
        irg = _irg(f)
        parent_iid = (irg.get("parent") or {}).get("iid")
        if not parent_iid:
            parent_iid = getattr(getattr(f, "parent", None), "iid", None)
        if not parent_iid:
            continue
        parent_key = key_by_entity_iid.get(parent_iid, parent_iid)
        if parent_key == k:
            continue
        edges[parent_key].add(k)
        reverse_edges[k].add(parent_key)

    # Locate the root: accept either the collapsed bin key OR a raw iid.
    root_key = process_iid
    if process_iid not in frames_by_key:
        # try prefix "bin:"
        candidate = f"bin:{process_iid.lower()}"
        if candidate in frames_by_key:
            root_key = candidate
        else:
            raise HTTPException(status_code=404,
                                detail=f"process {process_iid} not in case {case_id}")

    # BFS ancestors (parents-of-root) up to 5 levels
    ancestors: set[str] = set()
    frontier = {root_key}
    for _depth in range(5):
        nxt = set()
        for k in frontier:
            for p in reverse_edges.get(k, ()):
                if p not in ancestors and p != root_key:
                    ancestors.add(p)
                    nxt.add(p)
        if not nxt: break
        frontier = nxt

    # BFS descendants (children-of-root) up to 5 levels
    descendants: set[str] = set()
    frontier = {root_key}
    for _depth in range(5):
        nxt = set()
        for k in frontier:
            for c in edges.get(k, ()):
                if c not in descendants and c != root_key:
                    descendants.add(c)
                    nxt.add(c)
        if not nxt: break
        frontier = nxt

    subgraph_keys = ancestors | {root_key} | descendants

    def _node(key: str) -> dict[str, Any]:
        fs = frames_by_key.get(key, [])
        label = key.split(":", 1)[-1] if ":" in key else key
        verdict = "benign"
        mitre_set: set[str] = set()
        first_ts = last_ts = None
        entity_iid = None
        root_iid = None
        depth = 0
        for f in fs:
            m = getattr(f, "mitre", ()) or ()
            for t in m: mitre_set.add(t)
            rule = getattr(f, "rule_id", None) or (getattr(f, "provenance", {}) or {}).get("rule_id")
            v = "malicious" if (m and rule) else ("suspicious" if m else "benign")
            if v == "malicious" or (v == "suspicious" and verdict != "malicious"):
                verdict = v
            ts = getattr(f, "ts", None)
            if ts:
                if not first_ts or ts < first_ts: first_ts = ts
                if not last_ts  or ts > last_ts:  last_ts  = ts
            irg = _irg(f)
            if entity_iid is None:
                entity_iid = (irg.get("entity") or {}).get("iid")
            if root_iid is None:
                root_iid = (irg.get("root") or {}).get("iid")
            d = (irg.get("execution") or {}).get("depth")
            if isinstance(d, int) and d > depth:
                depth = d
        return {
            "key": key, "label": label, "event_count": len(fs),
            "verdict": verdict, "mitre": sorted(mitre_set),
            "first_ts": first_ts, "last_ts": last_ts,
            "entity_iid": entity_iid,
            "root_iid":   root_iid,
            "depth":      depth,
            "role": ("root" if key == root_key
                     else ("ancestor" if key in ancestors else "descendant")),
        }

    def _events_for(key: str) -> list[dict[str, Any]]:
        return [f.to_dict() for f in frames_by_key.get(key, [])]

    return {
        "ok": True,
        "case_id": case_id,
        "root": root_key,
        "root_label": root_key.split(":", 1)[-1] if ":" in root_key else root_key,
        "nodes": [_node(k) for k in sorted(subgraph_keys)],
        "edges": [
            {"parent": p, "child": c}
            for p in sorted(subgraph_keys)
            for c in sorted(edges.get(p, ()))
            if c in subgraph_keys
        ],
        "events": {k: _events_for(k) for k in subgraph_keys},
        "stats": {
            "ancestor_count":   len(ancestors),
            "descendant_count": len(descendants),
            "total_events":     sum(len(frames_by_key[k]) for k in subgraph_keys),
        },
    }
