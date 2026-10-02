"""Process graph: parent→child causality by evidence, synthetic roots for unresolved parents,
lane model for the UI, and lineage isolation. Temporal proximity alone never creates an edge."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .contracts import CORRELATED, ID_PID_ONLY, PROVEN_CAUSAL, UNRESOLVED, parse_instant
from .identity import parent_spoof

FILE_KINDS = ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE", "FILE_MOVE", "FILE_EXECUTE")


def _node(key: str, ev: Optional[Dict[str, Any]], *, synthetic: bool = False, observed: bool = True,
          label: Optional[str] = None) -> Dict[str, Any]:
    p = (ev or {}).get("process") or {}
    return {"key": key, "synthetic": synthetic, "observed": observed,
            "identity_state": (ev or {}).get("process_identity"), "pid": p.get("pid"), "guid": p.get("guid"),
            "image": p.get("image"), "command_line": p.get("command_line"), "user": p.get("user"),
            "sha256": p.get("sha256"), "start_ms": parse_instant(p.get("start_time")), "start_seen": False,
            "end_ms": None, "first_ms": None, "last_ms": None, "event_ids": [], "label": label or p.get("image"),
            "parent_key": None, "causal_state": None, "causal_basis": None, "candidate_parent": None,
            "parent_spoof": None}


def build_graph(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    unattributed: List[str] = []
    for ev in sorted(events, key=lambda e: (e["observed_ms"] or 0, e["event_id"])):
        k = ev.get("process_key")
        if not k:
            if ev["kind"] in ("NETWORK_CONNECT", "DNS_QUERY"):
                unattributed.append(ev["event_id"])
            continue
        n = nodes.get(k) or _node(k, ev)
        nodes[k] = n
        for f in ("image", "command_line", "user", "sha256", "guid", "pid"):
            n[f] = n[f] if n[f] is not None else (ev["process"] or {}).get(f)
        t = ev["observed_ms"]
        n["first_ms"] = t if n["first_ms"] is None else min(n["first_ms"], t)
        n["last_ms"] = t if n["last_ms"] is None else max(n["last_ms"], t)
        n["event_ids"].append(ev["event_id"])
        if ev["kind"] == "PROCESS_START":
            n["start_seen"] = True
            n["start_ms"] = n["start_ms"] if n["start_ms"] is not None else t
            n["_start_ev"] = ev
        elif ev["kind"] == "PROCESS_END":
            n["end_ms"] = t
        if n.get("_start_ev") is None and ev.get("parent_key"):
            n["_start_ev"] = n.get("_start_ev") or ev   # parent named on a non-start record (still evidence)
    for n in list(nodes.values()):
        _resolve_parent(n, nodes)
    for n in nodes.values():
        n.pop("_start_ev", None)
    return {"nodes": nodes, "unattributed_network": unattributed}


def _resolve_parent(n: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> None:
    ev = n.get("_start_ev")
    if n["synthetic"]:
        return
    if ev is None:
        _unresolved(n, nodes, None, "no creation record for this process in the evidence")
        return
    n["parent_spoof"] = parent_spoof(ev)
    pk, pid_state, ppid = ev.get("parent_key"), ev.get("parent_identity"), (ev.get("parent") or {}).get("pid")
    if pk and pid_state != ID_PID_ONLY:
        if pk not in nodes:
            nodes[pk] = _node(pk, None, observed=False, label=(ev.get("parent") or {}).get("image")
                              or f"pid {ppid} (named by child creation record)")
            nodes[pk].update(pid=ppid, guid=(ev.get("parent") or {}).get("guid"), identity_state=pid_state)
        n.update(parent_key=pk, causal_state=PROVEN_CAUSAL,
                 causal_basis="child creation record names a unique parent instance")
        return
    if ppid is not None:
        t = n["start_ms"] if n["start_ms"] is not None else n["first_ms"]
        cands = [m for m in nodes.values() if m is not n and not m["synthetic"] and m["pid"] == ppid
                 and m["start_ms"] is not None and t is not None and m["start_ms"] <= t
                 and (m["end_ms"] is None or m["end_ms"] >= t)]
        if len(cands) == 1:
            n.update(causal_state=CORRELATED, candidate_parent=cands[0]["key"],
                     causal_basis="reported parent pid matches exactly one live process instance (not proof)")
            _unresolved(n, nodes, ppid, None, keep_state=True)
            return
        _unresolved(n, nodes, ppid, f"reported parent pid {ppid} matches {len(cands)} live instances")
        return
    _unresolved(n, nodes, None, "creation record carries no parent identifier")


def _unresolved(n, nodes, ppid, reason, keep_state=False):
    tenant_dev = ":".join(n["key"].split(":")[1:3])
    rk = f"ur:{tenant_dev}:{ppid if ppid is not None else 'none'}"
    if rk not in nodes:
        nodes[rk] = _node(rk, None, synthetic=True, observed=False,
                          label=f"Parent not resolved (reported pid {ppid})" if ppid is not None
                          else "Parent not observed")
        nodes[rk]["causal_state"] = UNRESOLVED
    n["parent_key"] = rk
    if not keep_state:
        n.update(causal_state=UNRESOLVED, causal_basis=reason)


def lanes(events: List[Dict[str, Any]], t0: int, t1: int) -> Dict[str, Any]:
    g = build_graph(events)
    nodes = g["nodes"]
    children: Dict[Optional[str], List[str]] = {}
    for k, n in nodes.items():
        children.setdefault(n["parent_key"], []).append(k)
    order: List[Dict[str, Any]] = []

    def visit(k: str, depth: int, seen: Set[str]) -> None:
        if k in seen:
            return
        seen.add(k)
        n = nodes[k]
        start = n["start_ms"] if n["start_ms"] is not None else n["first_ms"]
        order.append({
            "lane_id": k, "lane_type": "UNRESOLVED_PARENT" if n["synthetic"] else "PROCESS", "depth": depth,
            "parent_lane": n["parent_key"], "causal_state": n["causal_state"], "causal_basis": n["causal_basis"],
            "candidate_parent": n["candidate_parent"], "label": n["label"], "pid": n["pid"], "image": n["image"],
            "command_line": n["command_line"], "user": n["user"], "sha256": n["sha256"],
            "identity_state": n["identity_state"], "observed": n["observed"], "parent_spoof": n["parent_spoof"],
            "span": {"from_ms": start, "to_ms": n["end_ms"]},
            "continues_before": (not n["start_seen"]) or (start is not None and start < t0),
            "continues_after": n["end_ms"] is None or n["end_ms"] > t1,
            "event_count": len(n["event_ids"])})
        for c in sorted(children.get(k, []), key=lambda x: (nodes[x]["first_ms"] or 0, x)):
            visit(c, depth + 1, seen)

    roots = [k for k, n in nodes.items() if n["parent_key"] is None or n["parent_key"] not in nodes]
    seen: Set[str] = set()
    for r in sorted(roots, key=lambda x: (nodes[x]["first_ms"] or 0, x)):
        visit(r, 0, seen)
    files: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        f = ev.get("file") or {}
        if ev["kind"] in FILE_KINDS and f.get("path"):
            lane = files.setdefault(f"file:{f['path'].lower()}", {
                "lane_id": f"file:{f['path'].lower()}", "lane_type": "FILE", "label": f["path"], "sha256": None,
                "event_count": 0, "touched_by": []})
            lane["event_count"] += 1
            lane["sha256"] = lane["sha256"] or f.get("sha256")
            if ev.get("process_key") and ev["process_key"] not in lane["touched_by"]:
                lane["touched_by"].append(ev["process_key"])
    out = order + sorted(files.values(), key=lambda x: x["lane_id"])
    if g["unattributed_network"]:
        out.append({"lane_id": "net:unattributed", "lane_type": "UNATTRIBUTED_NETWORK",
                    "label": "Network activity without process attribution",
                    "event_count": len(g["unattributed_network"])})
    return {"lanes": out, "graph": g}


def lane_of(ev: Dict[str, Any]) -> str:
    if ev.get("process_key"):
        return ev["process_key"]
    if ev["kind"] in FILE_KINDS and (ev.get("file") or {}).get("path"):
        return f"file:{ev['file']['path'].lower()}"
    return "net:unattributed"


def isolate(events: List[Dict[str, Any]], *, sha256: Optional[str] = None, filename: Optional[str] = None,
            process_key: Optional[str] = None) -> Dict[str, Any]:
    """Lineage isolation: seeds + PROVEN ancestors + all descendants. Correlated links are not followed."""
    nodes = build_graph(events)["nodes"]
    seeds: Set[str] = set()
    for ev in events:
        p, f = ev.get("process") or {}, ev.get("file") or {}
        if sha256 and sha256.lower() in ((p.get("sha256") or ""), (f.get("sha256") or "")):
            if ev.get("process_key"):
                seeds.add(ev["process_key"])
        name = (filename or "").lower()
        if name and any(x and x.lower().replace("\\", "/").rsplit("/", 1)[-1] == name
                        for x in (p.get("image"), f.get("path"))):
            if ev.get("process_key"):
                seeds.add(ev["process_key"])
    if process_key and process_key in nodes:
        seeds.add(process_key)
    keep = set(seeds)
    for s in seeds:
        cur = nodes[s]
        while cur["parent_key"] and cur["causal_state"] == PROVEN_CAUSAL and cur["parent_key"] in nodes:
            keep.add(cur["parent_key"])
            cur = nodes[cur["parent_key"]]
    grew = True
    while grew:
        grew = False
        for k, n in nodes.items():
            if k not in keep and n["parent_key"] in keep and n["causal_state"] == PROVEN_CAUSAL:
                keep.add(k)
                grew = True
    return {"seeds": sorted(seeds), "lane_ids": sorted(keep), "followed": [PROVEN_CAUSAL]}
