"""Stable process-instance identity, event identity and cross-store duplicate suppression."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .contracts import ID_GUID, ID_PID_ONLY, ID_START_TIME, parse_instant


def process_key(tenant_id: str, device_id: str, proc: Dict[str, Any],
                boot_id: Optional[str] = None) -> Tuple[Optional[str], str]:
    """(key, identity_state). Key = tenant+device+pid+start time [+boot]; PID reuse safe.

    A source GUID (one lifetime per host) is accepted when start time is absent. PID alone is
    never authoritative: it is keyed but marked so lineage can only be UNRESOLVED from it.
    """
    pid, start = proc.get("pid"), parse_instant(proc.get("start_time"))
    boot = f":{boot_id}" if boot_id else ""
    if pid is not None and start is not None:
        return f"pi:{tenant_id}:{device_id}:{pid}:{start}{boot}", ID_START_TIME
    if proc.get("guid"):
        return f"pg:{tenant_id}:{device_id}:{str(proc['guid']).strip('{}').lower()}", ID_GUID
    if pid is not None:
        return f"pp:{tenant_id}:{device_id}:{pid}{boot}", ID_PID_ONLY
    return None, ID_PID_ONLY


def parent_spoof(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Flag when the reported parent differs from creator evidence (e.g. PPID spoofing)."""
    par, cre = ev.get("parent") or {}, ev.get("creator") or {}
    if not cre or not par:
        return None
    for f in ("guid", "pid"):
        if cre.get(f) is not None and par.get(f) is not None:
            if str(cre[f]).strip("{}").lower() != str(par[f]).strip("{}").lower():
                return {"suspected": True, "reported_parent": {k: par.get(k) for k in ("pid", "guid", "image")},
                        "creator": {k: cre.get(k) for k in ("pid", "guid", "image")},
                        "basis": f"creator.{f} != parent.{f}"}
            return None
    return None


def fallback_event_id(tenant_id: str, device_id: str, ev: Dict[str, Any]) -> str:
    """Content identity when no source identity exists (same real activity → same id)."""
    p, f, n = ev.get("process") or {}, ev.get("file") or {}, ev.get("network") or {}
    material = [tenant_id, device_id, ev.get("kind"), ev.get("observed_ms"), p.get("pid"), p.get("guid"),
                f.get("path"), n.get("dest_ip"), n.get("dest_port")]
    return "ce_" + hashlib.sha256(json.dumps(material, default=str).encode()).hexdigest()[:24]


def _merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**v, **{kk: vv for kk, vv in out[k].items() if vv is not None}}
        elif out.get(k) in (None, "", [], {}):
            out[k] = v
    out["sources"] = sorted(set(a.get("sources") or []) | set(b.get("sources") or []))
    # ingest lateness: the EARLIEST store acceptance is the delivery time
    ins = [x for x in (a.get("ingested_ms"), b.get("ingested_ms")) if x is not None]
    out["ingested_ms"] = min(ins) if ins else None
    return out


def dedupe(events: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Collapse the same activity seen in several stores (stable event identity). Returns (events, suppressed)."""
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    suppressed = 0
    for ev in events:
        k = (ev["tenant_id"], ev["event_id"])
        if k in seen:
            seen[k] = _merge(seen[k], ev)
            suppressed += 1
        else:
            seen[k] = ev
    return list(seen.values()), suppressed
