"""Stage 1 · endpoint-scoped WINDOWED Device Trajectory projection.

The existing `/api/edr/device-trajectory` returns a whole window in one
response and scans the observation collection in Python. That cannot
carry an arbitrarily movable viewport, so this module adds a windowed
read over the SAME authoritative evidence — it is a projection, never a
second telemetry store:

    edr_raw_events → canonical evidence (v2_shadow_observations)
                   → this projection → viewport

Two axes, and the backend owns both mappings:

  * TIME  — `time_start` / `time_end`, paged with an opaque cursor of
    (timestamp, event_iid) so a page boundary can never duplicate or
    skip an event.
  * LANE  — `lane_start` / `lane_end` are indices into a DETERMINISTIC
    lane catalogue the backend computes: processes first ordered by
    lineage depth, then files, then network. Lane identity is a stable
    key (`process_iid`, file path, remote peer), never a severity rank,
    so vertical paging means the same thing on every request.

Because a lane catalogue can grow, every response carries
`lane_axis_version`. A client that sees it change knows its lane indices
moved and can re-anchor on `lane_id` — the alternative (silently
renumbering under a scrolling analyst) would show the wrong row's
evidence.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID = "nivxray::edr_plane::trajectory_window"
COLLECTION = "v2_shadow_observations"
GROUPS = ("PROCESS", "FILE", "NETWORK")
MAX_LIMIT = 2000

#: Canonical kinds → lane group. Anything unrecognised goes to PROCESS
#: only if it carries process evidence; otherwise it is OTHER and is
#: reported as such rather than being drawn on a lane it does not belong
#: to.
_FILE_KINDS = {"file_create", "file_write", "file_delete", "file_modify",
               "file_rename", "image_load", "file"}
_NET_KINDS = {"network_connect", "network", "dns_query", "dns",
              "network_accept", "http_request"}


def _cursor_encode(ts: str, iid: str) -> str:
    return base64.urlsafe_b64encode(
        json.dumps({"ts": ts, "iid": iid}).encode()).decode()


def _cursor_decode(cur: Optional[str]) -> Optional[Dict[str, str]]:
    if not cur:
        return None
    try:
        d = json.loads(base64.urlsafe_b64decode(cur.encode()).decode())
        return {"ts": str(d["ts"]), "iid": str(d["iid"])}
    except Exception:  # noqa: BLE001
        return None


def _ev(doc: Dict[str, Any]) -> Dict[str, Any]:
    e = doc.get("event")
    return e if isinstance(e, dict) else {}


def _raw(ev: Dict[str, Any]) -> Dict[str, Any]:
    r = ev.get("raw")
    return r if isinstance(r, dict) else {}


def _ts(doc: Dict[str, Any], ev: Dict[str, Any]) -> Optional[str]:
    return ev.get("ts") or doc.get("captured_at")


def _group_and_key(ev: Dict[str, Any]) -> Tuple[str, str, str]:
    """(group, lane_id, label) from evidence only. No substitution: a
    network-only observation is NOT given a process lane."""
    kind = str(ev.get("kind") or "").lower()
    proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
    raw = _raw(ev)
    if kind in _FILE_KINDS:
        path = raw.get("target") or raw.get("file") or raw.get("path")
        if path:
            return "FILE", f"file::{path}", str(path)
    if kind in _NET_KINDS:
        peer = (raw.get("remote_ip") or raw.get("destination")
                or raw.get("entity") or raw.get("dns_query"))
        if peer:
            return "NETWORK", f"net::{peer}", str(peer)
    iid = proc.get("iid") or ev.get("process_iid")
    if iid:
        return "PROCESS", f"proc::{iid}", str(proc.get("name") or iid)
    return "OTHER", "other::unattributed", "unattributed observation"


async def _scan(db, *, ident: Dict[str, Any], time_start: Optional[str],
                time_end: Optional[str]) -> List[Dict[str, Any]]:
    """One indexed-shaped query per request, scoped to the endpoint."""
    iid = ident.get("device_iid")
    host = ident.get("hostname")
    ors: List[Dict[str, Any]] = []
    if iid:
        ors += [{"event.device_iid": iid}, {"device_iid": iid}]
    if host:
        ors += [{"event.raw.computer": host}, {"event.computer": host},
                {"event.raw.hostname": host}]
    if not ors:
        return []
    q: Dict[str, Any] = {"$or": ors}
    if time_start or time_end:
        rng: Dict[str, Any] = {}
        if time_start:
            rng["$gte"] = time_start
        if time_end:
            rng["$lte"] = time_end
        q["event.ts"] = rng
    return [d async for d in db[COLLECTION].find(q, {"_id": 0})]


def _depth(iid: Optional[str], parents: Dict[str, Optional[str]],
           seen: Optional[set] = None) -> int:
    """Lineage depth from parent_iid links. Cycle-safe, and an unobserved
    parent stops the chain rather than inventing an ancestor."""
    seen = seen or set()
    d = 0
    cur = iid
    while cur and cur in parents and parents[cur] and cur not in seen:
        seen.add(cur)
        cur = parents[cur]
        d += 1
        if d > 64:
            break
    return d


def build_lane_catalogue(docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic lane axis. Processes by lineage depth, then files,
    then network — an activity/causality order, never a severity rank."""
    lanes: Dict[str, Dict[str, Any]] = {}
    parents: Dict[str, Optional[str]] = {}
    for doc in docs:
        ev = _ev(doc)
        group, lane_id, label = _group_and_key(ev)
        ts = _ts(doc, ev)
        proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
        if group == "PROCESS" and proc.get("iid"):
            parents[str(proc["iid"])] = (str(proc["parent_iid"])
                                         if proc.get("parent_iid") else None)
        lane = lanes.setdefault(lane_id, {
            "lane_id": lane_id, "group": group, "label": label,
            "process_iid": proc.get("iid") if group == "PROCESS" else None,
            "parent_iid": proc.get("parent_iid") if group == "PROCESS"
            else None,
            "parent_state": ("OBSERVED" if proc.get("parent_iid")
                             else "NOT_OBSERVED") if group == "PROCESS"
            else "NOT_APPLICABLE",
            "first_seen": ts, "last_seen": ts, "count": 0})
        lane["count"] += 1
        if ts:
            if not lane["first_seen"] or ts < lane["first_seen"]:
                lane["first_seen"] = ts
            if not lane["last_seen"] or ts > lane["last_seen"]:
                lane["last_seen"] = ts

    for lane in lanes.values():
        lane["depth"] = (_depth(lane.get("process_iid"), parents)
                         if lane["group"] == "PROCESS" else 0)

    order = {g: i for i, g in enumerate(GROUPS + ("OTHER",))}
    ranked = sorted(lanes.values(),
                    key=lambda ln: (order.get(ln["group"], 9), ln["depth"],
                                    ln["first_seen"] or "", ln["lane_id"]))
    for i, lane in enumerate(ranked):
        lane["lane_index"] = i
    digest = hashlib.sha256(
        "|".join(ln["lane_id"] for ln in ranked).encode()).hexdigest()[:16]
    return {"lanes": ranked, "by_id": {ln["lane_id"]: ln for ln in ranked},
            "lane_axis_version": digest,
            "group_counts": {g: sum(1 for ln in ranked if ln["group"] == g)
                             for g in GROUPS + ("OTHER",)}}


def _event_iid(doc: Dict[str, Any], ev: Dict[str, Any],
               lane_id: str) -> str:
    """A STABLE, UNIQUE identity per observation.

    `event.iid` alone is not unique — the same iid is reused across
    observations, and paging on it produced 8 duplicate rows out of 406
    in the Stage 1 proof. A viewport that merges pages must be able to
    de-duplicate, so the identity is composed of the canonical id plus a
    digest of the fields that distinguish this observation. It is derived
    only from persisted values, so it is identical on every request.
    """
    base = str(ev.get("iid") or doc.get("canonical_event_id")
               or doc.get("iid") or "obs")
    raw = _raw(ev)
    fingerprint = "|".join(str(v) for v in (
        _ts(doc, ev), lane_id, ev.get("kind"), doc.get("canonical_event_id"),
        doc.get("case_id"), raw.get("command_line") or raw.get("text"),
        raw.get("target"), raw.get("pid"), (ev.get("provenance") or {})
        .get("ingest_job_id")))
    return f"{base}#{hashlib.sha256(fingerprint.encode()).hexdigest()[:10]}"


def _project(doc: Dict[str, Any], lane: Dict[str, Any]) -> Dict[str, Any]:
    """One trajectory event. Provenance travels with it; a field with no
    evidence is omitted, never filled in."""
    ev = _ev(doc)
    raw = _raw(ev)
    proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
    return {
        "event_iid": _event_iid(doc, ev, lane["lane_id"]),
        "canonical_iid": ev.get("iid"),
        "timestamp": _ts(doc, ev),
        "event_type": ev.get("kind") or "observation",
        "lane_id": lane["lane_id"], "lane_index": lane["lane_index"],
        "lane_group": lane["group"],
        "process": proc.get("name"),
        "process_state": "OBSERVED" if proc.get("name") else "UNKNOWN",
        "process_iid": proc.get("iid") or doc.get("process_iid"),
        "parent_process_iid": proc.get("parent_iid"),
        "pid": raw.get("pid"), "ppid": raw.get("ppid"),
        "image": proc.get("image") or raw.get("image_path"),
        "command_line": raw.get("command_line") or raw.get("text"),
        "user": raw.get("user"),
        "file": raw.get("target") or raw.get("file"),
        "network": raw.get("remote_ip") or raw.get("destination"),
        "severity": ev.get("severity") or "info",
        "rule_id": raw.get("rule_id") or raw.get("rule_label"),
        "provenance": {
            "raw_event_id": ((ev.get("provenance") or {})
                             .get("ingest_job_id")),
            "canonical_event_id": doc.get("canonical_event_id"),
            "evidence_id": doc.get("iid") or ev.get("iid"),
            "incident_id": doc.get("case_id"),
            "adapter": doc.get("adapter"),
            "parser_state": ((ev.get("provenance") or {})
                             .get("parser_state")),
        },
    }


async def query_window(db, *, identity: Dict[str, Any],
                       time_start: Optional[str] = None,
                       time_end: Optional[str] = None,
                       lane_start: int = 0, lane_end: int = 40,
                       cursor: Optional[str] = None,
                       limit: int = 500) -> Dict[str, Any]:
    limit = max(1, min(int(limit), MAX_LIMIT))
    docs = await _scan(db, ident=identity, time_start=time_start,
                       time_end=time_end)
    cat = build_lane_catalogue(docs)

    rows: List[Dict[str, Any]] = []
    for doc in docs:
        _, lane_id, _ = _group_and_key(_ev(doc))
        lane = cat["by_id"].get(lane_id)
        if not lane:
            continue
        rows.append(_project(doc, lane))
    rows.sort(key=lambda r: (r["timestamp"] or "", r["event_iid"]))

    in_lane = [r for r in rows
               if lane_start <= r["lane_index"] < lane_end]
    after = _cursor_decode(cursor)
    if after:
        in_lane = [r for r in in_lane
                   if (r["timestamp"] or "", r["event_iid"])
                   > (after["ts"], after["iid"])]
    page = in_lane[:limit]
    has_more = len(in_lane) > len(page)
    nxt = (_cursor_encode(page[-1]["timestamp"] or "", page[-1]["event_iid"])
           if page and has_more else None)

    stamps = [r["timestamp"] for r in rows if r["timestamp"]]
    return {
        "engine_id": ENGINE_ID, "read_model": True,
        "endpoint": identity,
        "time_range": {"requested_start": time_start,
                       "requested_end": time_end,
                       "observed_start": min(stamps) if stamps else None,
                       "observed_end": max(stamps) if stamps else None},
        "lane_axis": {"lane_start": lane_start, "lane_end": lane_end,
                      "lane_axis_version": cat["lane_axis_version"],
                      "total_lanes": len(cat["lanes"]),
                      "group_counts": cat["group_counts"],
                      "lanes": [{k: ln[k] for k in
                                 ("lane_id", "lane_index", "group", "label",
                                  "depth", "process_iid",
                                  "parent_process_iid"
                                  if "parent_process_iid" in ln
                                  else "parent_iid", "parent_state",
                                  "first_seen", "last_seen", "count")}
                                for ln in cat["lanes"]
                                if lane_start <= ln["lane_index"]
                                < lane_end]},
        "events": page,
        "next_cursor": nxt, "has_more": has_more,
        "returned": len(page),
        "matched_in_window": len(in_lane),
        "matched_in_time_range": len(rows),
        "total_or_estimate": {"value": len(rows), "basis": "EXACT_COUNT_OF_"
                              "OBSERVATIONS_IN_REQUESTED_TIME_RANGE"},
        "provenance": {"source": COLLECTION,
                       "authoritative_chain": "edr_raw_events → canonical "
                       "evidence → this projection",
                       "creates_no_store": True},
    }


def empty_state(*, identity: Optional[Dict[str, Any]],
                enrolled: bool, observations_all_time: int,
                observations_in_window: int) -> Dict[str, Any]:
    """The honest state, named. Never a blank canvas and never a demo
    event on a production endpoint."""
    if not identity:
        return {"state": "ENDPOINT_NOT_RESOLVED",
                "message": "Select an endpoint to view operational Device "
                           "Trajectory."}
    if not enrolled and observations_all_time == 0:
        return {"state": "TELEMETRY_NOT_COLLECTED",
                "message": "Telemetry not collected — this reference has "
                           "never reported to NivXForge."}
    if observations_all_time == 0:
        return {"state": "NO_TELEMETRY",
                "message": "No telemetry available — endpoint has not "
                           "reported telemetry."}
    if observations_in_window == 0:
        return {"state": "NO_ACTIVITY_IN_RANGE",
                "message": "No activity observed in this time range. That "
                           "is an absence of observation, not an absence "
                           "of activity."}
    return {"state": "OBSERVED", "message": None}
