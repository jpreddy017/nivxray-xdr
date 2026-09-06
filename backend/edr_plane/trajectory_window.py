"""Endpoint-scoped WINDOWED Device Trajectory projection.

    edr_raw_events → canonical evidence (v2_shadow_observations)
                   → this projection → viewport

It is a read/projection layer and creates no store of its own.

Two axes, and the backend owns both mappings:

  * TIME  — `time_start` / `time_end`, paged with an opaque cursor of
    (timestamp, event_iid) so a page boundary can never duplicate or
    skip an event.
  * LANE  — `lane_start` / `lane_end` are indices into a DETERMINISTIC
    lane catalogue: processes first by lineage depth, then files, then
    network. Lane identity is a stable key (`process_iid`, file path,
    remote peer), never a severity rank.

THE LANE AXIS IS ENDPOINT-WIDE, NOT WINDOW-WIDE.  It is built from the
endpoint's whole observed history and the time window is applied only to
events.  The earlier build derived the catalogue from the time-filtered
documents, so lane 300 meant a different row in every window and deep
lane slices came back empty as soon as the viewport narrowed — the
analyst scrolled into rows that the request had renumbered out of
existence. An axis that renumbers under a scrolling analyst shows the
wrong row's evidence, so it is now invariant to the viewport and carries
`lane_axis_version` for the client to detect real catalogue growth.

Dispositions and `detected_by` are derived from persisted evidence only.
Nothing is ever called CLEAN: absence of a detection is not a verdict,
so unassessed activity is reported as UNKNOWN_NOT_ASSESSED.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID = "nivxray::edr_plane::trajectory_window"
COLLECTION = "v2_shadow_observations"
GROUPS = ("PROCESS", "FILE", "NETWORK")
MAX_LIMIT = 4000

#: Canonical kinds → lane group. Anything unrecognised goes to PROCESS
#: only if it carries process evidence; otherwise it is OTHER and is
#: reported as such rather than being drawn on a lane it does not belong
#: to.
_FILE_KINDS = {"file_create", "file_write", "file_delete", "file_modify",
               "file_rename", "image_load", "file"}
_NET_KINDS = {"network_connect", "network", "dns_query", "dns",
              "network_accept", "network_listen", "http_request"}

DISPOSITION_MALICIOUS = "MALICIOUS"
DISPOSITION_SUSPICIOUS = "SUSPICIOUS"
DISPOSITION_UNKNOWN = "UNKNOWN_NOT_ASSESSED"

_MALICIOUS_LABELS = {"malicious", "high", "critical", "compromise"}
_SUSPICIOUS_LABELS = {"medium", "suspicious", "anomalous"}

# Short-lived projection cache. A pan issues many overlapping windows
# over the SAME endpoint history; re-reading and re-projecting it per
# request is the difference between a fluid trajectory and a request
# that times out. Bounded and TTL'd, keyed by endpoint identity, and
# holding only derived values — it can never become a second store of
# record.
_SCAN_TTL_S = 90.0
_SCAN_MAX = 6
_proj_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


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


def _prov(ev: Dict[str, Any]) -> Dict[str, Any]:
    p = ev.get("provenance")
    return p if isinstance(p, dict) else {}


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


def _identity_key(ident: Dict[str, Any]) -> str:
    return f"{ident.get('device_iid') or ''}|{ident.get('hostname') or ''}"


async def _projected(db, *, ident: Dict[str, Any]) -> Dict[str, Any]:
    """The endpoint's whole observed history, projected once.

    Deliberately NOT time filtered: the lane axis is invariant to the
    viewport, which is what makes deep activity rows resolve at every
    zoom level.
    """
    key = _identity_key(ident)
    now = time.time()
    hit = _proj_cache.get(key)
    if hit and hit[0] > now:
        return hit[1]

    iid = ident.get("device_iid")
    host = ident.get("hostname")
    ors: List[Dict[str, Any]] = []
    if iid:
        ors += [{"event.device_iid": iid}, {"device_iid": iid}]
    if host:
        ors += [{"event.raw.computer": host}, {"event.computer": host},
                {"event.raw.hostname": host}]
    if not ors:
        return {"cat": build_lane_catalogue([]), "rows": []}
    docs = [d async for d in db[COLLECTION].find({"$or": ors}, {"_id": 0})]
    cat = build_lane_catalogue(docs)
    rows: List[Dict[str, Any]] = []
    for doc in docs:
        _, lane_id, _ = _group_and_key(_ev(doc))
        lane = cat["by_id"].get(lane_id)
        if lane:
            rows.append(_project(doc, lane))
    rows.sort(key=lambda r: (r["timestamp"] or "", r["event_iid"]))
    out = {"cat": cat, "rows": rows}

    if len(_proj_cache) >= _SCAN_MAX:
        _proj_cache.pop(next(iter(_proj_cache)), None)
    _proj_cache[key] = (now + _SCAN_TTL_S, out)
    return out


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


def classify(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Disposition + attribution from persisted evidence only."""
    raw = _raw(ev)
    labels = [str(x).lower() for x in (ev.get("labels") or [])
              if isinstance(x, (str, int))]
    mitre = [str(x) for x in (ev.get("mitre") or []) if x]
    conf = str(raw.get("confidence") or "").lower()
    kind = str(ev.get("kind") or "").lower()

    disposition = DISPOSITION_UNKNOWN
    if set(labels) & _MALICIOUS_LABELS or conf == "high":
        disposition = DISPOSITION_MALICIOUS
    elif set(labels) & _SUSPICIOUS_LABELS or conf == "medium":
        disposition = DISPOSITION_SUSPICIOUS

    return {
        "disposition": disposition,
        "is_detection": kind == "detection",
        "labels": labels,
        "mitre": mitre,
        "attributed": bool(mitre),
    }


def detected_by(doc: Dict[str, Any], ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Which engine produced this — named from provenance, never guessed.

    An empty list is a real answer: the observation is telemetry that no
    detection engine has claimed.
    """
    raw = _raw(ev)
    prov = _prov(ev)
    out: List[Dict[str, Any]] = []

    rule_id = raw.get("rule_id")
    if rule_id:  # a rule actually fired
        out.append({
            "engine": "NivXRay detection content",
            "component": raw.get("source") or prov.get("parser"),
            "rule_id": rule_id,
            "rule_label": raw.get("rule_label"),
            "confidence": raw.get("confidence"),
            "basis": "event.raw.rule_id",
        })
    for corr in (prov.get("correlation") or []):
        if corr and corr != rule_id:
            out.append({"engine": "NivXRay correlation",
                        "rule_id": corr, "basis": "provenance.correlation"})
    if str(ev.get("kind") or "").lower() == "detection":
        out.append({
            "engine": prov.get("source") or ev.get("adapter") or "sensor",
            "component": prov.get("normalizer") or prov.get("adapter"),
            "detail": raw.get("rule_label"),
            "basis": "canonical kind=detection",
        })
    if not out:
        origin = prov.get("origin") or doc.get("adapter")
        out.append({
            "engine": None,
            "component": origin,
            "basis": "no detection engine claimed this observation",
            "telemetry_only": True,
        })
    return out


def _artefact_files(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    art = ev.get("artefacts")
    files = (art or {}).get("file") if isinstance(art, dict) else None
    out = []
    for f in files or []:
        if isinstance(f, dict):
            out.append({"iid": f.get("iid"), "path": f.get("path"),
                        "sha256": f.get("sha256")})
    return out


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
        cls = classify(ev)
        if group == "PROCESS" and proc.get("iid"):
            parents[str(proc["iid"])] = (str(proc["parent_iid"])
                                         if proc.get("parent_iid") else None)
        lane = lanes.setdefault(lane_id, {
            "lane_id": lane_id, "group": group, "label": label,
            "process_iid": proc.get("iid") if group == "PROCESS" else None,
            "parent_iid": proc.get("parent_iid") if group == "PROCESS"
            else None,
            # Three distinct truths, never collapsed into one: the
            # sensor reported no parent at all; it reported a parent we
            # never observed; or the parent is a row on this axis.
            "parent_state": ("PENDING" if proc.get("parent_iid")
                             else "PARENT_NOT_REPORTED_BY_SENSOR")
            if group == "PROCESS" else "NOT_APPLICABLE",
            "image": proc.get("image") or _raw(ev).get("image_path"),
            "user": _raw(ev).get("user") or None,
            "first_seen": ts, "last_seen": ts, "count": 0,
            "malicious_count": 0, "suspicious_count": 0,
            "detection_count": 0, "attributed_count": 0,
            "exit_observed": False})
        lane["count"] += 1
        if str(ev.get("kind") or "").lower() == "process_exit":
            lane["exit_observed"] = True
        if cls["disposition"] == DISPOSITION_MALICIOUS:
            lane["malicious_count"] += 1
        elif cls["disposition"] == DISPOSITION_SUSPICIOUS:
            lane["suspicious_count"] += 1
        if cls["is_detection"]:
            lane["detection_count"] += 1
        if cls["attributed"]:
            lane["attributed_count"] += 1
        if not lane.get("image"):
            lane["image"] = proc.get("image") or _raw(ev).get("image_path")
        if not lane.get("user"):
            lane["user"] = _raw(ev).get("user") or None
        if ts:
            if not lane["first_seen"] or ts < lane["first_seen"]:
                lane["first_seen"] = ts
            if not lane["last_seen"] or ts > lane["last_seen"]:
                lane["last_seen"] = ts

    for lane in lanes.values():
        lane["depth"] = (_depth(lane.get("process_iid"), parents)
                         if lane["group"] == "PROCESS" else 0)

    # ── Lineage pre-order ────────────────────────────────────────
    # Ordering by (group, depth, first_seen) put every root first and
    # its children hundreds of rows away, so a real parent→child chain
    # rendered as a stack of unrelated rows. Cisco's vertical axis reads
    # as lineage: a process is immediately followed by the processes it
    # spawned. So the axis is a depth-first pre-order over the OBSERVED
    # lineage — derived from process_iid/parent_iid only, never from PID
    # and never invented. Files and network peers follow, as Cisco's
    # "Files & Network" section does.
    proc = [ln for ln in lanes.values() if ln["group"] == "PROCESS"]
    by_iid = {str(ln["process_iid"]): ln for ln in proc
              if ln.get("process_iid")}
    children: Dict[str, List[Dict[str, Any]]] = {}
    roots: List[Dict[str, Any]] = []
    for ln in proc:
        pid = str(ln["parent_iid"]) if ln.get("parent_iid") else None
        if pid and pid in by_iid:
            children.setdefault(pid, []).append(ln)
        else:
            roots.append(ln)
    key = lambda ln: (ln["first_seen"] or "", ln["lane_id"])  # noqa: E731
    roots.sort(key=key)
    for kids in children.values():
        kids.sort(key=key)

    ranked: List[Dict[str, Any]] = []
    seen_iids: set = set()
    stack = list(reversed(roots))
    while stack:
        ln = stack.pop()
        iid = str(ln.get("process_iid") or "")
        if iid in seen_iids:          # cycle-safe
            continue
        seen_iids.add(iid)
        ranked.append(ln)
        for kid in reversed(children.get(iid, [])):
            stack.append(kid)
    # A process caught in a lineage cycle would otherwise be dropped
    # from the axis entirely; it is appended rather than hidden.
    for ln in sorted(proc, key=key):
        if str(ln.get("process_iid") or "") not in seen_iids:
            ranked.append(ln)
            seen_iids.add(str(ln.get("process_iid") or ""))

    order = {g: i for i, g in enumerate(GROUPS + ("OTHER",))}
    ranked += sorted((ln for ln in lanes.values()
                      if ln["group"] != "PROCESS"),
                     key=lambda ln: (order.get(ln["group"], 9),
                                     ln["first_seen"] or "", ln["lane_id"]))
    for i, lane in enumerate(ranked):
        lane["lane_index"] = i

    # Parent→child connectors need the parent's ROW, and the parent row
    # is frequently outside the requested slice. Resolving it here is the
    # only way a windowed client can draw a lineage edge it cannot see
    # both ends of.
    by_proc = {ln["process_iid"]: ln for ln in ranked
               if ln.get("process_iid")}
    for lane in ranked:
        pid = lane.get("parent_iid")
        parent = by_proc.get(str(pid)) if pid else None
        lane["parent_lane_index"] = parent["lane_index"] if parent else None
        lane["parent_label"] = parent["label"] if parent else None
        if pid:
            lane["parent_state"] = ("OBSERVED" if parent
                                    else "PARENT_NOT_OBSERVED_VISIBILITY_GAP")
        # A process whose exit was never reported has an OPEN lifeline.
        # Drawing it as if it ended at its last observation would assert
        # a termination nothing observed.
        lane["end_state"] = (
            "NOT_APPLICABLE" if lane["group"] != "PROCESS"
            else "EXIT_OBSERVED" if lane["exit_observed"]
            else "END_NOT_OBSERVED")

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
        raw.get("target"), raw.get("pid"), _prov(ev).get("ingest_job_id")))
    return f"{base}#{hashlib.sha256(fingerprint.encode()).hexdigest()[:10]}"


def _project(doc: Dict[str, Any], lane: Dict[str, Any]) -> Dict[str, Any]:
    """One trajectory event. Provenance travels with it; a field with no
    evidence is omitted, never filled in."""
    ev = _ev(doc)
    raw = _raw(ev)
    prov = _prov(ev)
    proc = ev.get("process") if isinstance(ev.get("process"), dict) else {}
    cls = classify(ev)
    files = _artefact_files(ev)
    return {
        "event_iid": _event_iid(doc, ev, lane["lane_id"]),
        "canonical_iid": ev.get("iid"),
        "timestamp": _ts(doc, ev),
        "event_type": ev.get("kind") or "observation",
        "action": raw.get("action"),
        "lane_id": lane["lane_id"], "lane_index": lane["lane_index"],
        "lane_group": lane["group"],
        "process": proc.get("name"),
        "process_state": "OBSERVED" if proc.get("name") else "UNKNOWN",
        "process_iid": proc.get("iid") or doc.get("process_iid"),
        "parent_process_iid": proc.get("parent_iid"),
        "parent_lane_index": lane.get("parent_lane_index"),
        "parent_process_name": lane.get("parent_label"),
        "parent_state": lane.get("parent_state"),
        "pid": raw.get("pid"), "ppid": raw.get("ppid"),
        "image": proc.get("image") or raw.get("image_path"),
        "command_line": raw.get("command_line") or raw.get("text"),
        "user": raw.get("user"),
        "file": raw.get("target") or raw.get("file"),
        "network": raw.get("remote_ip") or raw.get("destination")
        or (raw.get("entity") if lane["group"] == "NETWORK" else None),
        "entity": raw.get("entity"),
        # Naming that cannot be misread: this is a digest of the parsed
        # event content, NOT the SHA-256 of a file on disk.
        "event_content_digest": raw.get("sha256") or doc.get("input_sha256"),
        "file_artefacts": files,
        "file_sha256": files[0]["sha256"] if files else None,
        "disposition": cls["disposition"],
        "is_detection": cls["is_detection"],
        "attributed": cls["attributed"],
        "labels": cls["labels"], "mitre": cls["mitre"],
        "rule_id": raw.get("rule_id"),
        # `raw.rule_label` is the sensor's DISPLAY label ("bash · process
        # create"), not a detection rule. Surfacing it as a rule would
        # make every ordinary process look detected, so it is carried
        # under its real name and `rule_label` is populated only when a
        # rule actually fired.
        "display_label": raw.get("rule_label"),
        "rule_label": raw.get("rule_label") if raw.get("rule_id") else None,
        "detected_by": detected_by(doc, ev),
        "provenance": {
            "raw_event_id": prov.get("ingest_job_id"),
            "canonical_event_id": doc.get("canonical_event_id"),
            "evidence_id": doc.get("iid") or ev.get("iid"),
            "incident_id": doc.get("case_id"),
            "adapter": doc.get("adapter"),
            "origin": prov.get("origin"),
            "source": prov.get("source"),
            "normalizer": prov.get("normalizer"),
            "parser_state": prov.get("parser_state"),
        },
    }


def _matches(row: Dict[str, Any], kinds: Optional[set],
             needle: Optional[str], dispositions: Optional[set]) -> bool:
    if kinds and str(row.get("event_type") or "").lower() not in kinds:
        return False
    if dispositions and row.get("disposition") not in dispositions:
        return False
    if needle:
        corpus = " ".join(str(v) for v in (
            row.get("process"), row.get("image"), row.get("command_line"),
            row.get("file"), row.get("network"), row.get("user"),
            row.get("rule_id"), row.get("rule_label"),
            row.get("display_label"),
            row.get("file_sha256"), row.get("event_content_digest"),
            row.get("event_type"), " ".join(row.get("mitre") or []),
        ) if v)
        if needle not in corpus.lower():
            return False
    return True


DAY_MS = 86400000
DAY_BINS = 240          # 6-minute resolution across 24 h


def _activity(rows: List[Dict[str, Any]],
              hist_day: Optional[str]) -> Dict[str, Any]:
    """Per-day volume for the 30-day navigator + per-6-minute volume for
    the 24-hour navigator. Counts of persisted observations only — a day
    with nothing observed stays empty and is never interpolated."""
    days: Dict[str, Dict[str, int]] = {}
    bins: Dict[int, Dict[str, Any]] = {}
    for r in rows:
        ts = r.get("timestamp")
        if not ts:
            continue
        day = str(ts)[:10]
        rec = days.setdefault(day, {"total": 0, "malicious": 0,
                                    "suspicious": 0, "detections": 0})
        rec["total"] += 1
        if r["disposition"] == DISPOSITION_MALICIOUS:
            rec["malicious"] += 1
        elif r["disposition"] == DISPOSITION_SUSPICIOUS:
            rec["suspicious"] += 1
        if r.get("is_detection"):
            rec["detections"] += 1
        if hist_day and day == hist_day:
            hm = str(ts)[11:19]
            try:
                h, m, s = (int(x) for x in hm.split(":"))
            except Exception:  # noqa: BLE001
                continue
            idx = min(DAY_BINS - 1,
                      int(((h * 3600 + m * 60 + s) / 86400) * DAY_BINS))
            b = bins.setdefault(idx, {"bin": idx, "total": 0, "malicious": 0,
                                      "detections": 0,
                                      "first_event_iid": r["event_iid"],
                                      "first_timestamp": ts})
            b["total"] += 1
            if r["disposition"] == DISPOSITION_MALICIOUS:
                b["malicious"] += 1
            if r.get("is_detection"):
                b["detections"] += 1
            if ts < b["first_timestamp"]:
                b["first_timestamp"] = ts
                b["first_event_iid"] = r["event_iid"]
    return {
        "days": [{"day": k, **v} for k, v in sorted(days.items())],
        "day_bins": [bins[k] for k in sorted(bins)] if hist_day else [],
        "day_bins_for": hist_day,
        "day_bin_count": DAY_BINS,
        "basis": "COUNTS_OF_PERSISTED_OBSERVATIONS",
    }


async def query_window(db, *, identity: Dict[str, Any],
                       time_start: Optional[str] = None,
                       time_end: Optional[str] = None,
                       lane_start: int = 0, lane_end: int = 40,
                       cursor: Optional[str] = None,
                       limit: int = 500,
                       kinds: Optional[str] = None,
                       q: Optional[str] = None,
                       dispositions: Optional[str] = None,
                       hist_day: Optional[str] = None) -> Dict[str, Any]:
    limit = max(1, min(int(limit), MAX_LIMIT))
    proj = await _projected(db, ident=identity)
    cat = proj["cat"]
    all_rows = proj["rows"]

    kind_set = ({k.strip().lower() for k in kinds.split(",") if k.strip()}
                if kinds else None)
    disp_set = ({d.strip().upper() for d in dispositions.split(",")
                 if d.strip()} if dispositions else None)
    needle = q.strip().lower() if q and q.strip() else None
    filtered = [r for r in all_rows
                if _matches(r, kind_set, needle, disp_set)]

    # A filter is an explicit analyst action, and Cisco visibly reduces
    # the trajectory to the matching artefacts. So when a filter is
    # active the axis is REBUILT over the rows that matched — otherwise a
    # single matching detection would sit on a row the analyst has to
    # hunt for. The unfiltered axis stays viewport-invariant; this axis
    # is filter-scoped and says so.
    axis_lanes = cat["lanes"]
    axis_version = cat["lane_axis_version"]
    axis_scope = "ENDPOINT_WIDE_INVARIANT_TO_VIEWPORT"
    if kind_set or disp_set or needle:
        keep_ids = {r["lane_id"] for r in filtered}
        kept = [ln for ln in cat["lanes"] if ln["lane_id"] in keep_ids]
        remap = {ln["lane_id"]: i for i, ln in enumerate(kept)}
        by_old_index = {ln["lane_index"]: ln for ln in cat["lanes"]}
        axis_lanes = []
        for i, ln in enumerate(kept):
            new = dict(ln)
            new["lane_index"] = i
            p_old = ln.get("parent_lane_index")
            p_lane = by_old_index.get(p_old) if p_old is not None else None
            new["parent_lane_index"] = (remap.get(p_lane["lane_id"])
                                        if p_lane else None)
            if ln.get("parent_iid") and new["parent_lane_index"] is None:
                new["parent_state"] = "PARENT_NOT_IN_FILTERED_VIEW"
            axis_lanes.append(new)
        axis_version = hashlib.sha256(
            ("|".join(ln["lane_id"] for ln in kept)
             + f"#{sorted(kind_set or [])}{sorted(disp_set or [])}{needle}")
            .encode()).hexdigest()[:16]
        axis_scope = "FILTER_SCOPED_ROWS_WITH_MATCHING_ACTIVITY"
        rebound = []
        for r in filtered:
            row = dict(r)
            row["lane_index"] = remap[r["lane_id"]]
            p_old = r.get("parent_lane_index")
            p_lane = by_old_index.get(p_old) if p_old is not None else None
            row["parent_lane_index"] = (remap.get(p_lane["lane_id"])
                                        if p_lane else None)
            rebound.append(row)
        filtered = rebound

    in_time = [r for r in filtered
               if (not time_start or (r["timestamp"] or "") >= time_start)
               and (not time_end or (r["timestamp"] or "") <= time_end)]
    in_lane = [r for r in in_time
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

    stamps = [r["timestamp"] for r in all_rows if r["timestamp"]]
    lane_fields = ("lane_id", "lane_index", "group", "label", "depth",
                   "process_iid", "parent_iid", "parent_lane_index",
                   "parent_label", "parent_state", "end_state",
                   "exit_observed", "image", "user", "first_seen",
                   "last_seen", "count", "malicious_count",
                   "suspicious_count", "detection_count",
                   "attributed_count")
    return {
        "engine_id": ENGINE_ID, "read_model": True,
        "endpoint": identity,
        "time_range": {"requested_start": time_start,
                       "requested_end": time_end,
                       "observed_start": min(stamps) if stamps else None,
                       "observed_end": max(stamps) if stamps else None},
        "lane_axis": {"lane_start": lane_start, "lane_end": lane_end,
                      "lane_axis_version": axis_version,
                      "total_lanes": len(axis_lanes),
                      "axis_scope": axis_scope,
                      "group_counts": cat["group_counts"],
                      "lanes": [{k: ln.get(k) for k in lane_fields}
                                for ln in axis_lanes
                                if lane_start <= ln["lane_index"]
                                < lane_end]},
        "events": page,
        "next_cursor": nxt, "has_more": has_more,
        "returned": len(page),
        "matched_in_window": len(in_lane),
        "matched_in_time_range": len(in_time),
        "matched_after_filters": len(filtered),
        "observations_all_time": len(all_rows),
        "activity": _activity(filtered, hist_day),
        "filters_applied": {"kinds": sorted(kind_set) if kind_set else [],
                            "q": needle,
                            "dispositions": sorted(disp_set) if disp_set
                            else []},
        "event_type_counts": _type_counts(all_rows),
        "total_or_estimate": {"value": len(in_time), "basis": "EXACT_COUNT_"
                              "OF_OBSERVATIONS_IN_REQUESTED_TIME_RANGE"},
        "provenance": {"source": COLLECTION,
                       "authoritative_chain": "edr_raw_events → canonical "
                       "evidence → this projection",
                       "creates_no_store": True},
    }


def _type_counts(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for r in rows:
        k = str(r.get("event_type") or "observation")
        counts[k] = counts.get(k, 0) + 1
    return [{"event_type": k, "count": v}
            for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]


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
