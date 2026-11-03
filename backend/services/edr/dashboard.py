"""EDR Dashboard · current fleet state and historical evidence, kept apart.

Two different questions share one screen, so the answer keeps them separate:

* **Fleet status** describes the LATEST successful read of the fleet. It is
  never relabelled by the historical date range — choosing September does not
  make today's blind endpoints a September measurement.
* **Sightings, activity and event history** are historical, selected on the
  OBSERVED UTC time the endpoint recorded, not on the time the platform
  ingested the record.

Counting happens before limiting: totals and distinct counts are computed over
the whole authorized, date-filtered result, and only the table rows are capped.
The scan itself is bounded and says so, because a dashboard that quietly reads
"the newest N" and prints a total is lying with arithmetic.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from deps import sync_collection

RAW = "edr_raw_events"
ENDPOINTS = "edr_endpoints"

#: One read of the dashboard reads at most this many raw events. Exceeded, the
#: board says so rather than presenting a partial count as a total.
SCAN_CAP = 40_000

#: An endpoint seen within this window is delivering now.
DELIVERING_WINDOW = timedelta(minutes=15)
STALE_WINDOW = timedelta(hours=24)

#: Observed time lives inside the payload, while the indexed field is ingest
#: time. Delivery can cross midnight — the September 23 sighting was ingested
#: on the 24th — so the scan widens by this much and the observed filter is
#: applied afterwards. Without the pad, a day-shifted sighting would vanish.
INGEST_PAD = timedelta(days=3)

ACTIVITY_LABEL = {"PROCESS_OBSERVED": "Process observed",
                  "CREATE": "File created", "MODIFY": "File modified",
                  "DELETE": "File deleted"}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _payload(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = doc.get("payload")
    if isinstance(p, dict):
        return p
    try:
        return json.loads(p) if p else None
    except (TypeError, ValueError):
        return None


def _path_of(p: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    for f in ("image_path", "image", "path"):
        if p.get(f):
            return str(p[f]), f
    return None, None


def fleet_status(tenant_id: str) -> Dict[str, Any]:
    """The latest successful read of the fleet — not a historical measurement."""
    eps = sync_collection(ENDPOINTS)
    raw = sync_collection(RAW)
    now = datetime.now(timezone.utc)
    enrolled = eps.count_documents({"tenant_id": tenant_id})
    delivering = set(raw.distinct("endpoint_ref", {
        "tenant_id": tenant_id,
        "ingest_time": {"$gte": _iso(now - DELIVERING_WINDOW)}}))
    recent = set(raw.distinct("endpoint_ref", {
        "tenant_id": tenant_id,
        "ingest_time": {"$gte": _iso(now - STALE_WINDOW)}}))
    stale = recent - delivering
    blind = max(0, enrolled - len(recent))
    return {
        "enrolled": enrolled,
        "delivering": len(delivering),
        "stale": len(stale),
        "blind": blind,
        "last_read_at": _iso(now),
        "basis": (f"Delivering = telemetry within {int(DELIVERING_WINDOW.total_seconds() // 60)} "
                  f"minutes; stale = within 24 hours; blind = nothing in 24 "
                  f"hours. This is the latest read of the fleet and is not "
                  f"affected by the historical date range."),
        "condition": ("FLEET_VISIBILITY_LOST" if enrolled and not delivering
                      else "PARTIAL_VISIBILITY" if blind or stale
                      else "DELIVERING"),
        "headline": (f"Fleet visibility lost · 0 of {enrolled} enrolled "
                     f"endpoints delivering" if enrolled and not delivering
                     else f"{len(delivering)} of {enrolled} enrolled endpoints "
                          f"delivering" + (f" · {blind} blind" if blind else "")),
    }


def board(tenant_id: str, *, start: str, end: str,
          sha256: Optional[str] = None, path_contains: Optional[str] = None,
          activity: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    """Historical evidence for one customer between two OBSERVED UTC times."""
    raw = sync_collection(RAW)
    try:
        s_dt = datetime.fromisoformat(start)
        e_dt = datetime.fromisoformat(end)
    except ValueError:
        return {"ok": False, "reason": "INVALID_RANGE",
                "note": "start and end must be ISO-8601 UTC timestamps"}
    if e_dt <= s_dt:
        return {"ok": False, "reason": "EMPTY_RANGE",
                "note": ("the range ends before it starts, so nothing was "
                         "looked up. This is not an empty result.")}

    # A filtered read must reach the whole window, not only the newest
    # SCAN_CAP events: the /var/tmp creations of September are the oldest
    # records in a six-week range, and a cap that silently excludes them
    # answers "nothing matched" to a question it never asked. Pushing the
    # filter into the query shrinks the candidate set to something the cap
    # comfortably contains.
    q: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "ingest_time": {"$gte": _iso(s_dt - INGEST_PAD),
                        "$lte": _iso(e_dt + INGEST_PAD)}}
    narrowed = []
    if sha256:
        q["payload"] = {"$regex": re.escape(sha256.lower())}
        narrowed.append("file digest")
    elif path_contains and path_contains.strip():
        q["payload"] = {"$regex": re.escape(path_contains.strip())}
        narrowed.append("path filter")

    cur = raw.find(
        q,
        projection={"_id": 0, "raw_id": 1, "endpoint_ref": 1, "payload": 1,
                    "ingest_time": 1, "trust_state": 1},
    ).sort("ingest_time", -1).limit(SCAN_CAP + 1)

    scanned = 0
    rows: List[Dict[str, Any]] = []
    for doc in cur:
        scanned += 1
        if scanned > SCAN_CAP:
            break
        p = _payload(doc)
        if not p:
            continue
        observed = str(p.get("observed_at") or "")
        if not (start <= observed <= end):
            continue
        digest = str(p.get("sha256") or "").lower() or None
        path, field = _path_of(p)
        act = str(p.get("operation") or p.get("activity") or "UNSPECIFIED")
        rows.append({
            "raw_id": doc.get("raw_id"),
            "endpoint_id": doc.get("endpoint_ref"),
            "observed_at": observed,
            "ingested_at": doc.get("ingest_time"),
            "sha256": digest,
            "path": path,
            "path_field": field,
            "activity": act,
            "activity_label": ACTIVITY_LABEL.get(act, act),
            "pid": p.get("pid"),
            "trust_state": doc.get("trust_state"),
        })

    truncated = scanned > SCAN_CAP
    with_digest = [r for r in rows if r["sha256"]]

    # ── files, counted across the whole date-filtered result ────────────────
    by_file: Dict[str, Dict[str, Any]] = {}
    for r in with_digest:
        f = by_file.setdefault(r["sha256"], {
            "sha256": r["sha256"], "sightings": 0, "names": [], "paths": set(),
            "endpoints": set(), "activities": {}})
        f["sightings"] += 1
        if r["path"]:
            f["paths"].add(r["path"])
            leaf = r["path"].rsplit("/", 1)[-1]
            if leaf and leaf not in f["names"]:
                f["names"].append(leaf)
        if r["endpoint_id"]:
            f["endpoints"].add(r["endpoint_id"])
        f["activities"][r["activity"]] = f["activities"].get(r["activity"], 0) + 1

    files = sorted(by_file.values(), key=lambda f: -f["sightings"])
    top = [{"sha256": f["sha256"],
            "name": (f["names"][0] if f["names"] else f["sha256"][:12]),
            "sightings": f["sightings"],
            "paths": len(f["paths"]),
            "endpoints": len(f["endpoints"]),
            "activities": {ACTIVITY_LABEL.get(k, k): v
                           for k, v in sorted(f["activities"].items(),
                                              key=lambda kv: -kv[1])}}
           for f in files[:10]]

    selected = sha256.lower() if sha256 else (top[0]["sha256"] if top else None)
    sel = by_file.get(selected) if selected else None
    selected_file = {
        "sha256": selected,
        "name": (sel["names"][0] if sel and sel["names"]
                 else (selected[:12] if selected else None)),
        "sightings": sel["sightings"] if sel else 0,
        "activities": {ACTIVITY_LABEL.get(k, k): v
                       for k, v in sorted((sel or {}).get("activities", {}).items(),
                                          key=lambda kv: -kv[1])},
        "recorded_paths": len(sel["paths"]) if sel else 0,
        "computers": len(sel["endpoints"]) if sel else 0,
        "observation_note": ("A process observation is a sensor observation, "
                             "not a launch: /proc polling emits one row per "
                             "process identity it saw and can repeat for the "
                             "same running process across reads."),
    } if selected else None

    # ── event history: filter, then count, then limit ───────────────────────
    # Only an explicitly requested file narrows the table. The board selects a
    # file for the activity panel by default, and letting that default also
    # filter the table made a path filter answer "0 of 0 for python3.11" to a
    # question about /usr/bin/sleep.
    scope = [r for r in rows if not sha256 or r["sha256"] == selected]
    needle = (path_contains or "").strip().lower()
    if needle:
        scope = [r for r in scope if needle in str(r["path"] or "").lower()]
    if activity and activity != "ALL":
        scope = [r for r in scope if r["activity"] == activity]
    scope.sort(key=lambda r: r["observed_at"], reverse=True)
    capped = scope[:max(1, min(limit, 500))]

    return {
        "ok": True,
        "tenant_id": tenant_id,
        "range": {"start": start, "end": end, "basis": "observed UTC"},
        "files": top,
        "files_total": len(files),
        "files_note": (f"Top {len(top)} files by sightings"
                       + (f" of {len(files)} in range" if len(files) > len(top)
                          else "")),
        "selected_file": selected_file,
        "events": capped,
        "events_matching": len(scope),
        "events_note": (f"Showing {len(capped)} of {len(scope)} matching "
                        f"sightings"
                        + (f" for {selected_file['name']}"
                           if sha256 and selected_file else "")
                        + (f", filtered on {' and '.join(narrowed)} across the "
                           f"whole window" if narrowed else "")),
        "sightings_in_range": len(rows),
        "activities_available": sorted({r["activity"] for r in scope}
                                       | {r["activity"] for r in rows}),
        "scan": {"events_read": min(scanned, SCAN_CAP), "cap": SCAN_CAP,
                 "truncated": truncated,
                 "note": (f"More than {SCAN_CAP} events were delivered in this "
                          f"window; the newest {SCAN_CAP} were read, so the "
                          f"counts describe that subset"
                          if truncated else
                          "every event delivered in this window was read, so "
                          "the counts are totals, not a subset"),
                 "ingest_pad_days": INGEST_PAD.days,
                 "observed_basis": ("rows are selected on the time the "
                                    "ENDPOINT observed them; the scan widens "
                                    "by 3 days on either side so a sighting "
                                    "delivered after midnight is not lost")},
    }
