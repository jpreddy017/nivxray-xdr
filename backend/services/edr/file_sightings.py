"""SHA-256 file sightings across one customer's endpoints.

`file_trajectory.py` keys on `v2_shadow_observations.artefacts.file[].sha256`
and correctly reports that the field is unpopulated. That is true of THAT
substrate, but it is no longer the whole picture: the Linux sensor reports the
digest of the executed image on every PROCESS_OBSERVED event, and those land in
`edr_raw_events.payload.sha256`.

Verified on the preview substrate before this module was written (tenant
`default`, 360,660 raw events):

  * `payload.sha256` is NEVER equal to the record's `payload_sha256` (0 of 1001
    sampled) — so it is not the evidence-integrity digest.
  * 55 distinct digests, and no digest appears under more than one
    `image_path` — a stable content→path mapping, i.e. a real file digest.
  * One digest (`17a623f3…`) appears under 14 distinct paths: the same content
    executed from `/usr/bin/sleep` and from copies under `/var/tmp`. That is a
    file trajectory in the plain sense of the word.

What a sighting means: this content was EXECUTED from this path
(`PROCESS_OBSERVED`), or was CREATED at it where the sensor watches that
directory (`FILE`/`CREATE` — 12 of the 809 sightings of `17a623f3…` are
creations under `/var/tmp/nivxforge-watch/`). File write, delete, move, scan and
quarantine are not observed at all, so absence here is never absence of a file.

Time rule: a sighting is placed at `payload.observed_at` — when the endpoint
observed it — never at `ingest_time`. The two fall on different UTC days
whenever delivery lags midnight, and an analyst sent to the ingest day is sent
to a day the evidence is not on.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from deps import sync_collection

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# A digest can carry thousands of sightings. Read a bounded slice and SAY the
# answer is bounded, rather than silently presenting part of the evidence as
# all of it.
SCAN_CAP = 4000
DEFAULT_LIMIT = 300

EVIDENCE_BASIS = ("edr_raw_events.payload.sha256 — the digest of the executed "
                  "image as reported by the endpoint sensor")


def _day(ts: Optional[str]) -> Optional[str]:
    return str(ts)[:10] if ts else None


#: Which payload field supplied a sighting's path, traced to the sensor
#: (`agents/nivxforge-linux/nivxforge_sensor.py`):
#:   * `image_path` — `collect_processes` reads `/proc/<pid>/exe` and hashes
#:     THAT file, so the digest belongs to the executed image at this path.
#:   * `path` — `collect_files` walks the watched directory and hashes the
#:     file it found, so the digest belongs to the file created at this path.
#: Naming the field is the difference between "this ran" and "this appeared".
PATH_FIELDS = ("image_path", "image", "path")


def _path_of(payload: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    for f in PATH_FIELDS:
        v = payload.get(f)
        if v:
            return str(v), f
    return None, None


def _sighting(doc: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    observed = payload.get("observed_at")
    ingested = doc.get("ingest_time")
    ingested = ingested if isinstance(ingested, str) else (
        ingested.isoformat() if ingested else None)
    path, path_field = _path_of(payload)
    return {
        "raw_id": doc.get("raw_id"),
        "endpoint_id": doc.get("endpoint_ref"),
        # A PROCESS_OBSERVED event names the executed image; a FILE/CREATE
        # event names the file it created. Both are this digest's own path.
        "path": path,
        "path_field": path_field,
        "size": payload.get("size"),
        "start_time": payload.get("start_time"),
        "activity_family": payload.get("activity"),
        "image": payload.get("image"),
        "activity": payload.get("operation") or payload.get("activity"),
        "observed_at": observed,
        "ingested_at": ingested,
        # The analyst is sent to the day the ENDPOINT saw it. When ingestion
        # lands on another UTC day, say so on the row itself.
        "observed_day_utc": _day(observed),
        "ingest_day_utc": _day(ingested),
        "ingest_day_differs": bool(observed and ingested
                                   and _day(observed) != _day(ingested)),
        "pid": payload.get("pid"),
        "ppid": payload.get("ppid"),
        "user": payload.get("user"),
        "command_line": payload.get("command_line"),
        "parent_image": payload.get("parent_image"),
        "collection_method": payload.get("collection_method"),
        "sensor_version": payload.get("sensor_version") or doc.get("sensor_version"),
        "trust_state": doc.get("trust_state"),
    }


def sightings(sha256: str, tenant_id: str,
              limit: int = DEFAULT_LIMIT,
              path_contains: Optional[str] = None) -> Dict[str, Any]:
    """Every sighting of one content digest within ONE customer.

    `tenant_id` is the server-resolved acting customer (see
    `routers.edr_tenancy.edr_tenant`); it is never taken from the query, so a
    hash cannot be used to read another customer's endpoints.

    `path_contains` is applied to EVERY authorized sighting before the
    per-endpoint limit. Filtering only the rows a capped read happened to
    return would hide the very creations an analyst filters for: the 12
    `/var/tmp` creations of `17a623f3…` are older than its newest 300
    executions, so a client-side filter finds nothing and reads as "never
    created there".
    """
    key = (sha256 or "").strip().lower()
    if not SHA256_RE.match(key):
        return {"ok": False, "reason": "INVALID_SHA256", "key": sha256,
                "note": ("A SHA-256 is 64 hexadecimal characters. Nothing was "
                         "looked up, so this is not an empty result.")}

    col = sync_collection("edr_raw_events")
    query = {"tenant_id": tenant_id,
             "payload": {"$regex": f'"sha256": ?"{key}"'}}
    docs = list(col.find(query, {
        "_id": 0, "raw_id": 1, "endpoint_ref": 1, "ingest_time": 1,
        "payload": 1, "sensor_version": 1, "trust_state": 1,
    }).limit(SCAN_CAP))

    rows: List[Dict[str, Any]] = []
    for d in docs:
        payload = d.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                continue
        if not isinstance(payload, dict):
            continue
        # The regex is a substring test; the digest itself is the authority.
        if str(payload.get("sha256") or "").lower() != key:
            continue
        rows.append(_sighting(d, payload))

    rows.sort(key=lambda r: str(r.get("observed_at") or ""), reverse=True)

    # ── the path filter, across the WHOLE history, before any limit ──────────
    needle = (path_contains or "").strip()
    all_rows = rows
    if needle:
        rows = [r for r in all_rows
                if needle.lower() in str(r.get("path") or "").lower()]
    filter_state = {
        "path_contains": needle or None,
        "matched_sightings": len(rows),
        "of_sightings": len(all_rows),
        "applied": ("across every authorized sighting, before the "
                    "per-endpoint limit"),
    } if needle else {"path_contains": None, "matched_sightings": None,
                      "of_sightings": len(all_rows), "applied": None}

    # Every path the digest was ever seen at stays visible even under a
    # filter: File details is where an analyst learns a /var/tmp copy exists
    # in the first place, and hiding it would hide the reason to filter.
    all_paths: List[str] = []
    for r in all_rows:
        if r.get("path") and r["path"] not in all_paths:
            all_paths.append(r["path"])

    # ── per-endpoint rollup, hostname only where the endpoint is registered ──
    refs = sorted({r["endpoint_id"] for r in rows if r.get("endpoint_id")})
    known: Dict[str, Dict[str, Any]] = {}
    if refs:
        for e in sync_collection("edr_endpoints").find(
                {"tenant_id": tenant_id, "endpoint_id": {"$in": refs}},
                {"_id": 0, "endpoint_id": 1, "hostname": 1, "os": 1,
                 "status": 1}):
            known[e["endpoint_id"]] = e

    endpoints: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        ref = r.get("endpoint_id") or "__unattributed__"
        ep = endpoints.get(ref)
        if ep is None:
            reg = known.get(ref)
            ep = endpoints[ref] = {
                "endpoint_id": r.get("endpoint_id"),
                "hostname": (reg or {}).get("hostname"),
                "os": (reg or {}).get("os"),
                "status": (reg or {}).get("status"),
                # An endpoint_ref on an event is not proof of a registered
                # endpoint; the two facts are reported separately.
                "identity": "registered" if reg else "unregistered_reference",
                "sighting_count": 0,
                "paths": [],
                "first_observed": None,
                "last_observed": None,
                "sightings": [],
            }
        ep["sighting_count"] += 1
        if r.get("path") and r["path"] not in ep["paths"]:
            ep["paths"].append(r["path"])
        ts = r.get("observed_at")
        if ts:
            if not ep["first_observed"] or str(ts) < str(ep["first_observed"]):
                ep["first_observed"] = ts
            if not ep["last_observed"] or str(ts) > str(ep["last_observed"]):
                ep["last_observed"] = ts
        if len(ep["sightings"]) < max(1, min(limit, DEFAULT_LIMIT)):
            ep["sightings"].append(r)

    endpoint_rows = sorted(endpoints.values(),
                           key=lambda e: (-e["sighting_count"],
                                          str(e.get("endpoint_id") or "")))
    paths: List[str] = []
    for e in endpoint_rows:
        for p in e["paths"]:
            if p not in paths:
                paths.append(p)

    observed = [r["observed_at"] for r in rows if r.get("observed_at")]
    # Delivery that crosses midnight is exactly the case that sends an analyst
    # to the wrong day, so these rows are surfaced even when the per-endpoint
    # slice above does not reach them.
    shifted = [r for r in rows if r["ingest_day_differs"]]

    # ── Cisco AMP's framing: visibility, entry point, attributes ─────────────
    # "Entry point" is AMP's patient zero: the endpoint that saw it FIRST. Ties
    # are kept rather than broken arbitrarily — two endpoints that first saw it
    # in the same instant are both candidates, and saying so is the answer.
    first_seen = min((e["first_observed"] for e in endpoint_rows
                      if e.get("first_observed")), default=None)
    entry_points = [{"endpoint_id": e["endpoint_id"], "hostname": e["hostname"],
                     "first_observed": e["first_observed"]}
                    for e in endpoint_rows if e.get("first_observed") == first_seen]

    names: List[str] = []
    for p in all_paths:
        leaf = str(p).replace("\\", "/").split("/")[-1]
        if leaf and leaf not in names:
            names.append(leaf)

    def _distinct(field: str, source: Optional[List[Dict[str, Any]]] = None) -> List[Any]:
        out: List[Any] = []
        for r in (all_rows if source is None else source):
            v = r.get(field)
            if v and v not in out:
                out.append(v)
        return out

    def _breakdown(source: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in source:
            a = r.get("activity") or "UNSPECIFIED"
            out[a] = out.get(a, 0) + 1
        return out

    activity_breakdown = _breakdown(rows)
    # Which payload field named the path, per event type. This is the
    # reconciliation between "14 recorded paths" and the sighting counts:
    # PROCESS_OBSERVED paths come from `image_path`, FILE/CREATE paths from
    # `path`, and a file that was both created and executed appears in both.
    path_provenance: Dict[str, Dict[str, Any]] = {}
    for r in all_rows:
        prov_key = f"{r.get('activity_family') or '?'}/{r.get('activity') or '?'}"
        ent = path_provenance.setdefault(
            prov_key, {"sightings": 0, "path_field": r.get("path_field"),
                       "distinct_paths": 0, "_seen": set()})
        ent["sightings"] += 1
        if r.get("path"):
            ent["_seen"].add(r["path"])
    for ent in path_provenance.values():
        ent["distinct_paths"] = len(ent.pop("_seen"))

    return {
        "ok": True,
        "sha256": key,
        "tenant": tenant_id,
        "total_sightings": len(rows),
        "total_sightings_unfiltered": len(all_rows),
        "filter": filter_state,
        "endpoint_count": len(endpoint_rows),
        "endpoints": endpoint_rows,
        "observed_paths": paths,
        "all_observed_paths": all_paths,
        "observed_names": names,
        "path_provenance": path_provenance,
        "activity_breakdown_unfiltered": _breakdown(all_rows),
        "visibility": {
            "first_observed": min(observed) if observed else None,
            "last_observed": max(observed) if observed else None,
            "endpoints": len(endpoint_rows),
            "basis": ("every sighting matching the path filter" if needle
                      else "every sighting read for this customer"),
        },
        "entry_points": entry_points,
        "entry_point_basis": (
            "the earliest observation among sightings matching the path filter"
            if needle else
            "the earliest observation of this digest in this customer. An "
            "endpoint seeing the same digest is not evidence that the file "
            "moved there from another endpoint; transfer is not observed."),
        "activity_breakdown": activity_breakdown,
        # What a PROCESS_OBSERVED count is and is not. `collect_processes`
        # emits once per (pid, start_ticks) read from /proc, so each row is a
        # distinct observed process identity — but discovery is polling, and
        # anything that starts and exits inside one interval is never seen.
        # So this is a count of OBSERVATIONS, never a count of launches.
        "process_observation_basis": (
            "PROCESS_OBSERVED is one row per process identity (pid + kernel "
            "start counter) that /proc polling actually saw. Processes that "
            "started and exited within a poll interval were never observed, "
            "so this is a count of observations, not of launches."),
        "attributes": {
            "sha256": key,
            "known_names": names,
            "known_paths": all_paths,
            "sizes_bytes": _distinct("size"),
            "users": _distinct("user"),
            "parent_images": _distinct("parent_image"),
            "sensor_versions": _distinct("sensor_version"),
            "collection_methods": _distinct("collection_method"),
        },
        # Cisco AMP shows size, real file type, signing certificate,
        # disposition and a network profile here. Size IS collected — but only
        # on FILE events, where the sensor stat()s the file it found; a process
        # observation carries no size. The rest do not exist on this substrate,
        # and an empty field an analyst reads as "clean" is worse than a stated
        # gap.
        "not_collected": [
            "file size on process observations (collected on FILE events only)",
            "real file type", "signing certificate",
            "file disposition / reputation", "network profile (ports, IPs, URLs)",
            "moved, scanned and quarantined events",
            "file creation outside the paths the sensor watches",
            "which process created a file — the writer is never attributed",
        ],
        "first_observed": min(observed) if observed else None,
        "last_observed": max(observed) if observed else None,
        "day_shifted_sightings": len(shifted),
        "day_shifted_examples": shifted[:5],
        "scanned": len(docs),
        "truncated": len(docs) >= SCAN_CAP,
        "evidence_basis": EVIDENCE_BASIS,
        "digest_basis": {
            "PROCESS/PROCESS_OBSERVED": (
                "collect_processes reads /proc/<pid>/exe and hashes THAT file: "
                "the digest is the executed image at image_path"),
            "FILE/CREATE": (
                "collect_files walks the watched directory and hashes the file "
                "it found: the digest is the file created at path, read at "
                "observation time"),
        },
        "time_basis": ("payload.observed_at — the time the ENDPOINT observed "
                       "the execution, not the time the record was ingested"),
        "collection_limit": ("The sensor reports the digest of an executed image, "
                             "and FILE/CREATE for the paths it watches. File write, "
                             "delete, move, scan and quarantine are not observed at "
                             "all, and creation outside a watched path is not seen, "
                             "so absence here is not absence of the file."),
        "scope": {
            "customer": tenant_id,
            "authority": "server",
            "note": ("Read within the server-resolved acting customer. A digest "
                     "seen on another customer's endpoints is not returned, and "
                     "an empty result for this customer is an honest zero."),
        },
    }
