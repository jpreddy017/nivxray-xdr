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

What this is NOT: file create/write/delete observation. The sensor does not
collect file-system activity, so a sighting here means "this content was
executed from this path at this time", never "this file was written here".

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


def _sighting(doc: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    observed = payload.get("observed_at")
    ingested = doc.get("ingest_time")
    ingested = ingested if isinstance(ingested, str) else (
        ingested.isoformat() if ingested else None)
    return {
        "raw_id": doc.get("raw_id"),
        "endpoint_id": doc.get("endpoint_ref"),
        "path": payload.get("image_path") or payload.get("image"),
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
              limit: int = DEFAULT_LIMIT) -> Dict[str, Any]:
    """Every sighting of one content digest within ONE customer.

    `tenant_id` is the server-resolved acting customer (see
    `routers.edr_tenancy.edr_tenant`); it is never taken from the query, so a
    hash cannot be used to read another customer's endpoints.
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
    return {
        "ok": True,
        "sha256": key,
        "tenant": tenant_id,
        "total_sightings": len(rows),
        "endpoint_count": len(endpoint_rows),
        "endpoints": endpoint_rows,
        "observed_paths": paths,
        "first_observed": min(observed) if observed else None,
        "last_observed": max(observed) if observed else None,
        "day_shifted_sightings": len(shifted),
        "day_shifted_examples": shifted[:5],
        "scanned": len(docs),
        "truncated": len(docs) >= SCAN_CAP,
        "evidence_basis": EVIDENCE_BASIS,
        "time_basis": ("payload.observed_at — the time the ENDPOINT observed "
                       "the execution, not the time the record was ingested"),
        "collection_limit": ("The sensor reports executed-image digests only. "
                            "A sighting means this content ran from this path; "
                            "file create, write and delete are not collected, "
                            "so absence here is not absence of the file."),
        "scope": {
            "customer": tenant_id,
            "authority": "server",
            "note": ("Read within the server-resolved acting customer. A digest "
                     "seen on another customer's endpoints is not returned, and "
                     "an empty result for this customer is an honest zero."),
        },
    }
