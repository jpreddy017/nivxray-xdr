"""B5-4 · DELIVERY FIDELITY · the BACKEND half of the measurement.

Read-only. Counts, per Sysmon Event ID, what the BACKEND can prove for a
given UTC window, and states which boundaries it cannot see at all.

    python3 scripts/b5_delivery_fidelity.py \
        --host DESKTOP-A9HGFJJ \
        --start 2026-09-22T15:43:00 --end 2026-09-22T16:46:00

Boundaries B0 (endpoint generated), B1 (sensor observed) and B2 (sensor
sent) are NOT visible from here. They come from the owner-run endpoint
script and from sensor counters that do not exist yet. Nothing below is
inferred by subtraction: a boundary this script cannot measure is
reported as `NOT_MEASURABLE_FROM_BACKEND`, never as zero and never as
loss.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import statistics
import sys

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402

load_dotenv("/app/backend/.env")

from pymongo import MongoClient                                 # noqa: E402

CANONICAL = "xdr_canonical_evidence"
BLOCKS = "xdr_ingest_routing_blocks"
DEDUPE = "xdr_ingest_dedupe"
COLLECTORS = "xdr_collectors"
SHADOW = "v2_shadow_observations"

_EID = re.compile(r"^sysmon-(\d+)-")


def _iso_minutes(v) -> str:
    return str(v or "")[:19].replace("T", " ")


def _delta_seconds(a: str, b: str) -> float | None:
    from datetime import datetime

    def p(x):
        try:
            return datetime.fromisoformat(str(x).replace("Z", "+00:00")
                                          .replace(" ", "T"))
        except Exception:  # noqa: BLE001
            return None
    pa, pb = p(a), p(b)
    if not pa or not pb:
        return None
    if pa.tzinfo and not pb.tzinfo:
        pb = pb.replace(tzinfo=pa.tzinfo)
    if pb.tzinfo and not pa.tzinfo:
        pa = pa.replace(tzinfo=pb.tzinfo)
    return (pb - pa).total_seconds()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--tenant", default=None)
    ap.add_argument("--start", required=True, help="window start, UTC ISO")
    ap.add_argument("--end", required=True, help="window end, UTC ISO")
    args = ap.parse_args()

    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    start, end = _iso_minutes(args.start), _iso_minutes(args.end)

    q: dict = {"host.hostname": args.host}
    if args.tenant:
        q["tenant_id"] = args.tenant

    # ── B4 · CANONICALIZED (and therefore also B3 ACCEPTED) ─────────
    per_eid = collections.Counter()
    per_kind = collections.Counter()
    collectors: set = set()
    tenants: set = set()
    record_ids: dict[int, set] = collections.defaultdict(set)
    lat_sensor_to_collector: list = []
    lat_collector_to_nivx: list = []
    lat_nivx_to_parsed: list = []
    out_of_window = 0

    for d in db[CANONICAL].find(q, {
            "_id": 0, "event_id": 1, "event_type": 1, "event_time": 1,
            "tenant_id": 1, "provenance": 1, "additional_fields": 1}):
        et = _iso_minutes(d.get("event_time"))
        if not (start <= et <= end):
            out_of_window += 1
            continue
        m = _EID.match(str(d.get("event_id") or ""))
        eid = int(m.group(1)) if m else -1
        per_eid[eid] += 1
        per_kind[d.get("event_type") or "?"] += 1
        tenants.add(d.get("tenant_id"))
        prov = d.get("provenance") or {}
        collectors.add(prov.get("collector_id"))
        rid = ((d.get("additional_fields") or {}).get("record_id")
               or prov.get("source_record_id"))
        if rid:
            record_ids[eid].add(rid)
        ts = (prov.get("timestamps") or {})

        def val(name):
            return (ts.get(name) or {}).get("value")
        for bucket, a, b in (
                (lat_sensor_to_collector, "sensor_observed_at",
                 "collector_received_at"),
                (lat_collector_to_nivx, "collector_received_at",
                 "nivx_received_at"),
                (lat_nivx_to_parsed, "nivx_received_at", "parsed_at")):
            s = _delta_seconds(val(a), val(b))
            if s is not None:
                bucket.append(s)

    # ── B3 · REFUSED, and dedupe (never counted as loss) ────────────
    blocks = collections.Counter()
    block_rows = []
    bq = {"at": {"$gte": args.start, "$lte": args.end + "z"}}
    if collectors:
        bq["collector_id"] = {"$in": [c for c in collectors if c]}
    for b in db[BLOCKS].find(bq, {"_id": 0}):
        reason = ((b.get("routing") or {}).get("routing_result")
                  or "BLOCKED")
        detail = ((b.get("routing") or {}).get("reason")
                  or (b.get("routing") or {}).get("routing_reason") or "")
        blocks[f"{reason}: {str(detail)[:90]}"] += 1
        if len(block_rows) < 5:
            block_rows.append({k: str(v)[:160] for k, v in b.items()
                               if k in ("at", "source_event_id",
                                        "payload_keys", "payload_shape",
                                        "declared_payload_format")})
    dedupe_suppressed = db[DEDUPE].count_documents(
        {"collector_id": {"$in": [c for c in collectors if c]}}
    ) if collectors else 0

    # ── collector-side counters, such as they are ───────────────────
    coll_state = []
    for cid in [c for c in collectors if c]:
        c = db[COLLECTORS].find_one({"id": cid}, {"_id": 0, "name": 1,
                                                  "state": 1,
                                                  "state_reason": 1,
                                                  "state_evidence": 1})
        if c:
            coll_state.append({"collector_id": cid, **{
                k: v for k, v in c.items()
                if k in ("name", "state", "state_reason", "state_evidence")}})

    def pct(v):
        if not v:
            return None
        return {"n": len(v), "p50": round(statistics.median(v), 3),
                "min": round(min(v), 3), "max": round(max(v), 3)}

    print(json.dumps({
        "window_utc": {"start": args.start, "end": args.end},
        "host": args.host,
        "tenants_seen": sorted(t for t in tenants if t),
        "collectors_seen": sorted(c for c in collectors if c),
        "boundaries": {
            "B0_endpoint_generated": "NOT_MEASURABLE_FROM_BACKEND · "
                                     "owner-run endpoint script only",
            "B1_sensor_observed": "NOT_MEASURABLE_FROM_BACKEND · the "
                                  "sensor exposes no per-channel read "
                                  "counter",
            "B2_sensor_sent": "PARTIAL · only records that ARRIVED carry "
                              "collector_received_at; what was sent and "
                              "never arrived is invisible here",
            "B3_backend_accepted": "MEASURED (= B4 rows)",
            "B3_backend_refused": "MEASURED (xdr_ingest_routing_blocks)",
            "B3_dedupe_suppressed": "MEASURED · correct behaviour, NOT "
                                    "loss",
            "B4_canonicalized": "MEASURED (xdr_canonical_evidence)",
        },
        "B4_per_sysmon_event_id": dict(sorted(per_eid.items())),
        "B4_per_event_type": dict(per_kind.most_common()),
        "B4_total_in_window": sum(per_eid.values()),
        "B4_distinct_source_record_ids": {k: len(v) for k, v
                                          in sorted(record_ids.items())},
        "rows_for_host_outside_window": out_of_window,
        "B3_refusals_in_window": dict(blocks.most_common()),
        "B3_refusal_samples": block_rows,
        "B3_dedupe_suppressed_all_time": dedupe_suppressed,
        "collector_state": coll_state,
        "delivery_latency_seconds": {
            "sensor_observed_to_collector_received":
                pct(lat_sensor_to_collector),
            "collector_received_to_nivx_received":
                pct(lat_collector_to_nivx),
            "nivx_received_to_parsed": pct(lat_nivx_to_parsed),
        },
        "verdict_note": ("B0/B1 are unavailable, so no per-Event-ID "
                         "COMPLETE / LOSS_LOCALISED verdict can be "
                         "issued from the backend alone. Pair this with "
                         "the endpoint script output."),
    }, indent=1, default=str))


if __name__ == "__main__":
    main()
