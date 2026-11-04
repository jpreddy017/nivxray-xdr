#!/usr/bin/env python3
"""GATE 0 §5 · where the ~39 ms/event backend cost actually goes.

MEASURE ONLY. Nothing here changes acceptance or durability semantics; it
instruments the real `_ingest_one` against the real local MongoDB and
counts the Mongo operations each stage issues.

Run from /app/backend:
    PROFILE_N=60 python ../scripts/b5gap1_ingest_cost_profile.py
"""
from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/../backend")

from edr_plane import delivery_counters as counters
from edr_plane import raw_events as raw
from edr_plane.enrollment import store
from routers import edr_enrollment as e

N = int(os.environ.get("PROFILE_N", "60"))
TENANT = os.environ.get("PROFILE_TENANT", "probe-t-00bf71")
ENDPOINT = os.environ.get("PROFILE_ENDPOINT", "ep_profile_b5gap1")

TIMES: dict[str, list[float]] = {}
OPS: Counter = Counter()


def _track(name: str, fn):
    """Wrap a coroutine function with a timer and an op counter."""
    async def _wrapped(*a, **k):
        t0 = time.perf_counter()
        try:
            return await fn(*a, **k)
        finally:
            TIMES.setdefault(name, []).append(time.perf_counter() - t0)
            OPS[name] += 1
    return _wrapped


class _Who:
    tenant_id = TENANT
    endpoint_id = ENDPOINT
    auth_method = "session"

    def provenance(self):
        return {"auth_method": "session", "endpoint_id": ENDPOINT}


class _Req:
    client = type("C", (), {"host": "127.0.0.1"})()


def payload(record_id: int) -> str:
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/"
           "event'><System><Provider Name='Microsoft-Windows-Sysmon' "
           "Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1"
           "</EventID><TimeCreated SystemTime='2026-06-01T10:04:00.0Z'/>"
           f"<EventRecordID>{record_id}</EventRecordID><Channel>"
           "Microsoft-Windows-Sysmon/Operational</Channel><Computer>"
           "NIVX-PROFILE</Computer></System><EventData>"
           "<Data Name='ProcessGuid'>{cccccccc-0000-0000-0000-"
           f"{record_id:012d}}}</Data>"
           f"<Data Name='ProcessId'>{record_id}</Data>"
           "<Data Name='Image'>C:\\Windows\\System32\\profile.exe</Data>"
           "<Data Name='UtcTime'>2026-06-01 10:04:00.000</Data>"
           "</EventData></Event>")
    return json.dumps({"observed_at": "2026-06-01T10:05:00+00:00",
                       "kind": "WINDOWS_EVENT_LOG",
                       "winlog": {"channel": "Microsoft-Windows-Sysmon/"
                                             "Operational",
                                  "record_id": record_id, "event_id": "1",
                                  "provider": "Microsoft-Windows-Sysmon",
                                  "computer": "NIVX-PROFILE",
                                  "time_created": "2026-06-01T10:04:00Z",
                                  "xml": xml}},
                      separators=(",", ":"))


def summarise(name: str) -> dict:
    samples = TIMES.get(name) or []
    if not samples:
        return {"calls_per_event": 0.0, "mean_ms": 0.0, "total_ms": 0.0}
    return {"calls_per_event": round(OPS[name] / N, 2),
            "mean_ms": round(statistics.mean(samples) * 1000, 3),
            "ms_per_event": round(sum(samples) / N * 1000, 3)}


async def main() -> None:
    import deps
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    deps.validate_config()
    deps.init_database()

    raw.append = _track("raw_append", raw.append)
    counters.record = _track("delivery_counters_record", counters.record)
    e.counters.record = counters.record
    e.raw.append = raw.append
    store.mark_reported = _track("store_mark_reported", store.mark_reported)
    store.get_endpoint = _track("store_get_endpoint", store.get_endpoint)
    e.store.mark_reported = store.mark_reported
    e.store.get_endpoint = store.get_endpoint
    e.bridge = _track("canonical_bridge", e.bridge)

    base = int(time.time() * 1000) % 1_000_000_000
    totals = []
    for i in range(N):
        t0 = time.perf_counter()
        await e._ingest_one(
            payload=payload(base + i), event_time=None,
            source_kind="sensor", sensor_version="profile",
            report_interval_seconds=30.0, who=_Who(), request=_Req(),
            report=True)
        totals.append(time.perf_counter() - t0)

    # Where does the bridge's cost actually sit: Mongo round trips, or CPU?
    mongo = {"ops": Counter(), "seconds": 0.0}

    def _instrument_collection(col):
        for op in ("find_one", "find_one_and_update", "update_one",
                   "insert_one", "count_documents", "replace_one",
                   "update_many", "insert_many", "delete_one",
                   "aggregate", "find"):
            original = getattr(col, op, None)
            if original is None:
                continue

            def _make(op_name, fn):
                async def _timed(*a, **k):
                    t0 = time.perf_counter()
                    try:
                        return await fn(*a, **k)
                    finally:
                        mongo["ops"][op_name] += 1
                        mongo["seconds"] += time.perf_counter() - t0
                return _timed

            if op in ("aggregate", "find"):
                continue          # cursors, not awaitables
            try:
                setattr(col, op, _make(op, original))
            except (AttributeError, TypeError):
                pass

    real_db = deps.db._require()
    seen = set()
    _orig_getitem = type(real_db).__getitem__

    def _patched(self, name):
        col = _orig_getitem(self, name)
        if name not in seen:
            seen.add(name)
            _instrument_collection(col)
        return col

    type(real_db).__getitem__ = _patched
    mongo["ops"].clear()
    mongo["seconds"] = 0.0
    probe_started = time.perf_counter()
    await e._ingest_one(
        payload=payload(base + N + 1), event_time=None,
        source_kind="sensor", sensor_version="profile",
        report_interval_seconds=30.0, who=_Who(), request=_Req(),
        report=True)
    probe_total = time.perf_counter() - probe_started
    type(real_db).__getitem__ = _orig_getitem

    stages = {name: summarise(name) for name in (
        "raw_append", "canonical_bridge", "delivery_counters_record",
        "store_get_endpoint", "store_mark_reported")}
    measured = sum(s["ms_per_event"] for s in stages.values())
    total = round(statistics.mean(totals) * 1000, 3)
    print(json.dumps({
        "events": N,
        "ingest_total_ms_per_event": total,
        "stages": stages,
        "measured_stage_sum_ms": round(measured, 3),
        "unattributed_ms_per_event": round(total - measured, 3),
        "delivery_counter_writes_per_event":
            stages["delivery_counters_record"]["calls_per_event"],
        "delivery_counter_ms_per_event":
            stages["delivery_counters_record"]["ms_per_event"],
        "delivery_counter_share_pct": round(
            100.0 * stages["delivery_counters_record"]["ms_per_event"]
            / total, 1) if total else 0.0,
        "one_event_mongo_breakdown": {
            "total_ms": round(probe_total * 1000, 3),
            "mongo_ops": dict(mongo["ops"]),
            "mongo_op_count": sum(mongo["ops"].values()),
            "mongo_ms": round(mongo["seconds"] * 1000, 3),
            "non_mongo_ms": round(
                (probe_total - mongo["seconds"]) * 1000, 3),
        },
        "note": "local loopback Mongo. No HTTP, no TLS, no auth dependency "
                "in this number.",
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
