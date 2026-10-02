"""Time semantics: lateness, coverage gaps, viewport aggregation, 30-day density."""
from __future__ import annotations

from collections.abc import Iterable
from itertools import pairwise
from typing import Any

from .contracts import SEVERITY_RANK, iso
from .lineage import lanes_of

DAY = 86_400_000
LATE_THRESHOLD_MS = 5 * 60_000
MAX_BUCKETS = 400
MAX_ROWS = 200
INTEREST_CAP = 200


def lateness(ev: dict[str, Any], threshold_ms: int = LATE_THRESHOLD_MS) -> dict[str, Any]:
    """Placement is ALWAYS observed_at. ingested_at only explains lateness."""
    o, i = ev.get("observed_ms"), ev.get("ingested_ms")
    if o is None or i is None:
        return {"state": "UNKNOWN", "lateness_ms": None, "late": None, "basis": "observed_at or ingested_at absent"}
    d = i - o
    return {"state": "LATE" if d > threshold_ms else "ON_TIME", "lateness_ms": d, "late": d > threshold_ms,
            "threshold_ms": threshold_ms}


def coverage(events: Iterable[dict[str, Any]], t0: int, t1: int, *, expected_interval_ms: int = 60_000,
             heartbeats_ms: Iterable[int] = (), declared_gaps: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    """Explicit intervals: REPORTING / NO_TELEMETRY_RECEIVED / SENSOR_DECLARED_GAP / SENSOR_OFFLINE.
    A gap is a statement about delivery, never about endpoint activity."""
    gap_ms = max(3 * expected_interval_ms, 10 * 60_000)
    alive = sorted({e["observed_ms"] for e in events if e.get("observed_ms") is not None and t0 <= e["observed_ms"] <= t1}
                   | {h for h in heartbeats_ms if t0 <= h <= t1})
    out: list[dict[str, Any]] = []
    marks = [t0] + alive + [t1]
    for a, b in pairwise(marks):
        if b - a > gap_ms:
            out.append({"from_ms": a, "to_ms": b, "state": "NO_TELEMETRY_RECEIVED"})
    for g in declared_gaps:
        a, b = max(t0, g["from_ms"]), min(t1, g["to_ms"])
        if a < b:
            out.append({"from_ms": a, "to_ms": b, "state": "SENSOR_OFFLINE" if g.get("kind") == "OFFLINE"
                        else "SENSOR_DECLARED_GAP", "basis": g.get("basis", "sensor declaration")})
    for x in out:
        x["from"], x["to"] = iso(x["from_ms"]), iso(x["to_ms"])
    return {"window": {"from": iso(t0), "to": iso(t1)}, "gap_threshold_ms": gap_ms,
            "intervals": sorted(out, key=lambda x: (x["from_ms"], x["state"])),
            "statement": "Gaps describe telemetry delivery, not endpoint inactivity: a gap is not 'no activity'."}


def viewport(events: list[dict[str, Any]], lane_ids: list[str], t0: int, t1: int, width_px: int,
             bucket_px: int = 8, rows: int = 50, offset: int = 0) -> dict[str, Any]:
    """Per-lane markers bounded by (rows × buckets). Lanes with ≤ n_buckets events return individual
    markers; denser lanes return buckets (count, max severity, kind mix) to expand on zoom."""
    n = max(1, min(MAX_BUCKETS, int(width_px) // max(1, int(bucket_px))))
    span = max(1, t1 - t0)
    bms = span / n
    rows = max(1, min(MAX_ROWS, int(rows)))
    page = lane_ids[offset:offset + rows]
    want = set(page)
    by: dict[str, list[dict[str, Any]]] = {k: [] for k in page}
    for ev in events:
        t = ev.get("observed_ms")
        if t is None or t < t0 or t > t1:
            continue
        for lid in lanes_of(ev):
            if lid in want:
                by[lid].append(ev)
    out = []
    for lid in page:
        evs = by[lid]
        if len(evs) <= n:
            out.append({"lane_id": lid, "mode": "EVENTS", "count": len(evs), "markers": [
                {"event_id": e["event_id"], "t_ms": e["observed_ms"], "kind": e["kind"], "severity": e["severity"],
                 "late": lateness(e)["late"]} for e in sorted(evs, key=lambda e: (e["observed_ms"], e["event_id"]))]})
            continue
        buckets: dict[int, dict[str, Any]] = {}
        for e in evs:
            i = min(n - 1, int((e["observed_ms"] - t0) / bms))
            b = buckets.setdefault(i, {"i": i, "from_ms": int(t0 + i * bms), "to_ms": int(t0 + (i + 1) * bms),
                                       "count": 0, "max_severity": "NONE", "kinds": {}})
            b["count"] += 1
            b["kinds"][e["kind"]] = b["kinds"].get(e["kind"], 0) + 1
            if SEVERITY_RANK[e["severity"]] > SEVERITY_RANK[b["max_severity"]]:
                b["max_severity"] = e["severity"]
        out.append({"lane_id": lid, "mode": "BUCKETS", "count": len(evs), "buckets": [buckets[i] for i in sorted(buckets)],
                    "expand_hint": "zoom into a bucket interval to receive individual markers"})
    return {"window": {"from": iso(t0), "to": iso(t1)}, "n_buckets": n, "bucket_ms": bms, "rows": rows,
            "offset": offset, "total_lanes": len(lane_ids), "lanes": out}


def density(events: Iterable[dict[str, Any]], ref_ms: int, days: int = 30) -> dict[str, Any]:
    days = max(1, min(int(days), 90))
    end = (ref_ms // DAY + 1) * DAY
    start = end - days * DAY
    counts = [0] * days
    interest: list[dict[str, Any]] = []
    for e in events:
        t = e.get("observed_ms")
        if t is None or t < start or t >= end:
            continue
        counts[(t - start) // DAY] += 1
        if e.get("detection") or SEVERITY_RANK[e["severity"]] >= SEVERITY_RANK["HIGH"]:
            interest.append({"event_id": e["event_id"], "t_ms": t, "kind": e["kind"], "severity": e["severity"],
                             "detection": bool(e.get("detection"))})
    interest.sort(key=lambda x: (-x["t_ms"], x["event_id"]))
    return {"days": [{"day": iso(start + i * DAY)[:10], "count": c} for i, c in enumerate(counts)],
            "events_of_interest": interest[:INTEREST_CAP], "interest_truncated": len(interest) > INTEREST_CAP,
            "basis": "UTC calendar days ending at the reference day; placement by observed_at"}
