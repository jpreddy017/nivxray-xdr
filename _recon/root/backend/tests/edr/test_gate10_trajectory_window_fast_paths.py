"""GATE 10 · the trajectory read must get FASTER without changing what
it says.

Two optimisations are asserted here, both semantic no-ops:

1. derived aggregates (`type_counts`, `activity`, observed extent, the
   lane buckets) are computed ONCE with the projection instead of on
   every read — and both projection builders must carry them, which is
   the defect that briefly produced a 500 when only one of them did;
2. an unfiltered viewport read serves its rows from the lane buckets
   instead of scanning the endpoint's whole history — the result must be
   byte-identical to the scan it replaced.
"""
from __future__ import annotations

from edr_plane import trajectory_window as tw


def _rows():
    return [
        {"lane_index": 0, "event_iid": "e1", "timestamp": "2026-06-01T00:00:01",
         "event_type": "process_create", "disposition": "CLEAN"},
        {"lane_index": 0, "event_iid": "e2", "timestamp": "2026-06-01T00:00:03",
         "event_type": "process_create", "disposition": "CLEAN"},
        {"lane_index": 1, "event_iid": "e3", "timestamp": "2026-06-01T00:00:02",
         "event_type": "network_connect", "disposition": "CLEAN"},
        {"lane_index": 7, "event_iid": "e4", "timestamp": "2026-06-02T00:00:00",
         "event_type": "network_connect", "disposition": "MALICIOUS"},
        # an observation with no activity time must not invent one
        {"lane_index": 1, "event_iid": "e5", "timestamp": None,
         "event_type": "process_create", "disposition": "CLEAN"},
    ]


def test_lane_buckets_partition_the_projection_exactly():
    rows = _rows()
    out = tw._with_derived({"cat": {}, "rows": rows, "bounded": False,
                            "docs_read": len(rows)})
    flat = [r for li in sorted(out["by_lane"]) for r in out["by_lane"][li]]
    assert len(flat) == len(rows)
    assert {r["event_iid"] for r in flat} == {r["event_iid"] for r in rows}
    for li, bucket in out["by_lane"].items():
        assert all(r["lane_index"] == li for r in bucket)


def test_the_observed_extent_ignores_rows_with_no_activity_time():
    out = tw._with_derived({"cat": {}, "rows": _rows(), "bounded": False,
                            "docs_read": 5})
    assert out["observed_start"] == "2026-06-01T00:00:01"
    assert out["observed_end"] == "2026-06-02T00:00:00"


def test_derived_aggregates_equal_the_per_request_computation():
    rows = _rows()
    out = tw._with_derived({"cat": {}, "rows": rows, "bounded": False,
                            "docs_read": len(rows)})
    assert out["type_counts"] == tw._type_counts(rows)
    assert out["activity_unfiltered"] == tw._activity(rows, None)


def test_a_bucket_read_equals_the_scan_it_replaced():
    rows = _rows()
    out = tw._with_derived({"cat": {}, "rows": rows, "bounded": False,
                            "docs_read": len(rows)})
    for lane_start, lane_end in ((0, 1), (0, 2), (1, 8), (0, 40), (9, 12)):
        picked = []
        for li in range(lane_start, lane_end):
            picked.extend(out["by_lane"].get(li, ()))
        picked.sort(key=lambda r: (r["timestamp"] or "", r["event_iid"]))
        scanned = [r for r in rows
                   if lane_start <= r["lane_index"] < lane_end]
        scanned.sort(key=lambda r: (r["timestamp"] or "", r["event_iid"]))
        assert picked == scanned, (lane_start, lane_end)


def test_both_projection_builders_carry_the_derived_aggregates():
    """The off-loop complete builder and the in-loop bounded builder fill
    the same cache. If only one carries the derived keys, the next read
    raises — which is exactly what happened before this test existed."""
    import inspect
    for fn in (tw._project_all_sync, tw._projected):
        src = inspect.getsource(fn)
        assert "_with_derived" in src, (
            f"{fn.__name__} builds a projection without the derived "
            f"aggregates; a cached projection must always carry them")
