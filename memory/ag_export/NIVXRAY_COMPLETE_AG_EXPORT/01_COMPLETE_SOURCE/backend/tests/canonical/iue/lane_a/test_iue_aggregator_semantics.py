"""Lane-A · Aggregation ≠ Correlation.

The two most consequential invariants of Stage 1:

1. Aggregation collapses ONLY records that share every canonical
   grouping field exactly.  It never merges records that only share
   an IOC.

2. Aggregation preserves count, first/last seen, provenance, and the
   full list of source record_ids.  Nothing is destroyed.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def _mk_record(record_id, canonical, source_file_id="src-1"):
    from services.iue.normalizers.field_map import NormalizedRecord
    return NormalizedRecord(
        record_id=record_id,
        source_file_id=source_file_id,
        input_id="in-1",
        tenant_id="t-1",
        canonical_fields=canonical,
        raw_fields={},
        alias_map={},
    )


def test_10000_equivalent_events_collapse_to_one_logical_event():
    """THE key contract: 10,000 identical events → 1 LogicalEvent with
    count=10,000, first_seen, last_seen, and full record_refs list."""
    from services.iue.aggregator import aggregate

    N = 10_000
    records = []
    for i in range(N):
        # Different sub-second timestamps → all collapse into the 1s bucket.
        ts = f"2026-02-14T12:00:00.{i:06d}Z"
        records.append(_mk_record(
            f"r-{i}",
            {
                "canonical.tenant.id":            "t-1",
                "canonical.event.timestamp":      ts,
                "canonical.event.action":         "login",
                "canonical.source.ip":            "10.0.0.1",
                "canonical.destination.ip":       "10.0.0.2",
                "canonical.process.command_line": "powershell -enc AAAA",
            },
        ))
    events = aggregate(records)
    assert len(events) == 1
    ev = events[0]
    assert ev.count == N
    assert len(ev.record_refs) == N
    assert ev.record_refs[0] == "r-0"
    assert ev.record_refs[-1] == f"r-{N-1}"
    assert ev.first_seen and ev.last_seen
    assert ev.first_seen < ev.last_seen
    assert ev.canonical_fields["canonical.source.ip"] == "10.0.0.1"


def test_records_sharing_only_ioc_are_NOT_aggregated():
    """Same source IP appears in three otherwise-unrelated records.
    Aggregation MUST return three separate LogicalEvents.  Correlation
    across shared IOC is ICE's job, not the aggregator's."""
    from services.iue.aggregator import aggregate

    shared_ip = "203.0.113.7"
    records = [
        _mk_record("r-a", {
            "canonical.tenant.id":            "t-1",
            "canonical.event.timestamp":      "2026-02-14T12:00:00Z",
            "canonical.event.action":         "login",
            "canonical.source.ip":            shared_ip,
            "canonical.process.command_line": "cmd.exe /c whoami",
        }),
        _mk_record("r-b", {
            "canonical.tenant.id":            "t-1",
            "canonical.event.timestamp":      "2026-02-14T13:00:00Z",
            "canonical.event.action":         "file_write",
            "canonical.source.ip":            shared_ip,
            "canonical.process.command_line": "powershell -enc BBB",
        }),
        _mk_record("r-c", {
            "canonical.tenant.id":            "t-1",
            "canonical.event.timestamp":      "2026-02-14T14:00:00Z",
            "canonical.event.action":         "network_connect",
            "canonical.source.ip":            shared_ip,
            "canonical.process.command_line": "curl http://x.example",
        }),
    ]
    events = aggregate(records)
    assert len(events) == 3, (
        f"Aggregator wrongly correlated by shared IOC — expected 3 "
        f"events, got {len(events)}"
    )
    assert {ev.count for ev in events} == {1}


def test_aggregator_preserves_full_record_refs():
    from services.iue.aggregator import aggregate

    records = [
        _mk_record("r-1", {
            "canonical.tenant.id":       "t-1",
            "canonical.event.timestamp": "2026-02-14T12:00:00.100Z",
            "canonical.event.action":    "login",
            "canonical.source.ip":       "10.0.0.1",
        }),
        _mk_record("r-2", {
            "canonical.tenant.id":       "t-1",
            "canonical.event.timestamp": "2026-02-14T12:00:00.900Z",
            "canonical.event.action":    "login",
            "canonical.source.ip":       "10.0.0.1",
        }),
    ]
    events = aggregate(records)
    assert len(events) == 1
    assert sorted(events[0].record_refs) == ["r-1", "r-2"]


def test_aggregator_never_correlates_across_source_files():
    """Two files with identical grouping keys → 2 separate LogicalEvent
    lists (one per file).  ICE reunifies later; not the aggregator."""
    from services.iue.aggregator import aggregate

    r1 = _mk_record("r-1", {
        "canonical.tenant.id":       "t-1",
        "canonical.event.timestamp": "2026-02-14T12:00:00Z",
        "canonical.event.action":    "login",
        "canonical.source.ip":       "10.0.0.1",
    }, source_file_id="file-A")
    r2 = _mk_record("r-2", {
        "canonical.tenant.id":       "t-1",
        "canonical.event.timestamp": "2026-02-14T12:00:00Z",
        "canonical.event.action":    "login",
        "canonical.source.ip":       "10.0.0.1",
    }, source_file_id="file-B")

    events_a = aggregate([r1])
    events_b = aggregate([r2])
    assert len(events_a) == 1
    assert len(events_b) == 1
    assert events_a[0].event_id != events_b[0].event_id, (
        "Aggregator MUST scope event_id to source_file_id — "
        "cross-file reunification is ICE's job"
    )


def test_1s_bucket_pins_deterministically():
    """Records within a 1s bucket aggregate; a record 1s later does not."""
    from services.iue.aggregator import aggregate

    records = [
        _mk_record("r-1", {
            "canonical.tenant.id":       "t-1",
            "canonical.event.timestamp": "2026-02-14T12:00:00.100Z",
            "canonical.event.action":    "login",
            "canonical.source.ip":       "10.0.0.1",
        }),
        _mk_record("r-2", {
            "canonical.tenant.id":       "t-1",
            "canonical.event.timestamp": "2026-02-14T12:00:00.900Z",
            "canonical.event.action":    "login",
            "canonical.source.ip":       "10.0.0.1",
        }),
        _mk_record("r-3", {
            "canonical.tenant.id":       "t-1",
            "canonical.event.timestamp": "2026-02-14T12:00:01.100Z",
            "canonical.event.action":    "login",
            "canonical.source.ip":       "10.0.0.1",
        }),
    ]
    events = aggregate(records)
    assert len(events) == 2
    # First event carries r-1, r-2; second event carries r-3.
    sizes = sorted(len(ev.record_refs) for ev in events)
    assert sizes == [1, 2]
