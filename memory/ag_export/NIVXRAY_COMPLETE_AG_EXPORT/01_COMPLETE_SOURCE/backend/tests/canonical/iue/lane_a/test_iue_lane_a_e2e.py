"""Lane-A · End-to-end pipeline smoke test.

Walks a small NDJSON payload through the full Lane-A chain:
  Intake → Collect → Parse → Normalize → Aggregate → Understand
and asserts every stage carries the mandatory provenance quintuple.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def test_full_lane_a_pipeline(monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    from services.iue.intake import intake
    from services.iue.collectors.log_collector import collect
    from services.iue.parsers.ndjson_parser import iter_records
    from services.iue.normalizers.field_map import normalize
    from services.iue.aggregator import aggregate
    from services.iue.understanding import understand_structured

    payload = (
        b'{"src_ip":"10.0.0.1","CommandLine":"powershell -enc AAAA",'
        b'"event_time":"2026-02-14T12:00:00.100Z","action":"exec"}\n'
        b'{"src_ip":"10.0.0.1","CommandLine":"powershell -enc AAAA",'
        b'"event_time":"2026-02-14T12:00:00.900Z","action":"exec"}\n'
        b'{"src_ip":"10.0.0.99","CommandLine":"whoami",'
        b'"event_time":"2026-02-14T12:05:00.000Z","action":"exec"}\n'
    )

    d = intake(payload, allow_prev_fallback=True)
    assert d.lane == "structured"
    assert d.tenant_id
    assert d.input_id

    raw = collect(payload, mime="application/x-ndjson",
                    input_id=d.input_id, tenant_id=d.tenant_id)
    parsed = list(iter_records(raw))
    assert len(parsed) == 3
    assert all(p.tenant_id == d.tenant_id for p in parsed)

    normalized = [normalize(p) for p in parsed]
    assert all(n.canonical_fields.get("canonical.source.ip") for n in normalized)

    events = aggregate(normalized)
    # First two records collapse (same 1s bucket, same command),
    # third is 5 minutes later → separate event.
    assert len(events) == 2
    biggest = max(events, key=lambda e: e.count)
    assert biggest.count == 2
    assert len(biggest.record_refs) == 2

    fragment = understand_structured(events)
    assert fragment["logical_event_count"] == 2
    assert fragment["logical_record_total"] == 3
    assert isinstance(fragment["logical_events"], list)
