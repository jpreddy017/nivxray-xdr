"""Lane-A · Record-boundary preservation.

One physical file → N ParsedRecords.  Parsers MUST NOT collapse or
drop records at this stage.  Malformed records must be yielded, not
silently swallowed.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[4]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def _raw(bytes_, mime):
    from services.iue.collectors.log_collector import collect
    return collect(bytes_, mime=mime, input_id="in-1", tenant_id="t-1")


def test_ndjson_yields_one_record_per_line():
    from services.iue.parsers.ndjson_parser import iter_records
    payload = (b'{"host":"a","event":"login"}\n'
                b'{"host":"b","event":"login"}\n'
                b'{"host":"c","event":"logout"}\n')
    raw = _raw(payload, "application/x-ndjson")
    records = list(iter_records(raw))
    assert len(records) == 3
    assert all(r.parse_status == "ok" for r in records)
    assert {r.raw_fields["host"] for r in records} == {"a", "b", "c"}


def test_ndjson_malformed_record_is_yielded_not_swallowed():
    from services.iue.parsers.ndjson_parser import iter_records
    payload = (b'{"ok":1}\n'
                b'not-json\n'
                b'{"ok":2}\n')
    raw = _raw(payload, "application/x-ndjson")
    records = list(iter_records(raw))
    assert len(records) == 3
    statuses = [r.parse_status for r in records]
    assert statuses == ["ok", "malformed", "ok"]


def test_json_top_level_array_yields_one_record_per_element():
    from services.iue.parsers.json_parser import iter_records
    payload = b'[{"a":1},{"a":2},{"a":3}]'
    raw = _raw(payload, "application/json")
    records = list(iter_records(raw))
    assert len(records) == 3
    assert [r.raw_fields["a"] for r in records] == [1, 2, 3]


def test_csv_header_row_becomes_dict_keys():
    from services.iue.parsers.csv_parser import iter_records
    payload = b"host,event\nserver-1,login\nserver-2,logout\n"
    raw = _raw(payload, "text/csv")
    records = list(iter_records(raw))
    assert len(records) == 2
    assert records[0].raw_fields == {"host": "server-1", "event": "login"}


def test_xml_yields_one_record_per_root_child():
    from services.iue.parsers.xml_parser import iter_records
    payload = (b"<alerts>"
                b"<alert><host>a</host></alert>"
                b"<alert><host>b</host></alert>"
                b"</alerts>")
    raw = _raw(payload, "application/xml")
    records = list(iter_records(raw))
    assert len(records) == 2
    assert [r.raw_fields["host"] for r in records] == ["a", "b"]
