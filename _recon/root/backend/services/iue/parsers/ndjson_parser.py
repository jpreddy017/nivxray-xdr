"""NDJSON parser — one JSON object per line."""
from __future__ import annotations

import json
from typing import Iterator

from ._errors import malformed_record, ok_record
from ._types import ParsedRecord
from ..security import enforce_record_count, SecurityCapExceeded


def iter_records(raw) -> Iterator[ParsedRecord]:
    try:
        text = raw.bytes_.decode(raw.encoding or "utf-8", errors="strict")
    except Exception as e:
        yield malformed_record(raw=raw, parser_name="ndjson",
                                 offset=0, error=f"decode: {e}")
        return

    lines = [ln for ln in text.split("\n") if ln.strip()]
    try:
        enforce_record_count(len(lines))
    except SecurityCapExceeded as e:
        yield malformed_record(raw=raw, parser_name="ndjson",
                                 offset=0, error=str(e))
        return

    for i, line in enumerate(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError as e:
            yield malformed_record(raw=raw, parser_name="ndjson",
                                     offset=i, error=f"json: {e}")
            continue
        if not isinstance(item, dict):
            item = {"_value": item}
        yield ok_record(raw=raw, parser_name="ndjson",
                         offset=i, raw_fields=item)
