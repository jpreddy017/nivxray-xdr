"""JSON parser — single top-level array or object → N ParsedRecords."""
from __future__ import annotations

import json
from typing import Iterator

from ._errors import malformed_record, ok_record
from ._types import ParsedRecord
from ..security import enforce_record_count, enforce_record_size, SecurityCapExceeded


def iter_records(raw) -> Iterator[ParsedRecord]:
    """Yield one ParsedRecord per top-level element.

    - Top-level list: one record per element (index = offset).
    - Top-level dict: one record (offset = 0).
    - Any other shape: single malformed record.
    """
    try:
        text = raw.bytes_.decode(raw.encoding or "utf-8", errors="strict")
    except Exception as e:
        yield malformed_record(raw=raw, parser_name="json",
                                 offset=0, error=f"decode: {e}")
        return

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        yield malformed_record(raw=raw, parser_name="json",
                                 offset=0, error=f"json: {e}")
        return

    items = obj if isinstance(obj, list) else [obj]
    try:
        enforce_record_count(len(items))
    except SecurityCapExceeded as e:
        yield malformed_record(raw=raw, parser_name="json",
                                 offset=0, error=str(e))
        return

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            yield ok_record(raw=raw, parser_name="json", offset=i,
                             raw_fields={"_value": item},
                             parse_errors=["non-object element wrapped in _value"])
            continue
        try:
            enforce_record_size(len(json.dumps(item).encode("utf-8")))
        except SecurityCapExceeded as e:
            yield malformed_record(raw=raw, parser_name="json",
                                     offset=i, error=str(e))
            continue
        yield ok_record(raw=raw, parser_name="json", offset=i,
                         raw_fields=item)
