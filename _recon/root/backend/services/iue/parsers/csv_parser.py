"""CSV parser — DictReader-backed, header row required."""
from __future__ import annotations

import csv
import io
from typing import Iterator

from ._errors import malformed_record, ok_record
from ._types import ParsedRecord
from ..security import enforce_record_count, SecurityCapExceeded


def iter_records(raw) -> Iterator[ParsedRecord]:
    try:
        text = raw.bytes_.decode(raw.encoding or "utf-8", errors="strict")
    except Exception as e:
        yield malformed_record(raw=raw, parser_name="csv",
                                 offset=0, error=f"decode: {e}")
        return

    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error as e:
        yield malformed_record(raw=raw, parser_name="csv",
                                 offset=0, error=f"csv: {e}")
        return

    rows = list(reader)
    try:
        enforce_record_count(len(rows))
    except SecurityCapExceeded as e:
        yield malformed_record(raw=raw, parser_name="csv",
                                 offset=0, error=str(e))
        return

    for i, row in enumerate(rows):
        yield ok_record(raw=raw, parser_name="csv", offset=i,
                         raw_fields={k: v for k, v in row.items()
                                       if k is not None})
