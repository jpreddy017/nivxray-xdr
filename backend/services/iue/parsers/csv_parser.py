"""CSV parser — DictReader-backed, header row required."""
from __future__ import annotations

import csv
import hashlib
import io
from typing import Iterator

from ._types import ParsedRecord
from ..security import enforce_record_count, SecurityCapExceeded


def _record_id(source_file_id: str, offset: int) -> str:
    return hashlib.sha256(f"{source_file_id}:{offset}".encode()).hexdigest()[:24]


def iter_records(raw) -> Iterator[ParsedRecord]:
    try:
        text = raw.bytes_.decode(raw.encoding or "utf-8", errors="strict")
    except Exception as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="csv",
            parse_status="malformed",
            parse_errors=[f"decode: {e}"],
        )
        return

    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="csv",
            parse_status="malformed",
            parse_errors=[f"csv: {e}"],
        )
        return

    rows = list(reader)
    try:
        enforce_record_count(len(rows))
    except SecurityCapExceeded as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="csv",
            parse_status="malformed",
            parse_errors=[str(e)],
        )
        return

    for i, row in enumerate(rows):
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, i),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=i, raw_fields={k: v for k, v in row.items()
                                    if k is not None},
            parser_name="csv",
        )
