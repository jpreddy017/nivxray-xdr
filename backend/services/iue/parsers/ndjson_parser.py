"""NDJSON parser — one JSON object per line."""
from __future__ import annotations

import hashlib
import json
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
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="ndjson",
            parse_status="malformed",
            parse_errors=[f"decode: {e}"],
        )
        return

    lines = [ln for ln in text.split("\n") if ln.strip()]
    try:
        enforce_record_count(len(lines))
    except SecurityCapExceeded as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="ndjson",
            parse_status="malformed",
            parse_errors=[str(e)],
        )
        return

    for i, line in enumerate(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError as e:
            yield ParsedRecord(
                record_id=_record_id(raw.source_file_id, i),
                source_file_id=raw.source_file_id,
                input_id=raw.input_id,
                tenant_id=raw.tenant_id,
                offset=i, raw_fields={},
                parser_name="ndjson",
                parse_status="malformed",
                parse_errors=[f"json: {e}"],
            )
            continue
        if not isinstance(item, dict):
            item = {"_value": item}
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, i),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=i, raw_fields=item,
            parser_name="ndjson",
        )
