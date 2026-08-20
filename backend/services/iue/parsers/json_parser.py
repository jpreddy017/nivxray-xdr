"""JSON parser — single top-level array or object → N ParsedRecords."""
from __future__ import annotations

import hashlib
import json
from typing import Iterator

from ._types import ParsedRecord
from ..security import enforce_record_count, enforce_record_size, SecurityCapExceeded


def _record_id(source_file_id: str, offset: int) -> str:
    return hashlib.sha256(f"{source_file_id}:{offset}".encode()).hexdigest()[:24]


def iter_records(raw) -> Iterator[ParsedRecord]:
    """Yield one ParsedRecord per top-level element.

    - Top-level list: one record per element (index = offset).
    - Top-level dict: one record (offset = 0).
    - Any other shape: single malformed record.
    """
    try:
        text = raw.bytes_.decode(raw.encoding or "utf-8", errors="strict")
    except Exception as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="json",
            parse_status="malformed",
            parse_errors=[f"decode: {e}"],
        )
        return

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="json",
            parse_status="malformed",
            parse_errors=[f"json: {e}"],
        )
        return

    items = obj if isinstance(obj, list) else [obj]
    try:
        enforce_record_count(len(items))
    except SecurityCapExceeded as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="json",
            parse_status="malformed",
            parse_errors=[str(e)],
        )
        return

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            yield ParsedRecord(
                record_id=_record_id(raw.source_file_id, i),
                source_file_id=raw.source_file_id,
                input_id=raw.input_id,
                tenant_id=raw.tenant_id,
                offset=i, raw_fields={"_value": item},
                parser_name="json",
                parse_status="partial",
                parse_errors=["non-object element wrapped in _value"],
            )
            continue
        try:
            enforce_record_size(len(json.dumps(item).encode("utf-8")))
        except SecurityCapExceeded as e:
            yield ParsedRecord(
                record_id=_record_id(raw.source_file_id, i),
                source_file_id=raw.source_file_id,
                input_id=raw.input_id,
                tenant_id=raw.tenant_id,
                offset=i, raw_fields={},
                parser_name="json",
                parse_status="malformed",
                parse_errors=[str(e)],
            )
            continue
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, i),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id,
            tenant_id=raw.tenant_id,
            offset=i, raw_fields=item,
            parser_name="json",
        )
