"""XML parser — one ParsedRecord per direct child element of the root.

Uses stdlib ``xml.etree.ElementTree`` with entity-expansion disabled to
avoid XXE / billion-laughs attacks (uses ``defusedxml`` if available).
"""
from __future__ import annotations

import hashlib
from typing import Iterator

try:
    from defusedxml import ElementTree as ET  # type: ignore
    _SAFE_XML = True
except Exception:  # defusedxml not installed → fall back with warnings
    import xml.etree.ElementTree as ET  # type: ignore
    _SAFE_XML = False

from ._types import ParsedRecord
from ..security import enforce_record_count, SecurityCapExceeded


def _record_id(source_file_id: str, offset: int) -> str:
    return hashlib.sha256(f"{source_file_id}:{offset}".encode()).hexdigest()[:24]


def _elem_to_dict(elem) -> dict:
    d = {}
    for k, v in (elem.attrib or {}).items():
        d[f"@{k}"] = v
    for child in list(elem):
        tag = child.tag.split("}", 1)[-1]  # strip namespace
        val = _elem_to_dict(child) if list(child) or child.attrib else (child.text or "")
        if tag in d:
            existing = d[tag]
            if isinstance(existing, list):
                existing.append(val)
            else:
                d[tag] = [existing, val]
        else:
            d[tag] = val
    if not d and elem.text:
        return {"_text": elem.text}
    return d


def iter_records(raw) -> Iterator[ParsedRecord]:
    try:
        root = ET.fromstring(raw.bytes_)  # nosec: safe via defusedxml when available
    except Exception as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="xml",
            parse_status="malformed",
            parse_errors=[f"xml: {e}"],
        )
        return

    children = list(root)
    if not children:  # root itself is the single record
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=0, raw_fields=_elem_to_dict(root),
            parser_name="xml",
            parse_errors=[] if _SAFE_XML else ["defusedxml_missing"],
        )
        return

    try:
        enforce_record_count(len(children))
    except SecurityCapExceeded as e:
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, 0),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=0, raw_fields={},
            parser_name="xml",
            parse_status="malformed",
            parse_errors=[str(e)],
        )
        return

    for i, child in enumerate(children):
        yield ParsedRecord(
            record_id=_record_id(raw.source_file_id, i),
            source_file_id=raw.source_file_id,
            input_id=raw.input_id, tenant_id=raw.tenant_id,
            offset=i, raw_fields=_elem_to_dict(child),
            parser_name="xml",
            parse_errors=[] if _SAFE_XML else ["defusedxml_missing"],
        )
