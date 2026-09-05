"""XML parser — one ParsedRecord per direct child element of the root.

Uses ``defusedxml`` when available to avoid XXE / billion-laughs attacks;
falls back to stdlib ``xml.etree`` with a warning captured in
``parse_errors=["defusedxml_missing"]``.
"""
from __future__ import annotations

from typing import Iterator

try:
    from defusedxml import ElementTree as ET  # type: ignore
    _SAFE_XML = True
except Exception:  # defusedxml not installed → fall back with warnings
    import xml.etree.ElementTree as ET  # type: ignore
    _SAFE_XML = False

from ._errors import malformed_record, ok_record
from ._types import ParsedRecord
from ..security import enforce_record_count, SecurityCapExceeded


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
    warn = [] if _SAFE_XML else ["defusedxml_missing"]

    try:
        root = ET.fromstring(raw.bytes_)  # nosec: safe via defusedxml when available
    except Exception as e:
        yield malformed_record(raw=raw, parser_name="xml",
                                 offset=0, error=f"xml: {e}")
        return

    children = list(root)
    if not children:
        yield ok_record(raw=raw, parser_name="xml", offset=0,
                         raw_fields=_elem_to_dict(root),
                         parse_errors=warn)
        return

    try:
        enforce_record_count(len(children))
    except SecurityCapExceeded as e:
        yield malformed_record(raw=raw, parser_name="xml",
                                 offset=0, error=str(e))
        return

    for i, child in enumerate(children):
        yield ok_record(raw=raw, parser_name="xml", offset=i,
                         raw_fields=_elem_to_dict(child),
                         parse_errors=warn)
