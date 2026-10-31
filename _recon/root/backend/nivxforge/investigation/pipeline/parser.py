"""Stage 2 · Parser.

Given raw text + InputClassification, produce a `ParsedInput` — a
structured representation the Vendor Detector (Stage 3) can inspect
WITHOUT re-parsing.

`ParsedInput` deliberately keeps a `records: List[Dict]` shape so
NDJSON, CSV and single JSON objects all normalise to a common list.

Never raises. If parsing fails for the declared class, we degrade to
`plain_text` with a diagnostic.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .input_classification import InputClass, InputClassification


@dataclass(frozen=True)
class ParsedInput:
    kind: str                          # matches InputClass
    records: List[Dict[str, Any]] = field(default_factory=list)
    text: Optional[str] = None         # for non-tabular inputs
    diagnostics: List[str] = field(default_factory=list)


def parse_input(raw: str,
                classification: InputClassification) -> ParsedInput:
    """Parse `raw` according to `classification`. Never raises."""
    diagnostics: List[str] = []
    kind = classification.kind

    if kind == InputClass.EMPTY:
        return ParsedInput(InputClass.EMPTY, records=[], text=None,
                           diagnostics=["empty input"])

    if kind == InputClass.JSON:
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            diagnostics.append(f"json parse failed: {e}")
            return ParsedInput(InputClass.PLAIN_TEXT, records=[],
                               text=raw, diagnostics=diagnostics)
        if isinstance(obj, list):
            recs = [x if isinstance(x, dict) else {"_value": x} for x in obj]
        elif isinstance(obj, dict):
            recs = [obj]
        else:
            recs = [{"_value": obj}]
        return ParsedInput(InputClass.JSON, records=recs, text=raw,
                           diagnostics=diagnostics)

    if kind == InputClass.NDJSON:
        recs: List[Dict[str, Any]] = []
        for i, line in enumerate(raw.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError) as e:
                diagnostics.append(f"ndjson line {i}: {e}")
                continue
            if isinstance(obj, dict):
                recs.append(obj)
            else:
                recs.append({"_value": obj})
        if not recs:
            return ParsedInput(InputClass.PLAIN_TEXT, records=[],
                               text=raw, diagnostics=diagnostics)
        return ParsedInput(InputClass.NDJSON, records=recs, text=raw,
                           diagnostics=diagnostics)

    if kind == InputClass.CSV:
        dialect_hint = classification.hint or "comma"
        delim = "\t" if dialect_hint == "tab" else ","
        try:
            reader = csv.DictReader(io.StringIO(raw), delimiter=delim)
            recs = [dict(row) for row in reader]
        except csv.Error as e:
            diagnostics.append(f"csv parse failed: {e}")
            return ParsedInput(InputClass.PLAIN_TEXT, records=[],
                               text=raw, diagnostics=diagnostics)
        return ParsedInput(InputClass.CSV, records=recs, text=raw,
                           diagnostics=diagnostics)

    if kind == InputClass.XML:
        recs = _parse_xml_events(raw)
        return ParsedInput(InputClass.XML, records=recs, text=raw,
                           diagnostics=diagnostics)

    if kind == InputClass.KEY_VALUE:
        recs = [_parse_kv_line(ln) for ln in raw.splitlines()
                if ln.strip()]
        return ParsedInput(InputClass.KEY_VALUE, records=recs, text=raw,
                           diagnostics=diagnostics)

    # ENCODED_CMD, PLAIN_COMMAND, PLAIN_TEXT — treated as one-record
    # text inputs. Downstream normalizers handle decoding.
    return ParsedInput(kind, records=[{"command_line": raw}], text=raw,
                       diagnostics=diagnostics)


# ── Helpers ──────────────────────────────────────────────────────────

_XML_DATA = re.compile(r"<Data\s+Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>",
                        re.IGNORECASE)
_XML_EVENT = re.compile(r"<Event(?:Data)?[^>]*>(.*?)</Event(?:Data)?>",
                         re.IGNORECASE | re.DOTALL)
# `<System><EventID>1</EventID><Provider Name='X'/>…</System>` fields
_XML_SIMPLE_TAG = re.compile(
    r"<([A-Za-z][A-Za-z0-9_]{1,40})(?:\s[^>]*)?>([^<]{1,4000})</\1>"
)


def _parse_xml_events(raw: str) -> List[Dict[str, Any]]:
    """Best-effort Windows EventXML / Sysmon parser without lxml."""
    out: List[Dict[str, Any]] = []
    for m in _XML_EVENT.finditer(raw):
        rec: Dict[str, Any] = {}
        for dm in _XML_DATA.finditer(m.group(1)):
            rec[dm.group(1)] = dm.group(2).strip()
        # Also capture simple <Tag>value</Tag> pairs (EventID, Channel,
        # Provider, etc.) from anywhere in the event block.
        for sm in _XML_SIMPLE_TAG.finditer(m.group(1)):
            tag = sm.group(1)
            if tag in ("Data", "EventData"):
                continue
            rec.setdefault(tag, sm.group(2).strip())
        if rec:
            out.append(rec)
    if out:
        # Merge sibling <System>+<EventData> records if the same file
        # produced two — pair them positionally.
        return _merge_paired_records(out)
    # Fallback: flat Data tags with no wrapping Event element.
    rec: Dict[str, Any] = {}
    for dm in _XML_DATA.finditer(raw):
        rec[dm.group(1)] = dm.group(2).strip()
    for sm in _XML_SIMPLE_TAG.finditer(raw):
        tag = sm.group(1)
        if tag in ("Data", "EventData"):
            continue
        rec.setdefault(tag, sm.group(2).strip())
    if rec:
        out.append(rec)
    return out


def _merge_paired_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A single <Event>...</Event> block matches both the outer Event
    element AND the inner <EventData> element with our regex. Merge
    consecutive records that share no overlapping keys."""
    if len(records) <= 1:
        return records
    merged: List[Dict[str, Any]] = []
    i = 0
    while i < len(records):
        cur = dict(records[i])
        if i + 1 < len(records):
            nxt = records[i + 1]
            if not (set(cur.keys()) & set(nxt.keys())):
                cur.update(nxt)
                merged.append(cur)
                i += 2
                continue
        merged.append(cur)
        i += 1
    return merged


_KV_TOKEN = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]{0,64})=(\"[^\"]*\"|'[^']*'|[^\s]+)")


def _parse_kv_line(line: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for m in _KV_TOKEN.finditer(line):
        k = m.group(1)
        v = m.group(2).strip("\"'")
        out[k] = v
    return out


__all__ = ["ParsedInput", "parse_input"]
