"""P2 Slice-1 · Sysmon Event 1 (Process Create) → canonical behavioral
evidence. See `/app/memory/adr/0010q-p2-slice-1-blueprint.md`.

Contract (locked):
  · Accepts a single Sysmon Event 1 or an `<Events>` wrapper containing
    Event 1 elements. Every Event MUST have `System.EventID == 1`.
  · Emits a list of `BehavioralEvidence` dict records. Each record's
    shape mirrors the P0.2 evidence-chain records so downstream
    consumers do not need a special branch.
  · Parent-child relationship is EVIDENCE, not truth. Corroboration
    counted separately; `parent_child_uncorroborated=True` when
    fewer than 2 corroborating fields are present.
  · The adapter does NOT invoke a MITRE mapper. The router hands the
    normalized `command_line` to `services.die.api.analyze()` — the
    UI-DEF-02 authoritative surface — separately.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

# Prefer defusedxml (XXE-safe) but degrade gracefully. The bare stdlib
# parser is still safe against XXE in Python 3.7+ because entity
# resolution defaults to disabled, but defusedxml adds belt-and-braces.
try:
    import defusedxml.ElementTree as _ET   # type: ignore
    _XML_PARSER = "defusedxml"
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as _ET    # type: ignore
    _XML_PARSER = "stdlib"

_WEV_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

ADAPTER_ID = "sysmon.eid1.slice1@1.0"


class SysmonAdapterError(ValueError):
    """Adapter refused the input. Carries a short machine code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# XML plumbing
# ---------------------------------------------------------------------------
def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_child(elem: Any, name: str) -> Optional[Any]:
    for c in elem:
        if _localname(c.tag) == name:
            return c
    return None


def _read_event_data(evt: Any) -> Dict[str, str]:
    ed = _find_child(evt, "EventData")
    if ed is None:
        return {}
    out: Dict[str, str] = {}
    for d in ed:
        if _localname(d.tag) != "Data":
            continue
        name = d.attrib.get("Name") or ""
        out[name] = (d.text or "").strip()
    return out


def _read_system(evt: Any) -> Dict[str, str]:
    sys_ = _find_child(evt, "System")
    if sys_ is None:
        return {}
    out: Dict[str, str] = {}
    for c in sys_:
        name = _localname(c.tag)
        if name == "EventID":
            out["EventID"] = (c.text or "").strip()
        elif name == "TimeCreated":
            out["TimeCreated"] = c.attrib.get("SystemTime", "") or ""
        elif name == "Computer":
            out["Computer"] = (c.text or "").strip()
    return out


def _iter_events(root: Any):
    """Yield every `<Event>` element inside a well-formed root."""
    tag = _localname(root.tag)
    if tag == "Event":
        yield root
        return
    if tag == "Events":
        for c in root:
            if _localname(c.tag) == "Event":
                yield c
        return
    # Unknown wrapper — search one level deep for Event children.
    for c in root:
        if _localname(c.tag) == "Event":
            yield c


# ---------------------------------------------------------------------------
# Evidence record construction
# ---------------------------------------------------------------------------
def _short_ref(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]


def _corroboration_flags(evt_data: Dict[str, str]) -> Dict[str, Any]:
    """Determine which corroborating fields accompany the parent-child claim.

    Per ADR-0010q §4 the parent-child link is EVIDENCE, not truth. We
    surface the corroboration count so the analyst sees the strength
    of the claim without any implicit verdict inference.
    """
    flags: Dict[str, bool] = {
        "parent_image_path": bool(evt_data.get("ParentImage", "").strip()
                                   and "\\" in (evt_data.get("ParentImage") or "")),
        "hashes":            bool(evt_data.get("Hashes", "").strip()),
        "user_session":      bool(evt_data.get("LogonId", "").strip()
                                   or evt_data.get("User", "").strip()),
        "integrity_level":   bool(evt_data.get("IntegrityLevel", "").strip()),
        "temporal_delta":    bool(evt_data.get("UtcTime", "").strip()
                                   and evt_data.get("ParentProcessGuid", "").strip()),
    }
    count = sum(1 for v in flags.values() if v)
    return {
        "flags":                    flags,
        "count":                    count,
        "sufficient_for_provenance": count >= 2,
    }


# The Sysmon Event-1 fields we lift into evidence records. Anything
# absent from the payload is simply not emitted (no fabricated values).
_EVIDENCE_FIELD_MAP = (
    ("CommandLine",    "process.command_line",     "high"),
    ("Image",          "process.image",            "high"),
    ("ParentImage",    "parent.image",             "medium"),
    ("ParentCommandLine", "parent.command_line",   "medium"),
    ("Hashes",         "process.hashes",           "high"),
    ("IntegrityLevel", "process.integrity_level",  "medium"),
    ("User",           "process.user",             "medium"),
    ("LogonId",        "process.logon_id",         "low"),
    ("ProcessId",      "process.pid",              "high"),
    ("ParentProcessId", "parent.pid",              "medium"),
    ("CurrentDirectory", "process.cwd",            "low"),
)


def _behavioral_records(evt_data: Dict[str, str],
                         system:   Dict[str, str],
                         evidence_ref: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for wire_name, canonical_field, confidence in _EVIDENCE_FIELD_MAP:
        v = (evt_data.get(wire_name) or "").strip()
        if not v:
            continue
        records.append({
            "source":         "sysmon.eid1",
            "event_or_rule":  "sysmon.process_create",
            "field":          canonical_field,
            "observed_value": v[:800],
            "evidence_ref":   evidence_ref,
            "confidence":     confidence,
            "provenance":     {
                "adapter": ADAPTER_ID,
                "wire_field": wire_name,
                "host":       system.get("Computer") or None,
                "time":       system.get("TimeCreated") or None,
            },
        })
    return records


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def normalize_sysmon_xml(xml_text: str,
                          max_bytes: int = 512 * 1024
                          ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Parse a Sysmon Event-1 XML payload and return
    `(evidence_records, meta)`.

    `meta` includes: `adapter`, `xml_parser`, `event_count`,
    `parent_child_evidence.uncorroborated_count`, and — most
    importantly — the flat `command_line` fields (indexed per event)
    so the caller can hand them to the authoritative MITRE surface.
    """
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise SysmonAdapterError("empty_input", "empty or non-string XML payload")
    if len(xml_text.encode("utf-8")) > max_bytes:
        raise SysmonAdapterError("payload_too_large",
                                  f"XML payload exceeds {max_bytes} bytes")

    try:
        root = _ET.fromstring(xml_text)
    except _ET.ParseError as exc:
        raise SysmonAdapterError("malformed_xml", f"XML parse error: {exc}") from exc

    events = list(_iter_events(root))
    if not events:
        raise SysmonAdapterError("no_event_element", "no <Event> element found")

    all_records: List[Dict[str, Any]] = []
    command_lines: List[str] = []
    uncorroborated = 0
    parent_child_pairs: List[Dict[str, Any]] = []

    for evt in events:
        system = _read_system(evt)
        eid_raw = system.get("EventID", "").strip()
        if eid_raw != "1":
            raise SysmonAdapterError(
                "unsupported_event_id",
                f"Slice-1 supports Sysmon Event 1 only; got EventID={eid_raw!r}",
            )
        evt_data = _read_event_data(evt)
        command_line = (evt_data.get("CommandLine") or "").strip()
        image        = (evt_data.get("Image") or "").strip()
        parent_image = (evt_data.get("ParentImage") or "").strip()
        evidence_ref = _short_ref("sysmon.eid1",
                                    system.get("TimeCreated", ""),
                                    image, command_line,
                                    evt_data.get("ProcessId", ""))
        records = _behavioral_records(evt_data, system, evidence_ref)
        all_records.extend(records)
        if command_line:
            command_lines.append(command_line)

        corr = _corroboration_flags(evt_data)
        if not corr["sufficient_for_provenance"]:
            uncorroborated += 1
        parent_child_pairs.append({
            "child_image":    image,
            "child_pid":      evt_data.get("ProcessId") or "",
            "parent_image":   parent_image,
            "parent_pid":     evt_data.get("ParentProcessId") or "",
            "corroboration":  corr,
            "parent_child_uncorroborated": not corr["sufficient_for_provenance"],
        })

    meta: Dict[str, Any] = {
        "adapter":        ADAPTER_ID,
        "xml_parser":     _XML_PARSER,
        "event_count":    len(events),
        "command_lines":  command_lines,
        "parent_child_pairs": parent_child_pairs,
        "parent_child_uncorroborated_count": uncorroborated,
        "limitations": {
            "ppid_spoofing":
                "Parent-child linkage in Sysmon Event 1 is not verifiable "
                "against PPID spoofing (T1134.004). Corroborate with image "
                "path, hash, user session, integrity level, and temporal "
                "sequence — see corroboration flags per event.",
        },
    }
    return all_records, meta
