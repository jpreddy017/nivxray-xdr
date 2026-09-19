"""W2-1 · EVTX rendered-XML decoder — the ONE place Windows XML becomes JSON.

The W2-1 Windows Event Log adapter delivers what Windows itself produced:
`EvtRender(EvtRenderEventXml)`. That is the authoritative record. Every
Windows DSM in this package, however, reads a decoded document
(`EventID`, `System`, `EventData`, and for Sysmon the EventData names at
the top level). Without a decode step the raw XML reaches `supports()` as
an opaque string, no DSM claims it, and a channel that is genuinely
RECEIVING reports `NO_DSM` forever.

This module is that decode step, and nothing more:

  * it INTERPRETS nothing — no event is classified, no field is renamed
    into a canonical vocabulary, no time is chosen. Those remain DSM
    decisions;
  * it INVENTS nothing — a element Windows did not emit is absent, never
    defaulted. `EventData` with no `Data` children decodes to `{}`, which
    is a different fact from "no EventData element";
  * it DISCARDS nothing — the verbatim XML is returned alongside the
    decoded form under `evtx_xml`, so the raw record stays the authority
    and `raw_ref` can still cite it.

Unnamed `<Data>` children (the classic `Windows PowerShell` channel emits
these) are preserved positionally under `EventData.Data`, because their
meaning is their position and renaming them would be an invention.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

DECODER_ID = "evtx-xml-decoder/1.0.0"

#: Keys under which a delivery may carry a rendered EVTX record. `xml` is
#: what the W2-1 adapter sends (`framework/windows_eventlog.py`).
ENVELOPE_XML_KEYS = ("xml", "event_xml", "raw_xml")

#: Decoded System children whose text is an integer in the EVTX schema.
_INT_SYSTEM_FIELDS = ("EventID", "Level", "Task", "Opcode", "Version",
                      "EventRecordID")


class EvtxXmlDecodeError(Exception):
    """The payload claimed to be a rendered EVTX record and was not."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _local(tag: str) -> str:
    """Element name without the EVTX namespace."""
    return str(tag).rsplit("}", 1)[-1]


def _maybe_int(value: Any) -> Any:
    text = str(value).strip() if value is not None else ""
    if text and (text.isdigit() or (text[0] == "-" and text[1:].isdigit())):
        try:
            return int(text)
        except ValueError:
            return value
    return value


def looks_like_evtx_xml(value: Any) -> bool:
    """Is this string a rendered Windows event record?

    Deliberately narrow: both an `Event` root and a `System` block must be
    present. A document that merely contains angle brackets is not claimed.
    """
    if not isinstance(value, str):
        return False
    head = value.lstrip()[:4096]
    return "<Event" in head and "<System" in head


def envelope_xml(doc: Any) -> Optional[str]:
    """The rendered XML a delivered document carries, or None."""
    if isinstance(doc, str):
        return doc if looks_like_evtx_xml(doc) else None
    if not isinstance(doc, dict):
        return None
    for key in ENVELOPE_XML_KEYS:
        value = doc.get(key)
        if looks_like_evtx_xml(value):
            return value
    return None


def _decode_system(node: ET.Element) -> Dict[str, Any]:
    system: Dict[str, Any] = {}
    for child in node:
        name = _local(child.tag)
        text = (child.text or "").strip()
        if name == "Provider":
            system["Provider"] = child.attrib.get("Name", "")
            if child.attrib.get("Guid"):
                system["ProviderGuid"] = child.attrib["Guid"]
            if child.attrib.get("EventSourceName"):
                system["EventSourceName"] = child.attrib["EventSourceName"]
        elif name == "TimeCreated":
            # The instant the provider WROTE the record. Named exactly as
            # the schema names it; which clock this is remains the DSM's
            # declaration, not ours.
            system["TimeCreated"] = child.attrib.get("SystemTime", "")
        elif name == "Security":
            # A SID stays a SID. No principal rendering happens here.
            if child.attrib.get("UserID"):
                system["UserID"] = child.attrib["UserID"]
        elif name == "Execution":
            for attr, key in (("ProcessID", "ProcessID"),
                              ("ThreadID", "ThreadID")):
                if child.attrib.get(attr):
                    system[key] = _maybe_int(child.attrib[attr])
        elif name == "Correlation":
            for attr in ("ActivityID", "RelatedActivityID"):
                if child.attrib.get(attr):
                    system[attr] = child.attrib[attr]
        elif name == "EventID":
            system["EventID"] = _maybe_int(text)
            if child.attrib.get("Qualifiers"):
                system["Qualifiers"] = _maybe_int(child.attrib["Qualifiers"])
        elif text or name in ("Channel", "Computer"):
            system[name] = (_maybe_int(text) if name in _INT_SYSTEM_FIELDS
                            else text)
    return system


def _decode_event_data(node: ET.Element) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    positional: List[str] = []
    for child in node:
        name = _local(child.tag)
        text = (child.text or "").strip()
        if name == "Data":
            key = child.attrib.get("Name")
            if key:
                data[key] = text
            else:
                positional.append(text)
        elif name == "Binary":
            data["Binary"] = text
        elif text:
            data[name] = text
    if positional:
        # Positional meaning is the only meaning these carry.
        data["Data"] = positional
    return data


def _flatten_leaves(node: ET.Element, out: Dict[str, Any]) -> None:
    for child in node:
        if len(child):
            _flatten_leaves(child, out)
            continue
        text = (child.text or "").strip()
        if text:
            out[_local(child.tag)] = text
        for attr, value in child.attrib.items():
            out[f"{_local(child.tag)}@{attr}"] = value


def decode(xml: str) -> Dict[str, Any]:
    """Rendered EVTX XML → decoded document.

    Raises `EvtxXmlDecodeError` when the payload is not a parseable event
    record. It is raised rather than swallowed: a malformed record is a
    collection or transport fault, and it must not look like a channel
    with nothing to say.
    """
    if not isinstance(xml, str) or not xml.strip():
        raise EvtxXmlDecodeError("EVTX_EMPTY", "no XML payload was supplied")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise EvtxXmlDecodeError("EVTX_MALFORMED_XML", str(exc)) from exc

    if _local(root.tag) != "Event":
        raise EvtxXmlDecodeError(
            "EVTX_NOT_AN_EVENT",
            f"root element is <{_local(root.tag)}>, not <Event>")

    decoded: Dict[str, Any] = {}
    system: Dict[str, Any] = {}
    event_data: Optional[Dict[str, Any]] = None
    user_data: Optional[Dict[str, Any]] = None

    for child in root:
        name = _local(child.tag)
        if name == "System":
            system = _decode_system(child)
        elif name == "EventData":
            event_data = _decode_event_data(child)
        elif name == "UserData":
            flat: Dict[str, Any] = {}
            _flatten_leaves(child, flat)
            user_data = flat
        elif name == "RenderingInfo":
            info: Dict[str, Any] = {}
            _flatten_leaves(child, info)
            if info:
                decoded["RenderingInfo"] = info

    if "EventID" not in system:
        raise EvtxXmlDecodeError(
            "EVTX_MISSING_EVENT_ID",
            "the record carries no System/EventID, so it cannot be routed")

    decoded["System"] = system
    if event_data is not None:
        decoded["EventData"] = event_data
    if user_data is not None:
        decoded["UserData"] = user_data

    # ── top-level promotion, for the DSM contracts that already exist ──
    # Sysmon's parser reads `event_id`, `provider` and the EventData names
    # at the top level; the Security parser reads `System`/`EventData`.
    # Both shapes are served from the SAME decode, so neither DSM has to
    # learn about XML.
    for key, value in (event_data or {}).items():
        decoded.setdefault(key, value)
    decoded["EventID"] = system["EventID"]
    decoded["event_id"] = system["EventID"]
    if system.get("Provider"):
        decoded["Provider"] = system["Provider"]
        decoded["provider"] = system["Provider"]
    if system.get("Computer"):
        decoded["Computer"] = system["Computer"]
        decoded["computer"] = system["Computer"]
    if system.get("Channel"):
        decoded["Channel"] = system["Channel"]
        decoded["channel"] = system["Channel"]
    if system.get("TimeCreated"):
        decoded["TimeCreated"] = system["TimeCreated"]
        decoded["time_created"] = system["TimeCreated"]
    for key in ("Level", "EventRecordID", "UserID", "Task", "Keywords",
                "Opcode", "Version", "ActivityID", "ProcessID", "ThreadID"):
        if key in system:
            decoded.setdefault(key, system[key])

    decoded["evtx_xml"] = xml
    decoded["evtx_decoder_id"] = DECODER_ID
    return decoded


def decode_document(doc: Any) -> Optional[Dict[str, Any]]:
    """Decode a delivered document that CARRIES rendered EVTX XML.

    The delivery's own keys win: `channel` as the collector declared it,
    NivX transport metadata under `_nivx`, and anything else the envelope
    already stated is preserved exactly. Only fields the XML supplied and
    the document lacked are added.

    Returns None when the document carries no EVTX XML — the caller then
    leaves it untouched, because "not a Windows record" and "a Windows
    record we failed to read" must never look the same.
    """
    xml = envelope_xml(doc)
    if xml is None:
        return None
    decoded = decode(xml)
    if not isinstance(doc, dict):
        return decoded
    merged = dict(decoded)
    merged.update({k: v for k, v in doc.items() if v is not None})
    # The verbatim XML is not duplicated: the delivery already carries it
    # under its own key, and a second copy would double the stored size of
    # every Windows record for no evidentiary gain.
    if any(k in doc for k in ENVELOPE_XML_KEYS):
        merged.pop("evtx_xml", None)
    else:
        merged["evtx_xml"] = xml
    merged["evtx_decoder_id"] = DECODER_ID
    return merged
