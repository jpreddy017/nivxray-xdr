"""v2/ingestion/normalizers/sysmon_xml.py · Sysmon XML → CES.

Accepts:
  · A single `<Event>` element
  · An `<Events>` wrapper with N children (most common exports)
  · A stream of `<Event>` elements concatenated (Get-WinEvent -Xml output)

The Sysmon EventData `<Data Name="X">Y</Data>` structure is the source
of truth for every field.

References:
  · https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
  · https://github.com/SwiftOnSecurity/sysmon-config
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from typing import Iterator

from ..canonical import CanonicalEventRecord, IngestionProvenance

NORMALIZER_ID = "sysmon_xml@1.0"

# The Windows Event XML namespace — used only when reading real
# `Get-WinEvent -Xml` output. Manual test fixtures may drop it.
_WEV = "http://schemas.microsoft.com/win/2004/08/events/event"


def _localname(tag: str) -> str:
    """Strip an XML namespace prefix if present."""
    return tag.rsplit("}", 1)[-1]


def _find_child(elem: ET.Element, name: str) -> ET.Element | None:
    """Find a direct child by local name, namespace-agnostic."""
    for c in elem:
        if _localname(c.tag) == name:
            return c
    return None


def _read_event_data(evt: ET.Element) -> dict[str, str]:
    """Return the EventData/Data map (name → text)."""
    ed = _find_child(evt, "EventData")
    out: dict[str, str] = {}
    if ed is None:
        return out
    for d in ed:
        if _localname(d.tag) != "Data":
            continue
        name = d.attrib.get("Name") or ""
        out[name] = (d.text or "").strip()
    return out


def _read_system(evt: ET.Element) -> dict[str, str]:
    sys_ = _find_child(evt, "System")
    out: dict[str, str] = {}
    if sys_ is None:
        return out
    for c in sys_:
        lname = _localname(c.tag)
        if lname == "Provider":
            out["Provider"] = c.attrib.get("Name") or ""
        elif lname == "EventID":
            out["EventID"] = (c.text or "").strip()
        elif lname == "TimeCreated":
            out["TimeCreated"] = c.attrib.get("SystemTime") or ""
        elif lname == "Computer":
            out["Computer"] = (c.text or "").strip()
        elif lname == "Channel":
            out["Channel"] = (c.text or "").strip()
        elif lname == "Security":
            out["UserID"] = c.attrib.get("UserID") or ""
    return out


def _iter_events(data: bytes) -> Iterator[ET.Element]:
    text = data.decode("utf-8", errors="ignore").strip()
    if not text:
        return
    # Wrap concatenated <Event> streams in a synthetic root only when
    # there's no existing outer <Events>...</Events> wrapper.
    if text.count("<Event ") > 1 and "<Events" not in text:
        text = f"<Events>\n{text}\n</Events>"
    # ElementTree is namespace-picky — declare it if missing
    if "<Event xmlns" not in text and f"xmlns=\"{_WEV}\"" not in text:
        # not fatal, ET will still parse. Do nothing.
        pass
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    if _localname(root.tag) == "Event":
        yield root
        return
    for c in root:
        if _localname(c.tag) == "Event":
            yield c


def normalize(data: bytes, *,
              provenance: IngestionProvenance,
              metrics=None) -> Iterator[CanonicalEventRecord]:
    """Yield CES records from a Sysmon XML dump."""
    prov = IngestionProvenance(**{**provenance.to_dict(), "normalizer": NORMALIZER_ID,
                                   "source": "sysmon", "format": "sysmon_xml"})
    for evt in _iter_events(data):
        try:
            sys_ = _read_system(evt)
            ed = _read_event_data(evt)
            try:
                eid = int(sys_.get("EventID") or 0)
            except ValueError:
                eid = 0
            r = CanonicalEventRecord(
                timestamp=sys_.get("TimeCreated", ""),
                provider=sys_.get("Provider", "Microsoft-Windows-Sysmon"),
                event_id=eid or None,
                channel=sys_.get("Channel", ""),
                computer=sys_.get("Computer", ""),
                device_id="",
                user=ed.get("User", ""),
                sid=sys_.get("UserID", ""),
                logon_id=ed.get("LogonId", ""),
                process_guid=ed.get("ProcessGuid", ""),
                process_id=ed.get("ProcessId", ""),
                parent_process_guid=ed.get("ParentProcessGuid", ""),
                parent_process_id=ed.get("ParentProcessId", ""),
                parent_image=ed.get("ParentImage", ""),
                image=ed.get("Image", ""),
                command_line=ed.get("CommandLine", ""),
                current_directory=ed.get("CurrentDirectory", ""),
                integrity_level=ed.get("IntegrityLevel", ""),
                file_path=ed.get("TargetFilename") or ed.get("ImageLoaded", ""),
                file_hash_md5=_extract_hash(ed.get("Hashes", ""), "MD5"),
                file_hash_sha1=_extract_hash(ed.get("Hashes", ""), "SHA1"),
                file_hash_sha256=_extract_hash(ed.get("Hashes", ""), "SHA256"),
                registry_key=ed.get("TargetObject", "") if eid in (12, 13, 14) else "",
                registry_value=ed.get("Details", "") if eid == 13 else "",
                registry_data=ed.get("Details", "") if eid == 13 else "",
                src_ip=ed.get("SourceIp", ""),
                src_port=ed.get("SourcePort", ""),
                dst_ip=ed.get("DestinationIp", ""),
                dst_port=ed.get("DestinationPort", ""),
                protocol=ed.get("Protocol", ""),
                dns_query=ed.get("QueryName", ""),
                dns_answer=ed.get("QueryResults", ""),
                url="",
                service=ed.get("Service", ""),
                task_name="",
                logon_type=ed.get("LogonType", ""),
                raw_event=dict(ed),
                provenance=prov,
            )
            if metrics is not None and eid and eid not in _KNOWN_SYSMON_IDS:
                metrics.note_unknown_event_id(eid)
            yield r
        except Exception as ex:
            if metrics is not None:
                metrics.note_parse_error(f"sysmon:{type(ex).__name__}:{ex!s:.80}")


_HASH_RE = re.compile(r"(?i)(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)")


def _extract_hash(blob: str, kind: str) -> str:
    if not blob:
        return ""
    for m in _HASH_RE.finditer(blob):
        if m.group(1).upper() == kind.upper():
            return m.group(2).lower()
    return ""


_KNOWN_SYSMON_IDS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 255}
