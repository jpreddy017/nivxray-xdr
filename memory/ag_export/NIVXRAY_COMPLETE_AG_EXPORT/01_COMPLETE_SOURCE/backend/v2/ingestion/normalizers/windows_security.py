"""v2/ingestion/normalizers/windows_security.py · Windows Security XML → CES.

The Windows Security channel uses the same Windows Event XML skeleton
as Sysmon but with different EventID → EventData bindings. Rather than
duplicate the ET plumbing we reuse the sysmon parser's helpers.

Fully covered event IDs for Phase 4.1:
  · 4624 · Logon success
  · 4625 · Logon failure
  · 4634 · Logoff
  · 4672 · Special privileges assigned to new logon
  · 4688 · Process creation (with cmdline if 4688 audit is enabled)
  · 4697 · Service installed
  · 4698 · Scheduled task created
  · 4720 · User account created
  · 4732 · Member added to sensitive group
  · 5140 · Network share accessed
  · 5145 · Detailed file share access
  · 7045 · System channel · service installed
  · 1102 · Audit log cleared
"""
from __future__ import annotations
from typing import Iterator
import xml.etree.ElementTree as ET

from ..canonical import CanonicalEventRecord, IngestionProvenance
from .sysmon_xml import _iter_events, _localname, _find_child, _read_system, _read_event_data

NORMALIZER_ID = "windows_security_xml@1.0"


def _map_winsec_ces(eid: int, ed: dict[str, str], sys_: dict[str, str],
                    provenance: IngestionProvenance) -> CanonicalEventRecord:
    computer = sys_.get("Computer", "")
    prov = IngestionProvenance(**{**provenance.to_dict(), "normalizer": NORMALIZER_ID,
                                   "source": "windows_security",
                                   "format": "windows_security_xml"})

    r = CanonicalEventRecord(
        timestamp=sys_.get("TimeCreated", ""),
        provider=sys_.get("Provider") or "Microsoft-Windows-Security-Auditing",
        event_id=eid,
        channel=sys_.get("Channel", "Security"),
        computer=computer,
        raw_event=dict(ed),
        provenance=prov,
    )

    # Common identity fields
    r.user = ed.get("TargetUserName", "") or ed.get("SubjectUserName", "")
    r.sid = ed.get("TargetUserSid", "") or ed.get("SubjectUserSid", "")
    r.logon_id = ed.get("TargetLogonId", "") or ed.get("SubjectLogonId", "")
    r.logon_type = ed.get("LogonType", "")

    if eid == 4688:                                          # process creation
        r.process_id = ed.get("NewProcessId", "")
        r.image = ed.get("NewProcessName", "")
        r.parent_process_id = ed.get("ProcessId", "")
        r.parent_image = ed.get("ParentProcessName", "")
        r.command_line = ed.get("CommandLine", "")
    elif eid in (4624, 4625, 4634, 4672, 4776):              # logon events
        # No process-level info; identity already assigned.
        pass
    elif eid == 4697 or eid == 7045:                         # service install
        r.service = ed.get("ServiceName", "")
        r.image = ed.get("ImagePath") or ed.get("ServiceFileName", "")
    elif eid in (4698, 4700, 4701):                          # scheduled tasks
        r.task_name = ed.get("TaskName", "")
        r.image = ed.get("Command", "")
    elif eid in (5140, 5145):                                # share access
        r.file_path = ed.get("ShareName", "") + (ed.get("RelativeTargetName") and ("/" + ed.get("RelativeTargetName", "")) or "")
        r.src_ip = ed.get("IpAddress", "")
    elif eid == 5156:                                        # WFP net connect
        r.src_ip = ed.get("SourceAddress", "")
        r.src_port = ed.get("SourcePort", "")
        r.dst_ip = ed.get("DestAddress", "")
        r.dst_port = ed.get("DestPort", "")
        r.protocol = ed.get("Protocol", "")
        r.image = ed.get("Application", "")
    return r


def normalize(data: bytes, *,
              provenance: IngestionProvenance,
              metrics=None) -> Iterator[CanonicalEventRecord]:
    for evt in _iter_events(data):
        try:
            sys_ = _read_system(evt)
            ed = _read_event_data(evt)
            try:
                eid = int(sys_.get("EventID") or 0)
            except ValueError:
                eid = 0
            if metrics is not None and eid and eid not in _KNOWN_WINSEC_IDS:
                metrics.note_unknown_event_id(eid)
            yield _map_winsec_ces(eid, ed, sys_, provenance)
        except Exception as ex:
            if metrics is not None:
                metrics.note_parse_error(f"winsec:{type(ex).__name__}:{ex!s:.80}")


_KNOWN_WINSEC_IDS = {4624, 4625, 4634, 4672, 4688, 4697, 4698, 4700, 4720,
                     4732, 4738, 4776, 5140, 5145, 5156, 7045, 1102}
