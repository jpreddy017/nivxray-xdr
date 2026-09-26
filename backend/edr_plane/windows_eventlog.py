"""Phase 0 · Windows Event Log → canonical evidence.

The Windows connector delivers one envelope per Windows Event Log record:

    {"kind": "WINDOWS_EVENT_LOG",
     "winlog": {"channel": ..., "record_id": ..., "event_id": ...,
                "provider": ..., "computer": ..., "time_created": ...,
                "xml": "<Event>…</Event>"}}

Before this module `canonical_bridge.parse()` refused that envelope
outright (`unknown sensor activity None`), because it only understood the
Linux connector's `activity` shape. A real Windows endpoint therefore
enrolled, authenticated and delivered successfully while producing NO
canonical evidence — its Device Trajectory, Process Tree, detections and
findings were all empty, and the endpoint still reported as fresh and
delivering. This module closes that gap.

What it does NOT do, deliberately:

* it invents no field. `EventData` is read as the source wrote it; an
  absent optional field stays absent and is named in `not_observed`;
* it fabricates no ProcessGuid. When Sysmon's `ProcessGuid` is present it
  is the AUTHORITATIVE Windows process identity. When it is not (Security
  4688 carries no such field), the best available source identity is
  preserved and the identity QUALITY is explicitly downgraded. The
  downgrade is a provenance state, never a substitute identifier;
* it maps no Windows evidence class onto a lane it does not belong to.
  Registry stays REGISTRY, DNS stays DNS, a logon stays AUTHENTICATION.

No new canonical schema is introduced: CES (`v2/ingestion/canonical.py`)
already mirrors the Sysmon + Windows Security union — `process_guid`,
`parent_process_guid`, `registry_key/value/data`, `dns_query`,
`dns_answer`, `sid`, `logon_id`, `logon_type`, `event_id`, `channel` —
and `_resolve_kind()` already owns Sysmon/Win-Sec event-id semantics.
This module fills that existing contract.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

ENVELOPE_KIND = "WINDOWS_EVENT_LOG"

SOURCE_VENDOR = "NivXForge"
SOURCE_PRODUCT = "WindowsSensor"
PAYLOAD_FORMAT = "nivxforge-windows-eventlog"
COLLECTION_METHOD = "WINDOWS_EVENTLOG_QUERY"

#: Identity quality states. These describe HOW WELL a process is known,
#: never WHICH process it is.
IDENTITY_PROCESS_GUID = "SOURCE_PROCESS_GUID"
IDENTITY_PID_ONLY = "PID_ONLY_NOT_AUTHORITATIVE"
IDENTITY_NOT_OBSERVED = "NOT_OBSERVED"

ACTIVITY_PROCESS = "PROCESS"
ACTIVITY_FILE = "FILE"
ACTIVITY_NETWORK = "NETWORK"
ACTIVITY_REGISTRY = "REGISTRY"
ACTIVITY_DNS = "DNS"
ACTIVITY_AUTHENTICATION = "AUTHENTICATION"

SYSMON_PROVIDER = "microsoft-windows-sysmon"
WINSEC_PROVIDER = "microsoft-windows-security-auditing"

#: (provider family, event id) → activity class. A record outside this map
#: is REFUSED with a truthful reason rather than being coerced into the
#: nearest lane.
SUPPORTED: Dict[Tuple[str, int], str] = {
    ("sysmon", 1): ACTIVITY_PROCESS,
    ("sysmon", 3): ACTIVITY_NETWORK,
    ("sysmon", 11): ACTIVITY_FILE,
    ("sysmon", 12): ACTIVITY_REGISTRY,
    ("sysmon", 13): ACTIVITY_REGISTRY,
    ("sysmon", 22): ACTIVITY_DNS,
    ("winsec", 4688): ACTIVITY_PROCESS,
    ("winsec", 4624): ACTIVITY_AUTHENTICATION,
}

#: Windows LogonType, mapped from the actual source value only.
LOGON_TYPES: Dict[str, str] = {
    "2": "INTERACTIVE", "3": "NETWORK", "4": "BATCH", "5": "SERVICE",
    "7": "UNLOCK", "8": "NETWORK_CLEARTEXT", "9": "NEW_CREDENTIALS",
    "10": "REMOTE_INTERACTIVE", "11": "CACHED_INTERACTIVE",
}

#: What this collection method cannot produce, per activity class. Carried
#: with the evidence so a gap is never read as "nothing happened".
NOT_SUPPORTED: Dict[str, Tuple[str, ...]] = {
    ACTIVITY_PROCESS: ("process.exit_time", "process.signer",
                       "process.signature_status"),
    ACTIVITY_FILE: ("file.sha256", "file.size", "file.signer"),
    ACTIVITY_NETWORK: ("network.bytes", "network.tcp_state"),
    ACTIVITY_REGISTRY: ("registry.previous_value",),
    ACTIVITY_DNS: ("dns.response_code_numeric",),
    ACTIVITY_AUTHENTICATION: ("authentication.session_end",),
}


class WindowsEventLogError(ValueError):
    """A truthful refusal. Carries a machine code and a human reason."""

    def __init__(self, code: str, reason: str):
        self.code, self.reason = code, reason
        super().__init__(f"{code}: {reason}")


def is_windows_envelope(ev: Any) -> bool:
    return (isinstance(ev, dict) and ev.get("kind") == ENVELOPE_KIND
            and isinstance(ev.get("winlog"), dict))


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _provider_family(provider: str) -> Optional[str]:
    p = (provider or "").strip().lower()
    if SYSMON_PROVIDER in p or p == "sysmon":
        return "sysmon"
    if WINSEC_PROVIDER in p or "security-auditing" in p:
        return "winsec"
    return None


def _int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _s(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_event_xml(xml: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """`(System fields, EventData name→value)` from a rendered Event XML.

    `wevtutil … /f:RenderedXml` emits a namespaced `<Event>` with a
    `<System>` block and a `<EventData>` block of `<Data Name="…">`
    children. Malformed XML is a refusal, not a partial guess.
    """
    if not isinstance(xml, str) or "<Event" not in xml:
        raise WindowsEventLogError(
            "WINDOWS_EVENT_XML_ABSENT",
            "the envelope carried no Windows Event XML, so there is nothing "
            "to canonicalise; the raw envelope is retained and replayable")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise WindowsEventLogError(
            "WINDOWS_EVENT_XML_MALFORMED",
            f"the Windows Event XML could not be parsed: {e}") from None

    system: Dict[str, Any] = {}
    data: Dict[str, str] = {}
    for block in root:
        name = _strip_ns(block.tag)
        if name == "System":
            for node in block:
                key = _strip_ns(node.tag)
                if key == "Provider":
                    system["provider"] = node.attrib.get("Name")
                elif key == "TimeCreated":
                    system["time_created"] = node.attrib.get("SystemTime")
                elif key == "Security":
                    system["security_user_id"] = node.attrib.get("UserID")
                elif key == "Execution":
                    system["execution_process_id"] = node.attrib.get(
                        "ProcessID")
                else:
                    system[key] = (node.text or "").strip() or None
        elif name == "EventData":
            for node in block:
                if _strip_ns(node.tag) != "Data":
                    continue
                key = node.attrib.get("Name")
                if key:
                    data[key] = (node.text or "").strip()
    return system, data


def classify(system: Dict[str, Any], envelope_winlog: Dict[str, Any]
             ) -> Tuple[str, str, int]:
    """`(family, activity, event_id)` — or a truthful refusal."""
    provider = (_s(system.get("provider"))
                or _s(envelope_winlog.get("provider")) or "")
    family = _provider_family(provider)
    event_id = _int(system.get("EventID")) or _int(
        envelope_winlog.get("event_id"))
    if event_id is None:
        raise WindowsEventLogError(
            "WINDOWS_EVENT_ID_ABSENT",
            "the record carried no EventID, so its meaning is unknown; the "
            "raw bytes are retained and replayable")
    if family is None:
        raise WindowsEventLogError(
            "WINDOWS_PROVIDER_NOT_SUPPORTED",
            f"provider {provider!r} is not a supported Windows evidence "
            f"source in this build (Sysmon and Windows Security only); the "
            f"record is retained raw and is not evidence of absence")
    activity = SUPPORTED.get((family, event_id))
    if activity is None:
        raise WindowsEventLogError(
            "WINDOWS_EVENT_ID_NOT_SUPPORTED",
            f"{family} EventID {event_id} is not canonicalised in this "
            f"build; the record is retained raw and replayable after the "
            f"event family is added. This is a coverage gap, not an "
            f"absence of activity")
    return family, activity, event_id


def _process_identity(guid: Optional[str], pid: Optional[str],
                      image: Optional[str], *, source: str
                      ) -> Dict[str, Any]:
    """Process evidence plus an explicit statement of identity QUALITY.

    `identity_quality` grades how well the process is known. It never
    replaces an identifier: when `ProcessGuid` is absent the PID and image
    are still preserved as correlation aids and are simply not presented
    as a lifetime-stable identity.
    """
    block: Dict[str, Any] = {}
    if pid is not None:
        block["pid"] = pid
    if image:
        block["executable_path"] = image
        block["name"] = image.replace("\\", "/").split("/")[-1]
    if guid:
        block["process_guid"] = guid
        block["identity_quality"] = IDENTITY_PROCESS_GUID
        block["identity_reason"] = (
            "Sysmon ProcessGuid identifies one process LIFETIME on this "
            "host, so ancestry and attribution survive PID reuse")
        block["field_provenance"] = {"process_guid": f"{source}:ProcessGuid"}
    elif pid is not None or image:
        block["identity_quality"] = IDENTITY_PID_ONLY
        block["identity_reason"] = (
            "this source carries no ProcessGuid, so the best available "
            "identity is a PID (and image where present). A PID is reused "
            "by the operating system: this is correlation context and must "
            "never be read as a lifetime-stable process identity")
        block["field_provenance"] = {
            k: f"{source}:{v}" for k, v in
            (("pid", "ProcessId"), ("executable_path", "Image"))
            if block.get(k) is not None}
    else:
        block["identity_quality"] = IDENTITY_NOT_OBSERVED
        block["identity_reason"] = (
            "this record named no process; which process acted was not "
            "observed and none is named")
    return block


def _parent(guid: Optional[str], pid: Optional[str], image: Optional[str],
            command_line: Optional[str], user: Optional[str],
            *, source: str) -> Dict[str, Any]:
    """Parent evidence, and how authoritative the ancestry link is."""
    out: Dict[str, Any] = {}
    if guid:
        out["parent_process_guid"] = guid
    if pid is not None:
        out["parent_pid"] = pid
    if image:
        out["parent_executable_path"] = image
        out["parent_name"] = image.replace("\\", "/").split("/")[-1]
    if command_line:
        out["parent_command_line"] = command_line
    if user:
        out["parent_user"] = user
    if guid:
        out["ancestry_state"] = "PARENT_OBSERVED_PROCESS_GUID"
        out["ancestry_reason"] = (
            f"the parent is named by ParentProcessGuid from {source}, which "
            f"binds this child to one parent LIFETIME")
    elif pid is not None or image:
        out["ancestry_state"] = "PARENT_OBSERVED_PID_ONLY"
        out["ancestry_reason"] = (
            "the parent is named by PID (and image where present) only. "
            "PIDs are reused, so this link is context and is not an "
            "authoritative ancestry claim")
    else:
        out["ancestry_state"] = "PARENT_NOT_OBSERVED"
        out["ancestry_reason"] = (
            "this record named no parent; the parent was not observed and "
            "none is inferred")
    return out


def _absent(data: Dict[str, str], *fields: str) -> List[str]:
    return [f for f in fields if not (data.get(f) or "").strip()]


def to_canonical(ev: Dict[str, Any]) -> Dict[str, Any]:
    """`WINDOWS_EVENT_LOG` envelope → the neutral canonical shape.

    Returns the same intermediate dict `canonical_bridge.parse()` returns
    for the Linux connector, so a single downstream path serves both.
    """
    winlog = ev.get("winlog") or {}
    system, data = parse_event_xml(winlog.get("xml"))
    family, activity, event_id = classify(system, winlog)
    source = "sysmon" if family == "sysmon" else "winsec"

    computer = (_s(system.get("Computer")) or _s(winlog.get("computer")))
    record_id = (_int(system.get("EventRecordID"))
                 or _int(winlog.get("record_id")))
    provider = (_s(system.get("provider")) or _s(winlog.get("provider")))
    channel = (_s(system.get("Channel")) or _s(winlog.get("channel")))
    # The OS's own statement of when the activity happened, preferred over
    # the moment the connector read the record.
    activity_time = (_s(data.get("UtcTime")) or _s(system.get("time_created"))
                     or _s(winlog.get("time_created")))

    canonical: Dict[str, Any] = {
        "source_vendor": SOURCE_VENDOR,
        "source_product": SOURCE_PRODUCT,
        "activity": activity,
        "observed_at": _s(ev.get("observed_at")),
        "activity_time": activity_time,
        "winlog": {
            "channel": channel, "provider": provider, "event_id": event_id,
            "record_id": record_id, "computer": computer,
            "time_created": (_s(system.get("time_created"))
                             or _s(winlog.get("time_created"))),
            "family": family,
            "level": _s(system.get("Level")),
            "event_data_fields": sorted(data.keys()),
        },
        "process": {},
        "file": {},
        "network": {},
        "registry": {},
        "dns": {},
        "authentication": {},
        "identity": {},
        "not_observed": [],
    }

    if activity == ACTIVITY_PROCESS and family == "sysmon":
        canonical["process"] = {
            **_process_identity(_s(data.get("ProcessGuid")),
                                _s(data.get("ProcessId")),
                                _s(data.get("Image")), source=source),
            **_parent(_s(data.get("ParentProcessGuid")),
                      _s(data.get("ParentProcessId")),
                      _s(data.get("ParentImage")),
                      _s(data.get("ParentCommandLine")),
                      _s(data.get("ParentUser")), source=source),
            "command_line": _s(data.get("CommandLine")),
            "current_directory": _s(data.get("CurrentDirectory")),
            "integrity_level": _s(data.get("IntegrityLevel")),
            "original_file_name": _s(data.get("OriginalFileName")),
            "file_version": _s(data.get("FileVersion")),
            "description": _s(data.get("Description")),
            "product": _s(data.get("Product")),
            "company": _s(data.get("Company")),
            "start_time": _s(data.get("UtcTime")),
            "hashes": _hashes(data.get("Hashes")),
        }
        canonical["identity"] = {
            "username": _s(data.get("User")),
            "logon_id": _s(data.get("LogonId")),
            "logon_guid": _s(data.get("LogonGuid")),
            "terminal_session_id": _s(data.get("TerminalSessionId")),
        }
        canonical["not_observed"] = _absent(
            data, "CommandLine", "Hashes", "ParentProcessGuid",
            "IntegrityLevel", "User")

    elif activity == ACTIVITY_PROCESS and family == "winsec":
        # 4688 carries no ProcessGuid — the identity downgrade below is the
        # honest consequence, not a deficiency to be papered over.
        canonical["process"] = {
            **_process_identity(None, _s(data.get("NewProcessId")),
                                _s(data.get("NewProcessName")),
                                source=source),
            **_parent(None, _s(data.get("CreatorProcessId")),
                      _s(data.get("CreatorProcessName")), None, None,
                      source=source),
            "command_line": _s(data.get("ProcessCommandLine")),
            "integrity_level": _s(data.get("MandatoryLabel")),
            "token_elevation_type": _s(data.get("TokenElevationType")),
            "start_time": activity_time,
            "hashes": {},
        }
        canonical["identity"] = {
            "username": _s(data.get("SubjectUserName")),
            "domain": _s(data.get("SubjectDomainName")),
            "sid": _s(data.get("SubjectUserSid")),
            "logon_id": _s(data.get("SubjectLogonId")),
        }
        canonical["not_observed"] = _absent(
            data, "ProcessCommandLine", "CreatorProcessName",
            "MandatoryLabel")
        canonical["not_observed"].append("ProcessGuid")

    elif activity == ACTIVITY_NETWORK:
        canonical["process"] = _process_identity(
            _s(data.get("ProcessGuid")), _s(data.get("ProcessId")),
            _s(data.get("Image")), source=source)
        initiated = (data.get("Initiated") or "").strip().lower()
        canonical["network"] = {
            "protocol": _s(data.get("Protocol")),
            "src_ip": _s(data.get("SourceIp")),
            "src_port": _s(data.get("SourcePort")),
            "src_hostname": _s(data.get("SourceHostname")),
            "dest_ip": _s(data.get("DestinationIp")),
            "dest_port": _s(data.get("DestinationPort")),
            # Sysmon's DestinationHostname is a reverse-resolution of the
            # peer performed by Windows. It is NOT a DNS query observation
            # and is never promoted into the DNS lane.
            "dest_hostname": _s(data.get("DestinationHostname")),
            "dest_hostname_basis": (
                "sysmon:DestinationHostname — Windows' own peer name for "
                "this connection; not a DNS query observation"),
            "direction": ("OUTBOUND" if initiated == "true"
                          else "INBOUND" if initiated == "false" else None),
            "initiated": _s(data.get("Initiated")),
        }
        canonical["identity"] = {"username": _s(data.get("User"))}
        canonical["not_observed"] = _absent(
            data, "SourceHostname", "DestinationHostname", "User")

    elif activity == ACTIVITY_FILE:
        canonical["process"] = _process_identity(
            _s(data.get("ProcessGuid")), _s(data.get("ProcessId")),
            _s(data.get("Image")), source=source)
        path = _s(data.get("TargetFilename"))
        canonical["file"] = {
            "path": path,
            "name": (path.replace("\\", "/").split("/")[-1] if path
                     else None),
            # Sysmon 11 is a CREATE. No other file operation is claimed.
            "operation": "CREATE",
            "creation_utc_time": _s(data.get("CreationUtcTime")),
            "hashes": _hashes(data.get("Hashes")),
        }
        canonical["identity"] = {"username": _s(data.get("User"))}
        canonical["not_observed"] = _absent(data, "Hashes", "User")

    elif activity == ACTIVITY_REGISTRY:
        canonical["process"] = _process_identity(
            _s(data.get("ProcessGuid")), _s(data.get("ProcessId")),
            _s(data.get("Image")), source=source)
        event_type = _s(data.get("EventType"))
        canonical["registry"] = {
            "key": _s(data.get("TargetObject")),
            # Sysmon 13 sets a VALUE and reports it in Details. Sysmon 12
            # creates or deletes a KEY and carries no value data.
            "value_data": _s(data.get("Details")) if event_id == 13 else None,
            "event_type": event_type,
            "operation": _registry_operation(event_id, event_type),
            "new_name": _s(data.get("NewName")),
        }
        canonical["identity"] = {"username": _s(data.get("User"))}
        canonical["not_observed"] = _absent(data, "User")
        if event_id == 12:
            canonical["not_observed"].append("Details")

    elif activity == ACTIVITY_DNS:
        canonical["process"] = _process_identity(
            _s(data.get("ProcessGuid")), _s(data.get("ProcessId")),
            _s(data.get("Image")), source=source)
        canonical["dns"] = {
            "query_name": _s(data.get("QueryName")),
            "query_status": _s(data.get("QueryStatus")),
            "query_results": _s(data.get("QueryResults")),
            "answers": _dns_answers(data.get("QueryResults")),
        }
        canonical["identity"] = {"username": _s(data.get("User"))}
        canonical["not_observed"] = _absent(data, "QueryResults", "User")

    else:  # ACTIVITY_AUTHENTICATION · Security 4624
        logon_type = _s(data.get("LogonType"))
        canonical["authentication"] = {
            "outcome": "SUCCESS",
            "logon_type": logon_type,
            # Interactive vs remote comes from the mapped LogonType and
            # from nowhere else. An unmapped value stays unmapped.
            "logon_type_name": LOGON_TYPES.get(str(logon_type or "")),
            "logon_type_basis": ("winsec:LogonType, mapped from the source "
                                 "value only"),
            "target_user": _s(data.get("TargetUserName")),
            "target_domain": _s(data.get("TargetDomainName")),
            "target_sid": _s(data.get("TargetUserSid")),
            "target_logon_id": _s(data.get("TargetLogonId")),
            "subject_user": _s(data.get("SubjectUserName")),
            "subject_domain": _s(data.get("SubjectDomainName")),
            "subject_sid": _s(data.get("SubjectUserSid")),
            "logon_process": _s(data.get("LogonProcessName")),
            "authentication_package": _s(
                data.get("AuthenticationPackageName")),
            "workstation_name": _s(data.get("WorkstationName")),
            "source_ip": _s(data.get("IpAddress")),
            "source_port": _s(data.get("IpPort")),
            "logon_guid": _s(data.get("LogonGuid")),
        }
        canonical["process"] = _process_identity(
            None, _s(data.get("ProcessId")), _s(data.get("ProcessName")),
            source=source)
        canonical["identity"] = {
            "username": _s(data.get("TargetUserName")),
            "domain": _s(data.get("TargetDomainName")),
            "sid": _s(data.get("TargetUserSid")),
            "logon_id": _s(data.get("TargetLogonId")),
        }
        canonical["not_observed"] = _absent(
            data, "IpAddress", "WorkstationName", "ProcessName")
        canonical["not_observed"].append("ProcessGuid")

    canonical["not_supported"] = list(NOT_SUPPORTED.get(activity, ()))
    canonical["collection_method"] = COLLECTION_METHOD
    return canonical


def _registry_operation(event_id: int, event_type: Optional[str]
                        ) -> Optional[str]:
    """The operation the SOURCE stated. Sysmon's own `EventType` wins."""
    stated = (event_type or "").strip().lower()
    if stated:
        return {"createkey": "KEY_CREATE", "deletekey": "KEY_DELETE",
                "deletevalue": "VALUE_DELETE", "setvalue": "VALUE_SET",
                "renamekey": "KEY_RENAME"}.get(stated, stated.upper())
    return "VALUE_SET" if event_id == 13 else None


def _hashes(raw: Any) -> Dict[str, str]:
    """Sysmon `Hashes` is `ALG=HEX,ALG=HEX`. Only what is present."""
    out: Dict[str, str] = {}
    for part in str(raw or "").split(","):
        if "=" not in part:
            continue
        alg, _, value = part.partition("=")
        alg, value = alg.strip().lower(), value.strip()
        if alg and value:
            out[{"imphash": "imphash"}.get(alg, alg)] = value
    return out


_IP = re.compile(r"^[0-9a-fA-F:.]+$")


def _dns_answers(raw: Any) -> List[str]:
    """Sysmon `QueryResults` is a `;`-separated answer list.

    Address answers appear bare or as the IPv4-mapped form
    `::ffff:93.184.216.34`. A `type:  5 www.example.com` entry is a CNAME
    record, not an address, and is not turned into one.
    """
    answers: List[str] = []
    for token in str(raw or "").split(";"):
        value = token.strip()
        if not value or value.lower().startswith("type:"):
            continue
        if value.lower().startswith("::ffff:") and value.count(".") == 3:
            value = value[len("::ffff:"):]
        if _IP.match(value) and any(c in value for c in ".:"):
            answers.append(value)
    return answers


def activity_identity_parts(canonical: Dict[str, Any]) -> Tuple[Any, ...]:
    """The identity of one Windows ACTIVITY, independent of delivery.

    A Windows Event Log record is already uniquely identified by its
    channel and `EventRecordID` on its host, so a redelivery of the same
    record is the same activity observed twice — not new activity.
    """
    winlog = canonical.get("winlog") or {}
    return (ENVELOPE_KIND, winlog.get("channel"), winlog.get("event_id"),
            winlog.get("record_id"))
