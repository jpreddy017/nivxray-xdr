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

from edr_plane.instant import rfc3339

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
#: B5-1 · a process TERMINATION is its own activity class, not a variant
#: of PROCESS. The PROCESS branch reads `UtcTime` as the process START
#: time; on Sysmon EventID 5 that same field is the EXIT time, so reusing
#: the branch would have recorded an exit instant as a start instant —
#: fabricated evidence of when the process began.
ACTIVITY_PROCESS_TERMINATION = "PROCESS_TERMINATION"
ACTIVITY_FILE = "FILE"
ACTIVITY_NETWORK = "NETWORK"
ACTIVITY_REGISTRY = "REGISTRY"
ACTIVITY_DNS = "DNS"
ACTIVITY_AUTHENTICATION = "AUTHENTICATION"

SYSMON_PROVIDER = "microsoft-windows-sysmon"

#: Sysmon's provider GUID. A bare `EventID` is NOT a Sysmon identifier:
#: `Microsoft-Windows-IsolatedUserMode` also emits EventID 5 (Secure
#: Trustlet start, not a termination), which is exactly how a count of
#: 249 "EID5" records once hid the 17 genuine ProcessTerminate events.
#: Every measurement of a Sysmon event id MUST be provider-qualified.
SYSMON_PROVIDER_GUID = "5770385F-C22A-43E0-BF4C-06F5698FFBD9"
WINSEC_PROVIDER = "microsoft-windows-security-auditing"

#: (provider family, event id) → activity class. A record outside this map
#: is REFUSED with a truthful reason rather than being coerced into the
#: nearest lane.
SUPPORTED: Dict[Tuple[str, int], str] = {
    ("sysmon", 1): ACTIVITY_PROCESS,
    #: B5-1 · Sysmon ProcessTerminate. Admitted so that a COLLECTED
    #: termination becomes evidence instead of a
    #: `WINDOWS_EVENT_ID_NOT_SUPPORTED` refusal. Admitting it does not
    #: generate it: the endpoint configuration still has to emit it.
    ("sysmon", 5): ACTIVITY_PROCESS_TERMINATION,
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
    #: EventID 5 states WHO exited and WHEN. It states nothing about how:
    #: Sysmon carries no exit code, and it repeats neither the command
    #: line, the hashes nor the parent it reported at creation.
    ACTIVITY_PROCESS_TERMINATION: ("process.exit_code",
                                   "process.command_line",
                                   "process.hashes",
                                   "process.parent_process_guid"),
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


# ── read-side resolution ──────────────────────────────────────────────
# Consumers (Events projection, facets, filters, process surface,
# response targeting) were written for the Linux connector's flat
# envelope, which carries a top-level `activity`. A Windows envelope does
# not, so those consumers read nothing and reported NOT STAMPED even
# though canonical evidence existed. Everything below RESOLVES the class
# the bridge already derived, from the SAME `SUPPORTED` table `classify()`
# uses. It never introduces a second mapping and never infers an activity
# from a numeric EventID alone.

#: Channel → provider family. A privileged channel is written by exactly
#: one provider, so it identifies the family when the envelope did not
#: carry the provider — and it is consulted ONLY then, never to override a
#: provider that is present but unsupported.
CHANNEL_FAMILY: Dict[str, str] = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "winsec",
}

#: Payload text signatures per family, for server-side aggregation where
#: the envelope cannot be deserialised (Mongo `$regexMatch`). Each
#: alternative is keyed to a field name or attribute, never a bare
#: substring, so a command line that merely MENTIONS Sysmon is not a
#: Sysmon record. The GUID and XML forms exist because a payload may
#: carry the provider only as a GUID, or as event XML rather than JSON.
FAMILY_PAYLOAD_REGEX: Dict[str, str] = {
    "sysmon": (r'"channel"\s*:\s*"Microsoft-Windows-Sysmon/Operational"'
               r'|"provider"\s*:\s*"[^"]*Sysmon'
               r'|"provider_guid"\s*:\s*"\{?' + SYSMON_PROVIDER_GUID +
               r'|<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
               r'|Name=.{0,2}Microsoft-Windows-Sysmon'
               r'|Guid=.{0,2}\{?' + SYSMON_PROVIDER_GUID),
    "winsec": (r'"channel"\s*:\s*"Security"'
               r'|"provider"\s*:\s*"[^"]*Security-Auditing'),
}


def _channel_family(channel: Any) -> Optional[str]:
    return CHANNEL_FAMILY.get((str(channel or "")).strip().lower())


#: Canonical class → the Events Explorer's filter/tile vocabulary. The
#: canonical evidence keeps its own name; only the PROJECTION is aliased,
#: because the console's class list came from the Linux connector and
#: spells this class `AUTH`. Without the alias a Security 4624 would be
#: counted under a class the console does not display, so the AUTH tile
#: would have stayed NOT OBSERVED even with the activity resolved.
PROJECTION_CLASS: Dict[str, str] = {ACTIVITY_AUTHENTICATION: "AUTH"}


def projection_class(activity: Optional[str]) -> Optional[str]:
    return PROJECTION_CLASS.get(activity or "", activity)


def _provider_of(winlog: Dict[str, Any]) -> Optional[str]:
    provider = _s(winlog.get("provider"))
    if provider:
        return provider
    xml = winlog.get("xml")
    if isinstance(xml, str):
        found = re.search(r"<Provider[^>]*Name=['\"]([^'\"]+)['\"]", xml)
        if found:
            return _s(found.group(1))
    return None


def _event_id_of(winlog: Dict[str, Any]) -> Optional[int]:
    event_id = _int(winlog.get("event_id"))
    if event_id is not None:
        return event_id
    xml = winlog.get("xml")
    if isinstance(xml, str):
        found = re.search(r"<EventID[^>]*>\s*(\d+)\s*<", xml)
        if found:
            return _int(found.group(1))
    return None


def envelope_activity(ev: Any) -> Tuple[Optional[str], str]:
    """`(activity, reason)` for a Windows envelope — the ONE resolver.

    `(None, reason)` for anything outside `SUPPORTED`, so an unsupported
    family stays an explicit coverage gap instead of being coerced into
    the nearest lane. Classification is provider-or-privileged-channel
    family **plus** EventID: an unrelated provider carrying the same
    numeric EventID resolves to nothing.
    """
    if not is_windows_envelope(ev):
        return None, "not a Windows Event Log envelope"
    winlog = ev["winlog"]
    provider = _provider_of(winlog)
    if provider:
        family = _provider_family(provider)
        if family is None:
            return None, (f"provider {provider!r} is not a supported Windows "
                          f"evidence source in this build; retained raw and "
                          f"not evidence of absence")
    else:
        family = _channel_family(winlog.get("channel"))
        if family is None:
            return None, ("the record named no supported provider and its "
                          "channel is not a known privileged channel")
    event_id = _event_id_of(winlog)
    if event_id is None:
        return None, "the record carried no EventID, so its meaning is unknown"
    activity = SUPPORTED.get((family, event_id))
    if activity is None:
        return None, (f"{family} EventID {event_id} is not canonicalised in "
                      f"this build; a coverage gap, not an absence of "
                      f"activity")
    return activity, f"canonical mapping ({family}, EventID {event_id})"


def envelope_event_time(ev: Any) -> Tuple[Optional[str], Optional[str]]:
    """`(event time, provenance)` — when the RECORD says it happened.

    The Windows sensor does not populate the transport's `event_time`
    field, so the raw document has none and the projection showed a blank.
    This reads the record's own `TimeCreated`, falling back to the
    sensor's observation time, and always says which one it used.
    """
    if not is_windows_envelope(ev):
        return None, None
    winlog = ev["winlog"]
    created = _s(winlog.get("time_created"))
    if not created and isinstance(winlog.get("xml"), str):
        found = re.search(r"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)['\"]",
                          winlog["xml"])
        created = _s(found.group(1)) if found else None
    if created:
        return created, "winlog.TimeCreated"
    observed = _s(ev.get("observed_at"))
    if observed:
        return observed, "sensor.observed_at"
    return None, None


def flat_view(ev: Any) -> Optional[Dict[str, Any]]:
    """A flat, Linux-connector-shaped projection of a Windows envelope.

    Consumers that walk raw payloads expect `activity`, `command_line`,
    `pid`, `image_path`, … . This projects `to_canonical()` into those
    keys so those surfaces can read Windows evidence WITHOUT a second
    mapping. Returns `None` when the record does not canonicalise, so an
    unsupported family is never surfaced as an activity.
    """
    if not is_windows_envelope(ev):
        return None
    try:
        canonical = to_canonical(ev)
    except WindowsEventLogError:
        return None
    proc = canonical.get("process") or {}
    identity = canonical.get("identity") or {}
    view = {
        "activity": canonical.get("activity"),
        "observed_at": canonical.get("activity_time")
                       or canonical.get("observed_at"),
        "start_time": proc.get("start_time"),
        "pid": proc.get("pid"),
        "ppid": proc.get("parent_pid"),
        "user": identity.get("username"),
        "image": proc.get("name"),
        "image_path": proc.get("executable_path"),
        "sha256": (proc.get("hashes") or {}).get("sha256"),
        "command_line": proc.get("command_line"),
        "parent_image": proc.get("parent_name"),
        "parent_image_path": proc.get("parent_executable_path"),
        "parent_lookup_state": proc.get("ancestry_state") or "NOT_OBSERVED",
        "collection_method": canonical.get("collection_method"),
        "not_observed": list(canonical.get("not_observed") or ()),
        "not_supported": list(canonical.get("not_supported") or ()),
        "process_guid": proc.get("process_guid"),
        "identity_quality": proc.get("identity_quality"),
        "windows_channel": (canonical.get("winlog") or {}).get("channel"),
        "windows_event_id": (canonical.get("winlog") or {}).get("event_id"),
        "view": "PROJECTED_FROM_WINDOWS_CANONICAL",
    }
    return {k: v for k, v in view.items() if v not in (None, [], "")}


def payload_event_id_regex(event_id: int) -> str:
    """Matches `"event_id": "4624"` / `"event_id": 4624` and nothing longer.

    PROVIDER-BLIND. Never use alone to COUNT a Sysmon event id — several
    Windows providers share low event ids. Use `sysmon_event_clause` or
    `is_sysmon_event`.
    """
    return r'"event_id"\s*:\s*"?%d"?\s*[,}]' % event_id


def event_id_regex(event_id: int) -> str:
    """`event_id` in either payload shape: JSON envelope or event XML."""
    return (r'("event_id"\s*:\s*"?%d"?\s*[,}]'
            r'|<EventID[^>]*>\s*%d\s*</EventID>)' % (event_id, event_id))


def sysmon_event_clause(event_id: int, payload_field: str = "payload"
                        ) -> Dict[str, Any]:
    """THE sanctioned `find()` clause for counting a genuine Sysmon event id.

    Requires BOTH the Sysmon provider (by name, provider GUID or its
    privileged channel) AND the event id. A bare event-id filter is not a
    valid measurement of Sysmon ProcessTerminate and must not be used.
    """
    return {"$and": [
        {payload_field: {"$regex": FAMILY_PAYLOAD_REGEX["sysmon"],
                         "$options": "i"}},
        {payload_field: {"$regex": event_id_regex(event_id),
                         "$options": "i"}}]}


def is_sysmon_event(payload: Any, event_id: int) -> bool:
    """True only when `payload` is a genuine Sysmon record of `event_id`.

    In-process counterpart of `sysmon_event_clause`, for counting over a
    corpus. A non-Sysmon provider carrying the same event id — an
    IsolatedUserMode Trustlet EventID 5, say — is False.
    """
    text = payload if isinstance(payload, str) else str(payload or "")
    if not re.search(FAMILY_PAYLOAD_REGEX["sysmon"], text, re.I):
        return False
    return bool(re.search(event_id_regex(event_id), text, re.I))


def activity_projection_expr(payload_field: str = "$payload",
                             derivations_field: str = "$derivations"
                             ) -> Dict[str, Any]:
    """Mongo expression resolving the activity class of a raw event.

    Generated FROM `SUPPORTED`, so the aggregation can never drift from
    the bridge's mapping. Windows branches additionally require that the
    event actually produced canonical evidence (a derivation carrying an
    `event_id`), so a coverage gap is never counted as an observed class.
    """
    payload = {"$ifNull": [payload_field, ""]}
    canonical_gate = {"$gt": [{"$size": {"$filter": {
        "input": {"$ifNull": [derivations_field, []]},
        "as": "d",
        "cond": {"$ne": [{"$ifNull": ["$$d.event_id", None]}, None]}}}}, 0]}
    branches = []
    for (family, event_id), activity in SUPPORTED.items():
        branches.append({"case": {"$and": [
            canonical_gate,
            {"$regexMatch": {"input": payload,
                             "regex": FAMILY_PAYLOAD_REGEX[family],
                             "options": "i"}},
            {"$regexMatch": {"input": payload,
                             "regex": payload_event_id_regex(event_id)}}]},
            "then": projection_class(activity)})
    linux = {"$regexFind": {"input": payload,
                            "regex": r'"activity"\s*:\s*"([A-Z_]+)"'}}
    return {"$let": {
        "vars": {"m": linux},
        "in": {"$cond": [
            {"$gt": [{"$size": {"$ifNull": ["$$m.captures", []]}}, 0]},
            {"$arrayElemAt": ["$$m.captures", 0]},
            {"$switch": {"branches": branches, "default": None}}]}}}


def activity_query_clauses(activity: str) -> List[Dict[str, Any]]:
    """`find()` clauses matching Windows records of one activity class.

    Returned as alternatives to be OR-ed with the Linux payload pattern by
    the caller; each requires canonical evidence to exist.
    """
    clauses: List[Dict[str, Any]] = []
    wanted = projection_class(activity.strip().upper())
    for (family, event_id), mapped in SUPPORTED.items():
        if projection_class(mapped) != wanted:
            continue
        clauses.append({"$and": [
            # $elemMatch, not dotted `derivations.event_id`: with a dotted
            # path `$ne: null` fails as soon as ANY element lacks the
            # field, and a detection derivation legitimately has no
            # event_id — which silently matched nothing.
            {"derivations": {"$elemMatch": {
                "event_id": {"$exists": True, "$ne": None}}}},
            {"payload": {"$regex": FAMILY_PAYLOAD_REGEX[family],
                         "$options": "i"}},
            {"payload": {"$regex": payload_event_id_regex(event_id)}}]})
    return clauses


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
    #
    # NEW INGESTION writes it as RFC 3339 UTC. Sysmon states this instant as
    # `2026-09-22 15:43:31.770` — the same instant, in a representation that
    # does not compare with an ISO bound. Only the WRITING changes here; the
    # instant is preserved exactly and the source string is retained below in
    # `winlog.activity_time_source`. A value we cannot parse is passed
    # through untouched rather than dropped.
    _utc_source = _s(data.get("UtcTime"))
    _created_source = (_s(system.get("time_created"))
                       or _s(winlog.get("time_created")))
    activity_time = (rfc3339(_utc_source) or _utc_source
                     or rfc3339(_created_source) or _created_source)

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
            #: the activity instant exactly as the source wrote it
            "activity_time_source": _utc_source or _created_source,
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
            "start_time": rfc3339(_utc_source) or _utc_source,
            "hashes": _hashes(data.get("Hashes")),
        }
        # B1 · field provenance for EVERY field this branch maps, not just
        # the identity. The XDR DSM plane already records
        # `hashes.sha256 → sysmon:EventData.Hashes(SHA256)`; this path
        # recorded provenance ONLY for `process_guid`, so the same fact
        # arrived with provenance on one dialect and without it on the
        # other. Provenance is part of the evidence.
        _prov = canonical["process"].setdefault("field_provenance", {})
        for _field, _wire in (("command_line", "CommandLine"),
                              ("current_directory", "CurrentDirectory"),
                              ("integrity_level", "IntegrityLevel"),
                              ("original_file_name", "OriginalFileName"),
                              ("executable_path", "Image"),
                              ("pid", "ProcessId"),
                              ("parent_pid", "ParentProcessId"),
                              ("parent_executable_path", "ParentImage"),
                              ("parent_command_line", "ParentCommandLine"),
                              ("parent_process_guid", "ParentProcessGuid")):
            if canonical["process"].get(_field):
                _prov.setdefault(_field, f"{source}:{_wire}")
        if canonical["process"].get("start_time"):
            _prov.setdefault("start_time", f"{source}:UtcTime")
        for _algo in (canonical["process"].get("hashes") or {}):
            _prov.setdefault(f"hashes.{_algo}",
                             f"{source}:EventData.Hashes({_algo.upper()})")
        canonical["identity"] = {
            "username": _s(data.get("User")),
            "logon_id": _s(data.get("LogonId")),
            "logon_guid": _s(data.get("LogonGuid")),
            "terminal_session_id": _s(data.get("TerminalSessionId")),
        }
        canonical["not_observed"] = _absent(
            data, "CommandLine", "Hashes", "ParentProcessGuid",
            "IntegrityLevel", "User")

    elif activity == ACTIVITY_PROCESS_TERMINATION and family == "sysmon":
        # B5-1 · Sysmon EventID 5. Only four things are stated:
        # ProcessGuid, ProcessId, Image, User — and `UtcTime`, which is
        # the EXIT instant. It is recorded as `exit_time` and NEVER as
        # `start_time`; no command line, hash, or parent is carried over
        # from the creation event, because this record does not state
        # them and the process they belonged to is identified by GUID,
        # not by copying fields between events.
        canonical["process"] = {
            **_process_identity(_s(data.get("ProcessGuid")),
                                _s(data.get("ProcessId")),
                                _s(data.get("Image")), source=source),
            "exit_time": activity_time,
        }
        _prov = canonical["process"].setdefault("field_provenance", {})
        _prov.setdefault("exit_time", f"{source}:UtcTime (EventID 5)")
        for _field, _wire in (("executable_path", "Image"),
                              ("pid", "ProcessId")):
            if canonical["process"].get(_field):
                _prov.setdefault(_field, f"{source}:{_wire}")
        canonical["identity"] = {"username": _s(data.get("User"))}
        canonical["not_observed"] = _absent(data, "User") + [
            # Stated as absent FROM THIS RECORD, so no consumer reads the
            # absence as "the process had no command line".
            "CommandLine", "Hashes", "ParentProcessGuid", "ParentImage",
            "process.start_time",
        ]

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
        # B3 · file-field provenance. A preserved hash with no provenance
        # cannot be traced to the wire field that produced it, and a file
        # hash must never be confusable with the writer's image hash.
        canonical["file"]["field_provenance"] = {
            **({"path": f"{source}:TargetFilename"} if path else {}),
            **({"name": f"{source}:TargetFilename (basename)"}
               if path else {}),
            "operation": f"{source}:EventID {event_id} (FileCreate)",
            **{f"hashes.{algo}": f"{source}:EventData.Hashes({algo.upper()})"
               for algo in (canonical["file"].get("hashes") or {})},
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
    #: B1/B5-1 · the OBSERVED KIND, from the one event-id vocabulary the
    #: platform already owns (`v2.ingestion.canonical`). This path used to
    #: state only the activity CLASS ("PROCESS"), so a consumer reading
    #: the canonical record could not tell a process creation from a
    #: process termination without re-deriving it from the Event ID — and
    #: process-identity lifetime resolution needs exactly that
    #: distinction. One fact, one name, one source of truth.
    from v2.ingestion.canonical import SYSMON_KIND, WINSEC_KIND
    canonical["observed_kind"] = (
        (SYSMON_KIND if family == "sysmon" else WINSEC_KIND).get(event_id))
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
    """Sysmon `Hashes` is `ALG=HEX,ALG=HEX`. Only what is present.

    B1 · the digest is lower-cased. A hex digest is case-insensitive, so
    this is lossless — and it is REQUIRED for convergence: Sysmon renders
    `SHA256=9F86…` in upper case, the XDR DSM plane stores `9f86…`, and
    an IOC / reputation lookup keyed on the lower-case form matched on
    one path and silently missed on the other. Two representations of one
    fact is two sources of truth.
    """
    out: Dict[str, str] = {}
    for part in str(raw or "").split(","):
        if "=" not in part:
            continue
        alg, _, value = part.partition("=")
        alg, value = alg.strip().lower(), value.strip().lower()
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
