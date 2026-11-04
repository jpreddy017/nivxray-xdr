"""NivXRay XDR — Windows PowerShell DSM, Parser & Normalizer (W2-1 lane).

Covers the two PowerShell channels the W2-1 Windows adapter acquires:

  Microsoft-Windows-PowerShell/Operational
      4103  module / pipeline execution details (ContextInfo + Payload)
      4104  script-block logging — the executed script text itself
      4105  script-block execution START
      4106  script-block execution STOP

  Windows PowerShell   (the classic channel)
      400   engine state change → Available
      403   engine state change → Stopped
      600   provider lifecycle
      500 / 501 / 800  pipeline execution detail

WHAT THIS DSM DELIBERATELY DOES NOT DO
  * It does not decode, deobfuscate, de-Base64 or otherwise interpret
    script text. `ScriptBlockText` is canonical evidence, carried verbatim.
    Command Intelligence is a DOWNSTREAM consumer of this evidence and is
    not invoked from here — it stays paused, and this lane does not create
    a back door into it.
  * It does not score or label a script as suspicious. A warning-level
    4104 is recorded as level 3; what that MEANS is a detection decision.
  * It does not claim process attribution. `System/Execution/ProcessID` is
    a PID with no lifetime evidence, so it is recorded as
    PID_ONLY_NOT_AUTHORITATIVE — usable as context, never as attribution.
  * It does not promote `TimeCreated` to an activity time. The PowerShell
    ETW channels carry no activity-occurrence field, so the basis is
    OBSERVATION_TIME and `activity_occurred_at` stays NOT_OBSERVED.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
import uuid

from services import event_time_basis
from services import tenant_authority

from .models import (
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    PROCESS_ATTRIBUTION_NOT_OBSERVED,
    PROCESS_ATTRIBUTION_PID_ONLY,
    ProcessEntity,
    ProvenanceEnvelope,
)
from . import evtx_xml

#: Event IDs this DSM parses. A PowerShell record outside this set is
#: REFUSED by the parser rather than normalized into an empty shell.
OPERATIONAL_EVENT_IDS = (4103, 4104, 4105, 4106)
CLASSIC_EVENT_IDS = (400, 403, 500, 501, 600, 800)
SUPPORTED_EVENT_IDS = OPERATIONAL_EVENT_IDS + CLASSIC_EVENT_IDS

EVENT_TYPES: Dict[int, str] = {
    4103: "powershell_pipeline_execution_detail",
    4104: "powershell_script_block_logged",
    4105: "powershell_script_block_start",
    4106: "powershell_script_block_stop",
    400: "powershell_engine_state_change",
    403: "powershell_engine_state_change",
    500: "powershell_pipeline_execution_detail",
    501: "powershell_pipeline_execution_detail",
    600: "powershell_provider_lifecycle",
    800: "powershell_pipeline_execution_detail",
}

#: PowerShell writes a `key=value` block into a single Data field (the
#: classic channel) or into `ContextInfo` (4103). These are the keys whose
#: names Microsoft publishes; a key outside the list is still carried, with
#: its own name, under `context_info`.
_CONTEXT_KEYS = {
    "severity": "severity",
    "host name": "host_name",
    "host version": "host_version",
    "host id": "host_id",
    "host application": "host_application",
    "engine version": "engine_version",
    "runspace id": "runspace_id",
    "pipeline id": "pipeline_id",
    "command name": "command_name",
    "command type": "command_type",
    "script name": "script_name",
    "command path": "command_path",
    "command line": "command_line",
    "sequence number": "sequence_number",
    "user": "user",
    "connected user": "connected_user",
    "shell id": "shell_id",
    "provider name": "provider_name",
    "new state": "new_state",
    "previous state": "previous_state",
    "newenginestate": "new_engine_state",
    "previousenginestate": "previous_engine_state",
    #: The classic `Windows PowerShell` channel writes the same keys
    #: WITHOUT spaces. Both spellings must land on the same canonical name,
    #: or the classic channel silently loses its host and engine evidence.
    "hostname": "host_name",
    "hostversion": "host_version",
    "hostid": "host_id",
    "hostapplication": "host_application",
    "engineversion": "engine_version",
    "runspaceid": "runspace_id",
    "pipelineid": "pipeline_id",
    "commandname": "command_name",
    "commandtype": "command_type",
    "scriptname": "script_name",
    "commandpath": "command_path",
    "commandline": "command_line",
    "sequencenumber": "sequence_number",
    "shellid": "shell_id",
    "providername": "provider_name",
    "newstate": "new_state",
    "previousstate": "previous_state",
    "connecteduser": "connected_user",
}

_KV_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _]*?)\s*=\s*(.*?)\s*$")


class WindowsPowerShellParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _get_ci(d: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    lower = {str(k).lower(): v for k, v in d.items() if v not in (None, "")}
    for k in keys:
        if k.lower() in lower:
            return lower[k.lower()]
    return default


def _windows_basename(path_value: str) -> str:
    if not path_value:
        return ""
    return re.split(r"[\\/]", str(path_value).strip().rstrip("\\/"))[-1]


def parse_context_block(text: Any) -> Dict[str, str]:
    """`key=value` lines PowerShell writes as one opaque string.

    Every recognised key is mapped to a stable name; an unrecognised key
    is kept under its own, lower-cased name. Nothing is dropped and
    nothing is invented — a block with no readable line yields `{}`.
    """
    out: Dict[str, str] = {}
    if not isinstance(text, str) or not text.strip():
        return out
    for line in text.replace("\r\n", "\n").split("\n"):
        m = _KV_LINE.match(line)
        if not m:
            continue
        raw_key, value = m.group(1).strip(), m.group(2).strip()
        if not raw_key or not value:
            continue
        key = _CONTEXT_KEYS.get(raw_key.lower())
        if key is None:
            key = raw_key.lower().replace(" ", "_")
        out.setdefault(key, value)
    return out


def _is_powershell(ev: Dict[str, Any]) -> bool:
    """Provider/channel evidence that this record is PowerShell's.

    Checked because 4103/4104 and 400/600 are small integers that other
    providers also use. Content may only CONFIRM a declaration (D15), and
    confirming it requires the provider, not just the number.
    """
    system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
    provider = str(_get_ci(ev, "Provider", "provider")
                   or _get_ci(system, "Provider", "provider") or "")
    channel = str(_get_ci(ev, "Channel", "channel")
                  or _get_ci(system, "Channel", "channel") or "")
    return ("powershell" in provider.lower()
            or "powershell" in channel.lower())


class WindowsPowerShellParser:
    id = "windows-powershell-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(ev, str) or evtx_xml.envelope_xml(ev) is not None:
            decoded = evtx_xml.decode_document(ev)
            if decoded is not None:
                ev = decoded
        if not isinstance(ev, dict):
            raise WindowsPowerShellParserError(
                "PS_INVALID_EVENT", "event is not a JSON/dict object")

        system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
        raw_eid = (_get_ci(ev, "EventID", "event_id", "eventid")
                   or _get_ci(system, "EventID", "event_id", "eventid"))
        if raw_eid is None:
            raise WindowsPowerShellParserError(
                "PS_MISSING_EVENT_ID", "event carries no EventID")
        try:
            eid = int(raw_eid)
        except Exception:
            raise WindowsPowerShellParserError(
                "PS_INVALID_EVENT_ID", f"EventID {raw_eid!r} is not an integer")
        if eid not in SUPPORTED_EVENT_IDS:
            raise WindowsPowerShellParserError(
                "PS_UNSUPPORTED_EID",
                f"PowerShell EventID {eid} is not parsed by this DSM")
        if not _is_powershell(ev):
            raise WindowsPowerShellParserError(
                "PS_WRONG_PROVIDER",
                "neither the provider nor the channel identifies this record "
                "as PowerShell")

        data = _get_ci(ev, "EventData", "event_data", "eventdata") or {}
        if isinstance(data, list):
            flat: Dict[str, Any] = {}
            positional: List[str] = []
            for item in data:
                if isinstance(item, dict) and item.get("@Name"):
                    flat[item["@Name"]] = item.get("#text", "")
                elif isinstance(item, dict) and item.get("Name"):
                    flat[item["Name"]] = item.get("Value", "")
                elif isinstance(item, str):
                    positional.append(item)
            if positional:
                flat["Data"] = positional
            data = flat
        elif not isinstance(data, dict):
            data = {}

        positional = data.get("Data") if isinstance(data.get("Data"), list) else []

        # ── the key=value block, wherever this event id keeps it ────────
        context_raw = _get_ci(data, "ContextInfo")
        if context_raw is None and positional:
            # Classic channel: the context block is the LAST positional
            # Data element that actually contains `key=value` lines.
            for candidate in reversed(positional):
                if isinstance(candidate, str) and "=" in candidate:
                    context_raw = candidate
                    break
        context = parse_context_block(context_raw)

        return {
            "parser_id": self.id,
            "raw": ev,
            "event_id": eid,
            "channel": str(_get_ci(ev, "Channel", "channel")
                           or _get_ci(system, "Channel") or ""),
            "provider": str(_get_ci(ev, "Provider", "provider")
                            or _get_ci(system, "Provider") or ""),
            "computer": str(_get_ci(ev, "Computer", "computer")
                            or _get_ci(system, "Computer") or ""),
            "time_created": str(_get_ci(ev, "TimeCreated", "time_created")
                                or _get_ci(system, "TimeCreated",
                                           "SystemTime") or ""),
            "supplied_time": str(_get_ci(ev, "timestamp") or ""),
            "user_sid": str(_get_ci(ev, "UserID") or _get_ci(system, "UserID")
                            or ""),
            "level": _get_ci(ev, "Level", default=_get_ci(system, "Level")),
            "execution_pid": _get_ci(ev, "ProcessID",
                                     default=_get_ci(system, "ProcessID")),
            "data": data,
            "positional": positional,
            "context": context,
        }


class WindowsPowerShellNormalizer:
    id = "windows-powershell-normalizer"

    def normalize(self, parsed: Dict[str, Any], dsm_id: str,
                  collector_id: str, integration_id: str, trace_id: str,
                  tenant_id: Optional[str] = None) -> Dict[str, Any]:
        raw = parsed["raw"]
        resolved_tenant, tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))

        eid = parsed["event_id"]
        data = parsed["data"]
        context = parsed["context"]
        now_iso = datetime.now(timezone.utc).isoformat()
        hostname = parsed["computer"]

        host = HostEntity(hostname=hostname, host_id=hostname,
                          os_family="windows")

        additional: Dict[str, Any] = {}
        field_provenance: Dict[str, str] = {}

        # ── the PowerShell host process, as far as the record proves ────
        host_application = context.get("host_application", "")
        pid_value: Optional[int] = None
        try:
            if parsed.get("execution_pid") is not None:
                pid_value = int(parsed["execution_pid"])
        except Exception:
            pid_value = None

        process = ProcessEntity()
        if host_application or pid_value is not None:
            process = ProcessEntity(
                # `HostApplication` is the command line of the process that
                # hosted the engine. Its first token is the image; the whole
                # string stays available as the command line.
                name=_windows_basename(host_application.split(" ")[0])
                     if host_application else "",
                command_line=host_application,
                pid=pid_value,
                attribution_state=(PROCESS_ATTRIBUTION_PID_ONLY
                                   if pid_value is not None
                                   else PROCESS_ATTRIBUTION_NOT_OBSERVED),
                attribution_reason=(
                    "System/Execution/ProcessID is a PID with no process "
                    "start time or process GUID, so it identifies a process "
                    "only for as long as the OS has not reused the number"
                    if pid_value is not None else
                    "this PowerShell record named no hosting process"),
            )
            if host_application:
                field_provenance["command_line"] = (
                    "windows_powershell:ContextInfo/Host Application")
            if pid_value is not None:
                field_provenance["pid"] = (
                    "windows_powershell:System/Execution/@ProcessID")
            process.field_provenance = field_provenance

        # ── the principal, only when the record named one ───────────────
        user = context.get("user") or context.get("connected_user") or ""
        domain, username = "", user
        if "\\" in user:
            domain, username = user.split("\\", 1)
        identity = IdentityEntity()
        if user or parsed.get("user_sid"):
            identity = IdentityEntity(
                principal_id=user or parsed.get("user_sid") or "",
                username=username,
                domain=domain,
                user_sid=parsed.get("user_sid") or "",
            )

        # ── per-event evidence ──────────────────────────────────────────
        if eid == 4104:
            script = str(_get_ci(data, "ScriptBlockText") or "")
            additional["script_block_text"] = script
            additional["script_block_length"] = len(script)
            additional["script_block_id"] = str(
                _get_ci(data, "ScriptBlockId") or "")
            additional["script_path"] = str(_get_ci(data, "Path") or "")
            # 4104 is chunked for long scripts. A consumer that reassembles
            # needs to know it is holding a fragment.
            msg_no = _get_ci(data, "MessageNumber")
            msg_total = _get_ci(data, "MessageTotal")
            if msg_no is not None:
                additional["message_number"] = str(msg_no)
            if msg_total is not None:
                additional["message_total"] = str(msg_total)
            if msg_no is not None and msg_total is not None:
                additional["script_block_complete"] = (
                    str(msg_no) == "1" and str(msg_total) == "1")
            additional["script_block_note"] = (
                "the script text is canonical evidence, carried verbatim. "
                "No decoding, deobfuscation or scoring is performed here")

        elif eid in (4105, 4106):
            additional["script_block_id"] = str(
                _get_ci(data, "ScriptBlockId") or "")
            additional["script_path"] = str(_get_ci(data, "Path") or "")
            additional["runspace_id"] = str(
                _get_ci(data, "RunspaceId") or context.get("runspace_id") or "")

        elif eid == 4103:
            payload = str(_get_ci(data, "Payload") or "")
            if payload:
                additional["payload"] = payload
            if context.get("command_name"):
                additional["command_name"] = context["command_name"]
            if context.get("command_line"):
                additional["invoked_command_line"] = context["command_line"]

        elif eid in (400, 403):
            additional["new_engine_state"] = (
                context.get("new_engine_state")
                or context.get("new_state") or "")
            additional["previous_engine_state"] = (
                context.get("previous_engine_state")
                or context.get("previous_state") or "")

        elif eid == 600:
            additional["provider_name"] = context.get("provider_name", "")
            additional["new_provider_state"] = context.get("new_state", "")

        if context:
            additional["context_info"] = dict(context)
        if parsed.get("level") is not None:
            additional["windows_level"] = str(parsed["level"])
        if parsed.get("channel"):
            additional["windows_channel"] = parsed["channel"]
        if context.get("engine_version"):
            additional["engine_version"] = context["engine_version"]
        if context.get("host_name"):
            additional["powershell_host_name"] = context["host_name"]
        additional["analysis_note"] = (
            "PowerShell script and pipeline evidence is normalized here and "
            "nowhere interpreted: Command Intelligence is a downstream "
            "consumer of this evidence and is not invoked by this DSM")

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=WindowsPowerShellParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        etb = event_time_basis.resolve(
            observation=([(parsed.get("time_created"),
                           "windows_powershell:System.TimeCreated.SystemTime")]
                         if parsed.get("time_created") else ()),
            supplied=([(parsed.get("supplied_time"),
                        "raw:timestamp — a generic key supplied by the "
                        "delivery; the PowerShell ETW schema does not "
                        "establish what instant it names")]
                      if parsed.get("supplied_time") else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "the PowerShell ETW channels carry no activity-occurrence "
                "field; TimeCreated is when the provider wrote the record "
                "and must not stand in for when the script ran"),
            observation_absent_reason=(
                "this record carried no TimeCreated/SystemTime"))

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Microsoft",
            source_product=("Windows PowerShell"
                            if eid in CLASSIC_EVENT_IDS
                            else "Microsoft-Windows-PowerShell"),
            source_event_id=str(eid),
            event_type=EVENT_TYPES.get(eid, "powershell_event"),
            event_time=etb.event_time,
            ingest_time=now_iso,
            host=host,
            identity=identity,
            process=process,
            raw_ref=raw,
            provenance=provenance,
            additional_fields=additional,
        )
        out = canonical.to_dict()
        event_time_basis.apply(out, etb)
        tenant_authority.record(out, tenant_claim)
        return out


class WindowsPowerShellDSM:
    id = "windows-powershell-evd"
    vendor = "Microsoft"
    product = "Windows PowerShell Event Log"
    version = "1"
    source_type = "ENDPOINT_SCRIPT_EXECUTION"

    def supports(self, ev: Dict[str, Any]) -> bool:
        if isinstance(ev, str) or evtx_xml.envelope_xml(ev) is not None:
            try:
                decoded = evtx_xml.decode_document(ev)
            except evtx_xml.EvtxXmlDecodeError:
                return False
            if decoded is not None:
                ev = decoded
        if not isinstance(ev, dict):
            return False
        system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
        eid = (_get_ci(ev, "EventID", "event_id", "eventid")
               or _get_ci(system, "EventID", "event_id", "eventid"))
        try:
            if int(eid) not in SUPPORTED_EVENT_IDS:
                return False
        except Exception:
            return False
        return _is_powershell(ev)

    def recognizes_format(self, ev: Dict[str, Any]) -> bool:
        """B4 · is this a readable PowerShell-channel record? FORMAT only —
        an unsupported EventID from a PowerShell channel is a coverage gap,
        not a malformed source."""
        view = evtx_xml.decoded_view(ev)
        if not isinstance(view, dict):
            return False
        return _is_powershell(view)

    def select_parser(self) -> WindowsPowerShellParser:
        return WindowsPowerShellParser()

    def select_normalizer(self) -> WindowsPowerShellNormalizer:
        return WindowsPowerShellNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {"id": self.id, "vendor": self.vendor, "product": self.product,
                "version": self.version, "source_type": self.source_type}
