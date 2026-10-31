"""NivXRay XDR — Microsoft Defender Event Log DSM (W2-1 lane).

Channel: `Microsoft-Windows-Windows Defender/Operational`.

    1006  malware or unwanted software DETECTED (scan result)
    1007  action taken against malware
    1008  action FAILED
    1009  item restored from quarantine
    1015  behaviour-monitoring detection
    1116  malware detected (real-time protection)
    1117  action taken (real-time protection)
    1118  remediation action failed
    1119  critical remediation failure
    1150 / 1151  platform health / health report
    5001  real-time protection DISABLED
    5004  real-time protection configuration changed
    5007  Defender configuration changed
    5010 / 5012  scanning for malware / viruses disabled

THE BOUNDARY THAT MATTERS
Defender's verdict is SOURCE EVIDENCE, not NivXRay's conclusion. This DSM
records what Microsoft observed and what Microsoft decided, with
provenance, and stops there:

    Defender observation/detection → canonical evidence
      → NivX detection / correlation / investigation → NivX verdict

So `additional_fields.vendor_verdict` carries Microsoft's own severity and
action verbatim, and nothing here writes a NivX verdict, promotes an
incident, or invokes Command Intelligence (which remains PAUSED).
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional
import uuid

from services import event_time_basis
from services import tenant_authority

from .models import (
    CanonicalTelemetryEvent,
    FileEntity,
    HostEntity,
    IdentityEntity,
    ProcessEntity,
    ProvenanceEnvelope,
)
from . import evtx_xml

DETECTION_EVENT_IDS = (1006, 1015, 1116)
ACTION_EVENT_IDS = (1007, 1008, 1009, 1117, 1118, 1119)
POSTURE_EVENT_IDS = (1150, 1151, 5001, 5004, 5007, 5010, 5012)
SUPPORTED_EVENT_IDS = (DETECTION_EVENT_IDS + ACTION_EVENT_IDS
                       + POSTURE_EVENT_IDS)

EVENT_TYPES: Dict[int, str] = {
    1006: "endpoint_malware_detected",
    1015: "endpoint_behaviour_detected",
    1116: "endpoint_malware_detected",
    1007: "endpoint_malware_action_taken",
    1117: "endpoint_malware_action_taken",
    1008: "endpoint_malware_action_failed",
    1118: "endpoint_malware_action_failed",
    1119: "endpoint_malware_action_failed",
    1009: "endpoint_quarantine_restored",
    1150: "endpoint_protection_health",
    1151: "endpoint_protection_health",
    5001: "endpoint_protection_disabled",
    5004: "endpoint_protection_configuration_changed",
    5007: "endpoint_protection_configuration_changed",
    5010: "endpoint_protection_scanning_disabled",
    5012: "endpoint_protection_scanning_disabled",
}

#: Microsoft's own severity vocabulary, carried verbatim and NOT mapped
#: onto NivXRay severity: a vendor's "Severe" is the vendor's claim.
_VENDOR_FIELDS = (
    ("Threat Name", "threat_name"), ("Threat ID", "threat_id"),
    ("Severity Name", "severity"), ("Severity ID", "severity_id"),
    ("Category Name", "category"), ("Category ID", "category_id"),
    ("Action Name", "action"), ("Action ID", "action_id"),
    ("Detection ID", "detection_id"), ("Detection Time", "detection_time"),
    ("Detection Source", "detection_source"),
    ("Detection User", "detection_user"),
    ("Status Description", "status_description"),
    ("State", "state"), ("Origin Name", "origin"),
    ("Execution Name", "execution"), ("Type Name", "detection_type"),
    ("Path", "path"), ("Process Name", "process_name"),
    ("Error Description", "error_description"),
    ("Error Code", "error_code"), ("Signature Version", "signature_version"),
    ("Engine Version", "engine_version"),
    ("Product Version", "product_version"),
    ("Feature Name", "feature_name"), ("Old Value", "old_value"),
    ("New Value", "new_value"), ("Value", "value"),
)


class WindowsDefenderParserError(Exception):
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


def _is_defender(ev: Dict[str, Any]) -> bool:
    system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
    provider = str(_get_ci(ev, "Provider", "provider")
                   or _get_ci(system, "Provider") or "")
    channel = str(_get_ci(ev, "Channel", "channel")
                  or _get_ci(system, "Channel") or "")
    hay = f"{provider} {channel}".lower()
    return "defender" in hay or "antimalware" in hay


class WindowsDefenderParser:
    id = "windows-defender-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(ev, str) or evtx_xml.envelope_xml(ev) is not None:
            try:
                decoded = evtx_xml.decode_document(ev)
            except evtx_xml.EvtxXmlDecodeError as exc:
                raise WindowsDefenderParserError(exc.code, exc.message)
            if decoded is not None:
                ev = decoded
        if not isinstance(ev, dict):
            raise WindowsDefenderParserError(
                "DEF_INVALID_EVENT", "event is not a JSON/dict object")

        system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
        raw_eid = (_get_ci(ev, "EventID", "event_id")
                   or _get_ci(system, "EventID", "event_id"))
        if raw_eid is None:
            raise WindowsDefenderParserError(
                "DEF_MISSING_EVENT_ID", "event carries no EventID")
        try:
            eid = int(raw_eid)
        except Exception:
            raise WindowsDefenderParserError(
                "DEF_INVALID_EVENT_ID",
                f"EventID {raw_eid!r} is not an integer")
        if eid not in SUPPORTED_EVENT_IDS:
            raise WindowsDefenderParserError(
                "DEF_UNSUPPORTED_EID",
                f"Defender EventID {eid} is not parsed by this DSM")
        if not _is_defender(ev):
            raise WindowsDefenderParserError(
                "DEF_WRONG_PROVIDER",
                "neither the provider nor the channel identifies this "
                "record as Microsoft Defender")

        data = _get_ci(ev, "EventData", "event_data") or {}
        if isinstance(data, list):
            flat: Dict[str, Any] = {}
            for item in data:
                if isinstance(item, dict) and item.get("@Name"):
                    flat[item["@Name"]] = item.get("#text", "")
                elif isinstance(item, dict) and item.get("Name"):
                    flat[item["Name"]] = item.get("Value", "")
            data = flat
        elif not isinstance(data, dict):
            data = {}
        if not data:
            user_data = _get_ci(ev, "UserData", "user_data")
            if isinstance(user_data, dict) and user_data:
                data = dict(user_data)

        vendor: Dict[str, str] = {}
        for wire, name in _VENDOR_FIELDS:
            value = _get_ci(data, wire, wire.replace(" ", ""))
            if value not in (None, ""):
                vendor[name] = str(value)

        return {
            "parser_id": self.id,
            "raw": ev,
            "event_id": eid,
            "computer": str(_get_ci(ev, "Computer", "computer")
                            or _get_ci(system, "Computer") or ""),
            "time_created": str(_get_ci(ev, "TimeCreated", "time_created")
                                or _get_ci(system, "TimeCreated",
                                           "SystemTime") or ""),
            "supplied_time": str(_get_ci(ev, "timestamp") or ""),
            "channel": str(_get_ci(ev, "Channel", "channel")
                           or _get_ci(system, "Channel") or ""),
            "level": _get_ci(ev, "Level", default=_get_ci(system, "Level")),
            "user_sid": str(_get_ci(ev, "UserID")
                            or _get_ci(system, "UserID") or ""),
            "data": data,
            "vendor": vendor,
        }


class WindowsDefenderNormalizer:
    id = "windows-defender-normalizer"

    def normalize(self, parsed: Dict[str, Any], dsm_id: str,
                  collector_id: str, integration_id: str, trace_id: str,
                  tenant_id: Optional[str] = None) -> Dict[str, Any]:
        raw = parsed["raw"]
        resolved_tenant, tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))

        eid = parsed["event_id"]
        vendor = parsed["vendor"]
        now_iso = datetime.now(timezone.utc).isoformat()
        hostname = parsed["computer"]

        host = HostEntity(hostname=hostname, host_id=hostname,
                          os_family="windows")

        path = vendor.get("path", "")
        file_entity = FileEntity()
        if path:
            file_entity = FileEntity(
                path=path, name=_windows_basename(path),
                field_provenance={
                    "path": "defender:EventData.Path",
                })

        proc_name = vendor.get("process_name", "")
        process = ProcessEntity()
        if proc_name and proc_name.lower() not in ("unknown", "not available"):
            process = ProcessEntity(
                name=_windows_basename(proc_name),
                executable_path=proc_name,
                attribution_reason=(
                    "Defender names the process it associated with the "
                    "detection; the record carries no PID or process start "
                    "time, so this is context, not attribution"),
            )

        user = vendor.get("detection_user", "")
        domain, username = "", user
        if "\\" in user:
            domain, username = user.split("\\", 1)
        identity = IdentityEntity()
        if user or parsed.get("user_sid"):
            identity = IdentityEntity(
                principal_id=user or parsed.get("user_sid") or "",
                username=username, domain=domain,
                user_sid=parsed.get("user_sid") or "")

        additional: Dict[str, Any] = {
            # Microsoft's OWN claim, verbatim and clearly labelled as the
            # vendor's. It is never read as a NivXRay verdict.
            "vendor_verdict": {
                "vendor": "Microsoft",
                "product": "Microsoft Defender Antivirus",
                **vendor,
                "authority_note": (
                    "this is Microsoft Defender's observation and decision. "
                    "It is SOURCE EVIDENCE for NivXRay detection, "
                    "correlation and investigation — it is not, and is never "
                    "promoted to, a NivXRay verdict"),
            },
            "evidence_class": (
                "ENDPOINT_PROTECTION_DETECTION" if eid in DETECTION_EVENT_IDS
                else "ENDPOINT_PROTECTION_RESPONSE" if eid in ACTION_EVENT_IDS
                else "ENDPOINT_PROTECTION_POSTURE"),
            "analysis_note": (
                "Defender evidence is normalized here and interpreted "
                "nowhere: Command Intelligence is a downstream consumer and "
                "is not invoked by this DSM"),
        }
        if parsed.get("channel"):
            additional["windows_channel"] = parsed["channel"]
        if parsed.get("level") is not None:
            additional["windows_level"] = str(parsed["level"])
        if eid in (5001, 5010, 5012):
            additional["protection_state"] = "DISABLED"
            additional["posture_note"] = (
                "endpoint protection was reported DISABLED. Absence of "
                "Defender detections after this point is not evidence of "
                "absence of malware")

        provenance = ProvenanceEnvelope(
            trace_id=trace_id, collector_id=collector_id,
            integration_id=integration_id, dsm_id=dsm_id,
            parser_id=WindowsDefenderParser.id, normalizer_id=self.id,
            ingest_time=now_iso)

        # Defender states its OWN detection instant for detection events.
        # That is the activity time the vendor measured; TimeCreated is when
        # the provider wrote the record. The two are never substituted.
        detection_time = vendor.get("detection_time", "")
        etb = event_time_basis.resolve(
            activity=([(detection_time,
                        "defender:EventData.Detection Time")]
                      if detection_time else ()),
            observation=([(parsed.get("time_created"),
                           "defender:System.TimeCreated.SystemTime")]
                         if parsed.get("time_created") else ()),
            supplied=([(parsed.get("supplied_time"),
                        "raw:timestamp — a generic key supplied by the "
                        "delivery; the Defender schema does not establish "
                        "what instant it names")]
                      if parsed.get("supplied_time") else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "this Defender record carried no `Detection Time`; "
                "TimeCreated is the record-generation instant and must not "
                "stand in for when the activity occurred"),
            observation_absent_reason=(
                "this record carried no TimeCreated/SystemTime"))

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Microsoft",
            source_product="Microsoft Defender Antivirus",
            source_event_id=str(eid),
            event_type=EVENT_TYPES.get(eid, "endpoint_protection_event"),
            event_time=etb.event_time,
            ingest_time=now_iso,
            host=host, identity=identity, process=process, file=file_entity,
            raw_ref=raw, provenance=provenance,
            additional_fields=additional)
        out = canonical.to_dict()
        event_time_basis.apply(out, etb)
        tenant_authority.record(out, tenant_claim)
        return out


class WindowsDefenderDSM:
    id = "windows-defender-evd"
    vendor = "Microsoft"
    product = "Microsoft Defender Antivirus Event Log"
    version = "1"
    source_type = "ENDPOINT_PROTECTION"

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
        eid = (_get_ci(ev, "EventID", "event_id")
               or _get_ci(system, "EventID", "event_id"))
        try:
            if int(eid) not in SUPPORTED_EVENT_IDS:
                return False
        except Exception:
            return False
        return _is_defender(ev)

    def recognizes_format(self, ev: Dict[str, Any]) -> bool:
        """B4 · is this a readable Defender-channel record? FORMAT only —
        an unsupported Defender EventID is a coverage gap, not a malformed
        source."""
        view = evtx_xml.decoded_view(ev)
        if not isinstance(view, dict):
            return False
        return _is_defender(view)

    def select_parser(self) -> WindowsDefenderParser:
        return WindowsDefenderParser()

    def select_normalizer(self) -> WindowsDefenderNormalizer:
        return WindowsDefenderNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {"id": self.id, "vendor": self.vendor, "product": self.product,
                "version": self.version, "source_type": self.source_type}
