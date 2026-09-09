"""Microsoft Defender for Endpoint (MDE) normaliser → CEMv1.

Handles the Advanced Hunting `DeviceAlertEvents` / `AlertInfo` shapes
and the SecurityAlert-graph shape surfaced through Sentinel exports.

Fields typically observed:

    - AlertId, AlertTitle, AlertSeverity, Category, ThreatFamilyName
    - DeviceName, DeviceId
    - FileName, FolderPath, SHA256, SHA1, MD5
    - InitiatingProcessCommandLine, InitiatingProcessFileName,
      InitiatingProcessFolderPath, InitiatingProcessSHA256
    - InitiatingProcessParentFileName, InitiatingProcessParentId,
      InitiatingProcessParentCommandLine
    - AccountName, AccountDomain
    - Timestamp
    - MitreTechniques (list of strings like "T1027")
    - RemoteUrl, RemoteIP
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from nivxforge.investigation.cem import (
    CanonicalEvent,
    CanonicalEventModel,
    Detection,
    EventKind,
    FileEntity,
    Host,
    Incident,
    Network,
    Process,
    User,
    VendorAdapter,
)
from ..parser import ParsedInput
from .base import (
    _try_parse_dt,
    coerce_containment,
    coerce_severity,
    make_provenance,
)


class MicrosoftDefenderNormalizer(VendorAdapter):
    vendor = "Microsoft Defender for Endpoint"
    adapter_id = "microsoft_defender"

    def can_parse(self, raw_input: str) -> bool:  # pragma: no cover
        s = raw_input.lower() if isinstance(raw_input, str) else ""
        return any(m in s for m in (
            "microsoft defender", "mdatp", "windowsdefenderatp",
            "devicealertevents", "alertinfo",
        ))

    def normalize(self, parsed: ParsedInput) -> CanonicalEventModel:
        prov_root = make_provenance(self.adapter_id, self.vendor,
                                     confidence=0.95)
        events: List[CanonicalEvent] = []
        incidents: List[Incident] = []
        for rec in parsed.records:
            evt = _record_to_event(rec, self.adapter_id, self.vendor)
            if evt is not None:
                events.append(evt)
            inc = _record_to_incident(rec, self.adapter_id, self.vendor)
            if inc is not None:
                incidents.append(inc)
        return CanonicalEventModel(
            vendor=self.vendor,
            vendor_route=self.adapter_id,
            incidents=incidents,
            events=events,
            provenance=prov_root,
        )


def _record_to_event(rec: Dict[str, Any], adapter_id: str,
                      vendor: str) -> Optional[CanonicalEvent]:
    if not isinstance(rec, dict):
        return None
    ts = _try_parse_dt(rec.get("Timestamp") or rec.get("TimeGenerated")
                       or rec.get("EventTime") or rec.get("timestamp"))
    prov = make_provenance(adapter_id, vendor, ts, confidence=0.95)

    device_name = rec.get("DeviceName") or rec.get("ComputerName")
    device_id = rec.get("DeviceId") or rec.get("MachineId")
    host = None
    if device_name or device_id:
        host = Host(
            id=str(device_id or ""),
            name=device_name,
            provenance=prov,
        )

    user = None
    account_name = rec.get("AccountName") or rec.get("UserName")
    if account_name:
        user = User(
            name=account_name,
            domain=rec.get("AccountDomain") or rec.get("UserDomain"),
            sid=rec.get("AccountSid") or rec.get("UserSid"),
            provenance=prov,
        )

    # Initiating process (the actor)
    init_cmd = rec.get("InitiatingProcessCommandLine") or rec.get("ProcessCommandLine")
    init_image = _join_path(rec.get("InitiatingProcessFolderPath"),
                             rec.get("InitiatingProcessFileName"))
    init_hash = rec.get("InitiatingProcessSHA256")
    proc = None
    if init_cmd or init_image or init_hash:
        proc = Process(
            pid=_int(rec.get("InitiatingProcessId")),
            ppid=_int(rec.get("InitiatingProcessParentId")),
            image=init_image or rec.get("InitiatingProcessFileName"),
            command_line=init_cmd,
            hash_sha256=init_hash if init_hash and len(str(init_hash)) == 64 else None,
            provenance=prov,
        )

    # Parent
    parent_proc = None
    parent_cmd = rec.get("InitiatingProcessParentCommandLine")
    parent_image = rec.get("InitiatingProcessParentFileName")
    if parent_cmd or parent_image:
        parent_proc = Process(
            image=parent_image,
            command_line=parent_cmd,
            provenance=prov,
        )

    # File under investigation
    file_ent = None
    file_name = rec.get("FileName")
    file_path = _join_path(rec.get("FolderPath"), file_name)
    sha256 = rec.get("SHA256")
    if file_name or file_path or sha256:
        file_ent = FileEntity(
            path=file_path,
            name=file_name,
            hash_sha256=sha256 if sha256 and len(str(sha256)) == 64 else None,
            hash_sha1=rec.get("SHA1"),
            hash_md5=rec.get("MD5"),
            provenance=prov,
        )

    # Network
    network = None
    remote_url = rec.get("RemoteUrl") or rec.get("Url")
    remote_ip = rec.get("RemoteIP") or rec.get("RemoteIp") or rec.get("DestinationIp")
    if remote_url or remote_ip:
        network = Network(
            url=remote_url,
            dst_ip=remote_ip,
            dst_port=_int(rec.get("RemotePort") or rec.get("DestinationPort")),
            protocol=rec.get("Protocol"),
            provenance=prov,
        )

    # Detection
    det_name = rec.get("AlertTitle") or rec.get("Title") or rec.get("DisplayName")
    detection = None
    if det_name:
        detection = Detection(
            id=str(rec.get("AlertId") or rec.get("SystemAlertId") or ""),
            name=str(det_name),
            severity=coerce_severity(rec.get("AlertSeverity") or rec.get("Severity")),
            category=rec.get("Category") or rec.get("AlertCategory"),
            threat_name=rec.get("ThreatName"),
            threat_family=rec.get("ThreatFamilyName"),
            provenance=prov,
        )

    # MITRE tactics/techniques — stash into event.raw so the
    # narrative engine's `_mitre_from_state` helper picks them up.
    tech = rec.get("MitreTechniques") or rec.get("Techniques")
    tact = rec.get("MitreTactics") or rec.get("Tactics")
    raw_slim: Dict[str, Any] = {}
    if isinstance(tech, list):
        raw_slim["mitre_techniques"] = [str(x) for x in tech]
    if isinstance(tact, list):
        raw_slim["mitre_tactics"] = [str(x) for x in tact]
    raw_slim.update({k: v for k, v in rec.items() if k in (
        "AlertId", "DeviceName", "InitiatingProcessCommandLine",
        "ThreatFamilyName",
    )})

    kind = _infer_kind(rec, network is not None, proc is not None,
                       detection is not None)

    containment = coerce_containment(
        rec.get("RemediationStatus") or rec.get("Status")
        or rec.get("ResponseAction")
    )

    return CanonicalEvent(
        event_id=str(rec.get("AlertId") or rec.get("EventId")
                     or rec.get("Id") or uuid.uuid4()),
        kind=kind,
        timestamp=ts,
        host=host,
        user=user,
        process=proc,
        parent_process=parent_proc,
        file=file_ent,
        network=network,
        detection=detection,
        containment=containment,
        raw=raw_slim,
        provenance=prov,
    )


def _record_to_incident(rec: Dict[str, Any], adapter_id: str,
                         vendor: str) -> Optional[Incident]:
    if not isinstance(rec, dict) or not rec.get("AlertId"):
        return None
    ts = _try_parse_dt(rec.get("Timestamp"))
    prov = make_provenance(adapter_id, vendor, ts, confidence=0.9)
    return Incident(
        incident_id=str(rec.get("AlertId")),
        title=str(rec.get("AlertTitle") or "Microsoft Defender alert"),
        severity=coerce_severity(rec.get("AlertSeverity")),
        first_seen=ts, last_seen=ts,
        containment=coerce_containment(rec.get("RemediationStatus")),
        provenance=prov,
    )


def _infer_kind(rec: Dict[str, Any], has_net: bool, has_proc: bool,
                 has_det: bool) -> EventKind:
    cat = str(rec.get("Category") or "").lower()
    if "network" in cat or has_net:
        return EventKind.network_connect
    if "process" in cat or "execution" in cat or has_proc:
        return EventKind.process_create
    if "file" in cat:
        return EventKind.file_create
    if has_det:
        return EventKind.detection
    return EventKind.generic


def _int(v: Any) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _join_path(folder: Any, name: Any) -> Optional[str]:
    if folder and name:
        sep = "\\" if "\\" in str(folder) else "/"
        return f"{folder}{sep}{name}"
    return folder or name or None


__all__ = ["MicrosoftDefenderNormalizer"]
