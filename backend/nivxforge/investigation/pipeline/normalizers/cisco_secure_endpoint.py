"""Cisco Secure Endpoint normalizer → CEMv1.

Handles common Secure Endpoint (formerly AMP for Endpoints) event
shapes surfaced through the v1/v2 REST APIs and syslog-forwarded JSON.

Fields commonly observed:
    - computer.hostname, computer.external_ip, computer.internal_ips
    - detection, detection_id, event_type, event_type_id
    - date, timestamp, group_guids
    - file.disposition, file.file_name, file.file_path
    - file.identity.sha256/md5, file.parent.identity.sha256
    - network_info.dirty_url, remote_ip, remote_port
    - command_line.arguments, cloud_ioc, tactics, techniques
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from nivxforge.investigation.cem import (
    CanonicalEvent,
    CanonicalEventModel,
    ContainmentState,
    Detection,
    EventKind,
    FileEntity,
    Host,
    Incident,
    Network,
    Process,
    Provenance,
    SeverityLevel,
    VendorAdapter,
)
from ..parser import ParsedInput
from .base import (
    _try_parse_dt,
    coerce_containment,
    coerce_severity,
    make_provenance,
)


class CiscoSecureEndpointNormalizer(VendorAdapter):
    vendor = "Cisco Secure Endpoint"
    adapter_id = "cisco_secure_endpoint"

    def can_parse(self, raw_input: str) -> bool:  # pragma: no cover
        s = raw_input.lower() if isinstance(raw_input, str) else ""
        return any(m in s for m in (
            "cisco secure endpoint", "amp for endpoints",
            "connector_guid", "event_type_id",
        ))

    def normalize(self, parsed: ParsedInput) -> CanonicalEventModel:
        prov_root = make_provenance(
            source=self.adapter_id, vendor=self.vendor, confidence=0.95
        )
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


# ── Field extractors ─────────────────────────────────────────────────

def _g(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Get first non-None field across candidate keys (case-sensitive)."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _nested(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _record_to_event(rec: Dict[str, Any], adapter_id: str,
                      vendor: str) -> Optional[CanonicalEvent]:
    if not isinstance(rec, dict):
        return None
    ts = _try_parse_dt(_g(rec, "date", "timestamp", "event_time",
                            "detected_at"))
    prov = make_provenance(adapter_id, vendor, ts, confidence=0.95)

    # ── Host
    comp = rec.get("computer") or {}
    host = None
    if isinstance(comp, dict) and comp:
        host = Host(
            id=str(comp.get("connector_guid") or ""),
            name=comp.get("hostname"),
            fqdn=comp.get("fqdn") or comp.get("dns_name"),
            ip=(comp.get("network_addresses") or [{}])[0].get("ip")
                 if isinstance(comp.get("network_addresses"), list)
                 else comp.get("external_ip") or comp.get("internal_ip"),
            os=comp.get("operating_system"),
            provenance=prov,
        )

    # ── Process
    cmd_line = (
        _nested(rec, "command_line.arguments")
        or _g(rec, "command_line", "CommandLine", "process_command_line")
    )
    if isinstance(cmd_line, list):
        cmd_line = " ".join(str(x) for x in cmd_line)
    file_data = rec.get("file") or {}
    parent_data = file_data.get("parent") if isinstance(file_data, dict) else None
    proc = None
    if (cmd_line or file_data):
        image_path = None
        if isinstance(file_data, dict):
            image_path = file_data.get("file_path") or file_data.get("file_name")
        hash_sha = None
        if isinstance(file_data, dict):
            ident = file_data.get("identity") or {}
            if isinstance(ident, dict):
                hash_sha = ident.get("sha256") or ident.get("SHA256")
        proc = Process(
            image=image_path,
            command_line=str(cmd_line) if cmd_line else None,
            hash_sha256=hash_sha,
            provenance=prov,
        )
    parent_proc = None
    if isinstance(parent_data, dict) and parent_data:
        pident = parent_data.get("identity") or {}
        parent_proc = Process(
            image=parent_data.get("file_name") or parent_data.get("file_path"),
            hash_sha256=pident.get("sha256") if isinstance(pident, dict) else None,
            provenance=prov,
        )

    # ── File
    file_ent = None
    if isinstance(file_data, dict) and file_data:
        ident = file_data.get("identity") or {}
        file_ent = FileEntity(
            path=file_data.get("file_path"),
            name=file_data.get("file_name"),
            hash_md5=ident.get("md5") if isinstance(ident, dict) else None,
            hash_sha1=ident.get("sha1") if isinstance(ident, dict) else None,
            hash_sha256=ident.get("sha256") if isinstance(ident, dict) else None,
            provenance=prov,
        )

    # ── Network
    net_data = rec.get("network_info") or rec.get("network") or {}
    network = None
    if isinstance(net_data, dict) and net_data:
        network = Network(
            src_ip=net_data.get("local_ip") or net_data.get("src_ip"),
            src_port=_int_or_none(net_data.get("local_port")),
            dst_ip=net_data.get("remote_ip") or net_data.get("dest_ip"),
            dst_port=_int_or_none(net_data.get("remote_port") or net_data.get("dest_port")),
            direction=net_data.get("nfm", {}).get("direction")
                      if isinstance(net_data.get("nfm"), dict) else None,
            protocol=net_data.get("protocol"),
            url=net_data.get("dirty_url") or net_data.get("url"),
            domain=net_data.get("domain") or net_data.get("dns_query"),
            provenance=prov,
        )

    # ── Detection
    det_name = (
        _g(rec, "detection", "event_type", "AlertTitle")
        or (rec.get("event_type_str") if isinstance(rec.get("event_type_str"), str) else None)
    )
    detection = None
    if det_name:
        detection = Detection(
            id=str(_g(rec, "detection_id", "event_type_id", default="") or ""),
            name=str(det_name),
            severity=coerce_severity(_g(rec, "severity", "threat_severity")),
            category=_g(rec, "category", "tactic"),
            rule_id=str(_g(rec, "cloud_ioc", default="") or "") or None,
            threat_name=_g(rec, "threat_name")
                         or (file_data.get("disposition") if isinstance(file_data, dict) else None),
            threat_family=_g(rec, "threat_family", "threat_family_name"),
            provenance=prov,
        )

    # ── Event kind heuristic
    kind = _infer_kind(rec, network is not None, proc is not None,
                        detection is not None)

    # ── Containment
    disp = None
    if isinstance(file_data, dict):
        disp = file_data.get("disposition")
    containment = coerce_containment(
        _g(rec, "containment", "action") or disp
        or ("quarantined" if str(disp or "").lower() == "malicious" else None)
    )

    return CanonicalEvent(
        event_id=str(_g(rec, "id", "detection_id", "event_id") or uuid.uuid4()),
        kind=kind,
        timestamp=ts,
        host=host,
        process=proc,
        parent_process=parent_proc,
        file=file_ent,
        network=network,
        detection=detection,
        containment=containment,
        raw=_slim_raw(rec),
        provenance=prov,
    )


def _record_to_incident(rec: Dict[str, Any], adapter_id: str,
                         vendor: str) -> Optional[Incident]:
    if not isinstance(rec, dict):
        return None
    if not any(k in rec for k in ("incident_id", "id", "detection_id")):
        return None
    ts = _try_parse_dt(_g(rec, "date", "timestamp"))
    prov = make_provenance(adapter_id, vendor, ts, confidence=0.9)
    file_data = rec.get("file") or {}
    disp = file_data.get("disposition") if isinstance(file_data, dict) else None
    return Incident(
        incident_id=str(_g(rec, "id", "detection_id", "incident_id") or ""),
        title=str(_g(rec, "detection", "event_type",
                     default=f"Cisco Secure Endpoint event") or ""),
        severity=coerce_severity(_g(rec, "severity", "threat_severity")),
        first_seen=ts,
        last_seen=ts,
        containment=coerce_containment(disp),
        provenance=prov,
    )


def _infer_kind(rec: Dict[str, Any], has_network: bool,
                has_process: bool, has_detection: bool) -> EventKind:
    et = str(rec.get("event_type") or "").lower()
    if "process" in et or "exec" in et:
        return EventKind.process_create
    if "dns" in et:
        return EventKind.dns_query
    if has_network:
        return EventKind.network_connect
    if "file" in et or "quarantine" in et:
        return EventKind.file_create
    if has_detection:
        return EventKind.detection
    if has_process:
        return EventKind.process_create
    return EventKind.generic


def _slim_raw(rec: Dict[str, Any], limit: int = 4000) -> Dict[str, Any]:
    """Persist a bounded raw representation for evidence traceback."""
    try:
        import json
        s = json.dumps(rec, default=str)
        if len(s) <= limit:
            return dict(rec)
        return {"_truncated": True, "_size": len(s), "_head": s[:limit]}
    except (TypeError, ValueError):
        return {"_repr": repr(rec)[:limit]}


def _int_or_none(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


__all__ = ["CiscoSecureEndpointNormalizer"]
