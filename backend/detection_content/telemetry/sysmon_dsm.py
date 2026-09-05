"""NivXRay XDR · Sysmon DSM · Parser · Normalizer.

Registers `Microsoft-Windows-Sysmon` as a first-class telemetry source
so that events flowing through `v2_ingestion` reach the AUTHORITATIVE
reasoning fabric via `xdr_pipeline.process_event_through_pipeline()`.

Supported Sysmon event IDs (initial safe subset):
    1  ProcessCreate
    3  NetworkConnect
    11 FileCreate
    12/13/14 RegistryEvent
    22 DnsQuery

Design invariants (owner-mandated):
- Do NOT create a parallel reasoning engine
- Do NOT create a parallel canonical evidence store
- Preserve provenance, tenant_id, evidence identity end-to-end
- Fail-closed: unsupported EventIDs return False from supports()
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from .models import (
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
)


class SysmonParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _first(d: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    if not isinstance(d, dict):
        return default
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


class SysmonParser:
    id = "sysmon-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise SysmonParserError("SM_INVALID_INPUT", "event is not a dict")
        eid = ev.get("event_id") or ev.get("EventID")
        try:
            eid_int = int(eid)
        except Exception:
            raise SysmonParserError("SM_INVALID_EVENT_ID", f"non-integer event_id: {eid!r}")
        provider = ev.get("provider") or ""
        if "Sysmon" not in str(provider):
            raise SysmonParserError("SM_WRONG_PROVIDER", f"not Sysmon: {provider!r}")
        return {
            "event_id": eid_int,
            "timestamp": ev.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "computer": _first(ev, "computer", "Computer"),
            "user": _first(ev, "user", "User"),
            "process": {
                "image": _first(ev, "image", "Image"),
                "pid": _first(ev, "process_id", "ProcessId"),
                "guid": _first(ev, "process_guid", "ProcessGuid"),
                "command_line": _first(ev, "command_line", "CommandLine"),
                "parent_image": _first(ev, "parent_image", "ParentImage"),
                "parent_pid": _first(ev, "parent_process_id", "ParentProcessId"),
                "parent_guid": _first(ev, "parent_process_guid", "ParentProcessGuid"),
            },
            "network": {
                "src_ip": _first(ev, "src_ip", "SourceIp"),
                "src_port": _first(ev, "src_port", "SourcePort"),
                "dst_ip": _first(ev, "dst_ip", "DestinationIp"),
                "dst_port": _first(ev, "dst_port", "DestinationPort"),
                "protocol": _first(ev, "protocol", "Protocol"),
                "dns_query": _first(ev, "dns_query", "QueryName"),
                "dns_answer": _first(ev, "dns_answer", "QueryResults"),
            },
            "file": {
                "path": _first(ev, "file_path", "TargetFilename"),
                "hash_sha256": _first(ev, "file_hash_sha256"),
                "hash_md5": _first(ev, "file_hash_md5"),
                "hash_sha1": _first(ev, "file_hash_sha1"),
            },
            "registry": {
                "key": _first(ev, "registry_key", "TargetObject"),
                "value": _first(ev, "registry_value"),
                "data": _first(ev, "registry_data", "Details"),
            },
            "channel": ev.get("channel") or "",
            "raw": ev,
        }


class SysmonNormalizer:
    id = "sysmon-normalizer"

    def normalize(self, parsed: Dict[str, Any], dsm_id: str, collector_id: str,
                  integration_id: str, trace_id: str) -> Dict[str, Any]:
        event_id = f"sysmon-{parsed['event_id']}-{uuid.uuid4().hex}"
        sysmon_eid = parsed["event_id"]

        # Map Sysmon Event ID → canonical event_type + capability tags
        et_map = {
            1: "process_create", 3: "network_connect", 11: "file_create",
            12: "registry_event", 13: "registry_event", 14: "registry_event",
            22: "dns_query",
        }
        event_type = et_map.get(sysmon_eid, f"sysmon_{sysmon_eid}")

        host = HostEntity(
            hostname=parsed["computer"] or "unknown",
            host_id=parsed["computer"] or "unknown",
        )
        identity = IdentityEntity(
            username=parsed["user"] or "",
            principal_id=parsed["user"] or "",
        ) if parsed["user"] else None

        proc = None
        p = parsed["process"]
        if p.get("image"):
            def _pid_or_none(v):
                try: return int(v) if v not in ("", None) else None
                except Exception: return None
            proc = ProcessEntity(
                name=(p.get("image") or "").split("\\")[-1],
                pid=_pid_or_none(p.get("pid")),
                ppid=_pid_or_none(p.get("parent_pid")),
                parent_name=(p.get("parent_image") or "").split("\\")[-1],
                executable_path=p.get("image", ""),
                command_line=p.get("command_line", ""),
            )

        net = None
        n = parsed["network"]
        if n.get("dst_ip") or n.get("dns_query"):
            def _port(v):
                try: return int(v) if v not in ("", None) else None
                except Exception: return None
            net = NetworkEntity(
                src_ip=n.get("src_ip", ""), src_port=_port(n.get("src_port")),
                dest_ip=n.get("dst_ip", ""), dest_port=_port(n.get("dst_port")),
                protocol=n.get("protocol", ""),
                dns_query=n.get("dns_query", ""),
            )

        prov = ProvenanceEnvelope(
            trace_id=trace_id,
            integration_id=integration_id,
            collector_id=collector_id,
            dsm_id=dsm_id,
            parser_id=SysmonParser.id,
            normalizer_id=self.id,
        )

        canonical = CanonicalTelemetryEvent(
            event_id=event_id,
            tenant_id="default",
            source_vendor="Microsoft",
            source_product="Sysmon",
            source_event_id=str(sysmon_eid),
            event_type=event_type,
            event_time=parsed["timestamp"],
            ingest_time=datetime.now(timezone.utc).isoformat(),
            host=host,
            identity=identity or IdentityEntity(),
            process=proc or ProcessEntity(),
            network=net or NetworkEntity(),
            raw_ref={"sysmon_event_id": sysmon_eid, "channel": parsed.get("channel", "")},
            provenance=prov,
            additional_fields={
                "channel": parsed.get("channel", ""),
                "sysmon_file": parsed["file"],
                "sysmon_registry": parsed["registry"],
            },
        )
        return canonical.to_dict()


class SysmonDSM:
    id = "microsoft-sysmon"
    vendor = "Microsoft"
    product = "Sysmon"
    version = "1"
    source_type = "ENDPOINT_SECURITY"

    SUPPORTED_EVENT_IDS = {1, 3, 11, 12, 13, 14, 22}

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        provider = ev.get("provider") or ""
        if "Sysmon" not in str(provider):
            return False
        try:
            return int(ev.get("event_id") or ev.get("EventID") or 0) in self.SUPPORTED_EVENT_IDS
        except Exception:
            return False

    def select_parser(self) -> SysmonParser:
        return SysmonParser()

    def select_normalizer(self) -> SysmonNormalizer:
        return SysmonNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {
            "id": self.id, "vendor": self.vendor, "product": self.product,
            "version": self.version, "source_type": self.source_type,
        }
