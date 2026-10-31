"""Sysmon normalizer → CEMv1.

Handles both:
  - EVTX-style XML (`<EventData><Data Name='CommandLine'>...</Data>`)
  - JSON exports from Winlogbeat / NXLog / Splunk UF where fields are
    flattened at the record top-level.

Common Sysmon event IDs covered:
    1  Process create
    3  Network connection
   11  File create
   12/13 Registry set/delete
    5  Process terminate
    6  Driver loaded
    7  Image loaded
   22  DNS query
   23  File delete
   25  Process tampering
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from nivxforge.investigation.cem import (
    CanonicalEvent,
    CanonicalEventModel,
    Dns,
    EventKind,
    FileEntity,
    Host,
    Network,
    Process,
    Registry,
    User,
    VendorAdapter,
)
from ..parser import ParsedInput
from .base import _try_parse_dt, make_provenance


_KIND_BY_EID: Dict[int, EventKind] = {
    1: EventKind.process_create,
    3: EventKind.network_connect,
    5: EventKind.process_terminate,
    11: EventKind.file_create,
    12: EventKind.registry_write,
    13: EventKind.registry_write,
    14: EventKind.registry_write,
    22: EventKind.dns_query,
    23: EventKind.file_delete,
}


class SysmonNormalizer(VendorAdapter):
    vendor = "Sysmon"
    adapter_id = "sysmon"

    def can_parse(self, raw_input: str) -> bool:  # pragma: no cover
        s = raw_input.lower() if isinstance(raw_input, str) else ""
        return "sysmon" in s or "microsoft-windows-sysmon" in s

    def normalize(self, parsed: ParsedInput) -> CanonicalEventModel:
        prov_root = make_provenance(self.adapter_id, self.vendor,
                                     confidence=0.9)
        events: List[CanonicalEvent] = []
        for rec in parsed.records:
            evt = _record_to_event(rec, self.adapter_id, self.vendor)
            if evt is not None:
                events.append(evt)
        return CanonicalEventModel(
            vendor=self.vendor,
            vendor_route=self.adapter_id,
            events=events,
            provenance=prov_root,
        )


def _record_to_event(rec: Dict[str, Any], adapter_id: str,
                      vendor: str) -> Optional[CanonicalEvent]:
    if not isinstance(rec, dict):
        return None
    eid = _int_or_none(rec.get("EventID") or rec.get("event_id")
                        or rec.get("EventId"))
    kind = _KIND_BY_EID.get(eid or -1, EventKind.generic)
    ts = _try_parse_dt(rec.get("UtcTime") or rec.get("TimeCreated")
                       or rec.get("@timestamp"))
    prov = make_provenance(adapter_id, vendor, ts, confidence=0.9)

    host = Host(
        name=rec.get("Computer") or rec.get("ComputerName")
              or rec.get("host") or rec.get("hostname"),
        provenance=prov,
    ) if any(k in rec for k in ("Computer", "ComputerName", "host", "hostname")) else None

    user = None
    if any(k in rec for k in ("User", "SubjectUserName", "TargetUserName")):
        raw_user = rec.get("User") or rec.get("SubjectUserName") or rec.get("TargetUserName")
        domain = None
        name = raw_user
        if isinstance(raw_user, str) and "\\" in raw_user:
            domain, name = raw_user.split("\\", 1)
        user = User(name=name, domain=domain, provenance=prov)

    process = None
    if any(k in rec for k in ("CommandLine", "Image", "ProcessGuid",
                               "ProcessId", "OriginalFileName")):
        process = Process(
            pid=_int_or_none(rec.get("ProcessId")),
            ppid=_int_or_none(rec.get("ParentProcessId")),
            image=rec.get("Image") or rec.get("OriginalFileName"),
            command_line=rec.get("CommandLine"),
            parent_command_line=rec.get("ParentCommandLine"),
            hash_sha256=_extract_hash(rec.get("Hashes"), "SHA256")
                         or rec.get("SHA256"),
            integrity_level=rec.get("IntegrityLevel"),
            provenance=prov,
        )
    parent_process = None
    if rec.get("ParentImage") or rec.get("ParentCommandLine"):
        parent_process = Process(
            pid=_int_or_none(rec.get("ParentProcessId")),
            image=rec.get("ParentImage"),
            command_line=rec.get("ParentCommandLine"),
            provenance=prov,
        )

    file_ent = None
    if kind in (EventKind.file_create, EventKind.file_delete) and rec.get("TargetFilename"):
        file_ent = FileEntity(
            path=rec.get("TargetFilename"),
            hash_sha256=_extract_hash(rec.get("Hashes"), "SHA256"),
            provenance=prov,
        )

    registry = None
    if kind == EventKind.registry_write and rec.get("TargetObject"):
        registry = Registry(
            key=str(rec.get("TargetObject")),
            value_name=rec.get("Details"),
            value_data=rec.get("Details"),
            provenance=prov,
        )

    network = None
    if kind == EventKind.network_connect:
        network = Network(
            src_ip=rec.get("SourceIp"),
            src_port=_int_or_none(rec.get("SourcePort")),
            dst_ip=rec.get("DestinationIp"),
            dst_port=_int_or_none(rec.get("DestinationPort")),
            protocol=rec.get("Protocol"),
            direction="outbound" if str(rec.get("Initiated")).lower() == "true" else None,
            domain=rec.get("DestinationHostname") or rec.get("QueryName"),
            provenance=prov,
        )

    dns = None
    if kind == EventKind.dns_query:
        query = rec.get("QueryName") or rec.get("query")
        if query:
            dns = Dns(
                query=str(query),
                query_type=rec.get("QueryType"),
                response=rec.get("QueryResults") or rec.get("QueryResult"),
                provenance=prov,
            )

    return CanonicalEvent(
        event_id=str(rec.get("EventRecordID") or rec.get("_id")
                     or uuid.uuid4()),
        kind=kind,
        timestamp=ts,
        host=host,
        user=user,
        process=process,
        parent_process=parent_process,
        file=file_ent,
        registry=registry,
        network=network,
        dns=dns,
        raw=dict(rec),
        provenance=prov,
    )


def _extract_hash(hashes: Any, algo: str) -> Optional[str]:
    if not hashes:
        return None
    if isinstance(hashes, str):
        # Sysmon: "SHA1=abc,MD5=def,SHA256=ghi"
        for part in hashes.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip().upper() == algo.upper():
                    return v.strip()
    return None


def _int_or_none(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


__all__ = ["SysmonNormalizer"]
