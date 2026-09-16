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

from services import event_time_basis
from services import tenant_authority

from .models import (
    PROCESS_ATTRIBUTION_AUTHORITATIVE,
    PROCESS_ATTRIBUTION_PID_ONLY,
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
    RegistryEntity,
)
from . import registry_evidence


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
            # D12 · three DIFFERENT timestamps, kept apart.
            #   UtcTime     — Sysmon's record of when the activity occurred
            #   TimeCreated — when the ETW provider wrote the record
            #   timestamp   — a generic key from whatever shipped the event
            # The normalizer declares which is which; nothing is defaulted
            # to the current clock here, because a parser that invents a
            # time makes the invention unrecoverable downstream.
            "utc_time": _first(ev, "utc_time", "UtcTime"),
            "time_created": _first(ev, "time_created", "TimeCreated",
                                   "SystemTime", "system_time"),
            "timestamp": ev.get("timestamp") or "",
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
                # D18 · Sysmon states the operation in EventType, and names
                # the rename target in NewName. Both are carried through so
                # the normalizer never has to guess the operation.
                "event_type": _first(ev, "registry_event_type", "EventType"),
                "new_name": _first(ev, "registry_new_name", "NewName"),
            },
            "channel": ev.get("channel") or "",
            "raw": ev,
        }


def _sysmon_query_results(value: Any) -> Dict[str, list]:
    """Split Sysmon's `QueryResults` into address answers and other records.

    Nothing is inferred: an entry is an address only when it parses as one.
    An empty / `-` result set yields two empty lists, which is the honest
    representation of "the query returned no address".
    """
    import ipaddress as _ipaddress
    import re as _re
    ips: list = []
    records: list = []
    if not value:
        return {"ips": ips, "records": records}
    for part in str(value).split(";"):
        entry = _re.sub(r"^type:\s*\d+\s+", "", part.strip()).strip()
        if not entry or entry == "-":
            continue
        candidate = entry[len("::ffff:"):] if entry.lower().startswith(
            "::ffff:") else entry
        try:
            _ipaddress.ip_address(candidate)
            ips.append(candidate)
        except ValueError:
            records.append(entry)
    return {"ips": ips, "records": records}


class SysmonNormalizer:
    id = "sysmon-normalizer"

    def normalize(self, parsed: Dict[str, Any], dsm_id: str, collector_id: str,
                  integration_id: str, trace_id: str,
                  tenant_id: str | None = None) -> Dict[str, Any]:
        # D13/D14 · the authenticated delivery is the only authority on
        # ownership. This normalizer previously hardcoded "default", which
        # put every Sysmon event in the wrong tenant; there is NO fallback.
        raw = parsed.get("raw") if isinstance(parsed.get("raw"), dict) else {}
        resolved_tenant, _tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))
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
        if p.get("image") or p.get("guid"):
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
            # ── N2.1 · stop discarding the identity Sysmon already gave ──
            # `ProcessGuid` is Sysmon's own lifetime-unique process
            # identity and it is stamped on EID 1, 3 AND 22 — so
            # process→connection and process→DNS are proven INSIDE one
            # record. It was parsed here and then dropped, which is why
            # NivX could not attribute network activity to a process on a
            # source that had already done the work.
            guid = str(p.get("guid") or "").strip()
            parent_guid = str(p.get("parent_guid") or "").strip()
            if guid:
                proc.process_guid = guid
                proc.field_provenance["process_guid"] = \
                    "sysmon:EventData.ProcessGuid"
                proc.attribution_state = PROCESS_ATTRIBUTION_AUTHORITATIVE
                proc.attribution_reason = (
                    "Sysmon stamped ProcessGuid on this record, and the "
                    "activity it describes is in the SAME record — the "
                    "source itself binds process and activity. A GUID is "
                    "unique on its own and needs no endpoint scope")
            elif proc.pid is not None:
                proc.attribution_state = PROCESS_ATTRIBUTION_PID_ONLY
                proc.attribution_reason = (
                    "this Sysmon record carried no ProcessGuid; a PID is "
                    "reused by the OS and is context, not attribution")
            else:
                proc.attribution_reason = (
                    "this Sysmon record named no process")
            if parent_guid:
                proc.parent_process_guid = parent_guid
                proc.field_provenance["parent_process_guid"] = \
                    "sysmon:EventData.ParentProcessGuid"
            if p.get("image"):
                proc.field_provenance["executable_path"] = \
                    "sysmon:EventData.Image"
            if proc.pid is not None:
                proc.field_provenance["pid"] = "sysmon:EventData.ProcessId"

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
            # ── N1/GAP-1 · Sysmon EID 22 `QueryResults` ────────────────
            # The answer side was parsed and then discarded for want of a
            # canonical field, which meant Sysmon could never evidence
            # `domain → resolved IP`. Microsoft writes it as
            # `type:  5 cdn.example.com;type:  1 93.184.216.34;` and
            # IPv4 answers as `::ffff:93.184.216.34`.
            answers = _sysmon_query_results(n.get("dns_answer"))
            if answers["ips"] or answers["records"]:
                net.dns_response_ips = answers["ips"]
                net.dns_response_records = answers["records"]
                net.field_provenance.update({
                    k: "sysmon:EventData.QueryResults"
                    for k, v in (("dns_response_ips", answers["ips"]),
                                 ("dns_response_records", answers["records"]))
                    if v})
            if n.get("src_ip"):
                net.field_provenance["src_ip"] = "sysmon:EventData.SourceIp"
            if n.get("dst_ip"):
                net.field_provenance["dest_ip"] = \
                    "sysmon:EventData.DestinationIp"
            if n.get("dns_query"):
                net.field_provenance["dns_query"] = \
                    "sysmon:EventData.QueryName"

        # ── D18 · registry evidence, only where the registry was OBSERVED ──
        registry = RegistryEntity()
        registry_mapping: Dict[str, Any] | None = None
        r = parsed.get("registry") or {}
        if sysmon_eid in (12, 13, 14) and r.get("key"):
            registry, registry_mapping = registry_evidence.from_sysmon(
                event_id=sysmon_eid,
                target_object=str(r.get("key") or ""),
                details=str(r.get("data") or ""),
                event_type=str(r.get("event_type") or ""),
                new_name=str(r.get("new_name") or ""))
            registry_mapping["associations"] = registry_evidence.associations(
                device=parsed["computer"], device_source="sysmon:Computer",
                process_path=p.get("image", ""),
                process_source="sysmon:EventData.Image",
                process_id=p.get("pid") or None,
                username=parsed["user"] or "",
                identity_source="sysmon:EventData.User")
            registry_mapping["raw_reference"] = {
                "sysmon_event_id": sysmon_eid,
                "channel": parsed.get("channel", ""),
                "target_object": str(r.get("key") or ""),
            }

        prov = ProvenanceEnvelope(
            trace_id=trace_id,
            integration_id=integration_id,
            collector_id=collector_id,
            dsm_id=dsm_id,
            parser_id=SysmonParser.id,
            normalizer_id=self.id,
        )

        # ── D12 · Sysmon is the one source that genuinely carries both ──
        # `UtcTime` is Sysmon's own record of when the activity happened;
        # `TimeCreated` is when the ETW provider wrote the record. They are
        # declared separately and never merged.
        now_iso = datetime.now(timezone.utc).isoformat()
        etb = event_time_basis.resolve(
            activity=([(parsed.get("utc_time"), "sysmon:EventData.UtcTime")]
                      if parsed.get("utc_time") else ()),
            observation=([(parsed.get("time_created"),
                           "sysmon:System.TimeCreated")]
                         if parsed.get("time_created") else ()),
            supplied=([(parsed.get("timestamp"),
                        "raw:timestamp — a generic key supplied by the "
                        "delivery; Sysmon's format does not establish it as "
                        "the activity instant")]
                      if parsed.get("timestamp") else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "this Sysmon event carried no UtcTime; TimeCreated is the "
                "ETW write instant and is NOT the activity instant"),
            observation_absent_reason=(
                "this Sysmon event carried no TimeCreated/SystemTime"))

        canonical = CanonicalTelemetryEvent(
            event_id=event_id,
            tenant_id=resolved_tenant,
            source_vendor="Microsoft",
            source_product="Sysmon",
            source_event_id=str(sysmon_eid),
            event_type=event_type,
            event_time=etb.event_time,
            ingest_time=now_iso,
            host=host,
            identity=identity or IdentityEntity(),
            process=proc or ProcessEntity(),
            network=net or NetworkEntity(),
            registry=registry,
            raw_ref={"sysmon_event_id": sysmon_eid,
                     "channel": parsed.get("channel", ""),
                     # N2.1 · the source's own identity stays reachable on
                     # the evidence, not only inside the parser.
                     "process_guid": str(
                         (parsed.get("process") or {}).get("guid") or ""),
                     "parent_process_guid": str(
                         (parsed.get("process") or {}).get(
                             "parent_guid") or "")},
            provenance=prov,
            additional_fields={
                "channel": parsed.get("channel", ""),
                "sysmon_file": parsed["file"],
                "sysmon_registry": parsed["registry"],
                **({"registry_mapping": registry_mapping}
                   if registry_mapping else {}),
            },
        )
        out = canonical.to_dict()
        event_time_basis.apply(out, etb)
        tenant_authority.record(out, _tenant_claim)
        return out


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
