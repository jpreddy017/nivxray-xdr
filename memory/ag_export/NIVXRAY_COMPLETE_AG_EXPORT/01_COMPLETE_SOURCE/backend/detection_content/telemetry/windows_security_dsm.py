"""
NivXRay XDR — Windows Security Event Log DSM, Parser & Normalizer.
Provides native support for high-fidelity Windows Security Events:
- Event ID 4688: Process Creation with full Command Line and Parent
- Event ID 4768: Kerberos Authentication Ticket Request (TGT / AS-REP Roasting telemetry)
- Event ID 4769: Kerberos Service Ticket Request (Kerberoasting telemetry)
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Optional
import uuid

from .models import (
    AuthEntity,
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
)


class WindowsSecurityParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _get_ci(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Case-insensitive dictionary lookup across multiple potential key names."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    lower_map = {str(k).lower(): v for k, v in d.items() if v is not None}
    for k in keys:
        kl = k.lower()
        if kl in lower_map:
            return lower_map[kl]
    return default


class WindowsSecurityParser:
    id = "windows-security-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise WindowsSecurityParserError("INVALID_EVENT", "Event is not a JSON/dict object")

        sys_block = ev.get("System") or ev.get("system") or {}
        event_id = (
            _get_ci(ev, "EventID", "event_id", "eventid")
            or _get_ci(sys_block, "EventID", "event_id", "eventid")
        )
        if event_id is None:
            raise WindowsSecurityParserError("MISSING_EVENT_ID", "Event missing EventID")

        try:
            eid_int = int(event_id)
        except Exception:
            raise WindowsSecurityParserError("INVALID_EVENT_ID", f"EventID '{event_id}' is not an integer")

        if eid_int not in (4688, 4768, 4769):
            raise WindowsSecurityParserError("UNSUPPORTED_EID", f"EventID {eid_int} not supported by this DSM")

        # Extract system header info
        system = sys_block if isinstance(sys_block, dict) else {}
        time_created = (
            _get_ci(ev, "TimeCreated", "time_created", "timecreated", "timestamp")
            or _get_ci(system, "TimeCreated", "time_created", "timecreated")
            or datetime.now(timezone.utc).isoformat()
        )
        computer = _get_ci(ev, "Computer", "computer", "host") or _get_ci(system, "Computer", "computer", "host") or ""

        # EventData block can be a dict or a list of Name/Value dicts
        event_data = _get_ci(ev, "EventData", "event_data", "eventdata") or {}
        if isinstance(event_data, list):
            flat_ed: Dict[str, Any] = {}
            for item in event_data:
                if isinstance(item, dict) and "@Name" in item:
                    flat_ed[item["@Name"]] = item.get("#text", "")
                elif isinstance(item, dict) and "Name" in item:
                    flat_ed[item["Name"]] = item.get("Value", "")
            event_data = flat_ed
        elif not isinstance(event_data, dict):
            event_data = {}

        return {
            "parser_id": self.id,
            "raw": ev,
            "event_id": eid_int,
            "timestamp": str(time_created),
            "computer": str(computer),
            "data": event_data,
        }


class WindowsSecurityNormalizer:
    id = "windows-security-normalizer"

    def normalize(
        self,
        parsed: Dict[str, Any],
        dsm_id: str,
        collector_id: str,
        integration_id: str,
        trace_id: str,
        tenant_id: Optional[str] = "default",
    ) -> Dict[str, Any]:
        raw = parsed["raw"]
        if tenant_id is None or (isinstance(tenant_id, str) and not tenant_id.strip()):
            raise ValueError("tenant_id is required: NO tenant fallback permitted")
        resolved_tenant = (raw if isinstance(raw, dict) else {}).get("tenant_id") or tenant_id
        if not resolved_tenant or not str(resolved_tenant).strip():
            raise ValueError("tenant_id is required: NO tenant fallback permitted")
        resolved_tenant = str(resolved_tenant).strip()

        eid = parsed["event_id"]
        data = parsed["data"] if isinstance(parsed.get("data"), dict) else {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build Host Entity
        hostname = parsed["computer"]
        host = HostEntity(
            hostname=hostname,
            host_id=hostname,
            os_family="windows",
        )

        identity = IdentityEntity()
        process = ProcessEntity()
        network = NetworkEntity()
        auth = AuthEntity()
        additional: Dict[str, Any] = {}
        event_type = "windows_security_event"

        if eid == 4688:
            event_type = "process_creation"
            new_proc = str(_get_ci(data, "NewProcessName", "ProcessName") or "")
            cmd_line = str(_get_ci(data, "CommandLine", "ProcessCommandLine") or "")
            parent_proc = str(_get_ci(data, "ParentProcessName") or "")
            user_name = str(_get_ci(data, "TargetUserName", "SubjectUserName") or "")
            domain = str(_get_ci(data, "TargetDomainName", "SubjectDomainName") or "")
            user_sid = str(_get_ci(data, "TargetUserSid", "SubjectUserSid") or "")
            logon_id = str(_get_ci(data, "TargetLogonId", "SubjectLogonId") or "")
            elevation = str(_get_ci(data, "TokenElevationType") or "")

            proc_basename = os.path.basename(new_proc) if new_proc else ""
            parent_basename = os.path.basename(parent_proc) if parent_proc else ""

            process = ProcessEntity(
                name=proc_basename or new_proc,
                executable_path=new_proc,
                command_line=cmd_line or new_proc,
                parent_name=parent_basename or parent_proc,
                integrity_level=str(_get_ci(data, "MandatoryLabel") or ""),
            )

            is_priv = elevation in ("%%1937", "TokenElevationTypeFull", "Full") or "admin" in user_name.lower()
            principal = f"{domain}\\{user_name}" if domain and user_name else user_name
            identity = IdentityEntity(
                principal_id=principal,
                username=user_name,
                domain=domain,
                user_sid=user_sid,
                logon_id=logon_id,
                is_privileged=is_priv,
            )

        elif eid == 4768:
            event_type = "kerberos_tgt_request"
            user_name = str(data.get("TargetUserName") or "")
            domain = str(data.get("TargetDomainName") or "")
            service_name = str(data.get("ServiceName") or "")
            ticket_options = str(data.get("TicketOptions") or "")
            status = str(data.get("Status") or "")
            enc_type = str(data.get("TicketEncryptionType") or "")
            ip = str(data.get("IpAddress") or "").replace("::ffff:", "")
            port_str = str(data.get("IpPort") or "")

            principal = f"{domain}\\{user_name}" if domain and user_name else user_name
            identity = IdentityEntity(
                principal_id=principal,
                username=user_name,
                domain=domain,
                user_sid=str(data.get("TargetSid") or ""),
            )

            port: Optional[int] = None
            if port_str and port_str.isdigit():
                port = int(port_str)

            network = NetworkEntity(
                src_ip=ip,
                src_port=port,
                direction="inbound",
            )

            auth_status = "SUCCESS" if status in ("0x0", "0") else "FAILURE"
            auth = AuthEntity(
                auth_type="kerberos_as_rep",
                service_name=service_name,
                status=auth_status,
                failure_reason=status if auth_status == "FAILURE" else "",
                ticket_options=ticket_options,
                ticket_encryption=enc_type,
            )
            additional["encryption_type"] = enc_type

        elif eid == 4769:
            event_type = "kerberos_service_ticket_request"
            user_name = str(data.get("TargetUserName") or "")
            service_name = str(data.get("ServiceName") or "")
            ticket_options = str(data.get("TicketOptions") or "")
            status = str(data.get("Status") or "")
            enc_type = str(data.get("TicketEncryptionType") or "")
            ip = str(data.get("IpAddress") or "").replace("::ffff:", "")
            port_str = str(data.get("IpPort") or "")

            identity = IdentityEntity(
                principal_id=user_name,
                username=user_name,
                user_sid=str(data.get("TargetSid") or ""),
            )

            port: Optional[int] = None
            if port_str and port_str.isdigit():
                port = int(port_str)

            network = NetworkEntity(
                src_ip=ip,
                src_port=port,
                direction="inbound",
            )

            auth_status = "SUCCESS" if status in ("0x0", "0") else "FAILURE"
            auth = AuthEntity(
                auth_type="kerberos_tgs_request",
                service_name=service_name,
                status=auth_status,
                failure_reason=status if auth_status == "FAILURE" else "",
                ticket_options=ticket_options,
                ticket_encryption=enc_type,
            )
            additional["service_name"] = service_name
            additional["encryption_type"] = enc_type

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=WindowsSecurityParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Microsoft",
            source_product="Windows Security Log",
            source_event_id=str(eid),
            event_type=event_type,
            event_time=parsed["timestamp"],
            ingest_time=now_iso,
            host=host,
            identity=identity,
            process=process,
            network=network,
            authentication=auth,
            raw_ref=raw,
            provenance=provenance,
            additional_fields=additional,
        )
        return canonical.to_dict()


class WindowsSecurityDSM:
    id = "windows-security-evd"
    vendor = "Microsoft"
    product = "Windows Security Event Log"
    version = "1"
    source_type = "ENDPOINT_SECURITY"

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        # Matches if EventID is 4688, 4768, 4769
        sys_block = ev.get("System") or ev.get("system") or {}
        eid = _get_ci(ev, "EventID", "event_id", "eventid") or _get_ci(sys_block, "EventID", "event_id", "eventid")
        try:
            return int(eid) in (4688, 4768, 4769)
        except Exception:
            return False

    def select_parser(self) -> WindowsSecurityParser:
        return WindowsSecurityParser()

    def select_normalizer(self) -> WindowsSecurityNormalizer:
        return WindowsSecurityNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source_type": self.source_type,
        }
