"""
NivXRay XDR — Linux Auditd DSM, Parser & Normalizer.
Provides native support for Linux Auditd telemetry:
- SYSCALL, EXECVE, and PROCTITLE records
- Deterministic unhexing of hex-encoded arguments and command lines
- Resolving process lineage (exe, pid, ppid), user context (uid, auid, euid), and terminal context.
"""
from __future__ import annotations

import binascii
from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
)


class LinuxAuditdParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _unhex_if_needed(s: str) -> str:
    """Unhex hex-encoded string if valid hex without whitespace."""
    s = s.strip().strip('"')
    if len(s) > 2 and len(s) % 2 == 0 and re.match(r"^[0-9a-fA-F]+$", s):
        try:
            decoded = binascii.unhexlify(s).decode("utf-8", errors="replace")
            # If it decoded into printable characters or null-separated args
            if any(c.isalnum() for c in decoded):
                return decoded.replace("\x00", " ").strip()
        except Exception:
            pass
    return s


class LinuxAuditdParser:
    id = "linux-auditd-parser"

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise LinuxAuditdParserError("INVALID_EVENT", "Event is not a JSON/dict object")

        # May receive pre-parsed dict or raw auditd line in "message" / "raw"
        raw_msg = ev.get("message") or ev.get("raw") or ""
        parsed_fields: Dict[str, Any] = dict(ev)

        if isinstance(raw_msg, str) and "type=" in raw_msg:
            # Parse auditd key=value pairs: type=SYSCALL msg=audit(1693829482.123:456): arch=c000003e syscall=59 ...
            kv_pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', raw_msg)
            for k, v_quoted, v_bare in kv_pairs:
                val = v_quoted if v_quoted else v_bare
                parsed_fields[k] = val

            # Parse timestamp from msg=audit(TIMESTAMP:ID)
            m = re.search(r"audit\((\d+(?:\.\d+)?):(\d+)\)", raw_msg)
            if m:
                epoch = float(m.group(1))
                parsed_fields["timestamp"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
                parsed_fields["audit_id"] = m.group(2)

        record_type = str(parsed_fields.get("type") or parsed_fields.get("record_type") or "").upper()
        if not record_type and "syscall" not in parsed_fields and "exe" not in parsed_fields:
            raise LinuxAuditdParserError("UNRECOGNIZED_AUDITD", "Event lacks auditd type, syscall, or exe markers")

        return {
            "parser_id": self.id,
            "raw": ev,
            "record_type": record_type or "SYSCALL",
            "fields": parsed_fields,
        }


class LinuxAuditdNormalizer:
    id = "linux-auditd-normalizer"

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
        resolved_tenant = (raw if isinstance(raw, dict) else {}).get("tenant_id") or parsed.get("tenant_id") or tenant_id
        if not resolved_tenant or not str(resolved_tenant).strip():
            raise ValueError("tenant_id is required: NO tenant fallback permitted")
        resolved_tenant = str(resolved_tenant).strip()

        fields = parsed["fields"]
        now_iso = datetime.now(timezone.utc).isoformat()

        # Host (no invented telemetry)
        hostname = str(fields.get("host") or fields.get("hostname") or fields.get("node") or "")
        host = HostEntity(
            hostname=hostname,
            host_id=hostname,
            os_family="linux",
        )

        # Process extraction
        exe = _unhex_if_needed(str(fields.get("exe") or ""))
        comm = _unhex_if_needed(str(fields.get("comm") or ""))
        proctitle = _unhex_if_needed(str(fields.get("proctitle") or ""))

        # Assemble argv arguments if present (a0, a1, a2, ...)
        argv: List[str] = []
        i = 0
        while f"a{i}" in fields:
            arg_val = _unhex_if_needed(str(fields[f"a{i}"]))
            argv.append(arg_val)
            i += 1

        cmd_line = proctitle or " ".join(argv) or comm or exe
        proc_name = os.path.basename(exe) if exe else comm

        pid: Optional[int] = None
        if "pid" in fields:
            try:
                pid = int(fields["pid"])
            except Exception:
                pass

        ppid: Optional[int] = None
        if "ppid" in fields:
            try:
                ppid = int(fields["ppid"])
            except Exception:
                pass

        process = ProcessEntity(
            name=proc_name or "unknown",
            executable_path=exe,
            command_line=cmd_line,
            pid=pid,
            ppid=ppid,
        )

        # User / Identity
        uid = str(fields.get("uid") or "")
        auid = str(fields.get("auid") or "")
        euid = str(fields.get("euid") or "")
        user_name = str(fields.get("user") or fields.get("username") or "")
        if not user_name:
            if uid == "0" or auid == "0":
                user_name = "root"
            else:
                user_name = f"uid:{uid or auid}"

        identity = IdentityEntity(
            principal_id=user_name,
            username=user_name,
            is_privileged=(uid == "0" or euid == "0" or auid == "0"),
        )

        event_time = (
            fields.get("timestamp")
            or raw.get("timestamp")
            or now_iso
        )

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=LinuxAuditdParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Linux",
            source_product="Auditd",
            source_event_id=str(fields.get("audit_id") or fields.get("syscall") or "auditd"),
            event_type="process_execution" if "execve" in str(fields.get("syscall", "")).lower() or exe else "auditd_syscall",
            event_time=str(event_time),
            ingest_time=now_iso,
            host=host,
            identity=identity,
            process=process,
            raw_ref=raw,
            provenance=provenance,
            additional_fields={"syscall": fields.get("syscall"), "record_type": parsed["record_type"]},
        )
        return canonical.to_dict()


class LinuxAuditdDSM:
    id = "linux-auditd"
    vendor = "Linux"
    product = "Linux Auditd"
    version = "1"
    source_type = "ENDPOINT_AUDIT"

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        # Direct key checks
        if ev.get("type") in ("SYSCALL", "EXECVE", "PROCTITLE", "AVC"):
            return True
        if "syscall" in ev and ("exe" in ev or "comm" in ev):
            return True
        # Check raw string
        msg = str(ev.get("message") or ev.get("raw") or "")
        return "type=SYSCALL" in msg or "type=EXECVE" in msg or "type=PROCTITLE" in msg

    def select_parser(self) -> LinuxAuditdParser:
        return LinuxAuditdParser()

    def select_normalizer(self) -> LinuxAuditdNormalizer:
        return LinuxAuditdNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source_type": self.source_type,
        }
