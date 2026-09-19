"""
NivXRay XDR — Windows Security Event Log DSM, Parser & Normalizer.
Provides native support for high-fidelity Windows Security Events:
- Event ID 4688: Process Creation with full Command Line and Parent
- Event ID 4768: Kerberos Authentication Ticket Request (TGT / AS-REP Roasting telemetry)
- Event ID 4769: Kerberos Service Ticket Request (Kerberoasting telemetry)
- Event ID 4624: Successful account logon (authentication evidence)
- Event ID 4625: Failed account logon (authentication evidence)

P0-3 (owner-authorised 2026-09-05): 4624/4625 added as a TELEMETRY COVERAGE
correction.  They are normalized as authentication/logon evidence onto the
existing AuthEntity/IdentityEntity canonical model.  No identity engine, no
UBAE, no behavioural baselining is introduced here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Optional
import uuid

from services import event_time_basis
from services import tenant_authority

from .models import (
    AuthEntity,
    CanonicalTelemetryEvent,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProcessEntity,
    ProvenanceEnvelope,
    RegistryEntity,
)
from . import evtx_xml
from . import registry_evidence



# Event IDs this DSM parses and normalizes.  4624/4625 added 2026-09-05
# (P0-3 telemetry coverage correction) — authentication/logon evidence.
# 4657 added 2026-09-15 (D18) — OBSERVED registry value modification.
#
# W2-1 lane (2026-06): the Security channel acquired by the native Windows
# adapter is normalized here, so its coverage was widened to the account,
# privilege, credential-use, scheduled-task and audit-integrity records the
# channel actually carries. Every addition normalizes onto the EXISTING
# canonical model — no new engine, no scoring, no baselining.
SUPPORTED_EVENT_IDS = (
    4688, 4768, 4769, 4624, 4625, 4657,
    4648,   # logon using explicitly supplied credentials
    4672,   # special privileges assigned to a new logon
    4720,   # user account created
    4726,   # user account deleted
    4732,   # member added to a security-enabled local group
    4776,   # credential validation by the NTLM authentication package
    4698,   # scheduled task created
    1102,   # the audit log itself was cleared
)

def _windows_basename(path_value: str) -> str:
    """Executable name from a Windows path.

    `os.path.basename` is POSIX on Linux and does NOT split backslashes, so a
    Windows image path was being written verbatim into `process.name`.  The
    full path stays in `process.executable_path`; `process.name` is strictly
    the executable name.
    """
    if not path_value:
        return ""
    return re.split(r"[\\/]", path_value.strip().rstrip("\\/"))[-1]


_LOGON_TYPE_LABELS = {
    2: "interactive", 3: "network", 4: "batch", 5: "service",
    7: "unlock", 8: "network_cleartext", 9: "new_credentials",
    10: "remote_interactive", 11: "cached_interactive",
}


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
        # W2-1 · the native Windows adapter delivers the record exactly as
        # Windows rendered it. Decode once, here, so the XML never reaches
        # the field extraction below as an opaque string.
        if isinstance(ev, str) or evtx_xml.envelope_xml(ev) is not None:
            try:
                decoded = evtx_xml.decode_document(ev)
            except evtx_xml.EvtxXmlDecodeError as exc:
                raise WindowsSecurityParserError(exc.code, exc.message)
            if decoded is not None:
                ev = decoded
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

        if eid_int not in SUPPORTED_EVENT_IDS:
            raise WindowsSecurityParserError("UNSUPPORTED_EID", f"EventID {eid_int} not supported by this DSM")

        # Extract system header info
        system = sys_block if isinstance(sys_block, dict) else {}
        # D12 · `TimeCreated` is when the logging subsystem WROTE the record.
        # It is normally close to the action; close is not the same, and the
        # EVTX format carries no separate activity-occurrence field. Both
        # halves are kept apart so the normalizer can say which it has, and
        # neither is defaulted to the current clock here.
        time_created = (
            _get_ci(ev, "TimeCreated", "time_created", "timecreated")
            or _get_ci(system, "TimeCreated", "time_created", "timecreated",
                       "SystemTime", "systemtime")
            or ""
        )
        supplied_time = _get_ci(ev, "timestamp") or ""
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

        # 1102 (audit log cleared) carries its subject in `UserData`, not
        # `EventData`. The two are different elements and are merged only
        # when EventData genuinely has nothing — never silently overlaid.
        if not event_data:
            user_data = _get_ci(ev, "UserData", "user_data")
            if isinstance(user_data, dict) and user_data:
                event_data = dict(user_data)

        return {
            "parser_id": self.id,
            "raw": ev,
            "event_id": eid_int,
            "timestamp": str(time_created),
            "time_created": str(time_created),
            "supplied_time": str(supplied_time),
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
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        raw = parsed["raw"]
        # D14 · the authenticated delivery is the only authority; a
        # payload-named tenant is an untrusted claim, recorded and unused.
        resolved_tenant, _tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))

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
        registry = RegistryEntity()
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

            proc_basename = _windows_basename(new_proc)
            parent_basename = _windows_basename(parent_proc)

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
                # D19 · 4768 states the pre-authentication type; "0" means
                # none was used. Recorded verbatim, never defaulted.
                preauth_type=str(_get_ci(data, "PreAuthType",
                                         "PreAuthenticationType") or ""),
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

        elif eid in (4624, 4625):
            # P0-3 · authentication / logon evidence.  Normalized onto the
            # existing AuthEntity + IdentityEntity model.  No identity
            # engine, no UBAE, no baselining.
            succeeded = (eid == 4624)
            event_type = "logon_success" if succeeded else "logon_failure"
            user_name = str(_get_ci(data, "TargetUserName") or "")
            domain = str(_get_ci(data, "TargetDomainName") or "")
            user_sid = str(_get_ci(data, "TargetUserSid") or "")
            logon_id = str(_get_ci(data, "TargetLogonId") or "")
            logon_type_raw = str(_get_ci(data, "LogonType") or "")
            workstation = str(_get_ci(data, "WorkstationName") or "")
            logon_process = str(_get_ci(data, "LogonProcessName") or "")
            auth_package = str(_get_ci(data, "AuthenticationPackageName") or "")
            proc_name = str(_get_ci(data, "ProcessName") or "")
            ip = str(_get_ci(data, "IpAddress") or "").replace("::ffff:", "")
            port_str = str(_get_ci(data, "IpPort") or "")

            logon_type: Optional[int] = None
            if logon_type_raw.strip().lstrip("-").isdigit():
                logon_type = int(logon_type_raw.strip())

            principal = f"{domain}\\{user_name}" if domain and user_name else user_name
            identity = IdentityEntity(
                principal_id=principal,
                username=user_name,
                domain=domain,
                user_sid=user_sid,
                logon_id=logon_id,
                is_privileged=("admin" in user_name.lower()),
            )

            if proc_name:
                process = ProcessEntity(
                    name=_windows_basename(proc_name),
                    executable_path=proc_name,
                )

            port: Optional[int] = None
            if port_str.isdigit():
                port = int(port_str)
            if ip or port is not None:
                network = NetworkEntity(
                    src_ip=ip,
                    src_port=port,
                    direction="inbound",
                )

            # 4625 carries Status/SubStatus; 4624 has no failure reason.
            status_code = str(_get_ci(data, "Status") or "")
            sub_status = str(_get_ci(data, "SubStatus") or "")
            auth = AuthEntity(
                auth_type=(auth_package.lower() or "windows_logon"),
                logon_type=logon_type,
                status="SUCCESS" if succeeded else "FAILURE",
                failure_reason=("" if succeeded
                                else (sub_status or status_code)),
            )

            # Only record what the event actually carried (rule #13).
            if logon_type is not None:
                additional["logon_type"] = logon_type
                label = _LOGON_TYPE_LABELS.get(logon_type)
                if label:
                    additional["logon_type_label"] = label
            if workstation:
                additional["workstation_name"] = workstation
            if logon_process:
                additional["logon_process"] = logon_process
            if auth_package:
                additional["authentication_package"] = auth_package
            if not succeeded and status_code:
                additional["status"] = status_code
            if not succeeded and sub_status:
                additional["sub_status"] = sub_status

        elif eid == 4657:
            # ── D18 · a registry VALUE was modified, as observed by the ──
            # Windows auditing subsystem. The actor comes from the same
            # record or is absent; nothing is attributed by proximity.
            event_type = "registry_value_modified"
            registry, reg_mapping = registry_evidence.from_windows_4657(data)
            proc_name = str(_get_ci(data, "ProcessName") or "")
            user_name = str(_get_ci(data, "SubjectUserName") or "")
            domain = str(_get_ci(data, "SubjectDomainName") or "")
            if proc_name:
                process = ProcessEntity(
                    name=_windows_basename(proc_name),
                    executable_path=proc_name,
                )
            if user_name:
                identity = IdentityEntity(
                    principal_id=(f"{domain}\\{user_name}"
                                  if domain else user_name),
                    username=user_name,
                    domain=domain,
                    user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                    logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
                )
            reg_mapping["associations"] = registry_evidence.associations(
                device=hostname, device_source="windows:Computer",
                process_path=proc_name,
                process_source="windows:EventData.ProcessName",
                process_id=_get_ci(data, "ProcessId"),
                username=user_name,
                identity_source="windows:EventData.SubjectUserName")
            reg_mapping["raw_reference"] = {
                "windows_event_id": eid,
                "object_name": registry.key_path,
                "handle_id": str(_get_ci(data, "HandleId") or ""),
            }
            additional["registry_mapping"] = reg_mapping

        elif eid == 4648:
            # A logon that supplied credentials EXPLICITLY — the subject and
            # the target account are different principals, and both are kept.
            event_type = "explicit_credential_logon"
            subj_user = str(_get_ci(data, "SubjectUserName") or "")
            subj_domain = str(_get_ci(data, "SubjectDomainName") or "")
            target_user = str(_get_ci(data, "TargetUserName") or "")
            target_domain = str(_get_ci(data, "TargetDomainName") or "")
            target_server = str(_get_ci(data, "TargetServerName") or "")
            proc_name = str(_get_ci(data, "ProcessName") or "")
            ip = str(_get_ci(data, "IpAddress") or "").replace("::ffff:", "")
            identity = IdentityEntity(
                principal_id=(f"{subj_domain}\\{subj_user}"
                              if subj_domain and subj_user else subj_user),
                username=subj_user, domain=subj_domain,
                user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
            )
            if proc_name:
                process = ProcessEntity(name=_windows_basename(proc_name),
                                        executable_path=proc_name)
            if ip:
                network = NetworkEntity(src_ip=ip, direction="outbound")
            auth = AuthEntity(auth_type="explicit_credentials",
                              status="REQUESTED")
            if target_user:
                additional["target_user_name"] = target_user
            if target_domain:
                additional["target_domain_name"] = target_domain
            if target_server:
                additional["target_server_name"] = target_server
            additional["status_note"] = (
                "4648 records that credentials were supplied explicitly; it "
                "does not state whether the resulting logon succeeded")

        elif eid == 4672:
            event_type = "special_privileges_assigned"
            subj_user = str(_get_ci(data, "SubjectUserName") or "")
            subj_domain = str(_get_ci(data, "SubjectDomainName") or "")
            privileges = str(_get_ci(data, "PrivilegeList") or "")
            identity = IdentityEntity(
                principal_id=(f"{subj_domain}\\{subj_user}"
                              if subj_domain and subj_user else subj_user),
                username=subj_user, domain=subj_domain,
                user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
                # The event itself states that privileged rights were
                # assigned to this logon. That is OBSERVED, not inferred.
                is_privileged=True,
            )
            if privileges:
                additional["privilege_list"] = [
                    p for p in re.split(r"[\s,]+", privileges.strip()) if p]

        elif eid in (4720, 4726):
            created = (eid == 4720)
            event_type = ("user_account_created" if created
                          else "user_account_deleted")
            subj_user = str(_get_ci(data, "SubjectUserName") or "")
            subj_domain = str(_get_ci(data, "SubjectDomainName") or "")
            identity = IdentityEntity(
                principal_id=(f"{subj_domain}\\{subj_user}"
                              if subj_domain and subj_user else subj_user),
                username=subj_user, domain=subj_domain,
                user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
            )
            # The ACTOR is `identity`; the account acted UPON is recorded
            # separately, because collapsing them would attribute the
            # change to its own victim.
            additional["target_user_name"] = str(
                _get_ci(data, "TargetUserName") or "")
            additional["target_domain_name"] = str(
                _get_ci(data, "TargetDomainName") or "")
            additional["target_user_sid"] = str(
                _get_ci(data, "TargetSid") or "")

        elif eid == 4732:
            event_type = "security_group_member_added"
            subj_user = str(_get_ci(data, "SubjectUserName") or "")
            subj_domain = str(_get_ci(data, "SubjectDomainName") or "")
            identity = IdentityEntity(
                principal_id=(f"{subj_domain}\\{subj_user}"
                              if subj_domain and subj_user else subj_user),
                username=subj_user, domain=subj_domain,
                user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
            )
            additional["group_name"] = str(
                _get_ci(data, "TargetUserName") or "")
            additional["group_domain"] = str(
                _get_ci(data, "TargetDomainName") or "")
            additional["group_sid"] = str(_get_ci(data, "TargetSid") or "")
            # 4732 names the member by SID; `MemberName` is frequently the
            # literal "-". Recorded exactly as delivered, not resolved here.
            additional["member_sid"] = str(_get_ci(data, "MemberSid") or "")
            additional["member_name"] = str(_get_ci(data, "MemberName") or "")

        elif eid == 4776:
            event_type = "credential_validation"
            target_user = str(_get_ci(data, "TargetUserName") or "")
            workstation = str(_get_ci(data, "Workstation") or "")
            status_code = str(_get_ci(data, "Status") or "")
            succeeded = status_code in ("0x0", "0")
            identity = IdentityEntity(principal_id=target_user,
                                      username=target_user)
            auth = AuthEntity(
                auth_type="ntlm",
                status="SUCCESS" if succeeded else "FAILURE",
                failure_reason="" if succeeded else status_code,
            )
            if workstation:
                additional["workstation_name"] = workstation
            if status_code:
                additional["status"] = status_code
            additional["authentication_package"] = str(
                _get_ci(data, "PackageName") or "")

        elif eid == 4698:
            event_type = "scheduled_task_created"
            subj_user = str(_get_ci(data, "SubjectUserName") or "")
            subj_domain = str(_get_ci(data, "SubjectDomainName") or "")
            identity = IdentityEntity(
                principal_id=(f"{subj_domain}\\{subj_user}"
                              if subj_domain and subj_user else subj_user),
                username=subj_user, domain=subj_domain,
                user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
            )
            additional["task_name"] = str(_get_ci(data, "TaskName") or "")
            # The task XML is the evidence. It is carried verbatim and is
            # NOT parsed into an action here: what a task will run is a
            # detection question, not a normalization one.
            additional["task_content"] = str(
                _get_ci(data, "TaskContent", "TaskContentNew") or "")

        elif eid == 1102:
            event_type = "audit_log_cleared"
            subj_user = str(_get_ci(data, "SubjectUserName") or "")
            subj_domain = str(_get_ci(data, "SubjectDomainName") or "")
            identity = IdentityEntity(
                principal_id=(f"{subj_domain}\\{subj_user}"
                              if subj_domain and subj_user else subj_user),
                username=subj_user, domain=subj_domain,
                user_sid=str(_get_ci(data, "SubjectUserSid") or ""),
                logon_id=str(_get_ci(data, "SubjectLogonId") or ""),
            )
            additional["integrity_note"] = (
                "the Security audit log was cleared. Records written before "
                "this point may be permanently absent from the endpoint, and "
                "an absence after it is not evidence of inactivity")

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=WindowsSecurityParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        # ── D12 · Windows Security: observation, never promoted ─────────
        # `System.TimeCreated.SystemTime` is the record-generation instant.
        # EVTX has no separate activity-occurrence field, so this DSM
        # deliberately declares an OBSERVATION and leaves
        # `activity_occurred_at` NOT_OBSERVED. We would rather show an
        # honest gap than manufacture causal ordering from a log-write time.
        etb = event_time_basis.resolve(
            observation=([(parsed.get("time_created"),
                           "windows:System.TimeCreated.SystemTime")]
                         if parsed.get("time_created") else ()),
            supplied=([(parsed.get("supplied_time"),
                        "raw:timestamp — a generic key supplied by the "
                        "delivery; the EVTX format does not establish what "
                        "instant it names")]
                      if parsed.get("supplied_time") else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "the Windows Security EVTX format carries no activity-"
                "occurrence field; TimeCreated is the record-generation "
                "instant and must not stand in for the activity"),
            observation_absent_reason=(
                "this record carried no TimeCreated/SystemTime"))

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Microsoft",
            source_product="Windows Security Log",
            source_event_id=str(eid),
            event_type=event_type,
            event_time=etb.event_time,
            ingest_time=now_iso,
            host=host,
            identity=identity,
            process=process,
            network=network,
            registry=registry,
            authentication=auth,
            raw_ref=raw,
            provenance=provenance,
            additional_fields=additional,
        )
        out = canonical.to_dict()
        event_time_basis.apply(out, etb)
        tenant_authority.record(out, _tenant_claim)
        return out


class WindowsSecurityDSM:
    id = "windows-security-evd"
    vendor = "Microsoft"
    product = "Windows Security Event Log"
    version = "1"
    source_type = "ENDPOINT_SECURITY"

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
        # Matches any EventID in SUPPORTED_EVENT_IDS.
        sys_block = ev.get("System") or ev.get("system") or {}
        eid = _get_ci(ev, "EventID", "event_id", "eventid") or _get_ci(sys_block, "EventID", "event_id", "eventid")
        try:
            return int(eid) in SUPPORTED_EVENT_IDS
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
