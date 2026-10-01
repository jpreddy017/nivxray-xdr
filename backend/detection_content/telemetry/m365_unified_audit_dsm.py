"""Microsoft 365 Unified Audit DSM (Office 365 Management Activity API).

Phase 1a of the Microsoft security telemetry DOMAIN — not a rule parser.
One DSM interprets the common Management Activity schema plus the
workload-specific schemas NivX subscribes to first:

    Audit.Exchange              (ExchangeAdmin / ExchangeItem: inbox rules,
                                 mailbox permissions, mailbox access)
    Audit.AzureActiveDirectory  (Entra: role assignment, app consent,
                                 credential added to a service principal)
    Audit.General               (workloads Microsoft does not give their own
                                 content type)

Discipline carried over from D11–D19:

* **Timestamps.** `CreationTime` is the instant the user performed the
  activity — Microsoft documents it as such, so it is the activity basis and
  nothing else may stand in for it. The Management Activity API also exposes
  `contentCreated`, which is when the aggregated content BLOB became
  available; that is an acquisition boundary, never the activity instant, and
  it is recorded (when the acquisition layer supplies it) as acquisition
  provenance only.
* **Tenant.** `OrganizationId` is Microsoft's tenant GUID. It is preserved as
  the PROVIDER's tenant identity for source binding and correlation. It is
  never treated as the NivX tenant — the authenticated delivery remains the
  only authority on ownership (D14).
* **Provider vocabulary.** `Operation`, `Workload`, `RecordType`,
  `ResultStatus`, `UserType` and `Parameters` are kept as Microsoft states
  them. Documented Microsoft enum names are resolved from the numeric codes
  Microsoft publishes; an unknown code is reported as `RecordType:<n>` /
  `UserType:<n>` rather than guessed. The verbatim record always travels in
  `raw_ref`.
* **No fabrication.** Absent actor, target, result, IP or timestamp stays
  absent. No canonical value is invented because a detection would like it.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services import event_time_basis
from services import tenant_authority

from .models import (
    CanonicalTelemetryEvent,
    CloudContext,
    HostEntity,
    IdentityEntity,
    NetworkEntity,
    ProvenanceEnvelope,
)

#: Microsoft-published `RecordType` names. Only codes Microsoft documents are
#: named; anything else is reported as the code itself.
RECORD_TYPES: Dict[int, str] = {
    1: "ExchangeAdmin", 2: "ExchangeItem", 3: "ExchangeItemGroup",
    4: "SharePoint", 6: "SharePointFileOperation", 8: "AzureActiveDirectory",
    9: "AzureActiveDirectoryAccountLogon", 10: "DataCenterSecurityCmdlet",
    11: "ComplianceDLPSharePoint", 13: "ComplianceDLPExchange",
    14: "SharePointSharingOperation",
    15: "AzureActiveDirectoryStsLogon", 18: "SecurityComplianceCenterEOPCmdlet",
    20: "PowerBIAudit", 21: "SharePointListOperation", 22: "SharePointCommentOperation",
    23: "DataGovernance", 25: "MicrosoftTeams", 28: "ThreatIntelligence",
    29: "MailSubmission", 30: "MicrosoftFlow", 40: "SecurityComplianceAlerts",
    41: "ThreatIntelligenceUrl", 42: "SecurityComplianceInsights",
    47: "ExchangeItemAggregated", 50: "MipLabel", 52: "AirInvestigation",
    61: "HygieneEvent", 64: "AirAdminActionInvestigation", 68: "Project",
    72: "MicrosoftForms", 78: "ComplianceDLPExchangeClassification",
}

#: Microsoft-published `UserType` names.
USER_TYPES: Dict[int, str] = {
    0: "Regular", 1: "Reserved", 2: "Admin", 3: "DcAdmin", 4: "System",
    5: "Application", 6: "ServicePrincipal", 7: "CustomPolicy",
    8: "SystemPolicy", 9: "PartnerTechnician", 10: "Guest",
}

#: Microsoft `UserType` codes that are non-human principals.
_NON_HUMAN_USER_TYPES = frozenset({4, 5, 6, 8})

#: Microsoft `UserType` codes that carry administrative authority.
_ADMIN_USER_TYPES = frozenset({2, 3})

_TRANSPORT_NS = "_nivx"


class M365UnifiedAuditParserError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _enum_name(value: Any, table: Dict[int, str], label: str) -> str:
    """Microsoft's own name for a numeric code, or the code, never a guess."""
    if value is None or value == "":
        return ""
    try:
        code = int(value)
    except (TypeError, ValueError):
        # Already a name (some exports emit the string form) — keep verbatim.
        return str(value)
    return table.get(code) or f"{label}:{code}"


def _parameters_dict(params: Any) -> Dict[str, Any]:
    """Exchange records carry `Parameters` as `[{Name, Value}, ...]`.

    Flattened to a mapping so a rule can cite it, with the verbatim list kept
    on the event under `additional_fields.parameters_verbatim`. A record that
    already uses a mapping is passed through unchanged.
    """
    if isinstance(params, dict):
        return dict(params)
    out: Dict[str, Any] = {}
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and p.get("Name") is not None:
                out[str(p["Name"])] = p.get("Value")
    return out


class M365UnifiedAuditParser:
    id = "m365-unified-audit-parser"

    #: The common-schema markers every Management Activity record carries.
    REQUIRED = ("RecordType", "Operation")

    def parse(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(ev, dict):
            raise M365UnifiedAuditParserError(
                "INVALID_EVENT", "Event is not a JSON/dict object")
        missing = [k for k in self.REQUIRED if ev.get(k) in (None, "")]
        if missing:
            raise M365UnifiedAuditParserError(
                "MISSING_M365_AUDIT_MARKERS",
                "Management Activity common schema requires "
                f"{', '.join(self.REQUIRED)}; missing {', '.join(missing)}")
        if ev.get("OrganizationId") in (None, "") and \
                ev.get("Workload") in (None, ""):
            raise M365UnifiedAuditParserError(
                "MISSING_M365_TENANT_BINDING",
                "a Management Activity record must carry OrganizationId or "
                "Workload; without either there is no source binding to "
                "record")
        return {"parser_id": self.id, "raw": ev, "data": ev,
                "acquisition": ((ev.get(_TRANSPORT_NS) or {}).get(
                    "m365_acquisition")
                    # Phase 1b · the acquisition layer delivers content-blob
                    # metadata under this namespaced key. It is NivX
                    # acquisition provenance, not a Microsoft field.
                    or ev.get("_m365_acquisition") or {})}


class M365UnifiedAuditNormalizer:
    id = "m365-unified-audit-normalizer"

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
        data = parsed["data"]
        acquisition = parsed.get("acquisition") or {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # D14 · the authenticated delivery decides ownership; a payload-named
        # tenant is an untrusted claim, recorded and unused.
        resolved_tenant, tenant_claim = tenant_authority.resolve(
            tenant_id, *tenant_authority.payload_claims(raw))

        operation = str(data.get("Operation") or "")
        workload = str(data.get("Workload") or "")
        record_type = _enum_name(data.get("RecordType"), RECORD_TYPES,
                                 "RecordType")
        result_status = str(data.get("ResultStatus") or "")
        org_id = str(data.get("OrganizationId") or "")
        source_event_id = str(data.get("Id") or "")
        creation_time = str(data.get("CreationTime") or "")

        # ── D12 · Microsoft documents `CreationTime` as the instant the
        # user performed the activity, so it establishes activity
        # occurrence. `contentCreated` (blob availability) is an acquisition
        # boundary and is NEVER promoted into this position.
        etb = event_time_basis.resolve(
            activity=([(creation_time, "m365:CreationTime")]
                      if creation_time else ()),
            clock=now_iso,
            clock_source=f"pipeline:normalizer clock at {self.id}",
            activity_absent_reason=(
                "this Management Activity record carried no CreationTime; no "
                "other field in the format names when the activity happened "
                "— contentCreated is blob availability, not activity time"),
            observation_absent_reason=(
                "the Management Activity API is a service audit log: "
                "Microsoft records the activity, not a sensor's observation "
                "of it"))

        # ── actor ────────────────────────────────────────────────────
        # `UserId` is the acting principal as Microsoft recorded it (a UPN
        # for a user, an app id or `Microsoft.Exchange...` for a service).
        # Entra records additionally carry `Actor` as a list of typed ids.
        user_id = str(data.get("UserId") or "")
        user_key = str(data.get("UserKey") or "")
        user_type_code = data.get("UserType")
        user_type = _enum_name(user_type_code, USER_TYPES, "UserType")
        actor_ids = [str(a.get("ID")) for a in (data.get("Actor") or [])
                     if isinstance(a, dict) and a.get("ID")]
        try:
            _code = int(user_type_code)
        except (TypeError, ValueError):
            _code = -1
        identity = IdentityEntity(
            principal_id=user_id or user_key or (
                actor_ids[0] if actor_ids else ""),
            username=user_id,
            domain=str(data.get("OrganizationName") or ""),
            is_privileged=_code in _ADMIN_USER_TYPES,
            service_principal_id=(str(data.get("ApplicationId") or "")
                                  if _code in _NON_HUMAN_USER_TYPES else ""),
        )

        # ── client network context ───────────────────────────────────
        # Three Microsoft spellings for the same fact, in the order the
        # workload schemas define them. Only one is ever present.
        client_ip = str(data.get("ClientIP")
                        or data.get("ClientIPAddress")
                        or data.get("ActorIpAddress") or "")
        network = NetworkEntity(src_ip=client_ip,
                                direction="inbound") if client_ip \
            else NetworkEntity()

        # ── target / affected object ─────────────────────────────────
        object_id = str(data.get("ObjectId") or "")
        mailbox_owner = str(data.get("MailboxOwnerUPN") or "")
        entra_targets = [str(t.get("ID")) for t in (data.get("Target") or [])
                         if isinstance(t, dict) and t.get("ID")]
        resource_ids = [r for r in ([object_id, mailbox_owner]
                                    + entra_targets) if r]

        parameters = _parameters_dict(data.get("Parameters"))

        cloud = CloudContext(
            provider="m365",
            provider_tenant_id=org_id,
            account_id=org_id,
            region="",
            service=workload,
            workload=workload,
            record_type=record_type,
            action=operation,
            result_status=result_status,
            principal_arn=str(data.get("UserKey") or ""),
            principal_type=user_type,
            application_id=str(data.get("ApplicationId") or ""),
            session_id=str(data.get("SessionId") or ""),
            request_parameters=parameters,
            resource_ids=resource_ids,
            user_agent=str(data.get("ClientInfoString")
                           or data.get("UserAgent") or ""),
        )

        host = HostEntity(
            hostname=(f"m365-tenant-{org_id}" if org_id
                      else "m365-cloud"),
            host_id=org_id,
            os_family="cloud",
        )

        provenance = ProvenanceEnvelope(
            trace_id=trace_id,
            collector_id=collector_id,
            integration_id=integration_id,
            dsm_id=dsm_id,
            parser_id=M365UnifiedAuditParser.id,
            normalizer_id=self.id,
            ingest_time=now_iso,
        )

        additional: Dict[str, Any] = {
            "workload": workload,            "record_type": record_type,
            "record_type_code": data.get("RecordType"),
            "user_type": user_type,
            "user_type_code": user_type_code,
            "operation": operation,
            "result_status": result_status,
            # Microsoft's own tenant identity, labelled as such so it can
            # never be mistaken for the NivX tenant.
            "provider_tenant_id": org_id,
            "provider_tenant_id_basis": (
                "m365:OrganizationId — the Microsoft tenant that produced "
                "this record; NOT the NivX tenant, which is established by "
                "the authenticated delivery"),
            "parameters_verbatim": data.get("Parameters"),
            "modified_properties": data.get("ModifiedProperties"),
            "extended_properties": data.get("ExtendedProperties"),
            "external_access": data.get("ExternalAccess"),
            "client_info_string": data.get("ClientInfoString"),
            "originating_server": data.get("OriginatingServer"),
            "scope": data.get("Scope"),
        }
        if acquisition:
            # Phase 1b acquisition provenance travels here, NEVER into the
            # activity-time basis: a blob's availability is not an activity.
            additional["m365_acquisition"] = {
                "content_id": acquisition.get("contentId"),
                "content_type": acquisition.get("contentType"),
                "content_uri": acquisition.get("contentUri"),
                "content_created": acquisition.get("contentCreated"),
                "content_expiration": acquisition.get("contentExpiration"),
                "acquired_at": acquisition.get("acquiredAt"),
                "publisher_identifier": acquisition.get(
                    "publisherIdentifier"),
                "microsoft_tenant_id": acquisition.get("microsoftTenantId"),
                # The transport identity this delivery was idempotent on,
                # and whether it came from Microsoft or from NivX.
                "record_reference": acquisition.get("recordReference"),
                "record_reference_basis": acquisition.get(
                    "recordReferenceBasis"),
                "microsoft_event_id": acquisition.get("microsoftEventId"),
                "basis": ("Office 365 Management Activity API content blob "
                          "metadata — contentCreated is when the blob became "
                          "available, not when the activity happened"),
            }

        canonical = CanonicalTelemetryEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=resolved_tenant,
            source_vendor="Microsoft",
            source_product="Microsoft 365 Unified Audit",
            source_event_id=source_event_id,
            event_type="cloud_audit",
            event_time=etb.event_time,
            ingest_time=now_iso,
            host=host,
            identity=identity,
            network=network,
            cloud=cloud,
            raw_ref=raw,
            provenance=provenance,
            additional_fields=additional,
        )
        out = canonical.to_dict()
        event_time_basis.apply(out, etb)
        tenant_authority.record(out, tenant_claim)
        return out


class M365UnifiedAuditDSM:
    id = "m365-unified-audit"
    vendor = "Microsoft"
    product = "Microsoft 365 Unified Audit (Management Activity API)"
    version = "1"
    source_type = "CLOUD_AUDIT"

    #: What this DSM can and cannot evidence — stated so a missing
    #: correlation is never silently blamed on the source.
    capability = {
        "content_types": ["Audit.Exchange", "Audit.AzureActiveDirectory",
                          "Audit.General"],
        "provides": ["activity time (CreationTime)", "operation", "workload",
                     "record type", "result status", "acting principal",
                     "principal type", "client IP where recorded",
                     "target object / mailbox owner", "request parameters",
                     "application id", "session id where recorded",
                     "Microsoft tenant id (OrganizationId)"],
        "does_not_provide": [
            "endpoint process or file evidence",
            "device identity — Management Activity records carry no device id",
            "mail body or attachment content",
            "DLP events (separate DLP.All content type, not subscribed)",
            "Graph API call telemetry (MicrosoftGraphActivityLogs, a "
            "different source)"],
        "caveats": [
            "records are aggregated into tenant content blobs; blob "
            "availability (contentCreated) is not activity time",
            "the API performs no server-side deduplication and does not "
            "guarantee ordering, so replay protection belongs to the "
            "acquisition layer",
            "audit logging must be enabled in the Microsoft tenant or the "
            "feed is legitimately empty"],
    }

    def supports(self, ev: Dict[str, Any]) -> bool:
        if not isinstance(ev, dict):
            return False
        if ev.get("RecordType") in (None, "") or ev.get("Operation") in (
                None, ""):
            return False
        return not (ev.get("OrganizationId") in (None, "")
                    and ev.get("Workload") in (None, ""))

    def select_parser(self) -> M365UnifiedAuditParser:
        return M365UnifiedAuditParser()

    def select_normalizer(self) -> M365UnifiedAuditNormalizer:
        return M365UnifiedAuditNormalizer()

    def identity(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source_type": self.source_type,
            "capability": self.capability,
        }
