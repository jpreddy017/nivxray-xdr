"""
NivXRay XDR — Telemetry Foundation & Normalization Models.
Defines strongly typed event models and normalization contracts across enterprise data sources.
Preserves all mandatory dimensions: tenant, source, source_event_id, event_time, ingest_time,
host/device, user/identity, process, command_line, network, file, authentication, cloud context,
raw evidence reference, and provenance.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class HostEntity:
    hostname: str = ""
    host_id: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    os_family: str = ""  # windows, linux, macos
    domain: str = ""


@dataclass
class IdentityEntity:
    principal_id: str = ""
    username: str = ""
    domain: str = ""
    user_sid: str = ""
    logon_id: str = ""
    is_privileged: bool = False
    service_principal_id: str = ""


@dataclass
class ProcessEntity:
    name: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_name: str = ""
    executable_path: str = ""
    command_line: str = ""
    integrity_level: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)


@dataclass
class NetworkEntity:
    src_ip: str = ""
    src_port: Optional[int] = None
    dest_ip: str = ""
    dest_port: Optional[int] = None
    protocol: str = ""
    direction: str = ""  # inbound, outbound, internal
    dns_query: str = ""


@dataclass
class FileEntity:
    path: str = ""
    name: str = ""
    action: str = ""  # create, read, write, delete, rename
    target_path: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    size_bytes: Optional[int] = None


@dataclass
class RegistryEntity:
    """D18 · OBSERVED registry activity.

    Populated only from telemetry that actually watched the registry
    (Sysmon 12/13/14, Windows Security 4657). A command line that merely
    mentions a registry path never fills this in — that is an inference
    about a process, and it stays on the process.
    """
    hive: str = ""
    key_path: str = ""
    value_name: str = ""
    value_data: str = ""
    value_type: str = ""
    action: str = ""      # create_key|delete_key|rename_key|set_value|…
    target_object: str = ""   # the source's verbatim object string
    new_key_path: str = ""    # rename target, when the source named one


@dataclass
class AuthEntity:
    auth_type: str = ""  # kerberos, ntlm, oauth, saml, ssh_key
    logon_type: Optional[int] = None
    service_name: str = ""  # SPN
    status: str = ""  # success, failure, preauth_required
    failure_reason: str = ""
    ticket_options: str = ""
    ticket_encryption: str = ""
    #: D19 · Kerberos pre-authentication type as the source stated it
    #: (Windows 4768 `PreAuthType`). "0" means no pre-auth was used, which
    #: is what AS-REP roasting needs — so the field must exist to be cited.
    preauth_type: str = ""


@dataclass
class CloudContext:
    provider: str = ""  # aws, azure, gcp, m365
    account_id: str = ""
    region: str = ""
    service: str = ""
    action: str = ""
    principal_arn: str = ""
    #: D19 · the principal TYPE as the provider stated it (CloudTrail
    #: `userIdentity.type`: IAMUser, AssumedRole, AWSService, Root…).
    #: Verbatim — provider vocabularies are not translated into each other.
    principal_type: str = ""
    #: D19 · the request parameters the provider recorded, verbatim. A cloud
    #: authorization decision lives in these (policy documents, inbox-rule
    #: definitions), so a rule that evaluates them needs a field to cite.
    request_parameters: Dict[str, Any] = field(default_factory=dict)
    #: Microsoft Phase 1 · the provider's OWN tenant identity
    #: (M365 `OrganizationId`). Kept for source binding and correlation; it
    #: is never the NivX tenant, which the authenticated delivery decides.
    provider_tenant_id: str = ""
    #: Microsoft Phase 1 · the provider's service/workload name for this
    #: record (`Workload`: Exchange, AzureActiveDirectory, SharePoint…),
    #: verbatim.
    workload: str = ""
    #: Microsoft Phase 1 · the provider's record classification
    #: (`RecordType`, resolved to Microsoft's published name).
    record_type: str = ""
    #: Microsoft Phase 1 · the provider's stated outcome for the operation
    #: (`ResultStatus`). Absent stays absent — a missing status is never
    #: read as success.
    result_status: str = ""
    #: Microsoft Phase 1 · the application / service-principal identity that
    #: performed the operation, where the provider recorded one.
    application_id: str = ""
    #: Microsoft Phase 1 · the provider's session identifier, where recorded.
    #: Preserved for future cross-domain correlation, not synthesised.
    session_id: str = ""
    resource_ids: List[str] = field(default_factory=list)
    user_agent: str = ""


@dataclass
class ProvenanceEnvelope:
    trace_id: str
    collector_id: str = "direct-telemetry"
    integration_id: str = "native"
    dsm_id: str = ""
    parser_id: str = ""
    normalizer_id: str = ""
    ingest_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class CanonicalTelemetryEvent:
    """Authoritative normalized event shape persisted into xdr_canonical_evidence."""
    event_id: str
    tenant_id: str
    source_vendor: str
    source_product: str
    source_event_id: str
    event_type: str
    event_time: str
    ingest_time: str
    host: HostEntity = field(default_factory=HostEntity)
    identity: IdentityEntity = field(default_factory=IdentityEntity)
    process: ProcessEntity = field(default_factory=ProcessEntity)
    network: NetworkEntity = field(default_factory=NetworkEntity)
    file: FileEntity = field(default_factory=FileEntity)
    registry: RegistryEntity = field(default_factory=RegistryEntity)
    authentication: AuthEntity = field(default_factory=AuthEntity)
    cloud: CloudContext = field(default_factory=CloudContext)
    raw_ref: Dict[str, Any] = field(default_factory=dict)
    provenance: ProvenanceEnvelope = field(default_factory=lambda: ProvenanceEnvelope(trace_id=str(uuid.uuid4())))
    additional_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to standard dictionary expected by xdr_pipeline and SSOT."""
        d = asdict(self)
        # Convenience root aliases for backward compatibility with detection rules
        d["timestamp"] = self.event_time
        d["command_line"] = self.process.command_line
        d["image"] = self.process.executable_path or self.process.name
        d["parent_image"] = self.process.parent_name
        d["user_id"] = self.identity.principal_id or self.identity.username
        d["host_id"] = self.host.host_id or self.host.hostname
        return d
