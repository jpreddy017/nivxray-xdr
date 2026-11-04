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
    """N2.1 · process evidence, with the identity the SOURCE gave us.

    A PID is not a process: the OS reuses it within minutes. A process is
    (where it ran, which PID, which lifetime) — which is why
    `attribution_state` exists. It has exactly three honest values:

      SOURCE_PROCESS_IDENTITY     the source stated an identity that is
                                  unique for the process's lifetime
                                  (Sysmon `ProcessGuid`, or a minted
                                  `process_iid` = endpoint + pid + start)
      PID_ONLY_NOT_AUTHORITATIVE  a PID with no lifetime evidence. Usable
                                  as context, NEVER as attribution
      NOT_OBSERVED                the owning process was not resolved

    `attribution_reason` keeps WHY, so a downstream reader never has to
    guess whether an absence is a collection gap or an absence of activity.
    """
    name: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_name: str = ""
    executable_path: str = ""
    command_line: str = ""
    integrity_level: str = ""
    #: W1 · the PE metadata name the vendor compiled into the binary
    #: (Sysmon `OriginalFileName`). It is NOT `name`: a renamed executable
    #: keeps its OriginalFileName, which is precisely what masquerading
    #: detections read. Collapsing the two destroys that distinction, so
    #: this field stays separate and stays ABSENT when unobserved.
    original_file_name: str = ""
    #: W1 · the parent's full image path and command line, as the source
    #: stated them. `parent_name` remains the basename for compatibility.
    parent_executable_path: str = ""
    parent_command_line: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    #: Source-minted process identity. `process_guid` is globally unique on
    #: its own; `process_iid` is unique WITHIN its endpoint.
    process_guid: str = ""
    parent_process_guid: str = ""
    process_iid: str = ""
    start_time: str = ""
    attribution_state: str = "NOT_OBSERVED"
    attribution_reason: str = ""
    field_provenance: Dict[str, str] = field(default_factory=dict)


#: The three honest attribution states, in one place so no module invents
#: a fourth.
PROCESS_ATTRIBUTION_AUTHORITATIVE = "SOURCE_PROCESS_IDENTITY"
PROCESS_ATTRIBUTION_PID_ONLY = "PID_ONLY_NOT_AUTHORITATIVE"
PROCESS_ATTRIBUTION_NOT_OBSERVED = "NOT_OBSERVED"


@dataclass
class NetworkEntity:
    """N1 · OBSERVED network and DNS activity.

    Every field below exists because an authoritative source states it. A
    field a source did not state stays at its empty default and is simply
    absent from `field_provenance` — the two are never confused, and no
    value is derived to make a detection convenient.

    `field_provenance` maps a canonical field name to the EXACT wire field
    that produced it (`"dns_response_ips": "zeek:dns.log answers"`), so a
    rule that cites a network field can always be traced to the source's
    own vocabulary.
    """
    src_ip: str = ""
    src_port: Optional[int] = None
    dest_ip: str = ""
    dest_port: Optional[int] = None
    protocol: str = ""
    direction: str = ""  # inbound, outbound, internal — only when STATED
    dns_query: str = ""
    #: N1 · DNS answer side. `dns_response_ips` is the join that makes
    #: domain → contacted address provable; before N1 it had nowhere to live,
    #: so Sysmon's QueryResults was parsed and then discarded.
    dns_query_type: str = ""
    dns_rcode: str = ""
    dns_response_ips: List[str] = field(default_factory=list)
    dns_response_records: List[str] = field(default_factory=list)
    dns_response_ttls: List[float] = field(default_factory=list)
    dns_authoritative: Optional[bool] = None
    dns_rejected: Optional[bool] = None
    dns_transaction_id: Optional[int] = None
    #: N1 · flow volume and outcome, as the observing sensor measured them.
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    packets_sent: Optional[int] = None
    packets_received: Optional[int] = None
    duration_ms: Optional[float] = None
    conn_state: str = ""
    conn_history: str = ""
    #: N1 · cross-source join keys. `flow_id` is the sensor's own identifier
    #: for this flow; `community_id` is the vendor-neutral flow hash, and it
    #: is recorded ONLY when the source actually emitted one.
    flow_id: str = ""
    community_id: str = ""
    #: N1 · WHICH network device observed this. Kept out of `host` on
    #: purpose: the sensor that saw a flow is not the endpoint that made it.
    sensor_device_id: str = ""
    sensor_device_name: str = ""
    field_provenance: Dict[str, str] = field(default_factory=dict)


@dataclass
class FileEntity:
    path: str = ""
    name: str = ""
    action: str = ""  # create, read, write, delete, rename
    target_path: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    size_bytes: Optional[int] = None
    #: W1 · maps a canonical file field to the EXACT wire field that
    #: produced it, so file evidence is as traceable as network evidence.
    field_provenance: Dict[str, str] = field(default_factory=dict)


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
