"""Wave 0 identity contracts.

Directive §3 rule that shapes all of these: **Endpoint Identity ≠
Authentication Mechanism ≠ Transport ≠ Telemetry Envelope.** None of the
models here carry a credential, a token, a transport detail or a wire
format. P0-A.2 enrolment will be the first CONSUMER of EndpointIdentity;
it is deliberately not its author, so mTLS can replace bearer auth later
without touching a single field below.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import Field

from .epistemic import EvidenceModel, Provenance, evidence_field


def _iid(prefix: str, *parts: object) -> str:
    """Deterministic identity. The same facts always yield the same iid, so
    a replay cannot mint a second identity for one real thing."""
    digest = hashlib.sha256(
        "\x1f".join("" if p is None else str(p) for p in parts).encode()
    ).hexdigest()
    return f"{prefix}_{digest[:20]}"


class EnrollmentState(str, Enum):
    """Lifecycle of the endpoint's RELATIONSHIP to the platform — not of
    its agent process (that is AgentLifecycle) and not of its evidence
    (that is TelemetryHealth)."""
    NEVER_ENROLLED = "NEVER_ENROLLED"
    ENROLLMENT_PENDING = "ENROLLMENT_PENDING"
    ENROLLED = "ENROLLED"
    REVOKED = "REVOKED"
    RETIRED = "RETIRED"


class IdentityConfidence(str, Enum):
    AUTHORITATIVE = "AUTHORITATIVE"   # a durable machine identity is bound
    INFERRED = "INFERRED"             # observation-derived only (e.g. hostname)
    UNATTRIBUTED = "UNATTRIBUTED"     # not a device; the observation is loose


# ── 1 · Endpoint Identity ─────────────────────────────────────────

class EndpointIdentity(EvidenceModel):
    """Contract 1. The durable identity of a protected device.

    `endpoint_id` is minted by the platform and is stable across hostname
    changes, IP changes, re-imaging and agent reinstall. `device_iid` is
    the existing NivXRay authoritative device identity and is REUSED, not
    replaced.

    An IP address is NEVER an endpoint identity (a rule already enforced by
    the P1.10a spread plane and preserved here).
    """
    endpoint_id: str
    tenant_id: str
    device_iid: Optional[str] = evidence_field()
    agent_id: Optional[str] = evidence_field()

    hostname: Optional[str] = evidence_field()
    fqdn: Optional[str] = evidence_field()
    platform: Optional[str] = evidence_field()
    os_name: Optional[str] = evidence_field()
    os_version: Optional[str] = evidence_field()
    architecture: Optional[str] = evidence_field()
    processor_id: Optional[str] = evidence_field(
        description="Hardware identity. Survives re-imaging; a hostname "
                    "does not.")
    machine_guid: Optional[str] = evidence_field()

    local_ips: list[str] = Field(default_factory=list)
    public_ip: Optional[str] = evidence_field()
    dns_servers: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)

    sensor_version: Optional[str] = evidence_field()
    sensor_install_date: Optional[str] = evidence_field()

    group: Optional[str] = evidence_field()
    policy_id: Optional[str] = evidence_field()

    enrollment_state: EnrollmentState = EnrollmentState.NEVER_ENROLLED
    identity_confidence: IdentityConfidence = IdentityConfidence.UNATTRIBUTED

    first_seen: Optional[str] = evidence_field()
    last_seen: Optional[str] = evidence_field()
    observation_count: int = 0

    provenance: Optional[Provenance] = None

    @staticmethod
    def mint(*, tenant_id: str, processor_id: str | None = None,
             machine_guid: str | None = None,
             device_iid: str | None = None,
             hostname: str | None = None) -> str:
        """Durable-identity precedence: hardware > machine guid > existing
        device_iid > hostname. Hostname is last because it is the only one
        an attacker can trivially change."""
        for kind, val in (("hw", processor_id), ("guid", machine_guid),
                          ("iid", device_iid), ("host", hostname)):
            if val:
                return _iid("ep", tenant_id, kind, val)
        raise ValueError(
            "cannot mint an endpoint_id with no durable attribute — "
            "an unattributed observation is not an endpoint")


# ── 3 · Process Identity ──────────────────────────────────────────

class ProcessIdentity(EvidenceModel):
    """Contract 3.

    `process_iid` binds (endpoint, pid, start_time) because a PID alone is
    reused by the OS within minutes. Without start_time in the identity,
    two unrelated processes collapse into one lifeline — which is how a
    fabricated process tree gets built by accident.
    """
    process_iid: str
    endpoint_id: str

    pid: Optional[int] = evidence_field()
    ppid: Optional[int] = evidence_field()
    image: Optional[str] = evidence_field(description="basename, e.g. cmd.exe")
    image_path: Optional[str] = evidence_field()
    sha256: Optional[str] = evidence_field()
    sha1: Optional[str] = evidence_field()
    md5: Optional[str] = evidence_field()
    command_line: Optional[str] = evidence_field()
    user: Optional[str] = evidence_field()
    integrity: Optional[str] = evidence_field()
    signer: Optional[str] = evidence_field()
    signature_status: Optional[str] = evidence_field()
    start_time: Optional[str] = evidence_field()
    exit_time: Optional[str] = evidence_field()
    session_id: Optional[str] = evidence_field()

    #: Directive §8 · lineage is EVIDENCE-BASED. `parent_iid` is populated
    #: only when the parent was actually observed. `lineage_state` says
    #: which of the three honest cases applies; a ghost root is a real
    #: answer, an invented explorer.exe is not.
    parent_iid: Optional[str] = evidence_field()
    lineage_state: str = Field(
        default="PARENT_NOT_OBSERVED",
        description="PARENT_OBSERVED | PARENT_NOT_OBSERVED | "
                    "PARENT_LINEAGE_INCOMPLETE_PARSER_FAILED")

    provenance: Optional[Provenance] = None

    @staticmethod
    def mint(*, endpoint_id: str, pid: int | None,
             start_time: str | None) -> str:
        if pid is None:
            raise ValueError(
                "cannot mint a process_iid without a PID — a process with "
                "no PID evidence is not a process lifeline")
        return _iid("proc", endpoint_id, pid, start_time or "NO_START_TIME")


LINEAGE_STATES = ("PARENT_OBSERVED", "PARENT_NOT_OBSERVED",
                  "PARENT_LINEAGE_INCOMPLETE_PARSER_FAILED")

#: What the process tree must render for each lineage state (directive §8).
LINEAGE_PRESENTATION = {
    "PARENT_OBSERVED": "verified relationship",
    "PARENT_NOT_OBSERVED": "[ROOT / PARENT NOT OBSERVED]",
    "PARENT_LINEAGE_INCOMPLETE_PARSER_FAILED":
        "[LINEAGE INCOMPLETE — PARSER FAILED]",
}


# ── 4 · File Identity ─────────────────────────────────────────────

class FileOperation(str, Enum):
    CREATE = "CREATE"
    MODIFY = "MODIFY"
    MOVE = "MOVE"
    COPY = "COPY"
    EXECUTE = "EXECUTE"
    DELETE = "DELETE"
    RESTORE = "RESTORE"
    RENAME = "RENAME"
    OPEN = "OPEN"


class FileIdentity(EvidenceModel):
    """Contract 4. Content identity is the SHA-256; path identity is not
    identity at all, because one file appears under many names.

    `content_digest_available` is explicit because the current substrate
    honestly cannot hash file content (see the truth audit): a SHA-256
    query today degrades to a name query, and the API says so rather than
    pretending to match on hash.
    """
    file_iid: str
    sha256: Optional[str] = evidence_field()
    sha1: Optional[str] = evidence_field()
    md5: Optional[str] = evidence_field()
    path: Optional[str] = evidence_field()
    filename: Optional[str] = evidence_field()
    extension: Optional[str] = evidence_field()
    size: Optional[int] = evidence_field()
    file_type: Optional[str] = evidence_field()
    signer: Optional[str] = evidence_field()
    operation: Optional[FileOperation] = evidence_field()
    disposition: Optional[str] = evidence_field(
        description="CLEAN | MALICIOUS | UNKNOWN | UNAVAILABLE — never "
                    "defaulted to CLEAN")
    prevalence: Optional[int] = evidence_field()
    content_digest_available: bool = False

    provenance: Optional[Provenance] = None

    @staticmethod
    def mint(*, sha256: str | None = None, path: str | None = None,
             filename: str | None = None) -> str:
        if sha256:
            return _iid("file", "sha256", sha256.lower())
        if path or filename:
            # Explicitly a WEAKER identity. Callers must keep
            # content_digest_available False so nothing claims a hash match.
            return _iid("filename", "name", (filename or path or "").lower())
        raise ValueError("cannot mint a file identity with no hash and no name")


# ── 5 · Network Identity ──────────────────────────────────────────

class NetworkDirection(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    LISTEN = "LISTEN"
    UNKNOWN = "UNKNOWN"


class NetworkIdentity(EvidenceModel):
    """Contract 5.

    A remote IP is a network peer. It is NEVER an endpoint and it is NEVER
    a process — the two fabrications this codebase has already had to fix
    once.
    """
    connection_iid: str
    endpoint_id: str
    process_iid: Optional[str] = evidence_field()

    direction: NetworkDirection = NetworkDirection.UNKNOWN
    protocol: Optional[str] = evidence_field()
    local_ip: Optional[str] = evidence_field()
    local_port: Optional[int] = evidence_field()
    remote_ip: Optional[str] = evidence_field()
    remote_port: Optional[int] = evidence_field()
    domain: Optional[str] = evidence_field()
    url: Optional[str] = evidence_field()
    dns_query: Optional[str] = evidence_field()
    dns_answers: list[str] = Field(default_factory=list)
    bytes_sent: Optional[int] = evidence_field()
    bytes_received: Optional[int] = evidence_field()

    provenance: Optional[Provenance] = None

    @staticmethod
    def mint(*, endpoint_id: str, local_ip: str | None,
             local_port: int | None, remote_ip: str | None,
             remote_port: int | None, protocol: str | None,
             event_time: str | None) -> str:
        return _iid("conn", endpoint_id, protocol, local_ip, local_port,
                    remote_ip, remote_port, event_time)


class RegistryIdentity(EvidenceModel):
    """Windows registry operation identity. Windows-only by nature: on
    Linux and macOS every field is NOT_SUPPORTED, never NOT_OBSERVED."""
    registry_iid: str
    endpoint_id: str
    process_iid: Optional[str] = evidence_field()
    hive: Optional[str] = evidence_field()
    key: Optional[str] = evidence_field()
    value_name: Optional[str] = evidence_field()
    value_data: Optional[str] = evidence_field()
    operation: Optional[str] = evidence_field()

    provenance: Optional[Provenance] = None


# ── 6 · Event Identity ────────────────────────────────────────────

class EventIdentity(EvidenceModel):
    """Contract 6. Identity of one telemetry OCCURRENCE.

    `dedup_key` is the verbatim digest of the raw payload, so a replayed
    or re-delivered event can never be counted twice (the idempotency rule
    proven in P1.10a). `event_time` is when it happened on the endpoint;
    `ingest_time` is when we learned about it. Late telemetry is a normal
    condition, not an error, so both are mandatory and separate.
    """
    event_id: str
    tenant_id: str
    endpoint_id: Optional[str] = evidence_field()
    event_time: Optional[str] = evidence_field()
    ingest_time: str
    event_type: str
    activity_type: Optional[str] = evidence_field()
    dedup_key: str
    raw_ref: Optional[str] = evidence_field(
        description="raw_id of the immutable original in edr_raw_events")

    provenance: Optional[Provenance] = None

    @staticmethod
    def mint(*, tenant_id: str, dedup_key: str) -> str:
        return _iid("evt", tenant_id, dedup_key)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()


# ── 7 · Evidence Identity ─────────────────────────────────────────

class EvidenceIdentity(EvidenceModel):
    """Contract 7. Identity of a DERIVED assertion built from events.

    Separate from EventIdentity on purpose: one event can produce several
    assertions, and an assertion can be re-derived at a new
    `replay_generation` when a parser or detection improves. Keeping them
    apart is what makes directive §5 replay possible without rewriting
    history.
    """
    evidence_id: str
    tenant_id: str
    endpoint_id: Optional[str] = evidence_field()
    event_ids: list[str] = Field(default_factory=list)
    claim: str = Field(
        description="The assertion in plain language. Must state what was "
                    "observed, never a conclusion the evidence cannot carry.")
    evidence_sufficiency: str = "UNKNOWN"
    confidence: Optional[float] = evidence_field()
    detection_refs: list[str] = Field(default_factory=list)
    ioc_refs: list[str] = Field(default_factory=list)
    mitre_refs: list[str] = Field(default_factory=list)

    provenance: Optional[Provenance] = None

    @staticmethod
    def mint(*, tenant_id: str, claim: str, event_ids: list[str],
             replay_generation: int = 0) -> str:
        return _iid("ev", tenant_id, claim, "|".join(sorted(event_ids)),
                    replay_generation)
