"""Contract 2 · the Telemetry Schema — canonical NivXForge endpoint evidence.

Directive §6: this is OUR model. No vendor's internal data model is
reproduced. Cisco, CrowdStrike, Microsoft, SentinelOne and Cortex are
capability benchmarks; their telemetry is TRANSLATED into this shape.

Not every platform populates every sub-model, and that is fine. What is
not fine is ambiguity — `EvidenceModel` makes a null evidence field
impossible unless its epistemic state says why.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field

from .epistemic import (EvidenceModel, Provenance, TelemetryHealth,
                        evidence_field)
from .identity import (FileIdentity, NetworkIdentity, ProcessIdentity,
                       RegistryIdentity)


class Platform(str, Enum):
    WINDOWS = "WINDOWS"
    MACOS = "MACOS"
    LINUX = "LINUX"
    UNKNOWN = "UNKNOWN"


class ActivityType(str, Enum):
    """The endpoint activity dimensions NivXForge collects. Directive §11
    extends the Cisco 43-item baseline with these; it does not replace it."""
    PROCESS = "PROCESS"
    FILE = "FILE"
    NETWORK = "NETWORK"
    DNS = "DNS"
    REGISTRY = "REGISTRY"
    SERVICE = "SERVICE"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    PERSISTENCE = "PERSISTENCE"
    IDENTITY = "IDENTITY"
    USB = "USB"
    DRIVER = "DRIVER"
    MODULE = "MODULE"
    MEMORY = "MEMORY"
    CONTAINER = "CONTAINER"
    BROWSER = "BROWSER"
    CLOUD = "CLOUD"
    SENSOR = "SENSOR"
    RESPONSE = "RESPONSE"
    DETECTION = "DETECTION"
    SYSTEM = "SYSTEM"


class UserSession(EvidenceModel):
    user: Optional[str] = evidence_field()
    domain: Optional[str] = evidence_field()
    session_id: Optional[str] = evidence_field()
    logon_type: Optional[str] = evidence_field()
    logon_time: Optional[str] = evidence_field()
    is_remote: Optional[bool] = evidence_field()
    privileges: list[str] = Field(default_factory=list)


class PersistenceArtifact(EvidenceModel):
    mechanism: Optional[str] = evidence_field(
        description="RUN_KEY | SERVICE | SCHEDULED_TASK | CRON | "
                    "LAUNCH_AGENT | STARTUP_FOLDER | SYSTEM_EXTENSION | "
                    "DRIVER | WMI_SUBSCRIPTION")
    target: Optional[str] = evidence_field()
    owner: Optional[str] = evidence_field()
    operation: Optional[str] = evidence_field()


class UsbDevice(EvidenceModel):
    device_id: Optional[str] = evidence_field()
    vendor: Optional[str] = evidence_field()
    product: Optional[str] = evidence_field()
    serial: Optional[str] = evidence_field()
    mount_point: Optional[str] = evidence_field()


class ServiceArtifact(EvidenceModel):
    name: Optional[str] = evidence_field()
    display_name: Optional[str] = evidence_field()
    binary_path: Optional[str] = evidence_field()
    start_type: Optional[str] = evidence_field()
    state: Optional[str] = evidence_field()
    operation: Optional[str] = evidence_field()


class ScheduledTaskArtifact(EvidenceModel):
    name: Optional[str] = evidence_field()
    action: Optional[str] = evidence_field()
    trigger: Optional[str] = evidence_field()
    principal: Optional[str] = evidence_field()
    operation: Optional[str] = evidence_field()


class EndpointEvidence(EvidenceModel):
    """The canonical endpoint evidence record.

    This is the ONLY shape the detection fabric, the reasoning fabric and
    the analyst console are permitted to consume. A vendor adapter's job is
    finished when it has produced one of these; it never reaches further
    into the platform.
    """
    # ── record identity ──
    tenant_id: str
    event_id: str
    dedup_key: str
    ingest_time: str

    # ── endpoint binding ──
    endpoint_id: Optional[str] = evidence_field()
    device_iid: Optional[str] = evidence_field()
    hostname: Optional[str] = evidence_field()
    platform: Platform = Platform.UNKNOWN
    sensor_version: Optional[str] = evidence_field()

    # ── when ──
    event_time: Optional[str] = evidence_field()

    # ── what ──
    event_type: str
    activity_type: Optional[ActivityType] = evidence_field()

    # ── the activity sub-models ──
    process: Optional[ProcessIdentity] = evidence_field()
    parent_process: Optional[ProcessIdentity] = evidence_field()
    file: Optional[FileIdentity] = evidence_field()
    network: Optional[NetworkIdentity] = evidence_field()
    registry: Optional[RegistryIdentity] = evidence_field()
    user_session: Optional[UserSession] = evidence_field()
    persistence: Optional[PersistenceArtifact] = evidence_field()
    usb_device: Optional[UsbDevice] = evidence_field()
    service: Optional[ServiceArtifact] = evidence_field()
    scheduled_task: Optional[ScheduledTaskArtifact] = evidence_field()

    # ── intelligence references (never inline conclusions) ──
    detection_refs: list[str] = Field(default_factory=list)
    ioc_refs: list[str] = Field(default_factory=list)
    mitre_refs: list[str] = Field(default_factory=list)

    # ── quality, provenance, honesty ──
    provenance: Provenance
    parser_state: str = Field(
        default="OK",
        description="OK | PARTIAL | FAILED. FAILED still yields a record — "
                    "an event that failed to parse DID occur.")
    parser_notes: list[str] = Field(default_factory=list)
    telemetry_quality: TelemetryHealth = TelemetryHealth.HEALTHY
    confidence: Optional[float] = evidence_field()
    raw_ref: Optional[str] = evidence_field(
        description="raw_id of the immutable original. Directive §5.")

    def observed_activities(self) -> tuple[str, ...]:
        """Which activity dimensions this record actually carries. Used by
        the console so an empty lane can be labelled 'no telemetry' rather
        than silently rendering nothing."""
        return tuple(
            name for name in ("process", "parent_process", "file", "network",
                              "registry", "user_session", "persistence",
                              "usb_device", "service", "scheduled_task")
            if self.is_observed(name))
