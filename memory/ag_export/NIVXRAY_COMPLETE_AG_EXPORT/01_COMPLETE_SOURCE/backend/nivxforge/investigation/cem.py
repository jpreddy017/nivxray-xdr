"""Canonical Event Model v1 (CEMv1).

Every vendor input normalises into CEMv1. Downstream investigation
stages consume ONLY CEMv1 — never vendor JSON, never raw payloads.

Versioned + immutable: additive fields require CEMv2 + a migration.
Existing CIOs must remain readable across schema versions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


CEM_VERSION = "v1"


# ─── Enumerations ────────────────────────────────────────────────────

class EventKind(str, Enum):
    process_create = "process_create"
    process_terminate = "process_terminate"
    file_create = "file_create"
    file_modify = "file_modify"
    file_delete = "file_delete"
    registry_write = "registry_write"
    registry_delete = "registry_delete"
    network_connect = "network_connect"
    dns_query = "dns_query"
    auth_success = "auth_success"
    auth_failure = "auth_failure"
    service_install = "service_install"
    task_scheduled = "task_scheduled"
    alert = "alert"
    detection = "detection"
    generic = "generic"


class SeverityLevel(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ContainmentState(str, Enum):
    none = "none"
    quarantined = "quarantined"
    blocked = "blocked"
    isolated = "isolated"
    remediated = "remediated"
    prevented = "prevented"


# ─── Provenance (Contract #4) ────────────────────────────────────────

class Provenance(BaseModel):
    """Every CEM entity carries provenance so citations remain
    traceable end-to-end (Contract #4)."""
    model_config = ConfigDict(frozen=True)

    source: str                             # stage / vendor adapter id
    vendor: Optional[str] = None
    timestamp: Optional[datetime] = None
    confidence: float = 1.0
    evidence_refs: List[str] = Field(default_factory=list)
    input_offset: Optional[List[int]] = None  # [start, end] byte offsets


# ─── Entity fragments ────────────────────────────────────────────────

class Host(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: Optional[str] = None
    name: Optional[str] = None
    fqdn: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None
    provenance: Provenance


class User(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: Optional[str] = None
    name: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None
    provenance: Provenance


class Process(BaseModel):
    model_config = ConfigDict(frozen=True)
    pid: Optional[int] = None
    ppid: Optional[int] = None
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_command_line: Optional[str] = None
    hash_sha256: Optional[str] = None
    integrity_level: Optional[str] = None
    signed: Optional[bool] = None
    provenance: Provenance


class FileEntity(BaseModel):
    model_config = ConfigDict(frozen=True)
    path: Optional[str] = None
    name: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None
    size: Optional[int] = None
    provenance: Provenance


class Registry(BaseModel):
    model_config = ConfigDict(frozen=True)
    hive: Optional[str] = None
    key: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    provenance: Provenance


class Network(BaseModel):
    model_config = ConfigDict(frozen=True)
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None  # inbound / outbound
    url: Optional[str] = None
    domain: Optional[str] = None
    provenance: Provenance


class Dns(BaseModel):
    model_config = ConfigDict(frozen=True)
    query: str
    query_type: Optional[str] = None
    response: Optional[str] = None
    provenance: Provenance


class Detection(BaseModel):
    """Vendor-emitted detection — the anchor for family recognition."""
    model_config = ConfigDict(frozen=True)
    id: Optional[str] = None
    name: str
    severity: SeverityLevel = SeverityLevel.informational
    category: Optional[str] = None
    rule_id: Optional[str] = None
    threat_name: Optional[str] = None
    threat_family: Optional[str] = None
    provenance: Provenance


# ─── Event ───────────────────────────────────────────────────────────

class CanonicalEvent(BaseModel):
    """A single normalised event. Every vendor row / alert / process
    telemetry line becomes one CanonicalEvent."""
    model_config = ConfigDict(frozen=True)

    event_id: str
    kind: EventKind
    timestamp: Optional[datetime] = None
    host: Optional[Host] = None
    user: Optional[User] = None
    process: Optional[Process] = None
    parent_process: Optional[Process] = None
    file: Optional[FileEntity] = None
    registry: Optional[Registry] = None
    network: Optional[Network] = None
    dns: Optional[Dns] = None
    detection: Optional[Detection] = None
    containment: ContainmentState = ContainmentState.none
    raw: Dict[str, Any] = Field(default_factory=dict,
                                  description="vendor-native fields, retained for evidence traceback only")
    provenance: Provenance


# ─── Incident envelope ───────────────────────────────────────────────

class Incident(BaseModel):
    """Vendor-emitted incident/alert envelope carrying one or more
    CanonicalEvents plus vendor-level context (incident id, first-seen,
    action, etc.)."""
    model_config = ConfigDict(frozen=True)

    incident_id: Optional[str] = None
    title: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.informational
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    containment: ContainmentState = ContainmentState.none
    provenance: Provenance


# ─── Root aggregate ──────────────────────────────────────────────────

class CanonicalEventModel(BaseModel):
    """CEMv1 root. Every downstream stage in the investigation
    pipeline consumes ONLY this object."""
    model_config = ConfigDict(frozen=True)

    version: str = CEM_VERSION
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    vendor: Optional[str] = None
    vendor_route: Optional[str] = None      # adapter id, e.g. "cisco_secure_endpoint"
    incidents: List[Incident] = Field(default_factory=list)
    events: List[CanonicalEvent] = Field(default_factory=list)
    provenance: Provenance


# ─── Adapter contract ────────────────────────────────────────────────

class VendorAdapter:
    """Abstract contract. Every vendor normaliser implements this and
    emits CEMv1. Downstream stages are forbidden from touching vendor
    payloads directly."""
    vendor: str = ""
    adapter_id: str = ""

    def can_parse(self, raw_input: str) -> bool:  # noqa: D401
        raise NotImplementedError

    def parse(self, raw_input: str) -> CanonicalEventModel:
        raise NotImplementedError


__all__ = [
    "CEM_VERSION",
    "EventKind",
    "SeverityLevel",
    "ContainmentState",
    "Provenance",
    "Host", "User", "Process", "FileEntity", "Registry", "Network",
    "Dns", "Detection",
    "CanonicalEvent",
    "Incident",
    "CanonicalEventModel",
    "VendorAdapter",
]
