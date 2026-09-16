"""Canonical Event Model · v1 · FROZEN schema.

Per GOVERNANCE.md §5–6:
  • Every entity carries provenance (source, adapter, versions,
    confidence, transformations, timestamps).
  • Entities, Events, and Relationships are stored separately.
  • Byte-identical output for identical input.

This file is IMMUTABLE once shipped. Bug fixes go into a v2 schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Final

VERSION: Final[str] = "v1"

# ─── Entity / event / relationship kind enums (locked) ───────────────
ENTITY_KINDS: Final[tuple[str, ...]] = (
    "device", "user", "identity", "session",
    "process", "command_line", "script", "thread", "memory", "kernel_event",
    "registry", "file", "directory", "hash", "certificate",
    "service", "driver", "scheduled_task", "wmi_subscription", "named_pipe",
    "network_conn", "dns_query", "http_transaction",
    "smb_session", "ssh_session", "rdp_session",
    "cloud_resource", "iam_action",
    "email", "attachment", "url", "domain", "ip_address", "port",
    "ioc", "mitre_technique", "malware_family", "threat_actor", "campaign",
    "detection", "alert", "incident", "behavior", "evidence",
)

EVENT_KINDS: Final[tuple[str, ...]] = (
    "process_create", "process_exit", "process_access",
    "image_load", "thread_create", "remote_thread_create",
    "memory_alloc", "memory_protect", "handle_open",
    "file_create", "file_write", "file_delete", "file_rename",
    "directory_create",
    "registry_create", "registry_value_set", "registry_delete",
    "network_connect", "network_listen",
    "dns_query", "http_request",
    "smb_share_access", "ssh_session_open", "rdp_session_open",
    "named_pipe_create",
    "service_install", "service_start", "driver_load",
    "scheduled_task_create", "wmi_subscribe",
    "kernel_event",
    "logon_success", "logon_failure", "token_manipulation",
    "privilege_escalation",
    "mail_delivery", "mail_read",
    "cloud_iam_action", "cloud_resource_change",
    "alert", "detection",
)

RELATIONSHIP_KINDS: Final[tuple[str, ...]] = (
    "executed", "spawned", "injected_into", "hollowed", "loaded",
    "downloaded", "uploaded",
    "created", "modified", "deleted", "renamed", "read", "written",
    "connected_to", "resolved", "queried",
    "authenticated_as", "assumed_role", "impersonated",
    "persisted_via", "escalated_via", "communicated_with",
    "sent_email_to", "received_email_from",
    "matched_ioc", "mapped_to_technique", "attributed_to",
)


# ─── Provenance (append-only per §5) ─────────────────────────────────
@dataclass(frozen=True)
class Provenance:
    origin: str                            # "customer-upload" | "api" | "adapter-stream"
    adapter: str                           # "sysmon@1.2.0"
    parser: str = "universal-parser@1.0.0"
    normalization: str = "cem@v1"
    correlation: tuple[str, ...] = ()
    evidence_source: tuple[str, ...] = ()  # evt_iid list
    confidence: float = 1.0
    transformations: tuple[dict[str, Any], ...] = ()
    observed_at: str | None = None         # ISO-8601 UTC
    ingested_at: str | None = None
    derived_at:  str | None = None
    engine_versions: dict[str, str] = field(default_factory=dict)


# ─── Entity ──────────────────────────────────────────────────────────
@dataclass
class Entity:
    iid: str                               # ULID with kind prefix, e.g. "proc_01H..."
    case_id: str
    kind: str                              # one of ENTITY_KINDS
    attrs: dict[str, Any] = field(default_factory=dict)
    first_seen: str | None = None          # ISO-8601 UTC
    last_seen:  str | None = None
    correlation_key: str | None = None
    provenance: Provenance | None = None

    def __post_init__(self) -> None:
        if self.kind not in ENTITY_KINDS:
            raise ValueError(f"Entity.kind {self.kind!r} not in ENTITY_KINDS")


# ─── Relationship ────────────────────────────────────────────────────
@dataclass
class Relationship:
    iid: str                               # "rel_01H..."
    case_id: str
    src_iid: str
    dst_iid: str
    kind: str                              # one of RELATIONSHIP_KINDS
    confidence: float                      # 0.0 – 1.0
    evidence_ids: tuple[str, ...] = ()
    created_at: str | None = None
    provenance: Provenance | None = None

    def __post_init__(self) -> None:
        if self.kind not in RELATIONSHIP_KINDS:
            raise ValueError(f"Relationship.kind {self.kind!r} not in RELATIONSHIP_KINDS")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Relationship.confidence {self.confidence} out of [0,1]")


# ─── Canonical Event ─────────────────────────────────────────────────
@dataclass
class CanonicalEvent:
    iid: str                               # "evt_01H..."
    case_id: str
    adapter: str                           # adapter name
    adapter_version: str
    ts: str                                # ISO-8601 UTC
    sequence: int                          # adapter-local monotonic
    kind: str                              # one of EVENT_KINDS
    device_iid: str | None = None
    actor_iid: str | None = None
    session_iid: str | None = None
    process_iid: str | None = None
    artefacts_iids: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)
    trust: dict[str, Any] = field(default_factory=dict)
    provenance: Provenance | None = None

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"CanonicalEvent.kind {self.kind!r} not in EVENT_KINDS")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Serialise tuples as lists for JSON friendliness.
        for k, v in list(d.items()):
            if isinstance(v, tuple):
                d[k] = list(v)
        return d


def now_utc() -> str:
    """Deterministic ISO-8601 UTC timestamp helper."""
    return datetime.now(timezone.utc).isoformat()
