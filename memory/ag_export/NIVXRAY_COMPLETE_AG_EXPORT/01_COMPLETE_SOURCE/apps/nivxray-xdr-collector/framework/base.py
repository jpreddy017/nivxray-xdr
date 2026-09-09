"""
Connector framework · base classes and canonical envelope.

Every connector — REST poller / syslog receiver / webhook receiver /
Windows adapter / vendor SDK adapter — inherits from `Connector`.
The framework never assumes any specific vendor semantics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime   import datetime, timezone
from enum       import Enum
from typing     import Any, Dict, List, Optional
import uuid


# ── Health enum ────────────────────────────────────────────────────
class Health(str, Enum):
    NEVER_CONNECTED       = "never_connected"
    CONNECTED             = "connected"
    DEGRADED              = "degraded"
    DISCONNECTED          = "disconnected"
    AUTHENTICATION_FAILED = "authentication_failed"
    RATE_LIMITED          = "rate_limited"
    ERROR                 = "error"


# ── Capability enum · a source EITHER supports this OR doesn't ─────
class Capability(str, Enum):
    DETECTIONS      = "detections"
    DEVICES         = "devices"
    PROCESSES       = "processes"
    NETWORK_EVENTS  = "network_events"
    FILE_EVENTS     = "file_events"
    USERS           = "users"
    VULNERABILITIES = "vulnerabilities"
    RESPONSE        = "response_actions"


# ── Canonical envelope · what leaves the collector plane ───────────
# Never destroy vendor-specific fields; keep raw payload + full
# provenance so the authoritative NivXRay backend can decide.
@dataclass
class Envelope:
    tenant_id:            str
    source:               str          # e.g. "crowdstrike-falcon"
    source_event_id:      Optional[str]
    connector_id:         str
    collector_id:         str
    collection_method:    str          # "rest-poll" | "syslog" | "webhook" | ...
    parser_version:       str
    source_timestamp:     Optional[str]
    collection_timestamp: str
    event_type:           str
    raw:                  Dict[str, Any]
    canonical:            Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id":            self.tenant_id,
            "source":               self.source,
            "source_event_id":      self.source_event_id,
            "connector_id":         self.connector_id,
            "collector_id":         self.collector_id,
            "collection_method":    self.collection_method,
            "parser_version":       self.parser_version,
            "source_timestamp":     self.source_timestamp,
            "collection_timestamp": self.collection_timestamp,
            "event_type":           self.event_type,
            "raw":                  self.raw,
            "canonical":            self.canonical,
        }


# ── Checkpoint · restart-safe, tenant + connector scoped ───────────
@dataclass
class Checkpoint:
    tenant_id:      str
    connector_id:   str
    cursor:         Optional[str] = None
    last_event_id:  Optional[str] = None
    last_timestamp: Optional[str] = None
    page_token:     Optional[str] = None
    vendor_state:   Dict[str, Any] = field(default_factory=dict)
    updated_at:     Optional[str] = None


# ── Metrics ────────────────────────────────────────────────────────
@dataclass
class ConnectorMetrics:
    last_success:            Optional[str] = None
    last_attempt:            Optional[str] = None
    events_collected:        int = 0
    events_accepted:         int = 0
    events_rejected:         int = 0
    events_duplicated:       int = 0
    events_failed:           int = 0
    api_latency_ms_p50:      Optional[float] = None
    api_latency_ms_p95:      Optional[float] = None
    collection_lag_seconds:  Optional[float] = None
    last_error:              Optional[str] = None


# ── Connector interface ────────────────────────────────────────────
class Connector:
    """Abstract connector.  Concrete adapters override `collect`."""

    #: unique across a tenant; assigned on registration
    identity: str
    #: e.g. "edr", "siem", "firewall", "identity"
    source_type: str
    #: human-friendly label
    label: str
    #: which Capabilities this source class supports (framework-level)
    capabilities: List[Capability] = []
    #: JSON schema for the vendor-specific configuration
    configuration_schema: Dict[str, Any] = {}
    #: what credential fields must be present (never stored plaintext)
    credential_requirements: List[str] = []

    def __init__(self, tenant_id: str, config: Dict[str, Any]):
        self.tenant_id = tenant_id
        self.config    = config
        self.identity  = f"{self.source_type}::{uuid.uuid4().hex[:8]}"
        self.health    = Health.NEVER_CONNECTED
        self.metrics   = ConnectorMetrics()
        self.checkpoint = Checkpoint(tenant_id=tenant_id, connector_id=self.identity)

    # ── lifecycle ── overridden by concrete connectors ────
    async def test_connection(self) -> Dict[str, Any]:
        return {"ok": False, "reason": "not_implemented",
                  "note": "Phase A framework · concrete adapters land in later phases."}

    async def start(self)  -> None: ...
    async def stop(self)   -> None: ...
    async def collect(self) -> List[Envelope]: return []

    # ── introspection ─────────────────────────────────────
    def describe(self) -> Dict[str, Any]:
        return {
            "identity":     self.identity,
            "source_type":  self.source_type,
            "label":        self.label,
            "tenant_id":    self.tenant_id,
            "health":       self.health.value,
            "capabilities": [c.value for c in self.capabilities],
            "metrics":      self.metrics.__dict__,
            "checkpoint":   {
                "cursor":         self.checkpoint.cursor,
                "last_event_id":  self.checkpoint.last_event_id,
                "last_timestamp": self.checkpoint.last_timestamp,
                "updated_at":     self.checkpoint.updated_at,
            },
        }
