"""Streaming data models and contracts for NivXRay Phase 4C Streaming Adapter."""
from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..contracts import canonical_json, sha256_digest


class WatermarkArrivalStatus(str, Enum):
    IN_ORDER = "IN_ORDER"
    OUT_OF_ORDER = "OUT_OF_ORDER"
    LATE = "LATE"
    CLOCK_SKEW_FUTURE = "CLOCK_SKEW_FUTURE"
    CLOCK_SKEW_PAST = "CLOCK_SKEW_PAST"


class LateEventReconciliationMode(str, Enum):
    RECONCILE_INCREMENTAL = "RECONCILE_INCREMENTAL"
    REJECT = "REJECT"
    DLQ = "DLQ"


class DLQFailureClass(str, Enum):
    AUTH_TENANT_MISMATCH = "AUTH_TENANT_MISMATCH"
    SCHEMA_VALIDATION_ERROR = "SCHEMA_VALIDATION_ERROR"
    PAYLOAD_INTEGRITY_VIOLATION = "PAYLOAD_INTEGRITY_VIOLATION"
    MALFORMED_TIMESTAMP = "MALFORMED_TIMESTAMP"
    NORMALIZATION_ERROR = "NORMALIZATION_ERROR"
    PERSISTENCE_ERROR = "PERSISTENCE_ERROR"
    QUEUE_OVERFLOW = "QUEUE_OVERFLOW"


@dataclass(frozen=True)
class WatermarkPolicy:
    """Configurable policy for watermark tracking and out-of-order bounds."""
    watermark_delay_seconds: float = 10.0
    allowed_clock_skew_seconds: float = 60.0
    late_event_reconciliation_mode: LateEventReconciliationMode = LateEventReconciliationMode.RECONCILE_INCREMENTAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "watermark_delay_seconds": self.watermark_delay_seconds,
            "allowed_clock_skew_seconds": self.allowed_clock_skew_seconds,
            "late_event_reconciliation_mode": self.late_event_reconciliation_mode.value,
        }


@dataclass(frozen=True)
class CoalescePolicy:
    """Configurable policy for sliding window event coalescing and immediate bypass."""
    coalesce_window_ms: float = 2000.0
    coalesce_max_events: int = 50
    # Milestone bypass triggers: can be ATT&CK technique IDs, canonical action types, or capability keywords
    bypass_action_prefixes: Tuple[str, ...] = (
        "credential.", "privilege.", "defense_evasion.", "execution.", "lateral."
    )
    bypass_techniques: Tuple[str, ...] = (
        "T1003", "T1059", "T1078", "T1021", "T1490", "T1562", "T1055"
    )
    bypass_capabilities: Tuple[str, ...] = (
        "CAP_CREDENTIAL_ACCESS", "CAP_PRIVILEGE_ESCALATION", "CAP_PERSISTENCE",
        "CAP_LATERAL_MOVEMENT", "CAP_RANSOMWARE_ENCRYPTION", "CAP_DEFENSE_EVASION"
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "coalesce_window_ms": self.coalesce_window_ms,
            "coalesce_max_events": self.coalesce_max_events,
            "bypass_action_prefixes": list(self.bypass_action_prefixes),
            "bypass_techniques": list(self.bypass_techniques),
            "bypass_capabilities": list(self.bypass_capabilities),
        }


@dataclass(frozen=True)
class StreamingEventEnvelope:
    """Authoritative transport-neutral envelope for live/replay streaming evidence."""
    source_id: str                      # e.g., "stream-edr-agent-01", "replay-source"
    authenticated_tenant_id: str        # Cryptographically authenticated tenant ID (mTLS/JWT context)
    event_id: str                       # Native event UUID or empty if Tier B
    event_timestamp: str                # ISO-8601 UTC event generation timestamp
    ingest_timestamp: str               # ISO-8601 UTC adapter ingestion timestamp
    schema_version: str = "1.0.0"       # Envelope schema version
    payload_signature: str = ""         # HMAC / SHA-256 integrity hash of payload
    provenance: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)

    def validate_envelope(self) -> Tuple[bool, Optional[str], Optional[DLQFailureClass]]:
        """Validate envelope integrity, schema, and strict tenant derivation."""
        if not self.source_id:
            return False, "Missing source_id in streaming envelope", DLQFailureClass.SCHEMA_VALIDATION_ERROR
        if not self.authenticated_tenant_id:
            return False, "Missing authenticated_tenant_id in streaming envelope", DLQFailureClass.AUTH_TENANT_MISMATCH
        if not self.event_timestamp:
            return False, "Missing event_timestamp in streaming envelope", DLQFailureClass.MALFORMED_TIMESTAMP

        # Strict Tenant Boundary: If payload contains tenant_id, it MUST match authenticated tenant!
        payload_tenant = self.payload.get("tenant_id")
        if payload_tenant is not None and str(payload_tenant) != self.authenticated_tenant_id:
            return False, (
                f"ERR_STREAM_TENANT_MISMATCH: Payload tenant '{payload_tenant}' does not match "
                f"authenticated stream context tenant '{self.authenticated_tenant_id}'"
            ), DLQFailureClass.AUTH_TENANT_MISMATCH

        # Check payload signature integrity if provided
        if self.payload_signature:
            computed_sig = sha256_digest(canonical_json(self.payload))
            if self.payload_signature != computed_sig:
                return False, "Payload signature mismatch (integrity violation)", DLQFailureClass.PAYLOAD_INTEGRITY_VIOLATION

        # Validate timestamp formats
        try:
            datetime.fromisoformat(self.event_timestamp.replace("Z", "+00:00"))
        except Exception:
            return False, f"Invalid event_timestamp format: '{self.event_timestamp}'", DLQFailureClass.MALFORMED_TIMESTAMP

        return True, None, None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "authenticated_tenant_id": self.authenticated_tenant_id,
            "event_id": self.event_id,
            "event_timestamp": self.event_timestamp,
            "ingest_timestamp": self.ingest_timestamp,
            "schema_version": self.schema_version,
            "payload_signature": self.payload_signature,
            "provenance": self.provenance,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> StreamingEventEnvelope:
        return cls(
            source_id=str(d.get("source_id", "")),
            authenticated_tenant_id=str(d.get("authenticated_tenant_id", "")),
            event_id=str(d.get("event_id", "")),
            event_timestamp=str(d.get("event_timestamp", "")),
            ingest_timestamp=str(d.get("ingest_timestamp", "")),
            schema_version=str(d.get("schema_version", "1.0.0")),
            payload_signature=str(d.get("payload_signature", "")),
            provenance=dict(d.get("provenance", {})),
            payload=dict(d.get("payload", {})),
        )


@dataclass(frozen=True)
class DLQRecord:
    """Immutable dead-letter record for unroutable or rejected streaming telemetry."""
    dlq_id: str
    source_id: str
    event_id: str
    tenant_id: str
    failure_class: str
    reason: str
    timestamp: str
    schema_version: str
    provenance: Dict[str, Any]
    raw_envelope: Dict[str, Any]
    replayed: bool = False
    replayed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dlq_id": self.dlq_id,
            "source_id": self.source_id,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "failure_class": self.failure_class,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "schema_version": self.schema_version,
            "provenance": self.provenance,
            "raw_envelope": self.raw_envelope,
            "replayed": self.replayed,
            "replayed_at": self.replayed_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> DLQRecord:
        return cls(
            dlq_id=str(d.get("dlq_id", "")),
            source_id=str(d.get("source_id", "")),
            event_id=str(d.get("event_id", "")),
            tenant_id=str(d.get("tenant_id", "")),
            failure_class=str(d.get("failure_class", "")),
            reason=str(d.get("reason", "")),
            timestamp=str(d.get("timestamp", "")),
            schema_version=str(d.get("schema_version", "1.0.0")),
            provenance=dict(d.get("provenance", {})),
            raw_envelope=dict(d.get("raw_envelope", {})),
            replayed=bool(d.get("replayed", False)),
            replayed_at=d.get("replayed_at"),
        )


@dataclass
class StreamingMetrics:
    """Observability counters and operational metrics for the streaming adapter."""
    events_received_total: int = 0
    events_deduplicated_total: int = 0
    events_processed_total: int = 0
    events_rejected_total: int = 0
    events_dlq_total: int = 0
    late_events_total: int = 0
    coalesced_events_total: int = 0
    immediate_flush_total: int = 0
    state_evaluations_total: int = 0
    state_transitions_total: int = 0
    evaluation_failures_total: int = 0
    ledger_failures_total: int = 0
    event_processing_lag_ms: float = 0.0
    watermark_lag_ms: float = 0.0
    queue_depth: int = 0
    backpressure_events_total: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events_received_total": self.events_received_total,
            "events_deduplicated_total": self.events_deduplicated_total,
            "events_processed_total": self.events_processed_total,
            "events_rejected_total": self.events_rejected_total,
            "events_dlq_total": self.events_dlq_total,
            "late_events_total": self.late_events_total,
            "coalesced_events_total": self.coalesced_events_total,
            "immediate_flush_total": self.immediate_flush_total,
            "state_evaluations_total": self.state_evaluations_total,
            "state_transitions_total": self.state_transitions_total,
            "evaluation_failures_total": self.evaluation_failures_total,
            "ledger_failures_total": self.ledger_failures_total,
            "event_processing_lag_ms": round(self.event_processing_lag_ms, 2),
            "watermark_lag_ms": round(self.watermark_lag_ms, 2),
            "queue_depth": self.queue_depth,
            "backpressure_events_total": self.backpressure_events_total,
        }
