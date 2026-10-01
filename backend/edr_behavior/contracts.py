"""Versioned contracts consumed and produced by the E3 sequence engine.

The engine never reads a Mongo store directly; everything enters as an
`EvidenceRecord` built by an adapter and leaves as a `Detection`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Three-valued evaluation used everywhere. Missing evidence is UNKNOWN, never FALSE.
TRUE, FALSE, UNKNOWN = "TRUE", "FALSE", "UNKNOWN"

# Evidence kinds (stage predicate types map onto these).
KIND_PROCESS = "PROCESS"
KIND_PROCESS_TERMINATION = "PROCESS_TERMINATION"
KIND_FILE = "FILE"
KIND_REGISTRY = "REGISTRY"
KIND_DNS = "DNS"
KIND_NETWORK = "NETWORK"
KIND_AUTH = "AUTH"
KIND_DETECTION = "DETECTION"
EVIDENCE_KINDS = frozenset({KIND_PROCESS, KIND_PROCESS_TERMINATION, KIND_FILE,
                            KIND_REGISTRY, KIND_DNS, KIND_NETWORK, KIND_AUTH,
                            KIND_DETECTION})

# Store tags for EvidenceRef. The canonical authority is pending (doc 1), so
# references carry the tag instead of assuming a collection.
STORE_RAW = "RAW"
STORE_SHADOW_OBSERVATION = "SHADOW_OBSERVATION"
STORE_XDR_CANONICAL = "XDR_CANONICAL"
STORE_UNSPECIFIED = "UNSPECIFIED"
STORES = frozenset({STORE_RAW, STORE_SHADOW_OBSERVATION, STORE_XDR_CANONICAL,
                    STORE_UNSPECIFIED})

# Parent/child linkage quality.
LINK_GUID = "SOURCE_PROCESS_GUID"
LINK_PID_SURROGATE = "PID_SURROGATE"
LINK_UNKNOWN = "UNKNOWN"

# Evaluation outcomes per (rule, trigger).
OUTCOME_MATCH = "MATCH"
OUTCOME_NO_MATCH = "NO_MATCH"
OUTCOME_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
OUTCOME_BUDGET = "BUDGET_EXCEEDED"
OUTCOME_SUPPRESSED = "SUPPRESSED"

# Detection status.
STATUS_OPEN = "OPEN"
STATUS_TESTING = "TESTING"
STATUS_SUPPRESSED = "SUPPRESSED"

MODE_LIVE = "LIVE"
MODE_RETRO = "RETRO"


def sha(*parts: Any) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(b"\x1f")
        h.update(("" if p is None else str(p)).encode("utf-8", "replace"))
    return h.hexdigest()


def utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class EvidenceRef:
    """Pointer to real evidence. Identity excludes `generation` (retry-safe)."""
    tenant_id: str
    raw_id: str
    canonical_event_id: Optional[str] = None
    generation: Optional[int] = None
    store: str = STORE_UNSPECIFIED
    record_id: Optional[str] = None
    sub_key: Optional[str] = None  # activity identity when one raw row yields many records

    def stable_key(self) -> str:
        return "ev_" + sha("evidence", self.tenant_id, self.raw_id,
                           self.sub_key or "")[:32]

    def to_dict(self) -> Dict[str, Any]:
        return {"tenant_id": self.tenant_id, "raw_id": self.raw_id,
                "canonical_event_id": self.canonical_event_id,
                "generation": self.generation, "store": self.store,
                "record_id": self.record_id, "sub_key": self.sub_key,
                "stable_key": self.stable_key()}


@dataclass(frozen=True)
class ProcessRef:
    """Runtime process identity as minted today (M1 canonical_bridge)."""
    process_iid: Optional[str]
    pid: Optional[str] = None
    process_guid: Optional[str] = None
    parent_pid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    start_time: Optional[str] = None
    attribution_state: Optional[str] = None


@dataclass(frozen=True)
class EvidenceRecord:
    """One normalized, tenant-owned piece of endpoint evidence."""
    tenant_id: str
    endpoint_id: str
    kind: str
    event_time: datetime
    ref: EvidenceRef
    fields: Dict[str, Any]
    process: Optional[ProcessRef] = None
    source: str = ""
    not_observed: Tuple[str, ...] = ()
    not_supported: Tuple[str, ...] = ()
    truncated_fields: Tuple[str, ...] = ()
    provenance: Dict[str, Any] = field(default_factory=dict)

    @property
    def stable_key(self) -> str:
        return self.ref.stable_key()

    def sort_key(self) -> Tuple[datetime, str]:
        return (self.event_time, self.stable_key)


@dataclass
class StageMatch:
    stage_id: str
    kind: str
    evidence: List[EvidenceRecord]
    optional: bool = False
    linkage: Dict[str, str] = field(default_factory=dict)

    @property
    def first(self) -> EvidenceRecord:
        return self.evidence[0]


@dataclass
class EvaluationResult:
    """Outcome of evaluating one rule for one trigger. Always explicit."""
    rule_id: str
    rule_version: int
    outcome: str
    reasons: List[str] = field(default_factory=list)
    stages: List[StageMatch] = field(default_factory=list)


@dataclass
class Detection:
    detection_id: str
    tenant_id: str
    endpoint_id: str
    rule_id: str
    rule_version: int
    rule_content_hash: str
    detection_type: str
    first_seen: str
    last_seen: str
    severity: str
    confidence: int
    status: str
    scope_key: str
    matched_stages: List[Dict[str, Any]]
    involved_entities: Dict[str, List[str]]
    evidence_refs: List[Dict[str, Any]]
    evidence_keys: List[str]
    raw_refs: List[str]
    canonical_event_ids: List[str]
    process_identities: List[str]
    mitre: List[Dict[str, str]]
    explanation: str
    provenance: Dict[str, Any]
    engine_version: str
    created_at: str
    suppression: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class MLSignal:
    """Boundary only: future model output. Never a verdict by itself."""
    model_id: str
    model_version: str
    feature_schema_version: str
    score: float
    confidence: int
    explanation: Dict[str, Any]
    evidence_refs: Tuple[EvidenceRef, ...]
    inference_time: datetime

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise ValueError("MLSignal requires evidence_refs")
        if not (0.0 <= float(self.score) <= 1.0):
            raise ValueError("MLSignal.score must be within [0, 1]")
        if not (0 <= int(self.confidence) <= 100):
            raise ValueError("MLSignal.confidence must be within [0, 100]")


@dataclass(frozen=True)
class Enrichment:
    """Boundary only: TI/OSINT result shape. Consumed via EnrichmentProvider."""
    observable: str
    type: str
    verdict: str  # MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN
    confidence: int
    providers: Tuple[str, ...]
    first_seen: Optional[str]
    last_seen: Optional[str]
    enrichment_time: str
    expiry: Optional[str]
    provenance: Dict[str, Any] = field(default_factory=dict)
