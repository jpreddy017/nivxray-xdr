"""Canonical IUE data contract (ADR-005 §3.2).

Phase 1: dataclasses only, no persistence, no network. Every field is
serialisable to canonical JSON via canonical.iue.determinism.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Union


# ── Capability enum (D4-3 dispatch list) ─────────────────────────────────
class Capability(str, Enum):
    INPUT_HEALTH        = "INPUT_HEALTH"
    DECODER             = "DECODER"
    ARCHIVE_EXTRACT     = "ARCHIVE_EXTRACT"
    ARTIFACT_SPLIT      = "ARTIFACT_SPLIT"
    IDA_ACQUIRE         = "IDA_ACQUIRE"
    IOC_EXTRACTOR       = "IOC_EXTRACTOR"
    COMMAND_DETECT      = "COMMAND_DETECT"
    VENDOR_NORMALISER   = "VENDOR_NORMALISER"
    SEMANTIC_AST        = "SEMANTIC_AST"
    DKP_MATCH           = "DKP_MATCH"
    MITRE_MAP           = "MITRE_MAP"
    ATTACK_CHAIN        = "ATTACK_CHAIN"
    THREAT_INTEL_ENRICH = "THREAT_INTEL_ENRICH"
    RECURSIVE_DISCOVERY = "RECURSIVE_DISCOVERY"
    PROCESS_TREE        = "PROCESS_TREE"
    LOLBAS_MATCH        = "LOLBAS_MATCH"
    QUALITY_SCORE       = "QUALITY_SCORE"


class DispatchPolicy(str, Enum):
    STRICT_ORDERED       = "strict_ordered"
    PARALLEL_WHERE_SAFE  = "parallel_where_safe"
    DAG                  = "dag"


# ── RawInput ─────────────────────────────────────────────────────────────
@dataclass
class RawInput:
    """Bytes-safe raw input at the front door of the canonical lifecycle."""
    payload: Union[bytes, str]
    filename: Optional[str] = None
    mime_hint: Optional[str] = None
    source_channel: Optional[str] = None

    def as_text(self) -> str:
        if isinstance(self.payload, bytes):
            try:
                return self.payload.decode("utf-8", errors="replace")
            except Exception:
                return self.payload.decode("latin-1", errors="replace")
        return self.payload

    def as_bytes(self) -> bytes:
        if isinstance(self.payload, bytes):
            return self.payload
        return self.payload.encode("utf-8", errors="replace")

    def size(self) -> int:
        return len(self.as_bytes())


# ── Provenance envelope (D3-z) ───────────────────────────────────────────
@dataclass
class Provenance:
    """Mandatory envelope on every appended entry. See ADR-005 P3."""
    engine: str
    version: str
    at: str                                     # ISO8601 UTC — set by caller only; composer uses "phase1"
    upstream_evidence_ids: List[str] = field(default_factory=list)


# ── Evidence entry ───────────────────────────────────────────────────────
@dataclass
class IUEEvidence:
    """Single evidence entry produced by a sub-classifier."""
    id: str                                      # e.g. "ev.bytes_magic.0001"
    source: str                                  # sub-classifier name
    observation: str                             # human-readable observation
    confidence: int                              # 0..100
    rationale: str
    meta: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[Provenance] = None


# ── Input health ─────────────────────────────────────────────────────────
@dataclass
class InputHealthResult:
    ok: bool
    blocking: bool
    size_bytes: int
    control_char_ratio: float
    encoding: str
    issues: List[Dict[str, Any]] = field(default_factory=list)


# ── Input profile ────────────────────────────────────────────────────────
@dataclass
class InputProfile:
    primary_type: str                            # canonical taxonomy identifier
    embedded: List[str] = field(default_factory=list)
    input_kind: str = ""                         # UIL InputKind string mirror
    encoding: str = "utf-8"
    size_bytes: int = 0
    byte_signature: Optional[str] = None         # first 16 bytes hex
    filename: Optional[str] = None
    mime_hint: Optional[str] = None


# ── Intent ───────────────────────────────────────────────────────────────
@dataclass
class Intent:
    label: str
    confidence: int
    evidence_ids: List[str] = field(default_factory=list)


# ── Confidence matrix ────────────────────────────────────────────────────
@dataclass
class ConfidenceMatrix:
    input_classification: int   # 0..100
    decode_path: int
    language_detection: int
    estimated_recovery: int
    artifact_completeness: int
    telemetry_richness: int


# ── PlanStep ─────────────────────────────────────────────────────────────
@dataclass
class PlanStep:
    engine: str                                  # e.g. "canonical.executor.decoder"
    action: str                                  # human-readable
    reason: str
    required: bool
    expected_output_kind: str                    # e.g. "decoded_text" | "artifact_list"
    capability: Capability = Capability.DECODER


# ── IUEDecision ──────────────────────────────────────────────────────────
@dataclass
class IUEDecision:
    """Canonical output of the IUE Composer. ADR-005 §3.2."""
    input_health: InputHealthResult
    input_profile: InputProfile
    intent: Intent
    capabilities: List[Capability]
    plan: List[PlanStep]
    confidence_matrix: ConfidenceMatrix
    dispatch_policy: DispatchPolicy
    provenance: Provenance
    next_engine_hint: str
    evidence: List[IUEEvidence]
    determinism_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
