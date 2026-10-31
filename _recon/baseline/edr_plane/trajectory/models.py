"""DT2-0 · Device Trajectory V2 first-class domain contracts.

Evidence-first. Every object here either carries an evidence reference or
states, in its own fields, why it cannot. The rules that matter:

* a Relationship without an evidence reference and a derivation basis is
  REJECTED at construction — the frontend never gets to decide truth;
* temporal proximity (and friends) is never a relationship basis;
* absence states are seven distinct truths, and the ones that assert
  something about collection require proof, otherwise UNKNOWN;
* density is a navigation quantity and carries no severity field at all;
* a process with no termination evidence has no end time — never invented.

Nothing in this module reads or writes a database. It is a pure contract
layer over the V1 projection, so DT2-0 has no write side effect.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

DT2_CONTRACT_VERSION = "dt2.0"

# ── authority / quality vocabularies ──────────────────────────────────
AUTHORITY_AUTHORITATIVE = "AUTHORITATIVE"
AUTHORITY_DERIVED = "DERIVED"
AUTHORITY_UNSTABLE = "UNSTABLE"
AUTHORITY_UNKNOWN = "UNKNOWN"
AUTHORITIES = (AUTHORITY_AUTHORITATIVE, AUTHORITY_DERIVED,
               AUTHORITY_UNSTABLE, AUTHORITY_UNKNOWN)

# ── relationship vocabulary ───────────────────────────────────────────
REL_PROCESS_PROCESS = "PROCESS_PROCESS"
REL_PROCESS_FILE = "PROCESS_FILE"
REL_PROCESS_REGISTRY = "PROCESS_REGISTRY"
REL_PROCESS_DNS = "PROCESS_DNS"
REL_PROCESS_NETWORK = "PROCESS_NETWORK"
REL_PROCESS_AUTH = "PROCESS_AUTH"
REL_DETECTION_OBSERVATION = "DETECTION_OBSERVATION"
REL_DETECTION_PROCESS = "DETECTION_PROCESS"
RELATIONSHIP_TYPES = (REL_PROCESS_PROCESS, REL_PROCESS_FILE,
                      REL_PROCESS_REGISTRY, REL_PROCESS_DNS,
                      REL_PROCESS_NETWORK, REL_PROCESS_AUTH,
                      REL_DETECTION_OBSERVATION, REL_DETECTION_PROCESS)

#: Accepted derivation bases. Each one names a binding that exists in the
#: canonical evidence itself.
BASIS_PARENT_GUID = "SYSMON_PARENT_PROCESS_GUID"
BASIS_PARENT_IDENTITY = "CANONICAL_PARENT_PROCESS_IDENTITY"
BASIS_ACTOR_BINDING = "CANONICAL_ACTOR_PROCESS_BINDING"
BASIS_DETECTION_EVIDENCE = "DETECTION_EVIDENCE_REFERENCE"
ACCEPTED_BASES = (BASIS_PARENT_GUID, BASIS_PARENT_IDENTITY,
                  BASIS_ACTOR_BINDING, BASIS_DETECTION_EVIDENCE)

#: Bases that are FORBIDDEN outright. These are the ways a graph gets to
#: look complete while being false.
FORBIDDEN_BASES = ("TEMPORAL_PROXIMITY", "TIMESTAMP_PROXIMITY",
                   "DISPLAY_ADJACENCY", "SAME_USERNAME", "SAME_FILENAME",
                   "LOOSE_PID_MATCH", "VISUAL_ADJACENCY", "GUESS")

# ── coverage vocabulary ───────────────────────────────────────────────
COV_OBSERVED = "OBSERVED"
COV_NOT_OBSERVED = "NOT_OBSERVED"
COV_NOT_COLLECTED = "NOT_COLLECTED"
COV_NOT_CANONICALIZED = "NOT_CANONICALIZED"
COV_PARSE_FAILURE = "PARSE_FAILURE"
COV_EVALUATION_FAILED = "EVALUATION_FAILED"
COV_UNKNOWN = "UNKNOWN"
COVERAGE_STATES = (COV_OBSERVED, COV_NOT_OBSERVED, COV_NOT_COLLECTED,
                   COV_NOT_CANONICALIZED, COV_PARSE_FAILURE,
                   COV_EVALUATION_FAILED, COV_UNKNOWN)
#: States that ASSERT something about collection or processing and
#: therefore cannot be emitted without proof. UNKNOWN is the fallback.
COVERAGE_REQUIRES_PROOF = (COV_NOT_COLLECTED, COV_NOT_CANONICALIZED,
                           COV_PARSE_FAILURE, COV_EVALUATION_FAILED)

# ── focus vocabulary ──────────────────────────────────────────────────
FOCUS_RESOLVED = "FOCUS_RESOLVED"
FOCUS_AMBIGUOUS = "AMBIGUOUS"
FOCUS_NOT_IN_RETENTION = "NOT_IN_RETENTION"
FOCUS_EVIDENCE_MISSING = "EVIDENCE_MISSING"
FOCUS_STATES = (FOCUS_RESOLVED, FOCUS_AMBIGUOUS, FOCUS_NOT_IN_RETENTION,
                FOCUS_EVIDENCE_MISSING)
FOCUS_KINDS = ("raw_event_id", "canonical_event_id", "observation_id",
               "process_iid", "detection_id", "timestamp")

#: Availability semantics. "unavailable" is not "empty".
AVAIL_AVAILABLE = "AVAILABLE"
AVAIL_EMPTY = "EMPTY"
AVAIL_UNAVAILABLE = "UNAVAILABLE"
AVAIL_NOT_EVALUATED = "NOT_EVALUATED"
AVAIL_UNKNOWN = "UNKNOWN"

ARTIFACT_TYPES = ("FILE", "REGISTRY", "DNS", "NETWORK", "AUTH")
UNATTRIBUTED = "UNATTRIBUTED"


def _d(obj: Any) -> Dict[str, Any]:
    return asdict(obj)


@dataclass(frozen=True)
class EvidenceReference:
    """A pointer back to something immutable."""
    kind: str                       # RAW_EVENT | CANONICAL_EVENT | OBSERVATION | DETECTION
    id: str
    collection: Optional[str] = None
    byte_preserved: bool = False

    def __post_init__(self) -> None:
        if not self.kind or not self.id:
            raise ValueError("EvidenceReference needs a kind and an id")


@dataclass(frozen=True)
class TrajectoryCursor:
    timestamp: str
    event_iid: str

    @staticmethod
    def parse(raw: Any) -> "TrajectoryCursor":
        if not isinstance(raw, dict):
            raise ValueError("cursor must be an object")
        ts, iid = raw.get("timestamp"), raw.get("event_iid")
        if not ts or not iid:
            raise ValueError("cursor needs timestamp and event_iid")
        return TrajectoryCursor(timestamp=str(ts), event_iid=str(iid))


@dataclass(frozen=True)
class ProcessInstance:
    """Process identity WITH its authority stated.

    ProcessGuid is authoritative. `computer:pid:image` is derived and
    downgraded. A bare pid is UNSTABLE and is never presented as identity.
    """
    process_iid: str
    endpoint_id: str
    identity_authority: str
    identity_basis: str
    process_guid: Optional[str] = None
    pid: Optional[int] = None
    image: Optional[str] = None
    name: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    parent_process_iid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_state: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    exit_observed: bool = False
    end_time: Optional[str] = None
    detection_state: Optional[str] = None
    evidence_ref: Tuple[EvidenceReference, ...] = ()

    def __post_init__(self) -> None:
        if self.identity_authority not in AUTHORITIES:
            raise ValueError(f"bad identity_authority {self.identity_authority}")
        if self.identity_authority == AUTHORITY_AUTHORITATIVE \
                and not self.process_guid:
            raise ValueError("AUTHORITATIVE process identity requires a guid")
        if self.end_time and not self.exit_observed:
            raise ValueError("end_time without termination evidence is invented")


@dataclass(frozen=True)
class ArtifactInstance:
    """A non-process object. Independent identity, own authority."""
    artifact_id: str
    artifact_type: str
    endpoint_id: str
    identity_authority: str
    identity_basis: str
    label: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    attributed_process_iid: Optional[str] = None
    attribution_state: str = UNATTRIBUTED
    evidence_ref: Tuple[EvidenceReference, ...] = ()

    def __post_init__(self) -> None:
        if self.artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"bad artifact_type {self.artifact_type}")
        if self.identity_authority not in AUTHORITIES:
            raise ValueError("bad identity_authority")
        if self.attribution_state == "ATTRIBUTED" \
                and not self.attributed_process_iid:
            raise ValueError("ATTRIBUTED artifact needs a process")


@dataclass(frozen=True)
class Observation:
    """Canonical endpoint activity. Never flattened into a fake process."""
    observation_id: str
    endpoint_id: str
    activity_class: Optional[str]
    source_time: Optional[str]
    observed_time: Optional[str]
    time_basis: str
    ingest_time: Optional[str] = None
    canonicalized_time: Optional[str] = None
    operation: Optional[str] = None
    process_iid: Optional[str] = None
    artifact_id: Optional[str] = None
    user: Optional[str] = None
    raw_evidence_ref: Optional[EvidenceReference] = None
    canonical_evidence_ref: Optional[EvidenceReference] = None
    source: Optional[str] = None
    source_event_type: Optional[str] = None
    support_state: str = COV_OBSERVED
    evaluation_state: Optional[str] = None
    disposition: Optional[str] = None
    parser_state: Optional[str] = None
    attribution_state: str = UNATTRIBUTED
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.observation_id or not self.endpoint_id:
            raise ValueError("Observation needs an id and an endpoint")


@dataclass(frozen=True)
class Relationship:
    """An evidence-backed edge. Constructed server-side only."""
    relationship_id: str
    relationship_type: str
    source_id: str
    target_id: str
    endpoint_id: str
    derivation_basis: str
    authority: str
    evidence_ref: Tuple[EvidenceReference, ...]
    observed_at: Optional[str] = None
    time_basis: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.relationship_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"bad relationship_type {self.relationship_type}")
        if not self.source_id or not self.target_id:
            raise ValueError("relationship needs both endpoints of the edge")
        if not self.evidence_ref:
            raise ValueError(
                "relationship without evidence_ref is rejected: an edge must "
                "answer WHY IT EXISTS")
        if not self.derivation_basis:
            raise ValueError("relationship without derivation_basis rejected")
        basis = self.derivation_basis.upper()
        if any(bad in basis for bad in FORBIDDEN_BASES):
            raise ValueError(
                f"forbidden derivation_basis {self.derivation_basis!r}: "
                "temporal proximity is never relationship authority")
        if basis not in ACCEPTED_BASES:
            raise ValueError(f"unrecognised derivation_basis {basis}")
        if self.authority not in AUTHORITIES:
            raise ValueError("bad relationship authority")


@dataclass(frozen=True)
class DetectionMarker:
    """Analytical output. Separate object; never mutates an Observation."""
    detection_id: str
    endpoint_id: str
    detected_at: Optional[str]
    evaluation_state: str                 # MATCHED | EVALUATED_NO_MATCH | NOT_EVALUATED | NOT_RECORDED
    engine: Optional[str] = None
    engine_version: Optional[str] = None
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    disposition: Optional[str] = None
    mitre: Tuple[str, ...] = ()
    mitre_authority: str = AUTHORITY_DERIVED
    observation_ids: Tuple[str, ...] = ()
    process_iid: Optional[str] = None
    process_binding_authority: str = AUTHORITY_UNKNOWN
    evidence_ref: Tuple[EvidenceReference, ...] = ()
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detection_id:
            raise ValueError("DetectionMarker needs an id")
        if self.process_iid and self.process_binding_authority not in (
                AUTHORITY_AUTHORITATIVE, AUTHORITY_DERIVED):
            raise ValueError(
                "detection→process binding requires a stated authority")


@dataclass(frozen=True)
class DensityBucket:
    """Navigation quantity. There is deliberately NO severity field."""
    start: str
    end: str
    stream: str                          # events | process | file | network | registry | dns | auth | detection
    count: int
    semantics: str = "NAVIGATION_ONLY_NOT_SEVERITY"

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError("density count cannot be negative")


@dataclass(frozen=True)
class CoverageInterval:
    state: str
    start: Optional[str]
    end: Optional[str]
    authority: str
    boundary_certainty: str              # PROVEN | UNKNOWN
    absence_inferable: bool
    reason: Optional[str] = None
    proof_ref: Tuple[EvidenceReference, ...] = ()
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state not in COVERAGE_STATES:
            raise ValueError(f"bad coverage state {self.state}")
        if self.state in COVERAGE_REQUIRES_PROOF and not self.proof_ref:
            raise ValueError(
                f"{self.state} requires proof; use UNKNOWN when a boundary "
                "cannot be proven")
        if self.state != COV_OBSERVED and self.absence_inferable \
                and self.state != COV_NOT_OBSERVED:
            raise ValueError(
                "absence may only be inferred from NOT_OBSERVED within the "
                "stated filter")


@dataclass(frozen=True)
class FocusTarget:
    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in FOCUS_KINDS:
            raise ValueError(f"bad focus kind {self.kind}")
        if not self.value:
            raise ValueError("focus target needs a value")


@dataclass(frozen=True)
class FocusResolution:
    state: str
    target: Optional[FocusTarget] = None
    basis: Optional[str] = None
    window: Optional[Dict[str, Any]] = None
    observation_id: Optional[str] = None
    process_iid: Optional[str] = None
    detection_id: Optional[str] = None
    relationship_path: Tuple[str, ...] = ()
    timestamp_only: bool = False

    def __post_init__(self) -> None:
        if self.state not in FOCUS_STATES:
            raise ValueError(f"bad focus state {self.state}")
        if self.state == FOCUS_RESOLVED and not (
                self.observation_id or self.process_iid or self.detection_id
                or self.timestamp_only):
            raise ValueError(
                "FOCUS_RESOLVED must name what it resolved — no silent "
                "generic fallback")


@dataclass(frozen=True)
class TrajectoryAxis:
    mode: str                            # ENDPOINT_INVARIANT | FILTER_SCOPED
    total_lanes: int
    lane_ids: Tuple[str, ...] = ()
    collapsed_lane_ids: Tuple[str, ...] = ()
    order: str = "LINEAGE_DEPTH_FIRST_PREORDER"

    def __post_init__(self) -> None:
        if self.mode not in ("ENDPOINT_INVARIANT", "FILTER_SCOPED"):
            raise ValueError("bad axis mode")


@dataclass
class TrajectoryWindow:
    """The DT2-0 contract object.

    Emitted as ADDITIVE keys alongside the V1 response, so a V1 client is
    untouched. Ranges are three separate truths: what was asked for, what
    the projection actually covered, and what evidence is available —
    because a short retention must never be reported as 30 days of
    NOT_COLLECTED.
    """
    endpoint_id: str
    requested_range: Dict[str, Any]
    effective_range: Dict[str, Any]
    available_range: Dict[str, Any]
    retention_boundary: Dict[str, Any]
    axis: TrajectoryAxis
    observations: List[Observation] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    detections: List[DetectionMarker] = field(default_factory=list)
    density: List[DensityBucket] = field(default_factory=list)
    coverage: List[CoverageInterval] = field(default_factory=list)
    process_instances: List[ProcessInstance] = field(default_factory=list)
    artifacts: List[ArtifactInstance] = field(default_factory=list)
    focus: Optional[FocusResolution] = None
    cursor: Optional[TrajectoryCursor] = None
    next_cursor: Optional[TrajectoryCursor] = None
    has_more: bool = False
    applied_filters: Dict[str, Any] = field(default_factory=dict)
    applied_search: Dict[str, Any] = field(default_factory=dict)
    time_basis: str = "SOURCE_TIME_THEN_OBSERVED_TIME"
    availability: Dict[str, str] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    contract_version: str = DT2_CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "endpoint_id": self.endpoint_id,
            "requested_range": self.requested_range,
            "effective_range": self.effective_range,
            "available_range": self.available_range,
            "retention_boundary": self.retention_boundary,
            "axis": _d(self.axis),
            "observations": [_d(o) for o in self.observations],
            "relationships": [_d(r) for r in self.relationships],
            "detections": [_d(x) for x in self.detections],
            "density": [_d(b) for b in self.density],
            "coverage": [_d(c) for c in self.coverage],
            "process_instances": [_d(p) for p in self.process_instances],
            "artifacts": [_d(a) for a in self.artifacts],
            "focus": _d(self.focus) if self.focus else None,
            "cursor": _d(self.cursor) if self.cursor else None,
            "next_cursor": _d(self.next_cursor) if self.next_cursor else None,
            "has_more": self.has_more,
            "applied_filters": self.applied_filters,
            "applied_search": self.applied_search,
            "time_basis": self.time_basis,
            "availability": self.availability,
            "provenance": self.provenance,
        }
