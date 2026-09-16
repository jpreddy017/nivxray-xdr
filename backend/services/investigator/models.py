"""Round 31 · NivXRay XDR · Autonomous Investigator · contracts.

Deterministic Pydantic v2 models.  Every model is a pure record —
no behavior lives here (see ``orchestrator.py`` / ``planner.py``).

The Investigator sits INSIDE the closed autonomous investigation loop:

    Evidence  →  IKG  →  IUE  →  Investigator  →  Capabilities
       ↑                                                │
       └────────── new evidence / findings ─────────────┘
"""
from __future__ import annotations

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


# ── Lifecycle state machine (§26 of AUTONOMOUS_INVESTIGATION.md) ────

LifecycleState = Literal[
    "WAITING_FOR_EVIDENCE",
    "UNDERSTANDING_EVIDENCE",
    "INVESTIGATING",
    "EXPANDING",
    "WAITING_FOR_CAPABILITY",
    "CONVERGING",
    "CONVERGED",
    "REOPENED",
    "FAILED",
]


ExecutionStatus = Literal[
    "PLANNED",
    "RUNNING",
    "OK",
    "SKIPPED_UNAVAILABLE",
    "SKIPPED_DUPLICATE",
    "SKIPPED_OUT_OF_SCOPE",
    "ERROR",
]


CapabilityAvailability = Literal[
    "cap-full",         # capability is registered and functional
    "cap-standby",      # registered but downstream dependency incomplete
    "cap-unavailable",  # not yet registered / no engine wired
]


FindingState = Literal[
    "OBSERVED",
    "SUPPORTED",
    "CORRELATED",
    "INFERRED",
    "HYPOTHESIS",
    "NOT_OBSERVED",
    "UNKNOWN",
    "CONTRADICTED",
]


# ── Plan / pivot ────────────────────────────────────────────────────

class PivotAction(BaseModel):
    """One planned investigative pivot.

    The planner deterministically emits pivots from IUE gaps
    (Round 30 · ``InvestigationGaps.gaps[].suggested_capability``).
    A pivot is not yet an execution — the selector must confirm
    that a capability with matching id is registered and available.
    """
    pivot_id: str = Field(..., description="Deterministic id derived from (incident_id, capability, target)")
    incident_id: str
    tenant_id: str
    gap_key: str
    capability: str
    target_kind: str = Field("incident", description="incident | entity | evidence")
    target_value: str
    reason: str
    triggering_evidence: List[str] = Field(default_factory=list)
    expected_outcome: str
    priority: int = Field(50, ge=0, le=100)
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ── Engine execution record (persisted in `engine_executions`) ──────

class EngineExecution(BaseModel):
    """Real capability invocation record.

    Persisted **only** when a capability actually ran (or was
    honestly skipped with the reason recorded).  Never fabricated.
    """
    execution_id: str
    tenant_id: str
    incident_id: str
    investigation_id: str
    pivot_id: str
    capability: str
    engine: str
    target_kind: str
    target_value: str
    trigger: str
    reason: str
    started_at: str
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    status: ExecutionStatus
    evidence_created: int = 0
    evidence_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ── Finding (evidence-adjacent product of a capability) ─────────────

class Finding(BaseModel):
    """A single fact produced by a capability.

    A finding is EVIDENCE-ADJACENT — it references canonical evidence
    but does not itself become canonical.  Its ``state`` obeys the §27
    evidence-state grammar.  Capabilities never mark a finding
    ``OBSERVED`` unless the finding is literally a direct read of a
    canonical field; correlation / inference findings carry the
    honest state ``CORRELATED`` or ``INFERRED``.
    """
    finding_id: str
    tenant_id: str
    incident_id: str
    execution_id: str
    capability: str
    engine: str
    kind: str = Field(..., description="prior_sighting | mitre_expansion | correlation | ...")
    subject_kind: str
    subject_value: str
    state: FindingState
    confidence: int = Field(0, ge=0, le=100)
    summary: str
    evidence_refs: List[str] = Field(default_factory=list)
    reasoning: str
    created_at: str
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ── Activity log entry (§18 · Investigation Activity feed) ──────────

class ActivityEntry(BaseModel):
    """A single line in the Investigation Activity feed.

    Every entry answers the §10 six questions (WHAT · WHY · EVIDENCE
    · CAPABILITY · RESULT · NEXT).  Rendered as one row in the tab.
    """
    at: str
    kind: Literal["LIFECYCLE", "PIVOT_PLANNED", "EXECUTION", "FINDING",
                    "SKIPPED", "CONVERGED"]
    lifecycle_state: LifecycleState
    what: str
    why: str
    evidence_refs: List[str] = Field(default_factory=list)
    capability: Optional[str] = None
    engine: Optional[str] = None
    result: Optional[str] = None
    next_hint: Optional[str] = None
    execution_id: Optional[str] = None
    finding_id: Optional[str] = None


# ── Investigation state (persisted per incident) ────────────────────

class InvestigationState(BaseModel):
    """One row in ``xdr_investigations``.  Keyed by (tenant, incident)."""
    investigation_id: str
    tenant_id: str
    incident_id: str
    state: LifecycleState
    state_history: List[Dict[str, str]] = Field(default_factory=list)
    iue_fingerprint: Optional[str] = None
    iue_version: Optional[int] = None
    pivots_planned: int = 0
    pivots_executed: int = 0
    pivots_skipped: int = 0
    findings_count: int = 0
    started_at: str
    updated_at: str
    converged_at: Optional[str] = None
    convergence_reason: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    honesty_note: str = (
        "Investigator emits findings + planned pivots + real engine "
        "executions.  It never fabricates evidence and never "
        "overrides the Verdict Engine (§10, §31)."
    )
