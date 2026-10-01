"""
NivXRay XDR — Playbook Orchestration Data Models.
Provides deterministic, strongly-typed models for enterprise response playbooks.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class PlaybookStage(str, Enum):
    TRIGGER           = "TRIGGER"
    ASSESS            = "ASSESS"
    COLLECT_EVIDENCE  = "COLLECT_EVIDENCE"
    RECOMMEND         = "RECOMMEND"
    SIMULATE          = "SIMULATE"
    STAGE             = "STAGE"
    APPROVE           = "APPROVE"
    EXECUTE           = "EXECUTE"
    VERIFY            = "VERIFY"
    REASSESS          = "REASSESS"
    COMPLETED         = "COMPLETED"
    BLOCKED           = "BLOCKED"
    FAILED            = "FAILED"


class TargetDomain(str, Enum):
    ENDPOINT = "endpoint"
    NETWORK  = "network"
    IDENTITY = "identity"
    CLOUD    = "cloud"
    EMAIL    = "email"
    BACKUP   = "backup"
    HYPERVISOR = "hypervisor"


@dataclass
class PlaybookTrigger:
    """Trigger conditions that activate a playbook."""
    trigger_kind: str  # threat_family | detection_rule | correlation_rule | security_state_change
    filter_key: str
    filter_value: str
    minimum_confidence: str = "medium"


@dataclass
class PlaybookStep:
    """One discrete, auditable action in a playbook."""
    step_number: int
    action_id: str  # maps to action in xdr_action_registry (e.g., 'ENDPOINT_ISOLATE')
    name: str
    description: str
    target_entity_kind: str  # host | user | ip | domain | file | service | cloud_role
    parameters_template: Dict[str, Any] = field(default_factory=dict)
    is_reversible: bool = True
    requires_dual_approval: bool = False
    verification_condition: str = ""
    rollback_action_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookDefinition:
    """Authoritative representation of a deterministic response playbook."""
    playbook_id: str
    name: str
    description: str
    target_domain: TargetDomain
    triggers: List[PlaybookTrigger]
    required_capabilities: List[str]
    steps: List[PlaybookStep]
    risk_level: str = "HIGH"  # LOW | MEDIUM | HIGH | CRITICAL
    approval_policy: str = "APPROVAL_REQUIRED"  # AUTO_APPROVE | APPROVAL_REQUIRED | DUAL_APPROVAL
    rollback_playbook_id: Optional[str] = None
    expected_residual_risk_reduction_pct: int = 50
    expected_business_disruption_score: int = 20
    is_active: bool = True
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["target_domain"] = self.target_domain.value
        return d


@dataclass
class PlaybookStepTrace:
    """Record of an individual step execution or simulation."""
    step_number: int
    action_id: str
    target_entity: str
    status: str  # SIMULATED | STAGED | SUCCEEDED | FAILED | NOT_CONFIGURED | BLOCKED
    executed_at: str
    elapsed_ms: int
    is_simulation: bool
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookExecutionTrace:
    """Full end-to-end execution and audit trace of a playbook lifecycle."""
    trace_id: str
    playbook_id: str
    incident_id: str
    tenant_id: str
    current_stage: PlaybookStage
    started_at: str
    completed_at: Optional[str]
    is_dry_run: bool
    simulated_world_id: str
    initial_residual_risk_pct: int
    projected_residual_risk_pct: int
    projected_business_disruption_score: int
    step_traces: List[PlaybookStepTrace] = field(default_factory=list)
    approval_details: Dict[str, Any] = field(default_factory=dict)
    verification_details: Dict[str, Any] = field(default_factory=dict)
    reassessment_summary: str = ""
    status_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["current_stage"] = self.current_stage.value
        return d
