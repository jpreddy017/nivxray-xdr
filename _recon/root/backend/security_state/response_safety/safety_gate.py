"""Response Safety Gate: multi-gate pre-execution validation."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    canonical_json,
    sha256_digest,
)
from ..intervention.optimizer import PlannedAction


@dataclass
class SafetyGateDecision:
    """Decision record for an intervention action before execution."""
    decision_id: str
    tenant_id: str
    action_id: str
    target_entity_id: str
    is_approved: bool
    requires_human_approval: bool
    policy_violations: List[str]
    safety_checks_passed: List[str]
    authorized_by: str
    evaluated_at: str
    decision_hash: str = ""

    def __post_init__(self) -> None:
        if not self.decision_hash:
            self.decision_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "decision_id": self.decision_id,
            "tenant_id": self.tenant_id,
            "action_id": self.action_id,
            "target_entity_id": self.target_entity_id,
            "is_approved": self.is_approved,
            "requires_human_approval": self.requires_human_approval,
            "policy_violations": sorted(self.policy_violations),
            "safety_checks_passed": sorted(self.safety_checks_passed),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponseSafetyGate:
    """Enforces multi-gate safety checks prior to executing response actions."""
    VERSION = "1.0.0"

    # Tier-0 systems protected against unilateral automated isolation
    TIER_0_PROTECTED_ENTITIES = {"server-dc-01", "dc-01.corp", "prod-k8s-master", "core-db-cluster"}

    def evaluate_action_safety(
        self,
        tenant_id: str,
        action: PlannedAction,
        caller_roles: List[str],
        caller_tenant_id: str,
        evidence_confidence: float,
        at_timestamp: str = "2026-09-04T00:00:00Z",
    ) -> SafetyGateDecision:
        """Validate safety gates for a single action."""
        passed: List[str] = []
        violations: List[str] = []
        requires_human = False

        # Gate 1: Strict Multi-Tenancy
        if caller_tenant_id != tenant_id or action.target_entity.tenant_id != tenant_id:
            violations.append(f"Tenant isolation breach: target tenant {action.target_entity.tenant_id} != caller {caller_tenant_id}")
        else:
            passed.append("Multi-tenant boundary verified")

        # Gate 2: Tier-0 Critical Asset Protection
        if action.target_entity.entity_id in self.TIER_0_PROTECTED_ENTITIES:
            requires_human = True
            violations.append(f"Protected Tier-0 asset {action.target_entity.entity_id} requires explicit dual SOC approval")
        else:
            passed.append("Critical asset impact threshold satisfied")

        # Gate 3: Confidence Floor
        if evidence_confidence < 0.70:
            violations.append(f"Evidence confidence {evidence_confidence:.2f} below required automation threshold 0.70")
        else:
            passed.append(f"Evidence confidence {evidence_confidence:.2f} meets safety threshold")

        # Gate 4: Authorization Scopes
        if action.action_id.startswith("endpoint.isolate") and "soc:analyst" not in caller_roles and "soc:admin" not in caller_roles:
            violations.append("Caller lacks required role 'soc:analyst' for endpoint isolation")
        else:
            passed.append("Role and authorization scope verified")

        approved = len(violations) == 0 and not requires_human

        return SafetyGateDecision(
            decision_id=f"gate-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            action_id=action.action_id,
            target_entity_id=action.target_entity.entity_id,
            is_approved=approved,
            requires_human_approval=requires_human,
            policy_violations=violations,
            safety_checks_passed=passed,
            authorized_by="system-automated" if approved else "pending-approval",
            evaluated_at=at_timestamp,
        )
