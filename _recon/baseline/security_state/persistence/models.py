"""Persistent Models and Schemas for NivXRay Security State and Ledger."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class PersistentSecurityStateRecord:
    """Canonical persistent record stored in MongoDB collection `security_states`."""
    tenant_id: str
    case_id: str
    version: int
    state_hash: str
    previous_state_hash: Optional[str]
    entity_ref: Dict[str, Any]
    epistemic_status: str
    classification: str
    active_capabilities: List[str]
    observed_facts: List[Dict[str, Any]]
    derived_facts: List[Dict[str, Any]]
    assumptions: List[Dict[str, Any]]
    contradictions: List[Dict[str, Any]]
    missing_evidence: List[Dict[str, Any]]
    attack_state: str
    reachability: Dict[str, Any]
    impact: Dict[str, Any]
    intervention_plan: Dict[str, Any]
    evidence_references: List[Dict[str, Any]]
    provenance: Dict[str, Any]
    lifecycle_status: str = "ACTIVE"  # 'ACTIVE', 'ARCHIVED', 'EXPIRED'
    commit_status: str = "COMMITTED"  # 'COMMITTED', 'PENDING_LEDGER', 'ABORTED'
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    engine_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PersistentSecurityStateRecord:
        clean_data = {k: v for k, v in data.items() if k != "_id"}
        return cls(**clean_data)


@dataclass
class PersistentLedgerBlockRecord:
    """Canonical immutable record stored in MongoDB collection `security_state_ledgers`."""
    tenant_id: str
    case_id: str
    sequence_number: int
    block_id: str
    event_type: str
    entity_id: str
    state_version: int
    previous_hash: str
    current_hash: str
    payload: Dict[str, Any]
    timestamp: str
    verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PersistentLedgerBlockRecord:
        clean_data = {k: v for k, v in data.items() if k != "_id"}
        return cls(**clean_data)
