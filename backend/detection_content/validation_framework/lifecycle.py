"""
NivXRay XDR — Content Lifecycle State Machine.
Manages deterministic rule lifecycle states:
ACQUIRED -> NORMALIZED -> TRANSLATED -> DEDUPLICATED -> VALIDATING ->
VALIDATED -> ENGINE_BOUND -> CONTEXTUALIZED -> SHADOW -> ACTIVE
and REJECTED, UNSUPPORTED, SUPERSEDED, DEPRECATED, ROLLED_BACK.
Maintains an append-only audit trail for every state transition.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class LifecycleState(str, Enum):
    ACQUIRED        = "ACQUIRED"
    NORMALIZED      = "NORMALIZED"
    TRANSLATED      = "TRANSLATED"
    DEDUPLICATED    = "DEDUPLICATED"
    VALIDATING      = "VALIDATING"
    VALIDATED       = "VALIDATED"
    ENGINE_BOUND    = "ENGINE_BOUND"
    CONTEXTUALIZED  = "CONTEXTUALIZED"
    SHADOW          = "SHADOW"
    ACTIVE          = "ACTIVE"
    # Terminal / Exception states
    REJECTED        = "REJECTED"
    UNSUPPORTED     = "UNSUPPORTED"
    SUPERSEDED      = "SUPERSEDED"
    DEPRECATED      = "DEPRECATED"
    ROLLED_BACK     = "ROLLED_BACK"


_ALLOWED_TRANSITIONS: Dict[LifecycleState, Set[LifecycleState]] = {
    LifecycleState.ACQUIRED: {
        LifecycleState.NORMALIZED,
        LifecycleState.REJECTED,
        LifecycleState.UNSUPPORTED,
    },
    LifecycleState.NORMALIZED: {
        LifecycleState.TRANSLATED,
        LifecycleState.UNSUPPORTED,
        LifecycleState.REJECTED,
    },
    LifecycleState.TRANSLATED: {
        LifecycleState.DEDUPLICATED,
        LifecycleState.UNSUPPORTED,
        LifecycleState.REJECTED,
    },
    LifecycleState.DEDUPLICATED: {
        LifecycleState.VALIDATING,
        LifecycleState.SUPERSEDED,
        LifecycleState.REJECTED,
    },
    LifecycleState.VALIDATING: {
        LifecycleState.VALIDATED,
        LifecycleState.REJECTED,
        LifecycleState.TRANSLATED,  # Retry after tweak
    },
    LifecycleState.VALIDATED: {
        LifecycleState.ENGINE_BOUND,
        LifecycleState.VALIDATING,
        LifecycleState.DEPRECATED,
    },
    LifecycleState.ENGINE_BOUND: {
        LifecycleState.CONTEXTUALIZED,
        LifecycleState.SHADOW,
        LifecycleState.DEPRECATED,
    },
    LifecycleState.CONTEXTUALIZED: {
        LifecycleState.SHADOW,
        LifecycleState.ACTIVE,
        LifecycleState.DEPRECATED,
    },
    LifecycleState.SHADOW: {
        LifecycleState.ACTIVE,
        LifecycleState.VALIDATING,  # Tuning
        LifecycleState.DEPRECATED,
    },
    LifecycleState.ACTIVE: {
        LifecycleState.SHADOW,     # Retuning
        LifecycleState.SUPERSEDED,
        LifecycleState.DEPRECATED,
        LifecycleState.ROLLED_BACK,
    },
    LifecycleState.ROLLED_BACK: {
        LifecycleState.SHADOW,
        LifecycleState.DEPRECATED,
    },
    # Terminal states
    LifecycleState.REJECTED: set(),
    LifecycleState.UNSUPPORTED: set(),
    LifecycleState.SUPERSEDED: set(),
    LifecycleState.DEPRECATED: set(),
}


@dataclass
class TransitionAuditRecord:
    content_id: str
    previous_state: str
    new_state: str
    actor: str  # user or system worker ID
    reason: str
    source_version: str
    tenant_id: str = "default"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ContentLifecycleManager:
    """Enforces state machine invariants and records append-only transition audits."""

    def __init__(self):
        self._states: Dict[str, LifecycleState] = {}
        self._history: Dict[str, List[TransitionAuditRecord]] = {}

    def _scoped_key(self, content_id: str, tenant_id: Optional[str]) -> str:
        return f"{tenant_id}::{content_id}" if tenant_id else content_id

    def get_state(self, content_id: str, tenant_id: Optional[str] = None) -> LifecycleState:
        key = self._scoped_key(content_id, tenant_id)
        return self._states.get(key, LifecycleState.ACQUIRED)

    def get_history(self, content_id: str, tenant_id: Optional[str] = None) -> List[TransitionAuditRecord]:
        key = self._scoped_key(content_id, tenant_id)
        return list(self._history.get(key, []))

    def transition(
        self,
        content_id: str,
        new_state: LifecycleState,
        actor: str,
        reason: str,
        source_version: str = "v1.0",
        tenant_id: Optional[str] = None,
    ) -> bool:
        key = self._scoped_key(content_id, tenant_id)
        curr_state = self._states.get(key, LifecycleState.ACQUIRED)

        # Allow initial transition from ACQUIRED to itself upon creation
        if key not in self._states and new_state == LifecycleState.ACQUIRED:
            self._states[key] = LifecycleState.ACQUIRED
            rec = TransitionAuditRecord(
                content_id=content_id,
                previous_state="NONE",
                new_state=new_state.value,
                actor=actor,
                reason=reason,
                source_version=source_version,
                tenant_id=tenant_id or "default",
            )
            self._history.setdefault(key, []).append(rec)
            return True

        allowed = _ALLOWED_TRANSITIONS.get(curr_state, set())
        if new_state not in allowed:
            raise ValueError(
                f"Illegal lifecycle transition for '{content_id}': cannot move from {curr_state.value} to {new_state.value}"
            )

        self._states[key] = new_state
        rec = TransitionAuditRecord(
            content_id=content_id,
            previous_state=curr_state.value,
            new_state=new_state.value,
            actor=actor,
            reason=reason,
            source_version=source_version,
            tenant_id=tenant_id or "default",
        )
        self._history.setdefault(key, []).append(rec)
        return True


LIFECYCLE_MANAGER = ContentLifecycleManager()
