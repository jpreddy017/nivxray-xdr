"""Contracts 8 & 9 · Response Command and Response Result.

Directive §10, the rule that makes these two contracts necessary rather
than convenient:

    REQUEST → AUTHORIZATION → POLICY → APPROVAL → DISPATCH
     → ENDPOINT ACK → EXECUTION → TELEMETRY → VERIFICATION
     → SECURITY STATE ↺

    Never report success without endpoint evidence.

`ResponseResult.status` therefore CANNOT be set to SUCCEEDED. The only way
to reach a successful terminal state is `VERIFIED`, and `verify()` refuses
to grant it without a verification evidence reference. A driverless action
returns `DRIVER_NOT_REGISTERED` — which is why the console renders
`⊘ RESPONSE DRIVER NOT REGISTERED` instead of a green tick.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from .epistemic import EvidenceModel, evidence_field


class ResponseAction(str, Enum):
    """Directive §10 + §11. Every action the endpoint control plane may be
    asked to perform."""
    ISOLATE = "ISOLATE"
    RELEASE_ISOLATION = "RELEASE_ISOLATION"
    KILL_PROCESS = "KILL_PROCESS"
    KILL_PROCESS_TREE = "KILL_PROCESS_TREE"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    DELETE_FILE = "DELETE_FILE"
    RESTORE_FILE = "RESTORE_FILE"
    SCAN = "SCAN"
    FETCH_FILE = "FETCH_FILE"
    REMOVE_PERSISTENCE = "REMOVE_PERSISTENCE"
    REMEDIATE = "REMEDIATE"
    APPLICATION_CONTROL = "APPLICATION_CONTROL"
    NETWORK_BLOCK = "NETWORK_BLOCK"
    FORENSIC_SNAPSHOT = "FORENSIC_SNAPSHOT"
    LIVE_QUERY = "LIVE_QUERY"
    RESTART_AGENT = "RESTART_AGENT"
    REFRESH_POLICY = "REFRESH_POLICY"
    MOVE_GROUP = "MOVE_GROUP"
    DIAGNOSE = "DIAGNOSE"
    REMOTE_UNINSTALL = "REMOTE_UNINSTALL"


class PolicyMode(str, Enum):
    """Directive §9.3. AUDIT is a REAL detection with a real alert and real
    telemetry — it is simply not an enforcement."""
    AUDIT = "AUDIT"
    PROTECT = "PROTECT"
    PREVENT = "PREVENT"


class EnforcementAction(str, Enum):
    NONE = "NONE"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    TERMINATE = "TERMINATE"
    QUARANTINE = "QUARANTINE"
    ISOLATE = "ISOLATE"


class EnforcementResult(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    DISPATCHED = "DISPATCHED"
    ACKED = "ACKED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"


class ResponseLifecycle(str, Enum):
    """The §10 loop as explicit states. There is deliberately no
    `SUCCEEDED`: an action that executed but was not confirmed by endpoint
    telemetry sits at `UNVERIFIED`, which is the honest answer."""
    REQUESTED = "REQUESTED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    POLICY_EVALUATION = "POLICY_EVALUATION"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    DISPATCHED = "DISPATCHED"
    ENDPOINT_ACKED = "ENDPOINT_ACKED"
    EXECUTING = "EXECUTING"
    EXECUTED_UNVERIFIED = "EXECUTED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    DRIVER_NOT_REGISTERED = "DRIVER_NOT_REGISTERED"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"


#: Terminal states. Note that only VERIFIED is a success.
RESPONSE_TERMINAL = frozenset({
    ResponseLifecycle.AUTHORIZATION_DENIED, ResponseLifecycle.POLICY_BLOCKED,
    ResponseLifecycle.APPROVAL_DENIED, ResponseLifecycle.VERIFIED,
    ResponseLifecycle.FAILED, ResponseLifecycle.EXPIRED,
    ResponseLifecycle.DRIVER_NOT_REGISTERED,
    ResponseLifecycle.CAPABILITY_UNAVAILABLE,
})

#: Legal transitions. Enforced by ResponseResult.advance() so nothing can
#: jump from REQUESTED straight to VERIFIED and claim a closed loop.
RESPONSE_TRANSITIONS: dict[ResponseLifecycle, tuple[ResponseLifecycle, ...]] = {
    ResponseLifecycle.REQUESTED: (
        ResponseLifecycle.AUTHORIZATION_PENDING,
        ResponseLifecycle.DRIVER_NOT_REGISTERED,
        ResponseLifecycle.CAPABILITY_UNAVAILABLE),
    ResponseLifecycle.AUTHORIZATION_PENDING: (
        ResponseLifecycle.POLICY_EVALUATION,
        ResponseLifecycle.AUTHORIZATION_DENIED),
    ResponseLifecycle.POLICY_EVALUATION: (
        ResponseLifecycle.APPROVAL_PENDING, ResponseLifecycle.DISPATCHED,
        ResponseLifecycle.POLICY_BLOCKED),
    ResponseLifecycle.APPROVAL_PENDING: (
        ResponseLifecycle.DISPATCHED, ResponseLifecycle.APPROVAL_DENIED,
        ResponseLifecycle.EXPIRED),
    ResponseLifecycle.DISPATCHED: (
        ResponseLifecycle.ENDPOINT_ACKED, ResponseLifecycle.FAILED,
        ResponseLifecycle.EXPIRED),
    ResponseLifecycle.ENDPOINT_ACKED: (
        ResponseLifecycle.EXECUTING, ResponseLifecycle.FAILED),
    ResponseLifecycle.EXECUTING: (
        ResponseLifecycle.EXECUTED_UNVERIFIED, ResponseLifecycle.FAILED),
    ResponseLifecycle.EXECUTED_UNVERIFIED: (
        ResponseLifecycle.VERIFIED, ResponseLifecycle.FAILED),
}


class ResponseCommand(BaseModel):
    """Contract 8. The REQUEST. Carries no result and no claim of outcome."""
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    command_id: str
    tenant_id: str
    endpoint_id: str
    action: ResponseAction

    target_process_iid: Optional[str] = None
    target_file_sha256: Optional[str] = None
    target_path: Optional[str] = None
    target_remote_ip: Optional[str] = None
    parameters: dict = Field(default_factory=dict)

    requested_by: str
    requested_at: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    policy_id: Optional[str] = None
    policy_mode: PolicyMode = PolicyMode.AUDIT
    playbook_id: Optional[str] = None
    detection_ref: Optional[str] = None
    incident_ref: Optional[str] = None

    requires_approval: bool = True
    reason: str = Field(description="Why this action is being requested. "
                                    "Recorded verbatim in the audit ledger.")
    expires_at: Optional[str] = None

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()


class ResponseResult(EvidenceModel):
    """Contract 9. The OUTCOME, with the §10 loop enforced.

    `verification_evidence_ref` is the endpoint telemetry that proves the
    action took effect. Without it there is no VERIFIED state, and
    therefore no success claim.
    """
    result_id: str
    command_id: str
    tenant_id: str
    endpoint_id: str
    action: ResponseAction

    status: ResponseLifecycle = ResponseLifecycle.REQUESTED
    enforcement_action: EnforcementAction = EnforcementAction.NONE
    enforcement_result: EnforcementResult = EnforcementResult.NOT_ATTEMPTED

    driver_id: Optional[str] = evidence_field(
        description="The registered response driver that executed this. "
                    "Absent means no driver exists — the honest reason the "
                    "console shows ⊘ RESPONSE DRIVER NOT REGISTERED.")
    dispatched_at: Optional[str] = evidence_field()
    acked_at: Optional[str] = evidence_field()
    executed_at: Optional[str] = evidence_field()
    verified_at: Optional[str] = evidence_field()
    verification_evidence_ref: Optional[str] = evidence_field(
        description="event_id of the endpoint telemetry that PROVES the "
                    "action took effect. Mandatory for VERIFIED.")

    failure_reason: Optional[str] = evidence_field()
    transitions: list[dict] = Field(default_factory=list)

    def advance(self, to: ResponseLifecycle, *, at: str | None = None,
                note: str | None = None) -> "ResponseResult":
        current = ResponseLifecycle(self.status)
        allowed = RESPONSE_TRANSITIONS.get(current, ())
        if to not in allowed:
            raise ValueError(
                f"illegal response transition {current.value} -> {to.value}. "
                f"Legal: {[a.value for a in allowed] or 'none (terminal)'}. "
                f"Directive §10 forbids skipping the loop.")
        self.transitions.append({
            "from": current.value, "to": to.value,
            "at": at or ResponseCommand.now(), "note": note})
        self.status = to
        return self

    def verify(self, *, evidence_ref: str, at: str | None = None
               ) -> "ResponseResult":
        """The ONLY route to a success claim."""
        if not evidence_ref:
            raise ValueError(
                "cannot verify a response without endpoint evidence. "
                "Directive §10: never report success without endpoint "
                "evidence.")
        self.advance(ResponseLifecycle.VERIFIED, at=at,
                     note=f"verified by {evidence_ref}")
        self.verification_evidence_ref = evidence_ref
        self.verified_at = at or ResponseCommand.now()
        self.enforcement_result = EnforcementResult.VERIFIED
        self.field_states["verification_evidence_ref"] = "OBSERVED"
        self.field_states["verified_at"] = "OBSERVED"
        return self

    @property
    def succeeded(self) -> bool:
        return (ResponseLifecycle(self.status) == ResponseLifecycle.VERIFIED
                and bool(self.verification_evidence_ref))
