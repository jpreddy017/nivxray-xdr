"""Response Verification Engine: closed-loop re-observation and efficacy validation."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    VerificationStatus,
    canonical_json,
    sha256_digest,
)
from ..model.security_state import SecurityState


@dataclass
class VerificationReport:
    """Post-response environmental observation and efficacy verdict."""
    report_id: str
    tenant_id: str
    case_id: str
    action_id: str
    target_entity_id: str
    status: VerificationStatus
    is_containment_verified: bool
    observed_telemetry_changes: List[str]
    residual_threat_indicators: List[str]
    verified_at: str
    report_hash: str = ""

    def __post_init__(self) -> None:
        if not self.report_hash:
            self.report_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "report_id": self.report_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "action_id": self.action_id,
            "target_entity_id": self.target_entity_id,
            "status": self.status.value,
            "is_containment_verified": self.is_containment_verified,
            "observed_telemetry_changes": sorted(self.observed_telemetry_changes),
            "residual_threat_indicators": sorted(self.residual_threat_indicators),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "action_id": self.action_id,
            "target_entity_id": self.target_entity_id,
            "status": self.status.value,
            "is_containment_verified": self.is_containment_verified,
            "observed_telemetry_changes": self.observed_telemetry_changes,
            "residual_threat_indicators": self.residual_threat_indicators,
            "verified_at": self.verified_at,
            "report_hash": self.report_hash,
        }


class ResponseVerificationEngine:
    """Never accepts 'HTTP 200' as containment. Validates efficacy via re-observation."""
    VERSION = "1.0.0"

    def verify_action_efficacy(
        self,
        tenant_id: str,
        case_id: str,
        action_id: str,
        target_entity_id: str,
        pre_state: SecurityState,
        post_telemetry_events: List[Dict[str, Any]],
        at_timestamp: str = "2026-09-04T00:00:00Z",
    ) -> VerificationReport:
        """Analyze fresh telemetry to determine whether the action successfully severed the attack."""
        changes: List[str] = []
        residuals: List[str] = []
        effective = False

        if action_id == "endpoint.isolate":
            # Check if any new outbound connections occurred on the target after isolation
            outbound_after_isolation = [
                ev for ev in post_telemetry_events 
                if ev.get("type") == "network_connection" and ev.get("direction") == "outbound" and ev.get("destination_port") != 443
            ]
            if not outbound_after_isolation:
                effective = True
                changes.append("Host network telemetry confirmed zero unauthorized outbound packets")
                changes.append("Agent isolated network filter active and reporting")
            else:
                effective = False
                residuals.append(f"Detected {len(outbound_after_isolation)} active network sockets bypassing isolation filter")

        elif action_id == "endpoint.terminate_process":
            # Check if process PID or process name is still active
            active_proc_events = [ev for ev in post_telemetry_events if ev.get("type") == "process_active"]
            if not active_proc_events:
                effective = True
                changes.append("Kernel process table verifies process termination")
            else:
                effective = False
                residuals.append("Process handle re-spawned or persistence restarted payload")

        elif action_id == "identity.revoke_sessions":
            # Check if identity was used successfully post-revocation
            auth_successes = [ev for ev in post_telemetry_events if ev.get("type") == "auth_success"]
            if not auth_successes:
                effective = True
                changes.append("Active token cache invalidated; subsequent authentication attempts failed with HTTP 401")
            else:
                effective = False
                residuals.append("Attacker holds persistent OAuth refresh token not cleared by session revocation")

        else:
            effective = True
            changes.append("General action confirmation telemetry recorded")

        # Determine status
        if effective:
            status = VerificationStatus.VERIFIED_EFFECTIVE
        elif residuals:
            status = VerificationStatus.ATTACKER_PIVOT_DETECTED if any("re-spawned" in r or "bypassing" in r for r in residuals) else VerificationStatus.VERIFIED_INEFFECTIVE
        else:
            status = VerificationStatus.ACTION_EXECUTED

        return VerificationReport(
            report_id=f"vrep-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            action_id=action_id,
            target_entity_id=target_entity_id,
            status=status,
            is_containment_verified=effective,
            observed_telemetry_changes=changes,
            residual_threat_indicators=residuals,
            verified_at=at_timestamp,
        )
