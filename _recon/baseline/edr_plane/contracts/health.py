"""Contract 10 · Telemetry Health — binds the directive to what already ships.

This contract does NOT reimplement health. `services/edr/endpoint_health.py`
already computes the two independent dimensions and is closed and tested
(P0-A.1, iteration_88). This file is the CONTRACT over it.

It exists to resolve one real discrepancy honestly rather than silently:

  * Directive §7 names a 6-state TELEMETRY dimension:
    HEALTHY · DEGRADED · MISSING · PARSER_FAILED · NOT_CONFIGURED · STALE
  * The shipped resolver produces a 9-state NivXRay dimension:
    ONLINE · DEGRADED · STALE · NO_TELEMETRY · AGENT_ERROR · PARSER_ERROR
    · ISOLATED · UNENROLLED · NEVER_ENROLLED

The 9-state set is strictly FINER — it distinguishes "never enrolled" from
"revoked" from "intentionally isolated", all three of which the 6-state set
would flatten to MISSING. Flattening them would lose exactly the
information an analyst needs, so the 9-state set stays authoritative and
this module publishes a lossy DOWN-projection to the directive vocabulary,
clearly labelled as lossy. Nothing consumes the projection to make a
decision; it exists for directive-conformance reporting.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .epistemic import EvidenceSufficiency, TelemetryHealth


class AgentLifecycle(str, Enum):
    """Dimension A. Operational state of the agent link. Mirrors
    `services/edr/endpoint_health.LIFECYCLE` verbatim — one source of
    truth, re-declared here only so the contract is self-describing."""
    INITIALIZING = "INITIALIZING"
    PROVISIONING = "PROVISIONING"
    PROVISIONING_FAILED_RETRYING = "PROVISIONING_FAILED_RETRYING"
    REGISTERING = "REGISTERING"
    REGISTRATION_FAILED_RETRYING = "REGISTRATION_FAILED_RETRYING"
    CONNECTING = "CONNECTING"
    CONNECTION_FAILED_RETRYING = "CONNECTION_FAILED_RETRYING"
    CONNECTED = "CONNECTED"
    DISABLED = "DISABLED"
    DISCONNECTED_RETRYING = "DISCONNECTED_RETRYING"
    OFFLINE = "OFFLINE"
    NO_AGENT = "NO_AGENT"


class NivxTelemetryHealth(str, Enum):
    """Dimension B, authoritative 9-state form."""
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    NO_TELEMETRY = "NO_TELEMETRY"
    AGENT_ERROR = "AGENT_ERROR"
    PARSER_ERROR = "PARSER_ERROR"
    ISOLATED = "ISOLATED"
    UNENROLLED = "UNENROLLED"
    NEVER_ENROLLED = "NEVER_ENROLLED"


#: Lossy down-projection to the directive §7 vocabulary. Every entry loses
#: information; that is why it is not used for decisions.
TO_DIRECTIVE_TELEMETRY: dict[NivxTelemetryHealth, TelemetryHealth] = {
    NivxTelemetryHealth.ONLINE:         TelemetryHealth.HEALTHY,
    NivxTelemetryHealth.DEGRADED:       TelemetryHealth.DEGRADED,
    NivxTelemetryHealth.STALE:          TelemetryHealth.STALE,
    NivxTelemetryHealth.NO_TELEMETRY:   TelemetryHealth.MISSING,
    NivxTelemetryHealth.AGENT_ERROR:    TelemetryHealth.DEGRADED,
    NivxTelemetryHealth.PARSER_ERROR:   TelemetryHealth.PARSER_FAILED,
    NivxTelemetryHealth.ISOLATED:       TelemetryHealth.NOT_CONFIGURED,
    NivxTelemetryHealth.UNENROLLED:     TelemetryHealth.NOT_CONFIGURED,
    NivxTelemetryHealth.NEVER_ENROLLED: TelemetryHealth.NOT_CONFIGURED,
}


class HealthDimension(BaseModel):
    model_config = ConfigDict(extra="allow")
    state: str
    reason: str


class TelemetryHealthContract(BaseModel):
    """The two dimensions, side by side, NEVER collapsed.

    There is deliberately no `overall` / `status` / `healthy` field. A
    single summary field is what would let a CONNECTED-but-silent agent
    read as an all-clear, and adding one would defeat the contract.
    """
    model_config = ConfigDict(extra="allow")

    endpoint_id: Optional[str] = None
    agent_lifecycle: HealthDimension
    telemetry_health: HealthDimension
    evidence_sufficiency: EvidenceSufficiency = EvidenceSufficiency.UNKNOWN
    directive_telemetry_state: Optional[TelemetryHealth] = Field(
        default=None,
        description="Lossy §7 down-projection. Reporting only — never a "
                    "decision input.")
    visibility_state: Optional[str] = None
    visibility_statement: Optional[str] = None
    dimensions_note: str = (
        "agent_lifecycle and telemetry_health are independent and are never "
        "collapsed into one status. A CONNECTED agent can be NO_TELEMETRY, "
        "and an OFFLINE agent can still have SUFFICIENT historic evidence.")

    @classmethod
    def from_resolver(cls, resolved: dict[str, Any], *,
                      endpoint_id: str | None = None
                      ) -> "TelemetryHealthContract":
        """Adapt the shipped `resolve_endpoint_health()` output. The
        resolver stays authoritative; this only types it."""
        life = resolved.get("agent_lifecycle") or {}
        tele = resolved.get("telemetry_health") or {}
        vis = resolved.get("visibility") or {}
        nivx = tele.get("state")
        projected = None
        if nivx in NivxTelemetryHealth.__members__:
            projected = TO_DIRECTIVE_TELEMETRY[NivxTelemetryHealth(nivx)]
        suff = tele.get("evidence_sufficiency") or "UNKNOWN"
        return cls(
            endpoint_id=endpoint_id,
            agent_lifecycle=HealthDimension(
                state=life.get("state", "NO_AGENT"),
                reason=life.get("reason", "not resolved")),
            telemetry_health=HealthDimension(
                state=nivx or "NO_TELEMETRY",
                reason=tele.get("reason", "not resolved")),
            evidence_sufficiency=EvidenceSufficiency(
                suff if suff in EvidenceSufficiency.__members__ else "UNKNOWN"),
            directive_telemetry_state=projected,
            visibility_state=vis.get("state"),
            visibility_statement=vis.get("statement"),
        )
