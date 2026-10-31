"""Wave 0 · the twelve executable NivXForge EDR contracts.

Directive §15 Wave 0 requires these twelve, and requires them EXECUTABLE
rather than documented:

  1. Endpoint Identity            → identity.EndpointIdentity
  2. Telemetry Schema             → telemetry.EndpointEvidence
  3. Process Identity             → identity.ProcessIdentity
  4. File Identity                → identity.FileIdentity
  5. Network Identity             → identity.NetworkIdentity
  6. Event Identity               → identity.EventIdentity
  7. Evidence Identity            → identity.EvidenceIdentity
  8. Response Command             → response.ResponseCommand
  9. Response Result              → response.ResponseResult
 10. Telemetry Health             → health.TelemetryHealthContract
 11. Capability Registry         → ..capability.model.Capability
 12. Sensor Capability Registry  → ..capability.model.SensorCapability

Every contract is built on ``epistemic.EvidenceModel``, which makes it
impossible to persist a null evidence field without stating WHY it is
null. That is the whole point of Wave 0: the honesty is enforced by the
type system, not by reviewer discipline.
"""
from .epistemic import (
    EpistemicState, Verdict, EvidenceSufficiency, TelemetryHealth,
    DetectionExecution, EvidenceModel, evidence_field,
    FORBIDDEN_EQUIVALENCES, EPISTEMIC_ABSENT,
)
from .identity import (
    EndpointIdentity, ProcessIdentity, FileIdentity, NetworkIdentity,
    EventIdentity, EvidenceIdentity, RegistryIdentity,
)
from .telemetry import EndpointEvidence, ActivityType, Platform
from .response import (
    ResponseCommand, ResponseResult, ResponseAction, PolicyMode,
    EnforcementAction, EnforcementResult, ResponseLifecycle,
)
from .health import TelemetryHealthContract, AgentLifecycle

CONTRACTS = {
    "endpoint_identity":           EndpointIdentity,
    "telemetry_schema":            EndpointEvidence,
    "process_identity":            ProcessIdentity,
    "file_identity":               FileIdentity,
    "network_identity":            NetworkIdentity,
    "event_identity":              EventIdentity,
    "evidence_identity":           EvidenceIdentity,
    "response_command":            ResponseCommand,
    "response_result":             ResponseResult,
    "telemetry_health":            TelemetryHealthContract,
}

__all__ = [
    "EpistemicState", "Verdict", "EvidenceSufficiency", "TelemetryHealth",
    "DetectionExecution", "EvidenceModel", "evidence_field",
    "FORBIDDEN_EQUIVALENCES", "EPISTEMIC_ABSENT",
    "EndpointIdentity", "ProcessIdentity", "FileIdentity",
    "NetworkIdentity", "EventIdentity", "EvidenceIdentity",
    "RegistryIdentity", "EndpointEvidence", "ActivityType", "Platform",
    "ResponseCommand", "ResponseResult", "ResponseAction", "PolicyMode",
    "EnforcementAction", "EnforcementResult", "ResponseLifecycle",
    "TelemetryHealthContract", "AgentLifecycle", "CONTRACTS",
]
