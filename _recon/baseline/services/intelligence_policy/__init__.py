"""NivXRay XDR Intelligence Policy — hierarchical governance layer.

Architecture (locked 2026-09-02):

    MSS/Tenant Global Policy
            ↓
    Incident Policy Override
            ↓
    Effective Intelligence Policy
            ↓
    Model Gateway
            ↓
    Provider Selection

Absolute rules:

  · Global policy is the CEILING.  An incident may only NARROW it.
    An incident MUST NEVER bypass a global restriction.
  · Offline AI, Offline LLM and the NivXRay XDR Narration Engine
    are ALWAYS AVAILABLE.  There is no OFF switch.  Their toggle
    slot exists only as a HEALTH readout.
  · Online AI is the master permission for cloud/online AI.  When
    Online AI is OFF, Online LLM is automatically unavailable
    regardless of its own switch.
  · AI/LLM policy MUST NOT change the deterministic security core
    (canonical evidence, correlation, verdict engine, ATT&CK
    evidence, incident, timeline, provenance, audit, response
    policy evaluation) — those remain fully operational.
  · In-flight narration requests complete under the policy that
    existed when they started.  New requests use the newly
    changed policy.  A policy snapshot is captured at request
    start.
"""
from .service import (
    IntelligencePolicy, EffectivePolicy, PolicySnapshot,
    IntelligencePolicyService,
    default_global_policy, default_incident_override,
    resolve_effective, capture_snapshot,
)

__all__ = [
    "IntelligencePolicy", "EffectivePolicy", "PolicySnapshot",
    "IntelligencePolicyService",
    "default_global_policy", "default_incident_override",
    "resolve_effective", "capture_snapshot",
]
