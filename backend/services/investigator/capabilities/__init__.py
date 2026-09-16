"""Round 32 · NivXRay XDR · Capability Fabric v1.

The Capability Fabric is the specialist-engine layer behind the
Autonomous Investigator.  Each capability answers ONE investigation
question, evidence-safely.

Boundary (owner-locked):
  * Capabilities never fabricate findings.
  * Every capability declares its evidence requirements; the selector
    honestly skips a pivot when the evidence is unavailable
    (§13 · Evidence sufficiency).
  * Findings are traceable to canonical evidence via ``evidence_refs``.
  * IUE → Autonomous Investigator → Capability Fabric → new evidence
    → IKG → IUE remains the closed loop.  Capabilities never bypass
    IUE and never override the Verdict Engine.
"""
from services.investigator.capabilities.base import (  # noqa: F401
    Capability, EvidenceSufficiency, register_capability,
    get_capability, all_capabilities,
)
from services.investigator.capabilities import registry  # noqa: F401


# Seed the registry (idempotent) so imports auto-populate.
registry.seed()
