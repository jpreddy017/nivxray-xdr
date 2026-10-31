"""
NivXRay XDR Narration Gateway — Phase 1.

Owner rules baked into the module contract:

  * NivXRay XDR owns narration end-to-end.  The gateway is
    provider-agnostic.  No consumer (UI, PDF report, R46 overlay,
    Attack Story, etc.) may talk to a specific LLM directly.

  * Deterministic narration is MANDATORY and never fails.  If
    every LLM provider is unavailable, exhausted, offline, or
    fails grounding validation, the gateway MUST return
    evidence-grounded prose from the deterministic narrator so
    the platform stays operational and explainable regardless.

  * Same governed facts across providers.  Only wording differs.
    The gateway guarantees identical `evidence_ids`,
    `finding_ids`, `technique_ids`, `entities`, `verdict`,
    `severity` and `confidence` regardless of which provider
    produced the prose.

  * Grounding validator rejects any LLM output that references
    an id/entity/verdict/confidence not present in the supplied
    `NarrationContext`.  Rejection triggers fallback to the next
    provider in the chain.
"""
from .contracts import (
    NarrationKind,
    NarrationContext,
    NarrationRequest,
    NarrationResult,
    GenerationMode,
    GroundingError,
)
from .gateway import NarrationGateway, get_gateway

__all__ = [
    "NarrationKind",
    "NarrationContext",
    "NarrationRequest",
    "NarrationResult",
    "GenerationMode",
    "GroundingError",
    "NarrationGateway",
    "get_gateway",
]
