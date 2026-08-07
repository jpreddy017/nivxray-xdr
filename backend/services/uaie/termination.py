"""UAIE Contract #8 · Fixed-Point Termination Certificate  (Rule R28.4)

Answers the question that a "queue-empty" stop cannot:

    "How do I know there is absolutely nothing left to investigate?"

After the main investigation loop drains its queue, the orchestrator
runs a final AUDIT pass over the entire investigation graph:

    for every artifact in the graph:
        for every registered recognizer:
            did this recognizer already speak on this artifact?
        for every registered capability:
            was this capability applied to this artifact?
        for every registered validator (matching the artifact's type):
            did this validator already diagnose this artifact?
        for every UNREACHABLE artifact:
            has every registered repair strategy for its diagnosed
            failure reason already been attempted?

If any of the above returns "no, and it COULD still have run", the
investigation is NOT at a fixed point.  The audit records exactly
which remaining transitions exist and the loop is invited to resume
(future iterations).  If no remaining transitions exist, the
Termination Certificate declares the investigation MATHEMATICALLY
COMPLETE — every deterministic avenue of discovery was exhausted.

The certificate is analyst-visible via
``ssot.termination_certificate`` and preserved in the immutable SSOT
store so the six-month reconstructability invariant (R28.2) covers
completeness proofs, not just artifact identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import Any, Dict, List


# ══════════════════════════════════════════════════════════════════
# Data contract
# ══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class RemainingTransition:
    """One deterministic action that COULD still be applied to the
    graph but wasn't.  If any of these exist, ``fixed_point`` is
    False and the analyst knows exactly why."""
    artifact_uri:  str
    actor:         str           # recognizer/capability/validator/repair name
    kind:          str           # "recognizer" · "capability" · "validator" · "repair"
    reason:        str = ""      # free-text: why we think this could still fire


@dataclass(frozen=True)
class TerminationCertificate:
    """The mathematical proof (or refutation) that the investigation
    has reached its fixed point.

    ``fixed_point=True`` means: replaying the same input on the same
    registry state would produce zero additional artifacts, evidence,
    repairs, validations, or state changes.  This is the invariant
    that separates a deterministic investigation engine from an
    orchestrated decoder pipeline.
    """
    fixed_point:                bool
    artifacts_examined:         int
    recognizers_checked:        int    # (artifact × recognizer) pairs evaluated
    capabilities_checked:       int    # (artifact × capability) pairs evaluated
    validators_checked:         int    # (artifact × validator)  pairs evaluated
    repair_strategies_checked:  int    # (unreachable_artifact × strategy) pairs evaluated
    remaining_transitions:      List[RemainingTransition] = field(default_factory=list)
    reason:                     str = ""
    # Roll-up counters for at-a-glance analyst summary.
    counts: Dict[str, int] = field(default_factory=dict)


CERT_REASON_FIXED_POINT = (
    "No deterministic action can derive additional artifacts, "
    "evidence, repairs, validations, or state changes."
)


__all__ = [
    "RemainingTransition",
    "TerminationCertificate",
    "CERT_REASON_FIXED_POINT",
]
