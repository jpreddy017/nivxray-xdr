"""
Workspace Convergence Engine — Phase 5.5 · Path C.

M1 · Convergence Loop Framework (this file).
Later milestones will populate the four transformation passes; M1
establishes only the deterministic iterative loop, the Canonical State
Contract check, the max-depth safeguard, and the Convergence
Certificate emission plumbing. No transformations are performed by M1 —
every pass is a no-op that returns the artifact unchanged. This is a
deliberate design point: the loop's own correctness must be provable
BEFORE any transformation logic is introduced.

Entrypoint::

    from workspace.convergence import converge, Artifact
    result = converge(Artifact.from_input(raw_input))

The engine is intentionally location-independent (per the spec
§"Architectural principles"). It has no dependency on FastAPI, no
dependency on the Workspace router, and no dependency on any decoder
implementation. Every function is pure.
"""
from .engine import (
    ConvergenceResult,
    MAX_ITERATION_DEPTH,
    converge,
)
from .artifact import Artifact
from .certificate import ConvergenceCertificate
from .provenance import IterationRecord, PassRecord

__all__ = [
    "Artifact",
    "ConvergenceCertificate",
    "ConvergenceResult",
    "IterationRecord",
    "MAX_ITERATION_DEPTH",
    "PassRecord",
    "converge",
]
