"""
Structural transformation pass · M1 placeholder.

The final implementation (M2) will perform AST reduction, operator
folding, and parentheses collapse. For M1 the pass is a strict no-op
that returns the artifact unchanged and reports ``changed=False``. This
lets the engine's own convergence-loop correctness be certified before
any transformation logic exists.

Contract (spec §Pass Independence Rule):
* Pure function of the current artifact state.
* Deterministic — identical inputs must produce identical outputs.
* No hidden mutable state.
* No decoder-specific side effects.
"""
from __future__ import annotations

from .artifact import Artifact
from .provenance import PassRecord

PASS_NAME = "structural"


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    return artifact, PassRecord(
        name=PASS_NAME,
        changed=False,
        transformations=(),
        notes=("M1 no-op — awaiting M2 implementation",),
    )


__all__ = ["PASS_NAME", "run"]
