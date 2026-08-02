"""
Semantic reconstruction pass · M1 placeholder.

The final implementation (M5) will perform string reassembly, runtime
simplification, and canonical folding. M1 is a strict no-op.
"""
from __future__ import annotations

from .artifact import Artifact
from .provenance import PassRecord

PASS_NAME = "semantic"


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    return artifact, PassRecord(
        name=PASS_NAME,
        changed=False,
        transformations=(),
        notes=("M1 no-op — awaiting M5 implementation",),
    )


__all__ = ["PASS_NAME", "run"]
