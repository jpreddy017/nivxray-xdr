"""
Content normalization pass · M1 placeholder.

The final implementation (M3) will handle environment-variable
expansion, quote/backtick cleanup, and constant folding. M1 is a
strict no-op (see structural.py for the contract).
"""
from __future__ import annotations

from .artifact import Artifact
from .provenance import PassRecord

PASS_NAME = "content"


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    return artifact, PassRecord(
        name=PASS_NAME,
        changed=False,
        transformations=(),
        notes=("M1 no-op — awaiting M3 implementation",),
    )


__all__ = ["PASS_NAME", "run"]
