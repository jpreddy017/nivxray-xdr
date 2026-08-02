"""
Decoder pass · M1 placeholder.

The final implementation (M4) will invoke the deterministic decoder
suite (Base64, UTF-16LE, GZIP, Hex, RC4/XOR). M1 is a strict no-op.
"""
from __future__ import annotations

from .artifact import Artifact
from .provenance import PassRecord

PASS_NAME = "decoder"


def run(artifact: Artifact) -> tuple[Artifact, PassRecord]:
    return artifact, PassRecord(
        name=PASS_NAME,
        changed=False,
        transformations=(),
        notes=("M1 no-op — awaiting M4 implementation",),
    )


__all__ = ["PASS_NAME", "run"]
