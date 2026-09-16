"""Handler Protocol — ADR-0001.

Every future handler must implement this Protocol and carry the
`HandlerMetadata` that ties it back to the ADR and the evidence that
justified its existence. No handler is registered in ADR-0001 itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Protocol, runtime_checkable

from nivxforge.core.cio import CIO
from nivxforge.framework.classifier import Artifact, Shape


@dataclass(frozen=True)
class HandlerMetadata:
    """Traceability record — every handler carries one.

    Fields:
        name           — handler name (matches CIO provenance).
        adr            — ADR filename that authorised this handler.
        evidence_count — number of real cases that justified the handler.
        first_seen     — ISO date of the earliest supporting case.
        last_seen      — ISO date of the latest supporting case.
        confidence     — post-implementation validation confidence 0.0–1.0.
        regression_tests — list of test node ids that pin this handler.
    """
    name: str
    adr: str
    evidence_count: int
    first_seen: str
    last_seen: str
    confidence: float
    regression_tests: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.name:
            raise ValueError("HandlerMetadata.name is required")
        if not self.adr:
            raise ValueError("HandlerMetadata.adr is required — every handler MUST cite its ADR")
        if self.evidence_count < 1:
            raise ValueError("HandlerMetadata.evidence_count must be ≥ 1 (Charter Rule 3)")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("HandlerMetadata.confidence must be in [0, 1]")


@runtime_checkable
class Handler(Protocol):
    """A family-specific processor. Reads Artifact + Shape, writes CIO."""

    metadata: HandlerMetadata
    family: str

    def process(self, artifact: Artifact, shape: Shape, cio: CIO) -> CIO:
        ...
