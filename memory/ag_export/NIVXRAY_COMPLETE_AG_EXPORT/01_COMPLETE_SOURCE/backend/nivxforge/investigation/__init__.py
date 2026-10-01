"""ADR-0014 · Canonical Investigation Object (CIO) module.

The CIO is the single source of truth produced by the Investigation
Engine. It is backed by an Evidence Graph (nodes + typed edges) which
IS the investigation — not adjacent to it. Every UI, report, export,
timeline, and summary reads from the CIO.

Public API (Slice-A):
    - `build_cio(fact_substrate) -> CIO`  · additive composer
    - `CIO`                                · Pydantic root model
    - `EvidenceGraph`                      · nodes + edges
    - `Node`, `Edge`                       · graph primitives
    - `ReasoningStep`                      · replayable decision record
    - `validate_cio(cio, *, legacy=None)` · G1+G2+G3 gate

Governance: ADR-0014, principles §1.1.
"""
from nivxforge.investigation.models import (
    CIO,
    CIOSource,
    ReasoningStep,
)
from nivxforge.investigation.graph import (
    EvidenceGraph,
    Node,
    Edge,
    NodeKind,
    EdgeKind,
)
from nivxforge.investigation.builder import build_cio
from nivxforge.investigation.validators import (
    validate_cio,
    CIOValidationError,
)

__all__ = [
    "CIO",
    "CIOSource",
    "ReasoningStep",
    "EvidenceGraph",
    "Node",
    "Edge",
    "NodeKind",
    "EdgeKind",
    "build_cio",
    "validate_cio",
    "CIOValidationError",
]
