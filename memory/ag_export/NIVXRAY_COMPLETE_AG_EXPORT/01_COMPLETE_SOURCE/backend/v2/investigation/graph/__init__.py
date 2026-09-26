"""Evidence Graph — homogeneous DAG over the canonical Evidence
primitive. Consumed by the Workspace UI to answer "why did the
Brain reach this conclusion?"."""
from __future__ import annotations

from .builder import build
from .models import (
    EdgeKind,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)

__all__ = [
    "build",
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceEdge",
    "NodeKind",
    "EdgeKind",
]
