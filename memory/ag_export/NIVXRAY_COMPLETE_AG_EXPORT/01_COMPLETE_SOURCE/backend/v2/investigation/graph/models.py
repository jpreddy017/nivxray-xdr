"""Evidence Graph · Phase 5 of the Investigation Brain.

Walks the canonical `Evidence` objects emitted by IU / CRE / RTE /
Intent and produces a homogeneous DAG the analyst can traverse to
answer "why did the Brain reach this conclusion?".

Nodes:
    input, artefact_type, wrapper, transformation, intent, evidence.
Edges:
    derives_from, produces, supports.

Every node carries either a canonical Evidence object or a direct
observation from the pipeline output — nothing is fabricated.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    INPUT           = "input"
    ARTEFACT_TYPE   = "artefact_type"     # IU classification
    WRAPPER         = "wrapper"           # CRE wrapper chain step
    TRANSFORMATION  = "transformation"    # RTE step
    LAYER           = "layer"             # RTE intermediate artefact
    INTENT          = "intent"            # Semantic Intent
    EVIDENCE        = "evidence"          # canonical Evidence citation


class EdgeKind(str, Enum):
    DERIVES_FROM = "derives_from"   # child artefact from parent
    PRODUCES     = "produces"       # step → output artefact
    SUPPORTS     = "supports"       # evidence → conclusion


@dataclass(frozen=True)
class EvidenceNode:
    id:          str
    kind:        NodeKind
    label:       str
    detail:      str = ""
    confidence:  int | None = None
    source:      str = ""
    meta:        dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass(frozen=True)
class EvidenceEdge:
    src:   str
    dst:   str
    kind:  EdgeKind

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind.value}


@dataclass
class EvidenceGraph:
    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


__all__ = [
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceEdge",
    "NodeKind",
    "EdgeKind",
]
