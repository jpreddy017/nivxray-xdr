"""v2/investigation — the Investigation Knowledge Graph (IKG) and the
Investigation builder. See ikg.py and builder.py for details.

Additive to v2. Feature-flagged behind NIVX_FLAG_VERDICT_ENGINE_V3.
"""
from .ikg import (
    InvestigationKnowledgeGraph, Node, Edge,
    VALID_NODE_TYPES, VALID_EDGE_TYPES,
)
from .builder import (
    Investigation, build_investigation, ENGINE_VERSION,
)

__all__ = [
    "InvestigationKnowledgeGraph", "Node", "Edge",
    "VALID_NODE_TYPES", "VALID_EDGE_TYPES",
    "Investigation", "build_investigation", "ENGINE_VERSION",
]
