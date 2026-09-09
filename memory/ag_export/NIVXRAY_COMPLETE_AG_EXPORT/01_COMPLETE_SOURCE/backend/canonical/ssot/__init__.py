"""Canonical SSOT — Phase 2 (D2-d authoritative tier + D6-r store).

Public API:
    from canonical.ssot import (
        AuthoritativeSSOT,
        SSOTStore,
        make_ssot_ref,
        SSOTRef,
        SCHEMA_VERSION,
    )

Phase 2 constraint: **additive only**. No existing SSOT touched, no
projection populated (Phase 4 territory), no route consumes this yet.
"""
from .authoritative import AuthoritativeSSOT, SCHEMA_VERSION
from .models import (
    Artifact,
    EvidenceGraph,
    ExecutionStep,
    GraphEdge,
    GraphNode,
    HistoricalItem,
    Provenance,
    ReasoningStep,
    Source,
    # Projection scaffolds (empty in Phase 2 per §5 of the spec)
    ActivityProjection,
    AttckProjection,
    IOCProjection,
    ReportsProjection,
    ThreatIntelProjection,
    VerdictProjection,
)
from .ssot_ref import SSOTRef, make_ssot_ref, validate_ref
from .store import SSOTStore, InMemorySSOTStore

__all__ = [
    "AuthoritativeSSOT",
    "SCHEMA_VERSION",
    "Artifact",
    "EvidenceGraph",
    "ExecutionStep",
    "GraphEdge",
    "GraphNode",
    "HistoricalItem",
    "Provenance",
    "ReasoningStep",
    "Source",
    "ActivityProjection",
    "AttckProjection",
    "IOCProjection",
    "ReportsProjection",
    "ThreatIntelProjection",
    "VerdictProjection",
    "SSOTRef",
    "make_ssot_ref",
    "validate_ref",
    "SSOTStore",
    "InMemorySSOTStore",
]
