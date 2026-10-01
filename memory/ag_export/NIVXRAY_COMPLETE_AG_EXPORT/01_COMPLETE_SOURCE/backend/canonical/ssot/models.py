"""Canonical SSOT dataclasses (ADR-005 §4.1 minimum information).

Structure enforces ADR-005 §4.3 authoritative-vs-projection boundary
as a code-level split:

    Authoritative tier          Projection tier (empty in Phase 2)
    ─────────────────────       ────────────────────────────────
    input_raw                   activity{}
    input_profile               iocs{}
    input_health                threat_intel{}
    iue_decision                attck{}
    plan                        attack_chain[]
    execution_trace             attack_story
    artifacts (recursive)       verdict
    evidence_graph              recommendations[]
    reasoning_steps             analyst_summary
    context.historical          executive_summary
    provenance                  reports{}
    metadata                    timeline[]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Provenance envelope (D3-z) ───────────────────────────────────────────
@dataclass
class Provenance:
    """Mandatory envelope on every appended entry (ADR-005 §4.2)."""
    engine: str
    version: str
    at: str
    upstream_evidence_ids: List[str] = field(default_factory=list)


# ── Source metadata ──────────────────────────────────────────────────────
@dataclass
class Source:
    surface: str = ""                       # 'workspace' | 'document' | 'api' | ...
    endpoint: str = ""                      # canonical entry route (informational)
    correlation_id: str = ""
    session_id: Optional[str] = None
    channel: str = ""                       # 'workspace_paste' | 'document_reinvestigate' | ...


# ── Evidence Graph ───────────────────────────────────────────────────────
@dataclass
class GraphNode:
    id: str
    kind: str                                # 'input' | 'artifact' | 'ioc' | 'process' | ...
    label: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[Provenance] = None


@dataclass
class GraphEdge:
    id: str
    from_node_id: str
    to_node_id: str
    kind: str                                # 'parent_of' | 'derived_from' | 'evidences' | ...
    attrs: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[Provenance] = None


@dataclass
class EvidenceGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)


# ── Reasoning step (D3-z decision-level provenance) ──────────────────────
@dataclass
class ReasoningStep:
    id: str
    rule: str
    rationale: str
    input_evidence_ids: List[str] = field(default_factory=list)
    output_evidence_ids: List[str] = field(default_factory=list)
    provenance: Optional[Provenance] = None


# ── Artifact (recursive via ssot_ref, D6-r) ──────────────────────────────
@dataclass
class Artifact:
    id: str
    kind: str
    label: str
    parent_evidence_id: Optional[str] = None
    investigation_ref: Optional[str] = None  # ssot_ref (D6-r)
    attrs: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[Provenance] = None


# ── Execution trace ──────────────────────────────────────────────────────
@dataclass
class ExecutionStep:
    step_id: str
    capability: str                          # Capability.value string
    engine: str
    status: str                              # 'planned' | 'executed' | 'skipped' | 'budget_exhausted' | 'error'
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    output_evidence_ids: List[str] = field(default_factory=list)
    notes: str = ""
    provenance: Optional[Provenance] = None


# ── Historical context ───────────────────────────────────────────────────
@dataclass
class HistoricalItem:
    kind: str                                # 'prior_case' | 'same_host_recent' | ...
    ref: str
    matched_at: str = ""
    attrs: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[Provenance] = None


@dataclass
class ContextBucket:
    historical: List[HistoricalItem] = field(default_factory=list)


# ── Projection tier — EMPTY in Phase 2 (Phase 4 populates) ───────────────
@dataclass
class ActivityProjection:
    processes: List[Dict[str, Any]] = field(default_factory=list)
    files: List[Dict[str, Any]] = field(default_factory=list)
    network: List[Dict[str, Any]] = field(default_factory=list)
    registry: List[Dict[str, Any]] = field(default_factory=list)
    auth: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IOCProjection:
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    hashes: Dict[str, List[str]] = field(default_factory=dict)  # {'md5': [...], 'sha1': [...], 'sha256': [...]}
    files: List[str] = field(default_factory=list)
    registry: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    bitcoin_addresses: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelProjection:
    hits: List[Dict[str, Any]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    enrichment_status: str = "not_run"


@dataclass
class AttckProjection:
    techniques: List[Dict[str, Any]] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    kill_chain: List[str] = field(default_factory=list)


@dataclass
class VerdictProjection:
    label: str = ""
    confidence: int = 0
    reason: str = ""
    contributors: List[Dict[str, Any]] = field(default_factory=list)
    input_completeness: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportsProjection:
    stix: Optional[Dict[str, Any]] = None
    sigma: Optional[Dict[str, Any]] = None
    yara: Optional[Dict[str, Any]] = None
    navigator: Optional[Dict[str, Any]] = None
    mdr: Optional[Dict[str, Any]] = None
