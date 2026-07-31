"""ADR-0014 · Canonical Investigation Object (CIO) — Pydantic schema (v0.1).

The CIO is the single product of the Investigation Engine. It is
backed by an Evidence Graph (see `graph.py`) and carries a stream of
ReasoningSteps recording every decision the engine made.

Slice-A scope: minimum viable CIO — root object + Source + ReasoningStep
placeholder. Verdict, summary, and reports are populated by later slices
(B / C / D).

Governance: ADR-0014 §1.1 principles 1, 2, 6, 7, 8.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field

from nivxforge.investigation.graph import EvidenceGraph


# ─── ReasoningStep (ADR-0014 §3) ────────────────────────────────────────

class ReasoningStep(BaseModel):
    """One replayable decision recorded by the Investigation Engine.

    Enables replay, debugging, explainability, analyst audit, training
    data, and LLM context — one structure covers all seven use cases
    (§1.1 principle 7).
    """
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(..., description="Dense monotonic id within the CIO, e.g. 'RS-001'.")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule: str = Field(..., description="Internal rule identifier — never surfaced to prose.")
    input_nodes: List[str] = Field(default_factory=list, description="Graph node ids this step read.")
    output_nodes: List[str] = Field(default_factory=list, description="Graph node ids this step produced.")
    confidence_before: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_after: float = Field(default=0.0, ge=0.0, le=1.0)
    explanation: str = Field(default="", description="Analyst-facing humanised explanation.")


# ─── Source & metadata ──────────────────────────────────────────────────

class CIOSource(BaseModel):
    """Where the investigation was initiated from."""
    model_config = ConfigDict(extra="forbid")

    surface: str = Field(default="api", description="'lab' | 'workspace' | 'api' | 'cli' | ...")
    endpoint: Optional[str] = None
    correlation_id: Optional[str] = None


# ─── CIO root (ADR-0014 §1 tree) ────────────────────────────────────────

class CIO(BaseModel):
    """Canonical Investigation Object · ADR-0014.

    Slice-A minimum viable shape. Later slices populate `verdict`,
    `summary`, `reports`, and enrich `reasoning_steps`.
    """
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"] = "0.1"
    cio_id: str = Field(..., description="Unique CIO id (uuid-derived).")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: CIOSource

    # ── input & artifacts ────────────────────────────────────────────
    input_text: str = Field(default="", description="Raw input under investigation.")
    input_kind: str = Field(default="text", description="Detected input kind (input-agnostic principle §1.1.8).")
    artifacts: List[Dict[str, Any]] = Field(default_factory=list, description="Attached artifacts (files/logs); Slice-A leaves empty.")

    # ── decode chain (readable projection over graph decoded_fragment nodes) ──
    decode_chain: List[Dict[str, Any]] = Field(default_factory=list)

    # ── the graph IS the investigation (§1.1.2) ──────────────────────
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)

    # ── ReasoningStep stream (§1.1.7 · Slice-B enriches) ─────────────
    reasoning_steps: List[ReasoningStep] = Field(default_factory=list)

    # ── aggregate confidence ────────────────────────────────────────
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # ── verdict placeholder (Slice-C populates) ─────────────────────
    verdict: Optional[Dict[str, Any]] = Field(default=None, description="Populated by Slice-C Reasoning Engine unification.")

    # ── timeline placeholder (Slice-B derives from reasoning_steps) ──
    timeline: List[Dict[str, Any]] = Field(default_factory=list)

    # ── summary placeholder (Slice-D populates: artifact/incident/executive) ──
    summary: Dict[str, Any] = Field(default_factory=dict)

    # ── recommendations placeholder ─────────────────────────────────
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)

    # ── reports placeholder (Slice-F: STIX/Navigator/MDR views) ──────
    reports: Dict[str, Any] = Field(default_factory=dict)

    # ── metadata (§1.1.6 · additive migration provenance) ────────────
    metadata: Dict[str, Any] = Field(default_factory=dict)


__all__ = ["CIO", "CIOSource", "ReasoningStep"]
