"""
Correlation → Verdict / Evidence Graph bridge.

Owner rules (absolute):

  · The existing Verdict Engine remains the sole authority for
    verdict, severity, confidence.  This module DOES NOT compute
    a verdict; it emits governed *inputs* the Verdict Engine can
    consume when it is ready to.
  · Correlation confidence is CORRELATION confidence.  It is
    NEVER passed through as verdict confidence or maliciousness.
  · Every `VerdictInput` retains its canonical_ids, source lane
    set, matching basis (`same_actor`|`same_ip`), temporal
    window and correlation rationale.
  · A correlation hint alone MUST NOT promote an ATT&CK
    technique to OBSERVED.  Emitting an input is a signal — not
    a fact — and the downstream engine is free to reject it.
  · Endpoint-only incidents behave exactly as before because
    this module only emits inputs for cross-lane groups (≥2
    distinct lanes).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

from .correlation import CrossLaneCorrelation


@dataclass(frozen=True)
class VerdictInput:
    """Governed input the existing Verdict Engine can consume.

    The Verdict Engine may choose to weight it or ignore it — we
    do not prescribe.  What we DO prescribe is that the input is
    fully governed: every element traces to a canonical_id and
    the rationale is explicit."""
    kind:              str                       # "cross_lane_correlation"
    correlation_key:   str
    matching_basis:    tuple[str, ...]           # ("same_actor",) / ("same_ip",) / both
    lanes:             tuple[str, ...]
    canonical_ids:     tuple[str, ...]
    actor_id:          str | None
    first_seen:        str | None
    last_seen:         str | None
    correlation_confidence: float                # NOT verdict confidence
    rationale:         str
    # Deliberately no `verdict_confidence`, `severity`, `maliciousness`
    # or `attck_promote` fields.  Those live in the Verdict Engine.


def build_verdict_inputs(
    groups: Iterable[CrossLaneCorrelation],
) -> list[VerdictInput]:
    out: list[VerdictInput] = []
    for g in groups:
        if len(set(g.lanes)) < 2:
            # Endpoint-only incidents get nothing from us — verdict
            # behaviour must be unchanged for those.
            continue
        rationale = _rationale(g)
        out.append(VerdictInput(
            kind                    = "cross_lane_correlation",
            correlation_key         = g.key,
            matching_basis          = g.reasons,
            lanes                   = g.lanes,
            canonical_ids           = g.canonical_ids,
            actor_id                = g.actor_id,
            first_seen              = g.first_seen,
            last_seen               = g.last_seen,
            correlation_confidence  = g.confidence,
            rationale               = rationale,
        ))
    return out


def _rationale(g: CrossLaneCorrelation) -> str:
    basis = " + ".join(g.reasons)
    lanes = ", ".join(g.lanes)
    return (
        f"Cross-lane correlation ({basis}) spans lanes [{lanes}] with "
        f"actor={g.actor_id or 'n/a'} between {g.first_seen} and "
        f"{g.last_seen}.  Correlation confidence "
        f"{g.confidence:.2f} reflects lane spread and event count, NOT "
        f"maliciousness — the Verdict Engine remains authoritative."
    )


# --------------------------------------------------------------------
# Evidence Graph edges — use the existing canonical evidence
# collection so no parallel graph is introduced.  Edges are
# emitted only when a correlation group already exists; we never
# create an edge from timestamp proximity alone.
# --------------------------------------------------------------------
@dataclass(frozen=True)
class EvidenceGraphEdge:
    src_canonical_id: str
    dst_canonical_id: str
    kind:             str                       # e.g. "cross_lane:same_actor"
    correlation_key:  str
    provenance:       dict[str, Any] = field(default_factory=dict)


def build_evidence_graph_edges(
    groups: Iterable[CrossLaneCorrelation],
) -> list[EvidenceGraphEdge]:
    edges: list[EvidenceGraphEdge] = []
    for g in groups:
        cids = list(g.canonical_ids)
        if len(cids) < 2:
            continue
        # Pairwise edges (small groups only; big groups get a hub
        # around the first id to keep O(n) rather than O(n²)).
        hub = cids[0]
        for cid in cids[1:]:
            edges.append(EvidenceGraphEdge(
                src_canonical_id = hub,
                dst_canonical_id = cid,
                kind             = "cross_lane:" + "+".join(g.reasons),
                correlation_key  = g.key,
                provenance       = {
                    "matching_basis":         list(g.reasons),
                    "lanes":                  list(g.lanes),
                    "correlation_confidence": g.confidence,
                    "first_seen":             g.first_seen,
                    "last_seen":              g.last_seen,
                    # Never fabricate a specific ATT&CK edge;
                    # attribution lives in AttackTechniqueEvidence.
                    "attck_promotion":        False,
                },
            ))
    return edges


def to_dict(v: VerdictInput | EvidenceGraphEdge) -> dict[str, Any]:
    return asdict(v)
