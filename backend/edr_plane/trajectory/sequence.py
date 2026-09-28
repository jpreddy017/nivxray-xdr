"""DT2-2C · the TEMPORAL / CAUSAL SEQUENCE primitive.

DIVISION OF RESPONSIBILITY
--------------------------
`relationships.py` establishes WHAT is related, from evidence only
(`ProcessEdge`, `ActivityEdge`). This module establishes HOW those
already-proven relationships are ORDERED, and exactly WHAT LEVEL of
causality may be claimed about each ordered link.

Nothing here manufactures a relationship. A `SequenceStep` can only
reference an edge that `relationships.py` already produced from evidence,
so there is no code path by which sequencing can invent a graph.

TIME IS NOT ONE VALUE
---------------------
source/observed, ingest, canonicalization and detection time are four
different facts about one observation and are kept as four separate
fields. Ordering uses source/observed time ONLY, and when that is absent
the step is explicitly not orderable rather than silently backfilled
from ingest time.

CAUSALITY IS A CLAIM, AND CLAIMS NEED EVIDENCE
----------------------------------------------
* CAUSAL_EVIDENCE      — the link rests on an existing evidence-backed
                         relationship (parent→child spawn feeding the
                         acting process of the next step).
* ORDERED_OBSERVATION  — both steps are proven to belong to the SAME
                         proven actor, so their order is factual, but
                         neither caused the other.
* CAUSALITY_UNKNOWN    — no evidence-backed link, or not orderable.

Temporal proximity NEVER promotes a link. Two unrelated observations one
millisecond apart stay in two separate sequences.

No behavioral/malicious classification, no ATT&CK, no scoring, no UI, no
database access, no schema change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from . import models as m
from .relationships import ActivityEdge, ProcessEdge

__all__ = [
    "TIME_SOURCE", "TIME_INGEST", "TIME_CANONICALIZED", "TIME_DETECTION",
    "ORDERING_TIME_ABSENT", "SEQUENCE_ORDERING_BASIS",
    "CAUSAL_EVIDENCE", "ORDERED_OBSERVATION", "CAUSALITY_UNKNOWN",
    "CAUSALITY_LEVELS", "EDGE_PROCESS", "EDGE_ACTIVITY",
    "StepTimes", "SequenceStep", "TemporalSequence",
    "step_times", "temporal_sequences",
]

# ── the four times, never collapsed ───────────────────────────────────
TIME_SOURCE = "SOURCE_TIME"
TIME_INGEST = "INGEST_TIME"
TIME_CANONICALIZED = "CANONICALIZATION_TIME"
TIME_DETECTION = "DETECTION_TIME"
ORDERING_TIME_ABSENT = "ORDERING_TIME_ABSENT"

#: Ordering is only ever applied to relationships that are ALREADY proven.
SEQUENCE_ORDERING_BASIS = "OBSERVED_TIME_OF_ALREADY_PROVEN_RELATIONSHIPS"

# ── causality levels ──────────────────────────────────────────────────
CAUSAL_EVIDENCE = "CAUSAL_EVIDENCE"
ORDERED_OBSERVATION = "ORDERED_OBSERVATION"
CAUSALITY_UNKNOWN = "CAUSALITY_UNKNOWN"
CAUSALITY_LEVELS = (CAUSAL_EVIDENCE, ORDERED_OBSERVATION,
                    CAUSALITY_UNKNOWN)

EDGE_PROCESS = "PROCESS_EDGE"
EDGE_ACTIVITY = "ACTIVITY_EDGE"

_REASON_FIRST = (
    "First step of the sequence: there is no preceding relationship, so "
    "no causal claim is made.")
_REASON_CAUSAL = (
    "The preceding relationship is an evidence-backed spawn whose child "
    "process IS the acting process of this step, so the lineage itself "
    "links them.")
_REASON_SAME_ACTOR = (
    "Both steps are bound by evidence to the same acting process, so "
    "their order is factual, but nothing shows one caused the other.")
_REASON_NO_LINK = (
    "No evidence-backed relationship connects the preceding step to this "
    "one; nearness in time is not causality.")
_REASON_NOT_ORDERABLE = (
    "One of the two steps has no source/observed time, so it cannot even "
    "be ordered, let alone claimed as causal.")

Edge = Union[ProcessEdge, ActivityEdge]


def _parse(ts: Any) -> Optional[datetime]:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class StepTimes:
    """Four distinct times about one observation. Never collapsed."""
    source_time: Optional[str] = None
    ingest_time: Optional[str] = None
    canonicalized_time: Optional[str] = None
    detection_time: Optional[str] = None

    @property
    def ordering_time(self) -> Optional[str]:
        """Ordering uses source/observed time ONLY."""
        return self.source_time

    @property
    def ordering_basis(self) -> str:
        return TIME_SOURCE if self.source_time else ORDERING_TIME_ABSENT

    @property
    def orderable(self) -> bool:
        return _parse(self.source_time) is not None

    def to_dict(self) -> Dict[str, Any]:
        return {"source_time": self.source_time,
                "ingest_time": self.ingest_time,
                "canonicalized_time": self.canonicalized_time,
                "detection_time": self.detection_time,
                "ordering_time": self.ordering_time,
                "ordering_basis": self.ordering_basis,
                "orderable": self.orderable}


@dataclass(frozen=True)
class SequenceStep:
    """One already-proven relationship, placed in order.

    `edge` MUST be an existing ProcessEdge or ActivityEdge. The step adds
    ordering and a causality LEVEL; it adds no relationship of its own.
    """
    step_id: str
    edge: Edge
    times: StepTimes
    link_to_previous: str = CAUSALITY_UNKNOWN
    link_reason: str = _REASON_FIRST
    link_basis: Optional[str] = None
    link_evidence_ref: Tuple[m.EvidenceReference, ...] = ()
    previous_step_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.edge, (ProcessEdge, ActivityEdge)):
            raise ValueError(
                "a SequenceStep must reference an EXISTING ProcessEdge or "
                "ActivityEdge; a sequence never manufactures a relationship")
        if self.link_to_previous not in CAUSALITY_LEVELS:
            raise ValueError(
                f"bad causality level {self.link_to_previous!r}")
        if not self.link_reason:
            raise ValueError("a causality level without a WHY is rejected")
        basis = (self.link_basis or "").upper()
        if basis and any(bad in basis for bad in m.FORBIDDEN_BASES):
            raise ValueError(
                f"forbidden link basis {self.link_basis!r}: temporal "
                "proximity is never causality")
        if self.link_to_previous == CAUSAL_EVIDENCE:
            if basis not in m.ACCEPTED_BASES:
                raise ValueError(
                    "CAUSAL_EVIDENCE requires the derivation basis of an "
                    "existing evidence-backed relationship")
            if not self.link_evidence_ref:
                raise ValueError(
                    "CAUSAL_EVIDENCE without evidence_ref is rejected: a "
                    "causal claim must answer WHY IT EXISTS")
            if not self.previous_step_id:
                raise ValueError(
                    "CAUSAL_EVIDENCE must name the step it descends from")

    # ── everything below is delegated, never restated ────────────────
    @property
    def edge_kind(self) -> str:
        return (EDGE_PROCESS if isinstance(self.edge, ProcessEdge)
                else EDGE_ACTIVITY)

    @property
    def actor_process_iid(self) -> Optional[str]:
        """The process the relationship is anchored on."""
        if isinstance(self.edge, ProcessEdge):
            return self.edge.parent.process_iid
        return self.edge.process.process_iid

    @property
    def produced_process_iid(self) -> Optional[str]:
        """The process this relationship brought into existence, if any."""
        if isinstance(self.edge, ProcessEdge):
            return self.edge.child.process_iid
        return None

    @property
    def identity_authority(self) -> str:
        return self.edge.authority

    @property
    def downgraded(self) -> bool:
        if isinstance(self.edge, ProcessEdge):
            return self.edge.parent.downgraded or self.edge.child.downgraded
        return self.edge.downgraded

    @property
    def evidence_ref(self) -> Tuple[m.EvidenceReference, ...]:
        return self.edge.evidence_ref

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "edge_kind": self.edge_kind,
            "edge_id": self.edge.edge_id,
            "relationship_type": self.edge.to_dict()["relationship_type"],
            "actor_process_iid": self.actor_process_iid,
            "produced_process_iid": self.produced_process_iid,
            "derivation_basis": self.edge.derivation_basis,
            "identity_authority": self.identity_authority,
            "downgraded": self.downgraded,
            "times": self.times.to_dict(),
            "link_to_previous": self.link_to_previous,
            "link_reason": self.link_reason,
            "link_basis": self.link_basis,
            "previous_step_id": self.previous_step_id,
            "link_evidence_ref": [
                {"kind": r.kind, "id": r.id, "collection": r.collection,
                 "byte_preserved": r.byte_preserved}
                for r in self.link_evidence_ref],
            "edge": self.edge.to_dict(),
        }


@dataclass(frozen=True)
class TemporalSequence:
    """An ordered run of relationships that are provably connected."""
    sequence_id: str
    endpoint_id: str
    steps: Tuple[SequenceStep, ...]
    root_process_iid: Optional[str] = None
    ordering_basis: str = SEQUENCE_ORDERING_BASIS
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("an empty sequence is not a sequence")
        if self.steps[0].link_to_previous != CAUSALITY_UNKNOWN:
            raise ValueError(
                "the first step has no predecessor and therefore cannot "
                "claim any causality")
        for step in self.steps:
            if step.edge.endpoint_id != self.endpoint_id:
                raise ValueError(
                    "a sequence never spans endpoints")

    @property
    def causality_summary(self) -> Dict[str, int]:
        out = {level: 0 for level in CAUSALITY_LEVELS}
        for step in self.steps[1:]:
            out[step.link_to_previous] += 1
        return out

    @property
    def has_causal_evidence(self) -> bool:
        return self.causality_summary[CAUSAL_EVIDENCE] > 0

    def to_dict(self) -> Dict[str, Any]:
        return {"sequence_id": self.sequence_id,
                "endpoint_id": self.endpoint_id,
                "root_process_iid": self.root_process_iid,
                "ordering_basis": self.ordering_basis,
                "step_count": len(self.steps),
                "causality_summary": self.causality_summary,
                "has_causal_evidence": self.has_causal_evidence,
                "steps": [s.to_dict() for s in self.steps],
                "provenance": dict(self.provenance)}


# ══════════════════════════════════════════════════════════════════════
# construction
# ══════════════════════════════════════════════════════════════════════

def step_times(edge: Edge, extra: Optional[Dict[str, Any]] = None
               ) -> StepTimes:
    """Collect the four times without inventing or merging any of them.

    `extra` is an optional per-observation mapping (ingest_time,
    canonicalized_time, detection_time) supplied by the caller from the
    canonical row. Absent values stay None — they are never backfilled
    from one another.
    """
    prov = dict(edge.provenance or {})
    src = dict(extra or {})

    def pick(*keys: str) -> Optional[str]:
        for key in keys:
            for bag in (src, prov):
                value = bag.get(key)
                if value:
                    return str(value)
        return None

    source = (edge.observed_at
              if edge.time_basis == TIME_SOURCE else None)
    return StepTimes(
        source_time=source or pick("source_time", "observed_time"),
        ingest_time=pick("ingest_time", "ingested_at"),
        canonicalized_time=pick("canonicalized_time", "canonicalization_time"),
        detection_time=pick("detection_time", "detected_at"))


def _link(previous: Optional[SequenceStep], edge: Edge
          ) -> Tuple[str, str, Optional[str],
                     Tuple[m.EvidenceReference, ...], Optional[str]]:
    """Decide the causality level for `edge` following `previous`."""
    if previous is None:
        return CAUSALITY_UNKNOWN, _REASON_FIRST, None, (), None
    actor = (edge.parent.process_iid if isinstance(edge, ProcessEdge)
             else edge.process.process_iid)
    if not previous.times.orderable or not _parse(edge.observed_at):
        return (CAUSALITY_UNKNOWN, _REASON_NOT_ORDERABLE, None, (),
                previous.step_id)
    if previous.produced_process_iid and \
            previous.produced_process_iid == actor:
        return (CAUSAL_EVIDENCE, _REASON_CAUSAL,
                previous.edge.derivation_basis,
                tuple(previous.evidence_ref) + tuple(edge.evidence_ref),
                previous.step_id)
    if previous.actor_process_iid and previous.actor_process_iid == actor:
        return (ORDERED_OBSERVATION, _REASON_SAME_ACTOR, None, (),
                previous.step_id)
    return CAUSALITY_UNKNOWN, _REASON_NO_LINK, None, (), previous.step_id


class _Union:
    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}

    def find(self, key: str) -> str:
        self._parent.setdefault(key, key)
        while self._parent[key] != key:
            key = self._parent[key] = self._parent[self._parent[key]]
        return key

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra


def temporal_sequences(
        process_edges: Iterable[ProcessEdge],
        activity_edges: Iterable[ActivityEdge],
        endpoint_id: str,
        *, times: Optional[Dict[str, Dict[str, Any]]] = None
) -> List[TemporalSequence]:
    """Order already-proven relationships into connected sequences.

    Grouping follows PROVEN process identity only: lineage edges join a
    parent to its child, and an activity edge joins its proven acting
    process. Relationships with no identity in common are never pulled
    into the same sequence, however close together they were observed.
    """
    pedges = [e for e in process_edges if e.endpoint_id == endpoint_id]
    aedges = [e for e in activity_edges if e.endpoint_id == endpoint_id]
    times = times or {}

    groups = _Union()
    for e in pedges:
        groups.union(e.parent.process_iid, e.child.process_iid)
    for e in aedges:
        groups.find(e.process.process_iid)

    children = {e.child.process_iid for e in pedges}
    buckets: Dict[str, List[Edge]] = {}
    for e in pedges:
        buckets.setdefault(groups.find(e.parent.process_iid), []).append(e)
    for e in aedges:
        buckets.setdefault(groups.find(e.process.process_iid), []).append(e)

    def extra_for(edge: Edge) -> Dict[str, Any]:
        key = (edge.provenance or {}).get("source_event_iid")
        return times.get(key, {}) if key else {}

    out: List[TemporalSequence] = []
    for root in sorted(buckets):
        edges = buckets[root]
        timed = [(e, step_times(e, extra_for(e))) for e in edges]
        ordered = sorted(
            [t for t in timed if t[1].orderable],
            key=lambda t: (_parse(t[1].source_time), t[0].edge_id))
        ordered += sorted([t for t in timed if not t[1].orderable],
                          key=lambda t: t[0].edge_id)

        steps: List[SequenceStep] = []
        previous: Optional[SequenceStep] = None
        for index, (edge, st) in enumerate(ordered):
            level, reason, basis, refs, prev_id = _link(previous, edge)
            step = SequenceStep(
                step_id=f"seq:{root}:{index}", edge=edge, times=st,
                link_to_previous=level, link_reason=reason,
                link_basis=basis, link_evidence_ref=refs,
                previous_step_id=prev_id)
            steps.append(step)
            previous = step

        members = {s.actor_process_iid for s in steps} | {
            s.produced_process_iid for s in steps if s.produced_process_iid}
        roots = sorted(p for p in members if p and p not in children)
        out.append(TemporalSequence(
            sequence_id=f"seq:{endpoint_id}:{root}",
            endpoint_id=endpoint_id, steps=tuple(steps),
            root_process_iid=roots[0] if len(roots) == 1 else None,
            provenance={"group_key": root,
                        "member_process_iids": sorted(p for p in members if p),
                        "ambiguous_root": len(roots) != 1}))
    return out
