"""DT2-2D · the BEHAVIORAL RELATIONSHIP primitive.

LAYERING (each layer may only read the one above it)
----------------------------------------------------
    canonical evidence
        → DT2-2A  ProcessEdge          (process ↔ process)
        → DT2-2B  ActivityEdge         (process ↔ dns/network/file/registry)
        → DT2-2C  TemporalSequence     (ordering + causality LEVEL)
        → DT2-2D  BehavioralRelationship  ← this module

A `BehavioralRelationship` is a STRUCTURAL statement about several
already-proven sequence steps. It is not a judgement about intent. It
references step ids and re-uses the evidence those steps already carry;
it cannot mint evidence, an edge, a process or a time of its own.

TRUTH LEVEL IS EPISTEMIC STRENGTH, NOT SUSPICION
------------------------------------------------
* OBSERVED   — one directly evidence-backed relationship, ProcessGuid-proven.
* DERIVED    — several steps joined by proven causality (lineage).
* CORRELATED — the join rests on ordering, or on a PID-based surrogate
               identity, so it is NOT direct observation. CORRELATED says
               nothing whatsoever about intent.
* INFERRED   — reserved for a future analytics producer. Defined here,
               deliberately UNUSED: constructing it requires naming an
               inference producer, and no producer exists yet.

CORRELATED and INFERRED are never serialized as OBSERVED: the truth level
travels with the object and `asserts_direct_observation` is a computed
property, not a caller-supplied flag.

No scoring, no ATT&CK, no severity, no verdict, no ML/UEBA, no beaconing,
persistence, credential or lateral classification. No UI, no database
access, no schema change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import models as m
from . import sequence as sq
from .relationships import ActivityEdge, ProcessEdge

__all__ = [
    "TRUTH_OBSERVED", "TRUTH_DERIVED", "TRUTH_CORRELATED",
    "TRUTH_INFERRED", "TRUTH_LEVELS", "TRUTH_DIRECT_EVIDENCE",
    "BEHAVIOR_PROCESS_CHAIN", "BEHAVIOR_EXECUTION_TO_DNS",
    "BEHAVIOR_EXECUTION_TO_NETWORK", "BEHAVIOR_EXECUTION_TO_FILE",
    "BEHAVIOR_EXECUTION_TO_REGISTRY", "BEHAVIOR_TYPES",
    "BEHAVIOR_BY_FAMILY", "FORBIDDEN_PROVENANCE_KEYS",
    "BehavioralRelationship", "behaviors", "behaviors_of",
]

# ── truth levels ──────────────────────────────────────────────────────
TRUTH_OBSERVED = "OBSERVED"
TRUTH_DERIVED = "DERIVED"
TRUTH_CORRELATED = "CORRELATED"
TRUTH_INFERRED = "INFERRED"
TRUTH_LEVELS = (TRUTH_OBSERVED, TRUTH_DERIVED, TRUTH_CORRELATED,
                TRUTH_INFERRED)
#: Levels that rest on evidence or on proven causality between evidence.
TRUTH_DIRECT_EVIDENCE = (TRUTH_OBSERVED, TRUTH_DERIVED)

# ── the only behavior types that exist at this stage ──────────────────
BEHAVIOR_PROCESS_CHAIN = "PROCESS_CHAIN"
BEHAVIOR_EXECUTION_TO_DNS = "EXECUTION_TO_DNS"
BEHAVIOR_EXECUTION_TO_NETWORK = "EXECUTION_TO_NETWORK"
BEHAVIOR_EXECUTION_TO_FILE = "EXECUTION_TO_FILE"
BEHAVIOR_EXECUTION_TO_REGISTRY = "EXECUTION_TO_REGISTRY"
BEHAVIOR_TYPES = (BEHAVIOR_PROCESS_CHAIN, BEHAVIOR_EXECUTION_TO_DNS,
                  BEHAVIOR_EXECUTION_TO_NETWORK,
                  BEHAVIOR_EXECUTION_TO_FILE,
                  BEHAVIOR_EXECUTION_TO_REGISTRY)

BEHAVIOR_BY_FAMILY = {"DNS": BEHAVIOR_EXECUTION_TO_DNS,
                      "NETWORK": BEHAVIOR_EXECUTION_TO_NETWORK,
                      "FILE": BEHAVIOR_EXECUTION_TO_FILE,
                      "REGISTRY": BEHAVIOR_EXECUTION_TO_REGISTRY}

#: Provenance keys that would smuggle a judgement into a structural
#: object. Rejected at construction so the boundary cannot erode.
FORBIDDEN_PROVENANCE_KEYS = (
    "severity", "score", "threat_score", "verdict", "disposition",
    "malicious", "suspicious", "mitre", "attack", "technique",
    "confidence_score", "ml", "ueba", "beaconing", "persistence",
    "credential_access", "lateral_movement")

_WHY_ACTIVITY_OBSERVED = (
    "The process→{family} relationship is directly evidence-backed by the "
    "canonical observation itself and both sides are ProcessGuid-proven, "
    "so this is OBSERVED and asserts nothing beyond that evidence.")
_WHY_ACTIVITY_CORRELATED = (
    "The process→{family} relationship is real, but its acting process is "
    "identified by a PID-based surrogate rather than a ProcessGuid, so the "
    "binding to that process instance is a correlation and is NOT "
    "presented as direct observation. This says nothing about intent.")
_WHY_CHAIN_DERIVED = (
    "Every hop of this chain is an evidence-backed parent→child spawn "
    "whose child is the parent of the next hop, so the chain is DERIVED "
    "from proven lineage. It is a structural relationship only and "
    "carries no judgement about intent.")
_WHY_CHAIN_CORRELATED = (
    "The chain is built from evidence-backed spawns, but at least one hop "
    "identifies a process by a PID-based surrogate, so the join across "
    "that hop is a correlation rather than proof and is NOT presented as "
    "direct observation. This says nothing about intent.")


@dataclass(frozen=True)
class BehavioralRelationship:
    """A structural behavior over already-proven sequence steps."""
    behavior_id: str
    endpoint_id: str
    behavior_type: str
    truth_level: str
    process_iids: Tuple[str, ...]
    step_ids: Tuple[str, ...]
    evidence_ref: Tuple[m.EvidenceReference, ...]
    reason: str
    identity_authority: str
    downgraded: bool
    link_levels: Tuple[str, ...] = ()
    derivation_bases: Tuple[str, ...] = ()
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    time_basis: str = sq.TIME_SOURCE
    sequence_id: Optional[str] = None
    inference_producer: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.behavior_type not in BEHAVIOR_TYPES:
            raise ValueError(
                f"unsupported behavior_type {self.behavior_type!r}: only "
                "the structural DT2-2D behaviors exist at this stage")
        if self.truth_level not in TRUTH_LEVELS:
            raise ValueError(f"bad truth_level {self.truth_level!r}")
        if not self.step_ids:
            raise ValueError(
                "a behavior MUST reference existing sequence step ids; a "
                "behavior with no steps is not derived from anything")
        if not self.process_iids:
            raise ValueError(
                "a behavior needs at least one participating process")
        if not self.evidence_ref:
            raise ValueError(
                "behavior without evidence_ref is rejected: it must answer "
                "WHY IT EXISTS, using the evidence its steps already carry")
        if not self.reason:
            raise ValueError("a behavior without a stated WHY is rejected")
        if self.identity_authority not in m.AUTHORITIES:
            raise ValueError("bad identity_authority")
        for level in self.link_levels:
            if level not in sq.CAUSALITY_LEVELS:
                raise ValueError(f"bad causality level {level!r}")
        for basis in self.derivation_bases:
            if any(bad in basis.upper() for bad in m.FORBIDDEN_BASES):
                raise ValueError(
                    f"forbidden derivation basis {basis!r}: temporal "
                    "proximity is never behavioral authority")
            if basis not in m.ACCEPTED_BASES:
                raise ValueError(f"unrecognised derivation basis {basis}")
        for key in self.provenance:
            if key.lower() in FORBIDDEN_PROVENANCE_KEYS:
                raise ValueError(
                    f"provenance key {key!r} is a judgement, not structure; "
                    "DT2-2D emits no scoring, severity or classification")
        if self.behavior_type == BEHAVIOR_PROCESS_CHAIN and (
                len(self.step_ids) < 2 or len(self.process_iids) < 3):
            raise ValueError(
                "PROCESS_CHAIN needs at least two spawn steps and three "
                "processes; a single spawn is already the DT2-2A edge")

        if self.truth_level == TRUTH_OBSERVED:
            if len(self.step_ids) != 1 or self.link_levels:
                raise ValueError(
                    "OBSERVED may only describe ONE directly evidence-"
                    "backed step; anything joined across steps is DERIVED "
                    "or CORRELATED")
            if self.downgraded:
                raise ValueError(
                    "a downgraded (PID-surrogate) identity cannot be "
                    "presented as OBSERVED")
        elif self.truth_level == TRUTH_DERIVED:
            if len(self.step_ids) < 2:
                raise ValueError("DERIVED must join at least two steps")
            if any(lv != sq.CAUSAL_EVIDENCE for lv in self.link_levels):
                raise ValueError(
                    "DERIVED requires every join to be CAUSAL_EVIDENCE; "
                    "ordering alone is CORRELATED")
            if self.downgraded:
                raise ValueError(
                    "a chain containing a PID-surrogate identity is "
                    "CORRELATED, not DERIVED")
        elif self.truth_level == TRUTH_CORRELATED:
            if not self.downgraded and not any(
                    lv != sq.CAUSAL_EVIDENCE for lv in self.link_levels):
                raise ValueError(
                    "CORRELATED must state what weakens it: a non-causal "
                    "join or a downgraded identity")
        else:                                      # INFERRED
            if not self.inference_producer:
                raise ValueError(
                    "INFERRED requires a named inference producer; DT2-2D "
                    "has none, so INFERRED is defined but unused")
        if self.start_time and self.end_time \
                and self.end_time < self.start_time:
            raise ValueError("behavior end_time precedes its start_time")

    @property
    def asserts_direct_observation(self) -> bool:
        """Computed, never caller-supplied. CORRELATED/INFERRED are False."""
        return self.truth_level == TRUTH_OBSERVED

    @property
    def evidence_backed(self) -> bool:
        return self.truth_level in TRUTH_DIRECT_EVIDENCE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "behavior_id": self.behavior_id,
            "endpoint_id": self.endpoint_id,
            "behavior_type": self.behavior_type,
            "truth_level": self.truth_level,
            "asserts_direct_observation": self.asserts_direct_observation,
            "evidence_backed": self.evidence_backed,
            "process_iids": list(self.process_iids),
            "step_ids": list(self.step_ids),
            "link_levels": list(self.link_levels),
            "derivation_bases": list(self.derivation_bases),
            "identity_authority": self.identity_authority,
            "downgraded": self.downgraded,
            "reason": self.reason,
            "start_time": self.start_time, "end_time": self.end_time,
            "time_basis": self.time_basis,
            "sequence_id": self.sequence_id,
            "inference_producer": self.inference_producer,
            "evidence_ref": [
                {"kind": r.kind, "id": r.id, "collection": r.collection,
                 "byte_preserved": r.byte_preserved}
                for r in self.evidence_ref],
            "provenance": dict(self.provenance),
        }


# ══════════════════════════════════════════════════════════════════════
# derivation over an EXISTING TemporalSequence
# ══════════════════════════════════════════════════════════════════════

_AUTH_RANK = {m.AUTHORITY_AUTHORITATIVE: 0, m.AUTHORITY_DERIVED: 1,
              m.AUTHORITY_UNSTABLE: 2, m.AUTHORITY_UNKNOWN: 3}


def _weakest(steps: Iterable[sq.SequenceStep]) -> str:
    return max((s.identity_authority for s in steps),
               key=lambda a: _AUTH_RANK[a])


def _span(steps: List[sq.SequenceStep]
          ) -> Tuple[Optional[str], Optional[str]]:
    times = sorted(s.times.source_time for s in steps
                   if s.times.source_time)
    return (times[0], times[-1]) if times else (None, None)


def _refs(steps: Iterable[sq.SequenceStep]
          ) -> Tuple[m.EvidenceReference, ...]:
    """Re-use the steps' own evidence. Nothing is manufactured."""
    out: List[m.EvidenceReference] = []
    seen = set()
    for step in steps:
        for ref in step.evidence_ref:
            key = (ref.kind, ref.id)
            if key not in seen:
                seen.add(key)
                out.append(ref)
    return tuple(out)


def _activity_behavior(sequence: sq.TemporalSequence,
                       step: sq.SequenceStep
                       ) -> Optional[BehavioralRelationship]:
    family = step.edge.activity.family
    behavior_type = BEHAVIOR_BY_FAMILY.get(family)
    if behavior_type is None:                 # unsupported stays unsupported
        return None
    downgraded = step.downgraded
    level = TRUTH_CORRELATED if downgraded else TRUTH_OBSERVED
    why = (_WHY_ACTIVITY_CORRELATED if downgraded
           else _WHY_ACTIVITY_OBSERVED).format(family=family)
    start, end = _span([step])
    return BehavioralRelationship(
        behavior_id=f"beh:{sequence.endpoint_id}:{behavior_type}:"
                    f"{step.edge.edge_id}",
        endpoint_id=sequence.endpoint_id, behavior_type=behavior_type,
        truth_level=level,
        process_iids=(step.actor_process_iid,),
        step_ids=(step.step_id,), evidence_ref=step.evidence_ref,
        reason=why, identity_authority=step.identity_authority,
        downgraded=downgraded,
        derivation_bases=(step.edge.derivation_basis,),
        start_time=start, end_time=end, sequence_id=sequence.sequence_id,
        provenance={"activity_family": family,
                    "activity_label": step.edge.activity.label,
                    "step_link_to_previous": step.link_to_previous,
                    "step_link_basis": step.link_basis})


def _chains(spawns: List[sq.SequenceStep]
            ) -> List[List[sq.SequenceStep]]:
    """Maximal lineage paths of two or more evidence-backed spawn steps."""
    by_parent: Dict[str, List[sq.SequenceStep]] = {}
    for step in spawns:
        by_parent.setdefault(step.actor_process_iid, []).append(step)
    children = {s.produced_process_iid for s in spawns}
    roots = sorted(p for p in by_parent if p not in children)

    out: List[List[sq.SequenceStep]] = []

    def walk(path: List[sq.SequenceStep], seen: set) -> None:
        tail = path[-1].produced_process_iid
        nexts = [s for s in by_parent.get(tail, ())
                 if s.produced_process_iid not in seen]
        if not nexts:
            if len(path) >= 2:
                out.append(list(path))
            return
        for step in sorted(nexts, key=lambda s: s.edge.edge_id):
            walk(path + [step], seen | {step.produced_process_iid})

    for root in roots:
        for step in sorted(by_parent[root], key=lambda s: s.edge.edge_id):
            walk([step], {root, step.produced_process_iid})
    return out


def _chain_behavior(sequence: sq.TemporalSequence,
                    path: List[sq.SequenceStep]) -> BehavioralRelationship:
    downgraded = any(s.downgraded for s in path)
    level = TRUTH_CORRELATED if downgraded else TRUTH_DERIVED
    why = _WHY_CHAIN_CORRELATED if downgraded else _WHY_CHAIN_DERIVED
    # Each hop is a proven parent→child join: exactly the DT2-2C
    # CAUSAL_EVIDENCE rule, restated from the edges themselves.
    levels = tuple([sq.CAUSAL_EVIDENCE] * (len(path) - 1))
    processes = (path[0].actor_process_iid,) + tuple(
        s.produced_process_iid for s in path)
    start, end = _span(path)
    return BehavioralRelationship(
        behavior_id=f"beh:{sequence.endpoint_id}:"
                    f"{BEHAVIOR_PROCESS_CHAIN}:{'>'.join(processes)}",
        endpoint_id=sequence.endpoint_id,
        behavior_type=BEHAVIOR_PROCESS_CHAIN, truth_level=level,
        process_iids=processes,
        step_ids=tuple(s.step_id for s in path),
        evidence_ref=_refs(path), reason=why,
        identity_authority=_weakest(path), downgraded=downgraded,
        link_levels=levels,
        derivation_bases=tuple(dict.fromkeys(
            s.edge.derivation_basis for s in path)),
        start_time=start, end_time=end, sequence_id=sequence.sequence_id,
        provenance={"hop_count": len(path),
                    "edge_ids": [s.edge.edge_id for s in path],
                    "step_link_levels": [s.link_to_previous
                                         for s in path]})


def behaviors_of(sequence: sq.TemporalSequence
                 ) -> List[BehavioralRelationship]:
    """Derive structural behaviors from ONE already-built sequence."""
    out: List[BehavioralRelationship] = []
    spawns = [s for s in sequence.steps
              if isinstance(s.edge, ProcessEdge)]
    for path in _chains(spawns):
        out.append(_chain_behavior(sequence, path))
    for step in sequence.steps:
        if isinstance(step.edge, ActivityEdge):
            behavior = _activity_behavior(sequence, step)
            if behavior is not None:
                out.append(behavior)
    return out


def behaviors(sequences: Iterable[sq.TemporalSequence]
              ) -> List[BehavioralRelationship]:
    """Derive structural behaviors from already-built sequences.

    Sequences are never merged here, so two unrelated observations that
    happened to be close in time cannot be fused into one behavior: they
    were already separated by DT2-2C on PROVEN identity.
    """
    out: List[BehavioralRelationship] = []
    for sequence in sequences:
        out.extend(behaviors_of(sequence))
    return out
