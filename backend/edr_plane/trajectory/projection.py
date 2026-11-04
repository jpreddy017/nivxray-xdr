"""DT2-2E · the DEVICE TRAJECTORY GRAPH projection contract.

This is a COMPOSITION layer, not another engine. It owns no relationship
logic, no coverage logic and no behavioral logic. It calls what already
exists and arranges it into the exact shape the AMP-class Process /
Relationship Timeline has to render:

    DT2-0 `contract.build`  → identities, coverage, availability, ranges,
                              detections, focus resolution
    DT2-2A `process_edges`  → parent → child
    DT2-2B `activity_edges` → process → DNS / NETWORK / FILE / REGISTRY
    DT2-2C `temporal_sequences` → order + causality LEVEL + split times
    DT2-2D `behaviors`      → structural behavioral relationships
                              ↓
                        TrajectoryGraph

Target shape:

    WINWORD.EXE
      └── spawned → powershell.exe
                      ├── DNS      → domain
                      ├── NETWORK  → IP:443
                      ├── FILE     → payload.dll
                      ├── REGISTRY → key
                      └── spawned  → rundll32.exe

RULES CARRIED FORWARD, NOT RE-DECIDED
-------------------------------------
* Every edge here IS a DT2-2A/2B edge: the client never derives an edge.
* Coverage/availability are re-exported from DT2-0 byte-for-byte. If
  DT2-0 could not prove absence, the graph stays UNKNOWN; an empty lane
  is never rendered as "nothing happened".
* A process lifeline is an EVIDENCE SPAN, never a process lifetime:
  `end_time` is always None while termination evidence is unavailable.
* Times stay split: source/observed, ingest, canonicalization, detection.
* Nothing here reads or writes a database, and no route is wired.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import behavior as bh
from . import contract as c
from . import models as m
from . import relationships as rel
from . import sequence as sq

__all__ = [
    "GRAPH_CONTRACT_VERSION", "NODE_PROCESS", "NODE_ACTIVITY",
    "PRESENCE_OBSERVED", "PRESENCE_REFERENCED",
    "LIFELINE_BASIS", "END_STATE_UNAVAILABLE",
    "ProcessNode", "ActivityNode", "GraphEdge", "TrajectoryGraph",
    "process_node_id", "activity_node_id", "build_graph",
]

GRAPH_CONTRACT_VERSION = "dt2.2e"

NODE_PROCESS = "PROCESS"
NODE_ACTIVITY = "ACTIVITY"

#: A process that has its own canonical observation in the window, versus
#: one that exists only because a child named it as its parent. Both are
#: real; only the first has its own evidence row.
PRESENCE_OBSERVED = "OBSERVED_IN_WINDOW"
PRESENCE_REFERENCED = "REFERENCED_BY_CHILD_EVIDENCE_ONLY"

LIFELINE_BASIS = "EVIDENCE_SPAN_NOT_PROCESS_LIFETIME"
END_STATE_UNAVAILABLE = "PROCESS_END_EVIDENCE_UNAVAILABLE"

_FOCUS_BY_REF_KIND = {"RAW_EVENT": "raw_event_id",
                      "CANONICAL_EVENT": "canonical_event_id",
                      "OBSERVATION": "observation_id"}


def process_node_id(process_iid: str) -> str:
    return f"pnode:{process_iid}"


def activity_node_id(process_iid: str, activity_id: str) -> str:
    return f"anode:{process_iid}:{activity_id}"


def _refs(refs: Iterable[m.EvidenceReference]) -> List[Dict[str, Any]]:
    return [{"kind": r.kind, "id": r.id, "collection": r.collection,
             "byte_preserved": r.byte_preserved} for r in refs]


def _evidence_focus(refs: Iterable[m.EvidenceReference]
                    ) -> List[Dict[str, str]]:
    """Exact evidence pivots, validated through the DT2-0 focus vocabulary."""
    out: List[Dict[str, str]] = []
    for ref in refs:
        kind = _FOCUS_BY_REF_KIND.get(ref.kind)
        if not kind:
            continue
        target = m.FocusTarget(kind=kind, value=ref.id)
        out.append({"kind": target.kind, "value": target.value})
    return out


@dataclass(frozen=True)
class ProcessNode:
    """A process instance as the timeline renders it."""
    node_id: str
    process_iid: str
    endpoint_id: str
    node_type: str = NODE_PROCESS
    label: Optional[str] = None
    image: Optional[str] = None
    pid: Optional[int] = None
    process_guid: Optional[str] = None
    user: Optional[str] = None
    command_line: Optional[str] = None
    identity_authority: str = m.AUTHORITY_UNKNOWN
    identity_basis: Optional[str] = None
    downgraded: bool = True
    presence: str = PRESENCE_OBSERVED
    depth: int = 0
    parent_process_iid: Optional[str] = None
    parent_node_id: Optional[str] = None
    parent_state: Optional[str] = None
    child_node_ids: Tuple[str, ...] = ()
    activity_node_ids: Tuple[str, ...] = ()
    lifeline: Dict[str, Any] = field(default_factory=dict)
    evidence_ref: Tuple[m.EvidenceReference, ...] = ()
    focus_targets: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.process_iid:
            raise ValueError("a process node needs a process identity")
        if self.lifeline.get("end_time") is not None:
            raise ValueError(
                "a lifeline end_time is a termination claim; without "
                "termination evidence it must stay None")

    @property
    def expandable(self) -> bool:
        return bool(self.child_node_ids or self.activity_node_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {"node_id": self.node_id, "node_type": self.node_type,
                "process_iid": self.process_iid,
                "endpoint_id": self.endpoint_id,
                "label": self.label, "image": self.image, "pid": self.pid,
                "process_guid": self.process_guid, "user": self.user,
                "command_line": self.command_line,
                "identity_authority": self.identity_authority,
                "identity_basis": self.identity_basis,
                "downgraded": self.downgraded, "presence": self.presence,
                "depth": self.depth,
                "parent_process_iid": self.parent_process_iid,
                "parent_node_id": self.parent_node_id,
                "parent_state": self.parent_state,
                "child_node_ids": list(self.child_node_ids),
                "activity_node_ids": list(self.activity_node_ids),
                "expandable": self.expandable,
                "lifeline": dict(self.lifeline),
                "evidence_ref": _refs(self.evidence_ref),
                "focus_targets": dict(self.focus_targets),
                "provenance": dict(self.provenance)}


@dataclass(frozen=True)
class ActivityNode:
    """A DNS / NETWORK / FILE / REGISTRY object attached to one process."""
    node_id: str
    endpoint_id: str
    family: str
    label: str
    process_iid: str
    process_node_id: str
    edge_id: str
    step_id: Optional[str] = None
    node_type: str = NODE_ACTIVITY
    kind: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    times: Dict[str, Any] = field(default_factory=dict)
    identity_authority: str = m.AUTHORITY_UNKNOWN
    downgraded: bool = True
    evidence_ref: Tuple[m.EvidenceReference, ...] = ()
    focus_targets: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.family not in rel.ACTIVITY_FAMILIES:
            raise ValueError(f"unsupported activity family {self.family!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {"node_id": self.node_id, "node_type": self.node_type,
                "endpoint_id": self.endpoint_id, "family": self.family,
                "label": self.label, "kind": self.kind,
                "attributes": dict(self.attributes),
                "process_iid": self.process_iid,
                "process_node_id": self.process_node_id,
                "edge_id": self.edge_id, "step_id": self.step_id,
                "times": dict(self.times),
                "identity_authority": self.identity_authority,
                "downgraded": self.downgraded,
                "evidence_ref": _refs(self.evidence_ref),
                "focus_targets": dict(self.focus_targets)}


@dataclass(frozen=True)
class GraphEdge:
    """A server-derived edge, rendered exactly as DT2-2A/2B produced it."""
    edge_id: str
    endpoint_id: str
    relationship_type: str
    source_node_id: str
    target_node_id: str
    derivation_basis: str
    reason: str
    authority: str
    downgraded: bool
    times: Dict[str, Any] = field(default_factory=dict)
    step_id: Optional[str] = None
    sequence_id: Optional[str] = None
    link_to_previous: Optional[str] = None
    previous_step_id: Optional[str] = None
    evidence_ref: Tuple[m.EvidenceReference, ...] = ()
    focus_targets: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_ref:
            raise ValueError(
                "a rendered edge without evidence_ref is rejected: the "
                "client never gets an edge it cannot justify")
        if not self.reason:
            raise ValueError("a rendered edge must carry its WHY")
        if self.derivation_basis not in m.ACCEPTED_BASES:
            raise ValueError(
                f"unrecognised derivation_basis {self.derivation_basis!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {"edge_id": self.edge_id, "endpoint_id": self.endpoint_id,
                "relationship_type": self.relationship_type,
                "source_node_id": self.source_node_id,
                "target_node_id": self.target_node_id,
                "derivation_basis": self.derivation_basis,
                "reason": self.reason, "authority": self.authority,
                "downgraded": self.downgraded, "times": dict(self.times),
                "step_id": self.step_id, "sequence_id": self.sequence_id,
                "link_to_previous": self.link_to_previous,
                "previous_step_id": self.previous_step_id,
                "evidence_ref": _refs(self.evidence_ref),
                "focus_targets": dict(self.focus_targets),
                "provenance": dict(self.provenance)}


@dataclass(frozen=True)
class TrajectoryGraph:
    """The whole render contract for one endpoint window."""
    endpoint_id: str
    process_nodes: Tuple[ProcessNode, ...]
    activity_nodes: Tuple[ActivityNode, ...]
    edges: Tuple[GraphEdge, ...]
    root_node_ids: Tuple[str, ...]
    order: Tuple[Dict[str, Any], ...]
    behaviors: Tuple[bh.BehavioralRelationship, ...]
    sequences: Tuple[Dict[str, Any], ...]
    detection_pivots: Tuple[Dict[str, Any], ...]
    navigation: Dict[str, Any]
    coverage: Tuple[m.CoverageInterval, ...]
    availability: Dict[str, str]
    ranges: Dict[str, Any]
    focus: Optional[m.FocusResolution] = None
    contract_version: str = GRAPH_CONTRACT_VERSION
    provenance: Dict[str, Any] = field(default_factory=dict)

    def node_ids(self) -> set:
        return ({n.node_id for n in self.process_nodes}
                | {n.node_id for n in self.activity_nodes})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "endpoint_id": self.endpoint_id,
            "process_nodes": [n.to_dict() for n in self.process_nodes],
            "activity_nodes": [n.to_dict() for n in self.activity_nodes],
            "edges": [e.to_dict() for e in self.edges],
            "root_node_ids": list(self.root_node_ids),
            "order": [dict(o) for o in self.order],
            "sequences": [dict(s) for s in self.sequences],
            "behaviors": [b.to_dict() for b in self.behaviors],
            "detection_pivots": [dict(d) for d in self.detection_pivots],
            "navigation": dict(self.navigation),
            # DT2-0 owns coverage truth; re-exported, never recomputed.
            "coverage": [{"state": iv.state, "start": iv.start,
                          "end": iv.end, "authority": iv.authority,
                          "boundary_certainty": iv.boundary_certainty,
                          "absence_inferable": iv.absence_inferable,
                          "reason": iv.reason,
                          "proof_ref": _refs(iv.proof_ref)}
                         for iv in self.coverage],
            "availability": dict(self.availability),
            "ranges": dict(self.ranges),
            "focus": ({"state": self.focus.state,
                       "basis": self.focus.basis,
                       "window": self.focus.window,
                       "observation_id": self.focus.observation_id,
                       "process_iid": self.focus.process_iid,
                       "process_node_id": (
                           process_node_id(self.focus.process_iid)
                           if self.focus.process_iid else None),
                       "detection_id": self.focus.detection_id,
                       "timestamp_only": self.focus.timestamp_only}
                      if self.focus else None),
            "provenance": dict(self.provenance),
        }


# ══════════════════════════════════════════════════════════════════════
# composition
# ══════════════════════════════════════════════════════════════════════

def _depths(parent_of: Dict[str, str]) -> Dict[str, int]:
    out: Dict[str, int] = {}

    def depth(iid: str, seen: frozenset) -> int:
        if iid in out:
            return out[iid]
        parent = parent_of.get(iid)
        if not parent or parent in seen:
            out[iid] = 0
        else:
            out[iid] = depth(parent, seen | {iid}) + 1
        return out[iid]

    for iid in list(parent_of) :
        depth(iid, frozenset())
    return out


def build_graph(v1: Dict[str, Any], *, endpoint_id: str,
                requested_start: Optional[str] = None,
                requested_end: Optional[str] = None,
                focus: Optional[m.FocusTarget] = None,
                times: Optional[Dict[str, Dict[str, Any]]] = None
                ) -> TrajectoryGraph:
    """Compose the render contract. No engine of its own."""
    window = c.build(v1, endpoint_id=endpoint_id,
                     requested_start=requested_start,
                     requested_end=requested_end, focus=focus)
    rows: List[Dict[str, Any]] = list(v1.get("events") or [])

    pedges = rel.process_edges(rows, endpoint_id)
    aedges = rel.activity_edges(rows, endpoint_id)
    sequences = sq.temporal_sequences(pedges, aedges, endpoint_id,
                                      times=times)
    behaviors = bh.behaviors(sequences)

    step_of: Dict[str, Tuple[sq.TemporalSequence, sq.SequenceStep]] = {}
    for seq in sequences:
        for step in seq.steps:
            step_of[step.edge.edge_id] = (seq, step)

    # ── process nodes ────────────────────────────────────────────────
    instances = {p.process_iid: p for p in window.process_instances}
    parent_of = {e.child.process_iid: e.parent.process_iid for e in pedges}
    children: Dict[str, List[str]] = {}
    for e in pedges:
        children.setdefault(e.parent.process_iid, []).append(
            e.child.process_iid)
    identity_of = {}
    for e in pedges:
        identity_of.setdefault(e.parent.process_iid, e.parent)
        identity_of.setdefault(e.child.process_iid, e.child)
    for e in aedges:
        identity_of.setdefault(e.process.process_iid, e.process)

    last_seen: Dict[str, str] = {}
    for _, step in step_of.values():
        stamp = step.times.source_time
        if not stamp:
            continue
        for iid in (step.actor_process_iid, step.produced_process_iid):
            if iid and stamp > last_seen.get(iid, ""):
                last_seen[iid] = stamp

    activities: Dict[str, List[str]] = {}
    activity_nodes: List[ActivityNode] = []
    for edge in aedges:
        seq, step = step_of[edge.edge_id]
        iid = edge.process.process_iid
        node_id = activity_node_id(iid, edge.activity.activity_id)
        activities.setdefault(iid, []).append(node_id)
        activity_nodes.append(ActivityNode(
            node_id=node_id, endpoint_id=endpoint_id,
            family=edge.activity.family, label=edge.activity.label,
            kind=edge.activity.kind,
            attributes=dict(edge.activity.attributes),
            process_iid=iid, process_node_id=process_node_id(iid),
            edge_id=edge.edge_id, step_id=step.step_id,
            times=step.times.to_dict(),
            identity_authority=edge.authority, downgraded=edge.downgraded,
            evidence_ref=edge.evidence_ref,
            focus_targets={"process": {"kind": "process_iid", "value": iid},
                           "evidence": _evidence_focus(edge.evidence_ref)}))

    depths = _depths(parent_of)
    known = set(instances) | set(identity_of)
    process_nodes: List[ProcessNode] = []
    for iid in sorted(known):
        inst = instances.get(iid)
        ident = identity_of.get(iid)
        refs = (inst.evidence_ref if inst else ())
        if not refs and ident is not None:
            for edge in pedges:
                if iid in (edge.parent.process_iid, edge.child.process_iid):
                    refs = edge.evidence_ref
                    break
        first = inst.first_seen if inst else None
        process_nodes.append(ProcessNode(
            node_id=process_node_id(iid), process_iid=iid,
            endpoint_id=endpoint_id,
            label=(inst.name if inst else None)
            or (ident.image if ident else None) or iid,
            image=(inst.image if inst else None)
            or (ident.image if ident else None),
            pid=(inst.pid if inst else None) or (ident.pid if ident else None),
            process_guid=(inst.process_guid if inst else None)
            or (ident.process_guid if ident else None),
            user=inst.user if inst else None,
            command_line=inst.command_line if inst else None,
            identity_authority=(inst.identity_authority if inst
                                else ident.authority),
            identity_basis=(inst.identity_basis if inst else ident.basis),
            downgraded=(ident.downgraded if ident
                        else inst.identity_basis != rel.IDENTITY_BASIS_GUID),
            presence=(PRESENCE_OBSERVED if inst else PRESENCE_REFERENCED),
            depth=depths.get(iid, 0),
            parent_process_iid=parent_of.get(iid),
            parent_node_id=(process_node_id(parent_of[iid])
                            if iid in parent_of else None),
            parent_state=inst.parent_state if inst else None,
            child_node_ids=tuple(process_node_id(x)
                                 for x in sorted(children.get(iid, ()))),
            activity_node_ids=tuple(sorted(activities.get(iid, ()))),
            lifeline={"first_evidence_at": first,
                      "last_evidence_at": last_seen.get(iid) or first,
                      "end_time": None,
                      "end_state": END_STATE_UNAVAILABLE,
                      "exit_observed": False,
                      "basis": LIFELINE_BASIS,
                      "end_evidence_availability":
                          window.availability.get("process_end_evidence")},
            evidence_ref=refs,
            focus_targets={"process": {"kind": "process_iid", "value": iid},
                           "parent": ({"kind": "process_iid",
                                       "value": parent_of[iid]}
                                      if iid in parent_of else None),
                           "children": [{"kind": "process_iid", "value": x}
                                        for x in sorted(
                                            children.get(iid, ()))],
                           "evidence": _evidence_focus(refs)},
            provenance={"identity_graded_by": "dt2-2a",
                        "has_own_observation": inst is not None}))

    # ── edges ────────────────────────────────────────────────────────
    edges: List[GraphEdge] = []
    for edge in pedges:
        seq, step = step_of[edge.edge_id]
        edges.append(GraphEdge(
            edge_id=edge.edge_id, endpoint_id=endpoint_id,
            relationship_type=m.REL_PROCESS_PROCESS,
            source_node_id=process_node_id(edge.parent.process_iid),
            target_node_id=process_node_id(edge.child.process_iid),
            derivation_basis=edge.derivation_basis, reason=edge.reason,
            authority=edge.authority,
            downgraded=edge.parent.downgraded or edge.child.downgraded,
            times=step.times.to_dict(), step_id=step.step_id,
            sequence_id=seq.sequence_id,
            link_to_previous=step.link_to_previous,
            previous_step_id=step.previous_step_id,
            evidence_ref=edge.evidence_ref,
            focus_targets={
                "parent": {"kind": "process_iid",
                           "value": edge.parent.process_iid},
                "child": {"kind": "process_iid",
                          "value": edge.child.process_iid},
                "evidence": _evidence_focus(edge.evidence_ref)},
            provenance={**dict(edge.provenance),
                        "guid_proven": edge.guid_proven,
                        "link_reason": step.link_reason}))
    for edge in aedges:
        seq, step = step_of[edge.edge_id]
        iid = edge.process.process_iid
        edges.append(GraphEdge(
            edge_id=edge.edge_id, endpoint_id=endpoint_id,
            relationship_type=edge.relationship_type,
            source_node_id=process_node_id(iid),
            target_node_id=activity_node_id(iid,
                                            edge.activity.activity_id),
            derivation_basis=edge.derivation_basis, reason=edge.reason,
            authority=edge.authority, downgraded=edge.downgraded,
            times=step.times.to_dict(), step_id=step.step_id,
            sequence_id=seq.sequence_id,
            link_to_previous=step.link_to_previous,
            previous_step_id=step.previous_step_id,
            evidence_ref=edge.evidence_ref,
            focus_targets={
                "process": {"kind": "process_iid", "value": iid},
                "activity": {"kind": "observation_id",
                             "value": str((edge.provenance or {}).get(
                                 "source_event_iid") or "")},
                "evidence": _evidence_focus(edge.evidence_ref)},
            provenance={**dict(edge.provenance),
                        "link_reason": step.link_reason}))

    # ── order + before/after navigation ──────────────────────────────
    order: List[Dict[str, Any]] = []
    for seq in sequences:
        for index, step in enumerate(seq.steps):
            previous = seq.steps[index - 1] if index else None
            following = (seq.steps[index + 1]
                         if index + 1 < len(seq.steps) else None)
            order.append({
                "step_id": step.step_id, "sequence_id": seq.sequence_id,
                "index": index, "edge_id": step.edge.edge_id,
                "edge_kind": step.edge_kind,
                "node_id": (process_node_id(step.produced_process_iid)
                            if step.produced_process_iid
                            else activity_node_id(
                                step.actor_process_iid,
                                step.edge.activity.activity_id)),
                "actor_node_id": process_node_id(step.actor_process_iid),
                "previous_step_id": previous.step_id if previous else None,
                "next_step_id": following.step_id if following else None,
                "link_to_previous": step.link_to_previous,
                "link_reason": step.link_reason,
                "times": step.times.to_dict()})

    available = window.available_range
    navigation = {
        "ordered_step_ids": [o["step_id"] for o in order],
        "cursor": ({"timestamp": window.cursor.timestamp,
                    "event_iid": window.cursor.event_iid}
                   if window.cursor else None),
        "next_cursor": ({"timestamp": window.next_cursor.timestamp,
                         "event_iid": window.next_cursor.event_iid}
                        if window.next_cursor else None),
        "has_more": window.has_more,
        "before": {"pivot": ({"kind": "timestamp",
                              "value": available.get("from")}
                             if available.get("from") else None),
                   "state": m.AVAIL_UNKNOWN,
                   "basis": "EARLIER_ACTIVITY_NOT_PROVABLE_FROM_WINDOW"},
        "after": {"pivot": ({"kind": "timestamp",
                             "value": available.get("to")}
                            if available.get("to") else None),
                  "state": m.AVAIL_UNKNOWN,
                  "basis": "LATER_ACTIVITY_NOT_PROVABLE_FROM_WINDOW"},
        "time_basis": sq.TIME_SOURCE,
        "ordering_basis": sq.SEQUENCE_ORDERING_BASIS,
    }

    detection_pivots = tuple(
        {"detection_id": d.detection_id,
         "detected_at": d.detected_at,
         "evaluation_state": d.evaluation_state,
         "focus": {"kind": "detection_id", "value": d.detection_id},
         "observation_focus": [{"kind": "observation_id", "value": o}
                               for o in d.observation_ids],
         "process_node_id": (process_node_id(d.process_iid)
                             if d.process_iid else None),
         "process_binding_authority": d.process_binding_authority,
         "evidence_ref": _refs(d.evidence_ref)}
        for d in window.detections)

    root_ids = tuple(process_node_id(n.process_iid) for n in process_nodes
                     if n.parent_process_iid is None)

    return TrajectoryGraph(
        endpoint_id=endpoint_id,
        process_nodes=tuple(process_nodes),
        activity_nodes=tuple(activity_nodes),
        edges=tuple(edges), root_node_ids=root_ids, order=tuple(order),
        behaviors=tuple(behaviors),
        sequences=tuple({"sequence_id": s.sequence_id,
                         "root_process_iid": s.root_process_iid,
                         "root_node_id": (process_node_id(s.root_process_iid)
                                          if s.root_process_iid else None),
                         "step_count": len(s.steps),
                         "step_ids": [x.step_id for x in s.steps],
                         "causality_summary": s.causality_summary,
                         "ordering_basis": s.ordering_basis}
                        for s in sequences),
        detection_pivots=detection_pivots, navigation=navigation,
        coverage=tuple(window.coverage), availability=dict(
            window.availability),
        ranges={"requested": window.requested_range,
                "effective": window.effective_range,
                "available": window.available_range,
                "retention_boundary": window.retention_boundary},
        focus=window.focus,
        provenance={"composes": ["dt2.0", "dt2-2a", "dt2-2b", "dt2-2c",
                                 "dt2-2d"],
                    "derives_relationships": False,
                    "client_may_derive_edges": False,
                    "coverage_source": "dt2.0.contract.coverage",
                    "creates_no_store": True,
                    "dt2_contract_version": window.contract_version})
