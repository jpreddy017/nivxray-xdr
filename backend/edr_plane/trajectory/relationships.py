"""DT2-2 · the evidence-backed PROCESS RELATIONSHIP primitive.

This is the first DT2-2 slice: the server-side domain model for a
parent-process → child-process edge, with the identity authority of BOTH
endpoints stated explicitly and the reason the edge exists carried on the
edge itself.

WHY THIS EXISTS ALONGSIDE DT2-0 `Relationship`
----------------------------------------------
DT2-0 gave us an edge that must carry evidence and a non-proximity
derivation basis — that stays authoritative and is NOT changed here.
What DT2-0 does not express is the *identity grade of each endpoint*.
`contract.relationships()` stamps every parent edge
`AUTHORITY_AUTHORITATIVE`, so a Security-4688 edge whose parent is known
only by PID is currently presented with the same confidence as a Sysmon-1
edge carrying a ProcessGuid. For a Process/Relationship Timeline that is
not good enough: an analyst reading lineage must be able to see which
edges are GUID-proven and which are PID-derived surrogates.

`ProcessEdge` therefore grades the edge from its two endpoint identities
and never reports more confidence than its weaker endpoint.

INVARIANTS
----------
* ProcessGuid is authoritative identity.
* A PID-derived identity is DERIVED and explicitly flagged `downgraded`.
* A bare PID with no image is UNSTABLE and never presented as identity.
* An edge is emitted ONLY when a single canonical observation binds child
  to parent. Two observations that merely happen to be close in time
  NEVER produce an edge.
* Every edge carries `evidence_ref` and a human-readable `reason`.
* Nothing here reads or writes a database, and no schema changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import models as m

__all__ = [
    "IDENTITY_BASIS_GUID", "IDENTITY_BASIS_PID_IMAGE",
    "IDENTITY_BASIS_PID_ONLY", "IDENTITY_BASIS_ABSENT",
    "EDGE_REASON_GUID", "EDGE_REASON_IDENTITY",
    "ProcessIdentity", "ProcessEdge", "identity_of", "process_edges",
]

# ── identity bases, most to least trustworthy ─────────────────────────
IDENTITY_BASIS_GUID = "SYSMON_PROCESS_GUID"
IDENTITY_BASIS_PID_IMAGE = "COMPUTER_PID_IMAGE_DERIVED_NO_GUID"
IDENTITY_BASIS_PID_ONLY = "PID_ONLY_NOT_GLOBALLY_STABLE"
IDENTITY_BASIS_ABSENT = "IDENTITY_NOT_PRESENT_IN_EVIDENCE"

EDGE_REASON_GUID = (
    "The child observation reported its parent's ProcessGuid, so the "
    "sensor itself bound this child to this parent.")
EDGE_REASON_IDENTITY = (
    "The child observation carried a canonical parent process identity "
    "derived without a ProcessGuid; the edge is real but the parent "
    "identity is a PID-based surrogate and may be affected by PID reuse.")

# Authority ordering, weakest last. An edge is never stronger than its
# weakest endpoint.
_AUTHORITY_RANK = {
    m.AUTHORITY_AUTHORITATIVE: 0,
    m.AUTHORITY_DERIVED: 1,
    m.AUTHORITY_UNSTABLE: 2,
    m.AUTHORITY_UNKNOWN: 3,
}


@dataclass(frozen=True)
class ProcessIdentity:
    """One endpoint of a process edge, WITH its authority stated."""
    process_iid: Optional[str]
    authority: str
    basis: str
    process_guid: Optional[str] = None
    pid: Optional[int] = None
    image: Optional[str] = None

    def __post_init__(self) -> None:
        if self.authority not in _AUTHORITY_RANK:
            raise ValueError(f"bad identity authority {self.authority!r}")
        if not self.basis:
            raise ValueError("identity without a basis is rejected")

    @property
    def downgraded(self) -> bool:
        """True when this identity is NOT ProcessGuid-proven."""
        return self.basis != IDENTITY_BASIS_GUID

    @property
    def presentable(self) -> bool:
        """A bare PID is never presented to an analyst as identity."""
        return (self.process_iid is not None
                and self.authority in (m.AUTHORITY_AUTHORITATIVE,
                                       m.AUTHORITY_DERIVED))

    def to_dict(self) -> Dict[str, Any]:
        return {"process_iid": self.process_iid,
                "authority": self.authority, "basis": self.basis,
                "downgraded": self.downgraded,
                "presentable": self.presentable,
                "process_guid": self.process_guid, "pid": self.pid,
                "image": self.image}


@dataclass(frozen=True)
class ProcessEdge:
    """A parent → child process edge that can justify its own existence."""
    edge_id: str
    endpoint_id: str
    parent: ProcessIdentity
    child: ProcessIdentity
    derivation_basis: str
    evidence_ref: Tuple[m.EvidenceReference, ...]
    reason: str
    observed_at: Optional[str] = None
    time_basis: str = "SOURCE_TIME"
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.parent.process_iid or not self.child.process_iid:
            raise ValueError(
                "a process edge needs BOTH endpoints; a half-known edge is "
                "not a relationship")
        if self.parent.process_iid == self.child.process_iid:
            raise ValueError("a process cannot be its own parent")
        if not self.evidence_ref:
            raise ValueError(
                "process edge without evidence_ref is rejected: an edge must "
                "answer WHY IT EXISTS")
        if not self.reason:
            raise ValueError("process edge without a stated reason rejected")
        basis = (self.derivation_basis or "").upper()
        if not basis:
            raise ValueError("process edge without derivation_basis rejected")
        if any(bad in basis for bad in m.FORBIDDEN_BASES):
            raise ValueError(
                f"forbidden derivation_basis {self.derivation_basis!r}: "
                "temporal proximity is never relationship authority")
        if basis not in m.ACCEPTED_BASES:
            raise ValueError(f"unrecognised derivation_basis {basis}")

    @property
    def authority(self) -> str:
        """Never stronger than the weaker of the two endpoints."""
        return max((self.parent.authority, self.child.authority),
                   key=lambda a: _AUTHORITY_RANK[a])

    @property
    def guid_proven(self) -> bool:
        return (self.parent.basis == IDENTITY_BASIS_GUID
                and self.child.basis == IDENTITY_BASIS_GUID)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id, "endpoint_id": self.endpoint_id,
            "relationship_type": m.REL_PROCESS_PROCESS,
            "parent": self.parent.to_dict(), "child": self.child.to_dict(),
            "authority": self.authority, "guid_proven": self.guid_proven,
            "derivation_basis": self.derivation_basis,
            "reason": self.reason, "observed_at": self.observed_at,
            "time_basis": self.time_basis,
            "evidence_ref": [
                {"kind": r.kind, "id": r.id, "collection": r.collection,
                 "byte_preserved": r.byte_preserved}
                for r in self.evidence_ref],
            "provenance": dict(self.provenance),
        }


def _ref(kind: str, value: Any, collection: Optional[str] = None,
         byte_preserved: bool = False) -> Optional[m.EvidenceReference]:
    if not value:
        return None
    return m.EvidenceReference(kind=kind, id=str(value),
                               collection=collection,
                               byte_preserved=byte_preserved)


def _refs(row: Dict[str, Any]) -> Tuple[m.EvidenceReference, ...]:
    prov = row.get("provenance") or {}
    found = (_ref("RAW_EVENT", prov.get("raw_event_id"),
                  "edr_raw_events", True),
             _ref("CANONICAL_EVENT", prov.get("canonical_event_id")),
             _ref("OBSERVATION", prov.get("evidence_id")
                  or row.get("event_iid"), "v2_shadow_observations"))
    return tuple(r for r in found if r)


def identity_of(row: Dict[str, Any], *, role: str = "child"
                ) -> ProcessIdentity:
    """Grade one endpoint's identity from a single canonical observation.

    `role` is "child" (the acting process) or "parent".
    """
    if role not in ("child", "parent"):
        raise ValueError(f"role must be child or parent, not {role!r}")
    prov = row.get("provenance") or {}
    if role == "child":
        iid = row.get("process_iid")
        guid = prov.get("process_guid") or row.get("process_guid")
        pid = row.get("pid")
        image = row.get("image") or row.get("process")
    else:
        iid = row.get("parent_process_iid")
        guid = (prov.get("parent_process_guid")
                or row.get("parent_process_guid"))
        pid = row.get("ppid") or row.get("parent_pid")
        image = row.get("parent_image") or row.get("parent_process")

    if guid:
        authority, basis = m.AUTHORITY_AUTHORITATIVE, IDENTITY_BASIS_GUID
    elif pid and image:
        authority, basis = m.AUTHORITY_DERIVED, IDENTITY_BASIS_PID_IMAGE
    elif pid:
        authority, basis = m.AUTHORITY_UNSTABLE, IDENTITY_BASIS_PID_ONLY
    else:
        authority, basis = m.AUTHORITY_UNKNOWN, IDENTITY_BASIS_ABSENT
    return ProcessIdentity(process_iid=iid, authority=authority,
                           basis=basis, process_guid=guid,
                           pid=int(pid) if isinstance(pid, int) else None,
                           image=image)


def process_edges(rows: Iterable[Dict[str, Any]], endpoint_id: str
                  ) -> List[ProcessEdge]:
    """Derive parent → child edges bound by the evidence itself.

    An edge is produced ONLY from an observation that names its own
    parent. Rows are never compared with each other, so there is no path
    by which temporal proximity, ordering or adjacency could invent an
    edge. Unattributed rows simply yield nothing.
    """
    out: List[ProcessEdge] = []
    seen: set = set()
    for row in rows:
        child = identity_of(row, role="child")
        parent = identity_of(row, role="parent")
        if not child.process_iid or not parent.process_iid:
            continue
        if child.process_iid == parent.process_iid:
            continue
        refs = _refs(row)
        if not refs:
            # No immutable pointer ⇒ nothing to justify the edge with.
            continue
        key = (parent.process_iid, child.process_iid)
        if key in seen:
            continue
        seen.add(key)
        if parent.basis == IDENTITY_BASIS_GUID:
            basis, reason = m.BASIS_PARENT_GUID, EDGE_REASON_GUID
        else:
            basis, reason = m.BASIS_PARENT_IDENTITY, EDGE_REASON_IDENTITY
        out.append(ProcessEdge(
            edge_id=f"pedge:{parent.process_iid}:{child.process_iid}",
            endpoint_id=endpoint_id, parent=parent, child=child,
            derivation_basis=basis, evidence_ref=refs, reason=reason,
            observed_at=row.get("timestamp"),
            provenance={"parent_state": row.get("parent_state"),
                        "source_event_iid": row.get("event_iid")}))
    return out
