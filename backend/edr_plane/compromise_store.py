"""COMPROMISE STORE + CONTRIBUTOR RESOLVER (read side of the contract).

The flow this closes, end to end:

    detection / IOC mechanism
        ↓   (only a contract constructor may produce this)
    compromise_event
        ↓   contributing_event_refs[]
    canonical OBSERVATION identities   (`observation_id`, never a content hash)
        ↓
    trajectory projection
        ↓
    frontend

The frontend never decides contributor membership. It receives the
authority's own list, already resolved against the projection, plus an
explicit account of any reference that could NOT be resolved. A reference
that does not resolve is reported as unresolved — never substituted with
the nearest event.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .compromise_contract import (
    CONTRIBUTORS_NOT_PROVEN,
    CONTRIBUTORS_PROVEN,
    CompromiseContractError,
    CompromiseEvent,
    ContributingEventRef,
)

COLLECTION = "edr_compromise_events"

REF_RESOLVED = "RESOLVED_TO_OBSERVATION"
REF_UNRESOLVED_NOT_IN_PROJECTION = "UNRESOLVED_NOT_IN_PROJECTION"
REF_REJECTED_CROSS_TENANT = "REJECTED_CROSS_TENANT_REFERENCE"
REF_REJECTED_CROSS_DEVICE = "REJECTED_CROSS_DEVICE_REFERENCE"

STORE_REJECTED_INVALID = "REJECTED_CONTRACT_VIOLATION"


def _rehydrate(doc: Dict[str, Any]) -> CompromiseEvent:
    """A stored document back through the CONTRACT.

    Re-validating on read is deliberate: a row that was written before a
    rule existed, or edited outside the contract, must not be able to
    reach the UI as if an authority had produced it.
    """
    refs = tuple(
        ContributingEventRef(
            event_iid=str(r.get("observation_id") or ""),
            contribution_basis=str(r.get("contribution_basis") or ""),
            stated_by=str(r.get("stated_by") or ""),
            evidence_ref=r.get("evidence_ref"))
        for r in (doc.get("contributing_event_refs") or ()))
    return CompromiseEvent(
        compromise_event_id=str(doc.get("compromise_event_id") or ""),
        indicator_id=str(doc.get("indicator_id") or ""),
        authority=str(doc.get("authority") or ""),
        derivation_basis=str(doc.get("derivation_basis") or ""),
        description=str(doc.get("description") or ""),
        contributing_event_refs=refs,
        evidence_refs=tuple(doc.get("evidence_refs") or ()),
        tactics=tuple(doc.get("tactics") or ()),
        techniques=tuple(doc.get("techniques") or ()),
        observed_at=doc.get("observed_at"),
        contributors_state=str(doc.get("contributors_state")
                               or (CONTRIBUTORS_PROVEN if refs
                                   else CONTRIBUTORS_NOT_PROVEN)),
    )


async def persist(db: Any, compromise: CompromiseEvent, *, tenant_id: str,
                  device_iid: str, raised_by: str) -> str:
    """Store a compromise that a CONTRACT CONSTRUCTOR produced.

    The typed object is the only accepted input, so an inferred
    contributor cannot be written at all.
    """
    if not isinstance(compromise, CompromiseEvent):
        raise CompromiseContractError(
            "COMPROMISE_TYPE_INVALID",
            "only a validated CompromiseEvent may be persisted")
    doc = compromise.to_dict()
    doc["contributing_event_refs"] = [
        {"observation_id": r.event_iid,
         "contribution_basis": r.contribution_basis,
         "stated_by": r.stated_by,
         **({"evidence_ref": r.evidence_ref} if r.evidence_ref else {})}
        for r in compromise.contributing_event_refs]
    doc.update({"tenant_id": tenant_id, "device_iid": device_iid,
                "raised_by": raised_by})
    await db[COLLECTION].update_one(
        {"tenant_id": tenant_id, "device_iid": device_iid,
         "compromise_event_id": compromise.compromise_event_id},
        {"$set": doc}, upsert=True)
    return compromise.compromise_event_id


async def resolve_for_device(db: Any, *, tenant_id: Optional[str],
                             device_iid: Optional[str],
                             observation_ids: Iterable[str],
                             ) -> Dict[str, Any]:
    """Every authoritative compromise for this device, with its
    contributor references resolved against THIS projection.

    Returns the compromises, a `observation_id -> [compromise ids]` map for
    contributor emphasis, and a per-reference resolution account.
    """
    projected = {str(o) for o in observation_ids if o}
    out: List[Dict[str, Any]] = []
    contributor_of: Dict[str, List[str]] = {}
    rejected: List[Dict[str, Any]] = []
    if not (tenant_id and device_iid):
        return {"compromise_events": [], "contributor_of": {},
                "rejected": [], "state": "NO_DEVICE_SCOPE"}

    # Scoped at the query. A compromise raised for another tenant or
    # another device is never even read, and the re-check below refuses
    # one that somehow carries a foreign scope.
    cursor = db[COLLECTION].find({"tenant_id": tenant_id,
                                  "device_iid": device_iid})
    async for doc in cursor:
        if doc.get("tenant_id") != tenant_id:
            rejected.append({"compromise_event_id":
                             doc.get("compromise_event_id"),
                             "state": REF_REJECTED_CROSS_TENANT})
            continue
        if doc.get("device_iid") != device_iid:
            rejected.append({"compromise_event_id":
                             doc.get("compromise_event_id"),
                             "state": REF_REJECTED_CROSS_DEVICE})
            continue
        try:
            compromise = _rehydrate(doc)
        except CompromiseContractError as ex:
            rejected.append({"compromise_event_id":
                             doc.get("compromise_event_id"),
                             "state": STORE_REJECTED_INVALID,
                             "code": ex.code, "reason": ex.reason})
            continue

        payload = compromise.to_dict()
        refs: List[Dict[str, Any]] = []
        resolved: List[str] = []
        unresolved: List[Dict[str, Any]] = []
        for ref in compromise.contributing_event_refs:
            entry = ref.to_dict()
            entry["observation_id"] = ref.event_iid
            entry.pop("event_iid", None)
            if ref.event_iid in projected:
                entry["resolution_state"] = REF_RESOLVED
                resolved.append(ref.event_iid)
                contributor_of.setdefault(ref.event_iid, []).append(
                    compromise.compromise_event_id)
            else:
                # NOT the nearest event. An unresolvable reference stays
                # unresolved, so nothing gets emphasised by accident.
                entry["resolution_state"] = REF_UNRESOLVED_NOT_IN_PROJECTION
                unresolved.append(entry)
            refs.append(entry)
        payload["contributing_event_refs"] = refs
        payload["resolved_observation_ids"] = resolved
        payload["unresolved_event_refs"] = unresolved
        payload["contributor_emphasis"] = (
            "RENDER_CONTRIBUTORS" if resolved else "RENDER_NO_CONTRIBUTORS")
        payload["raised_by"] = doc.get("raised_by")
        out.append(payload)

    out.sort(key=lambda c: (str(c.get("observed_at") or ""),
                            c["compromise_event_id"]))
    return {"compromise_events": out,
            "contributor_of": contributor_of,
            "rejected": rejected,
            "state": "AUTHORITATIVE_COMPROMISES_RESOLVED" if out
                     else "NO_AUTHORITATIVE_COMPROMISE_OBSERVED"}
