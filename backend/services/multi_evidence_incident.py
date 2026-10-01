"""X1 · the multi-evidence incident — one attack, many pieces of evidence.

An incident used to be anchored to ONE canonical event, which meant the
platform could detect things but could not say that two detections were
the same attack. This composes evidence instead — and the composition rule
is the whole safety argument:

    Two pieces of evidence belong to the same incident ONLY when they
    share an entity whose identity_state is AUTHORITATIVE.

A shared address, a shared hostname, a shared username or a shared instant
compose nothing. That is not a tuning parameter; it is the invariant the
previous two gates were built to protect.

Nothing is ever destroyed here. Replayed evidence re-resolves to the same
ids and updates `last_observed` instead of duplicating. Contradictory
evidence is recorded as CONTRADICTED with both sides kept. A retracted
relationship becomes UNRESOLVED and keeps its evidence refs, because the
evidence was still observed even when the conclusion was wrong.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services import entity_resolution as er

ENTITIES = "xdr_entities"
RELATIONSHIPS = "xdr_entity_relationships"
INCIDENTS = "xdr_multi_evidence_incidents"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ensure_indexes(db: Any) -> None:
    await db[ENTITIES].create_index([("tenant_id", 1), ("entity_id", 1)],
                                    unique=True)
    await db[RELATIONSHIPS].create_index(
        [("tenant_id", 1), ("relationship_id", 1)], unique=True)
    await db[INCIDENTS].create_index([("tenant_id", 1), ("incident_id", 1)],
                                     unique=True)
    await db[INCIDENTS].create_index([("tenant_id", 1), ("entity_ids", 1)])


async def _upsert_entity(db: Any, e: er.Entity) -> Dict[str, Any]:
    doc = e.to_doc()
    await db[ENTITIES].update_one(
        {"tenant_id": e.tenant_id, "entity_id": e.id},
        {"$setOnInsert": {"entity_id": e.id, "tenant_id": e.tenant_id,
                          "entity_type": e.entity_type, "key": e.key,
                          "first_observed": e.first_observed},
         "$set": {"identity_state": e.identity_state,
                  "identity_basis": e.identity_basis,
                  "last_observed": e.last_observed,
                  "attributes": doc["attributes"]},
         "$addToSet": {"evidence_refs": {"$each": doc["evidence_refs"]},
                       "sources": {"$each": doc["sources"]}}},
        upsert=True)
    return await db[ENTITIES].find_one(
        {"tenant_id": e.tenant_id, "entity_id": e.id}, {"_id": 0})


async def _upsert_relationship(db: Any, r: er.Relationship
                               ) -> Dict[str, Any]:
    """Contradiction is detected here, and both sides survive it."""
    doc = r.to_doc()
    prior = await db[RELATIONSHIPS].find_one(
        {"tenant_id": r.tenant_id, "relationship_id": r.id}, {"_id": 0})
    state = r.state
    contradiction = None
    if prior and prior.get("state") not in (state, er.REL_CONTRADICTED):
        # The SAME two entities related two different ways. Keep both
        # claims and say so; never let the newer one quietly win.
        state = er.REL_CONTRADICTED
        contradiction = {
            "previous_state": prior["state"], "asserted_state": r.state,
            "previous_evidence_refs": prior.get("evidence_refs", []),
            "asserted_evidence_refs": doc["evidence_refs"],
            "noted_at": _now(),
            "note": ("two pieces of evidence disagree about this "
                     "relationship; both are retained and neither is "
                     "treated as settled"),
        }
    update: Dict[str, Any] = {
        "$setOnInsert": {"relationship_id": r.id, "tenant_id": r.tenant_id,
                         "relationship_type": r.relationship_type,
                         "source_entity": r.source_entity,
                         "target_entity": r.target_entity,
                         "first_observed": r.first_observed},
        "$set": {"state": state, "identity_basis": r.identity_basis,
                 "reason": r.reason, "last_observed": r.last_observed},
        "$addToSet": {"evidence_refs": {"$each": doc["evidence_refs"]},
                      "sources": {"$each": doc["sources"]}},
    }
    if contradiction:
        update["$push"] = {"contradictions": contradiction}
    await db[RELATIONSHIPS].update_one(
        {"tenant_id": r.tenant_id, "relationship_id": r.id}, update,
        upsert=True)
    return await db[RELATIONSHIPS].find_one(
        {"tenant_id": r.tenant_id, "relationship_id": r.id}, {"_id": 0})


async def retract_relationship(db: Any, *, tenant_id: str,
                               relationship_id: str, reason: str) -> dict:
    """Withdraw a conclusion WITHOUT destroying the evidence behind it."""
    await db[RELATIONSHIPS].update_one(
        {"tenant_id": tenant_id, "relationship_id": relationship_id},
        {"$set": {"state": er.REL_UNRESOLVED, "retracted_at": _now(),
                  "retraction_reason": reason,
                  "retraction_note": ("the conclusion was withdrawn; the "
                                      "evidence that produced it was still "
                                      "observed and is retained")}})
    return await db[RELATIONSHIPS].find_one(
        {"tenant_id": tenant_id, "relationship_id": relationship_id},
        {"_id": 0})


async def compose(db: Any, *, tenant_id: str, canonical: Dict[str, Any],
                  detections: Optional[List[dict]] = None,
                  correlations: Optional[List[dict]] = None) -> Dict[str, Any]:
    """Resolve one canonical event and compose it into an incident.

    Returns the incident, plus what was resolved and why it composed (or
    why it did not).
    """
    entities = er.resolve_entities(canonical, tenant_id)
    if not entities:
        return {"composed": False,
                "reason": "no entity could be resolved from this evidence",
                "entities": [], "relationships": []}
    relationships = er.derive_relationships(canonical, entities)
    stored_entities = [await _upsert_entity(db, e) for e in entities]
    stored_rels = [await _upsert_relationship(db, r) for r in relationships]

    mergeable = [e for e in entities
                 if e.identity_state in er.MERGEABLE_IDENTITY_STATES]
    event_id = canonical.get("event_id")
    now = _now()

    if not mergeable:
        # Real evidence, no authoritative anchor: it gets its OWN incident
        # rather than being attached to whatever shares its address.
        anchor_ids: List[str] = []
        basis = ("no authoritative entity was resolved; this evidence "
                 "stands alone rather than merging on a declared identity")
    else:
        anchor_ids = [e.id for e in mergeable]
        basis = ("composed on authoritative entities: "
                 + ", ".join(f"{e.entity_type}:{e.identity_basis[:40]}"
                             for e in mergeable))

    existing = None
    if anchor_ids:
        existing = await db[INCIDENTS].find_one(
            {"tenant_id": tenant_id, "anchor_entity_ids": {"$in": anchor_ids}},
            {"_id": 0})

    incident_id = (existing["incident_id"] if existing
                   else "minc_" + er._digest(tenant_id, event_id or now))
    await db[INCIDENTS].update_one(
        {"tenant_id": tenant_id, "incident_id": incident_id},
        {"$setOnInsert": {"incident_id": incident_id,
                          "tenant_id": tenant_id, "created_at": now,
                          "first_observed": entities[0].first_observed},
         "$set": {"updated_at": now,
                  "last_observed": entities[0].last_observed,
                  "composition_basis": basis,
                  "capability_not_verdict": True},
         "$addToSet": {
             "event_ids": {"$each": [event_id] if event_id else []},
             "anchor_entity_ids": {"$each": anchor_ids},
             "entity_ids": {"$each": [e.id for e in entities]},
             "relationship_ids": {"$each": [r.id for r in relationships]},
             "detections": {"$each": list(detections or [])},
             "correlations": {"$each": list(correlations or [])},
             "sources": {"$each": [er._source(canonical)]}}},
        upsert=True)
    incident = await db[INCIDENTS].find_one(
        {"tenant_id": tenant_id, "incident_id": incident_id}, {"_id": 0})
    return {"composed": True, "merged_into_existing": bool(existing),
            "incident": incident, "entities": stored_entities,
            "relationships": stored_rels,
            "anchor_entity_ids": anchor_ids, "reason": basis}


async def trace(db: Any, *, tenant_id: str, incident_id: str) -> dict:
    """Every relationship in an incident, back to the evidence that made it.

    An incident that cannot be traced to canonical evidence is not an
    incident; it is an opinion.
    """
    inc = await db[INCIDENTS].find_one(
        {"tenant_id": tenant_id, "incident_id": incident_id}, {"_id": 0})
    if not inc:
        return {"found": False}
    rels = [r async for r in db[RELATIONSHIPS].find(
        {"tenant_id": tenant_id,
         "relationship_id": {"$in": inc.get("relationship_ids", [])}},
        {"_id": 0})]
    ents = [e async for e in db[ENTITIES].find(
        {"tenant_id": tenant_id,
         "entity_id": {"$in": inc.get("entity_ids", [])}}, {"_id": 0})]
    untraceable = [r["relationship_id"] for r in rels
                   if not r.get("evidence_refs")]
    return {"found": True, "incident": inc, "entities": ents,
            "relationships": rels,
            "every_relationship_cites_evidence": not untraceable,
            "untraceable_relationship_ids": untraceable}
