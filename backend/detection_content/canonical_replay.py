"""Preserve first canonical evidence for stable authenticated endpoint replay."""
import hashlib
import json
from pymongo.errors import DuplicateKeyError

CONTRACT = "endpoint_canonical_replay_v1"

async def persist_canonical(collection, canonical, raw_event):
    from edr_plane.canonical_bridge import CANONICAL_EVENT_ID_AUTHORITY
    envelope = raw_event.get("_authenticated_ingest")
    tenant = canonical.get("tenant_id")
    event_id = canonical.get("event_id")
    protected = (
        isinstance(envelope, dict)
        and envelope.get("canonical_event_id_authority") == CANONICAL_EVENT_ID_AUTHORITY
        and envelope.get("canonical_event_id") == event_id
        and isinstance(event_id, str) and bool(event_id.strip())
        and isinstance(tenant, str) and bool(tenant.strip())
        and (canonical.get("provenance") or {}).get("trust_state") == "AUTHENTICATED"
    )
    if not protected:
        inserted = await collection.insert_one(dict(canonical))
        return canonical, inserted.inserted_id
    key = "ec_" + hashlib.sha256(json.dumps(
        [CONTRACT, tenant, event_id], separators=(",", ":")
    ).encode()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps(
        raw_event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()).hexdigest()
    row = {**canonical, "_id": key, "processing_receipt": {
        "contract": CONTRACT, "input_sha256": fingerprint}}
    try:
        await collection.insert_one(dict(row))
    except DuplicateKeyError as exc:
        if (exc.details or {}).get("keyPattern") != {"_id": 1}:
            raise
        winner = await collection.find_one({
            "_id": key, "tenant_id": tenant, "event_id": event_id,
            "processing_receipt.contract": CONTRACT})
        if winner is None:
            raise
        if winner["processing_receipt"].get("input_sha256") != fingerprint:
            raise ValueError("canonical replay identity has conflicting input")
        row = winner
    # Preserve the original parse/ingest evidence and timestamps on replay.
    return {k: v for k, v in row.items() if k != "_id"}, key
