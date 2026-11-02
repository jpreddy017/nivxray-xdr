"""Idempotent citation writes for protected canonical endpoint records."""
import hashlib
import json
from pymongo.errors import DuplicateKeyError

CONTRACT = "endpoint_detection_citation_v1"

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

async def persist_citations(collection, rows, *, protected=False):
    if not rows:
        return
    if not protected:
        await collection.insert_many(rows)
        return
    for row in rows:
        scope = [row.get(k) for k in ("tenant_id", "canonical_event_id", "rule_id")]
        if not all(isinstance(v, str) and v.strip() for v in scope):
            raise ValueError("protected citation requires tenant, event and rule identity")
        key = "dc_" + _digest([CONTRACT, *scope, row.get("rule_version"),
                               row.get("engine_id")])
        # Evaluation time varies on retry. All actual citation content must
        # still agree; a changed rule without a changed version is a conflict.
        fingerprint = _digest({k: v for k, v in row.items() if k != "evaluated_at"})
        stored = {**row, "_id": key, "processing_receipt": {
            "contract": CONTRACT, "input_sha256": fingerprint}}
        try:
            await collection.insert_one(stored)
        except DuplicateKeyError as exc:
            if (exc.details or {}).get("keyPattern") != {"_id": 1}:
                raise
            winner = await collection.find_one({
                "_id": key, "tenant_id": scope[0],
                "canonical_event_id": scope[1], "rule_id": scope[2],
                "processing_receipt.contract": CONTRACT})
            if winner is None:
                raise
            if winner["processing_receipt"].get("input_sha256") != fingerprint:
                raise ValueError("citation replay identity has conflicting input")
