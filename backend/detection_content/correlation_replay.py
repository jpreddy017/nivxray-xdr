"""Replay identity for new, tenant-scoped single-event correlation writes.

This is not a migration of legacy random-ID matches and does not make the
whole pipeline idempotent. Identity-poor legacy callers remain explicit.
"""
import hashlib
import json
from pymongo.errors import DuplicateKeyError

CONTRACT = "single_event_correlation_v1"

def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")).hexdigest()

async def persist_match(collection, doc, *, tenant_id, rule, signal,
                        engine_version):
    event_id, rule_id = doc.get("source_event_id"), doc.get("rule_id")
    if not all(isinstance(v, str) and v.strip()
               for v in (tenant_id, event_id, rule_id)):
        legacy = {**doc, "replay_protection": "UNAVAILABLE_IDENTITY"}
        await collection.insert_one(dict(legacy))
        return legacy
    definition = {k: rule.get(k) for k in (
        "rule_id", "id", "version", "rule_version", "conditions",
        "operators", "name", "severity_hint", "attack_techniques")}
    revision = digest(definition)
    match_id = "cm_" + digest([CONTRACT, tenant_id, event_id, rule_id,
                              revision, engine_version])
    input_digest = digest({"signal": signal,
                           "severity_hint": doc.get("severity_hint"),
                           "attack_techniques": doc.get("attack_techniques")})
    stored = {**doc, "_id": match_id, "match_id": match_id,
              "tenant_id": tenant_id, "replay_protection": CONTRACT,
              "rule_revision_sha256": revision,
              "effect_input_sha256": input_digest}
    try:
        await collection.insert_one(dict(stored))
    except DuplicateKeyError as exc:
        if (exc.details or {}).get("keyPattern") != {"_id": 1}:
            raise
        winner = await collection.find_one({
            "_id": match_id, "tenant_id": tenant_id,
            "source_event_id": event_id, "rule_id": rule_id,
            "replay_protection": CONTRACT})
        if winner is None:
            raise
        if winner.get("effect_input_sha256") != input_digest:
            raise ValueError("correlation replay identity has conflicting input")
        stored = winner
    return {k: v for k, v in stored.items() if k != "_id"}
