"""Detection persistence. Tenant-scoped, optimistic-concurrency upserts."""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Protocol, Tuple

COLLECTION = "e3_behavior_detections"
CHECKPOINTS = "e3_behavior_replay_checkpoints"
# Index specs for the E3 branch only. Never applied to production by this code.
INDEXES: Dict[str, List[Tuple[List[Tuple[str, int]], Dict[str, Any]]]] = {
    COLLECTION: [
        ([("tenant_id", 1), ("detection_id", 1)], {"unique": True, "name": "uniq_tenant_detection"}),
        ([("tenant_id", 1), ("endpoint_id", 1), ("rule_id", 1), ("rule_version", 1), ("scope_key", 1)],
         {"name": "tenant_endpoint_rule_scope"}),
        ([("tenant_id", 1), ("evidence_keys", 1)], {"name": "tenant_evidence_keys"}),
        ([("tenant_id", 1), ("last_seen", -1)], {"name": "tenant_last_seen"}),
    ],
    CHECKPOINTS: [
        ([("tenant_id", 1), ("replay_id", 1), ("endpoint_id", 1)], {"unique": True, "name": "uniq_checkpoint"}),
    ],
}


class ConcurrencyConflict(RuntimeError):
    pass


class DetectionStore(Protocol):
    async def get(self, tenant_id: str, detection_id: str) -> Optional[Dict[str, Any]]: ...

    async def find_overlapping(self, *, tenant_id: str, endpoint_id: str, rule_id: str,
                               rule_version: int, scope_key: str,
                               evidence_keys: List[str]) -> Optional[Dict[str, Any]]: ...

    async def put(self, doc: Dict[str, Any], expected_revision: Optional[int]) -> int: ...


class InMemoryDetectionStore:
    def __init__(self) -> None:
        self._d: Dict[Tuple[str, str], Dict[str, Any]] = {}

    async def get(self, tenant_id, detection_id):
        d = self._d.get((tenant_id, detection_id))
        return copy.deepcopy(d) if d else None

    async def find_overlapping(self, *, tenant_id, endpoint_id, rule_id, rule_version, scope_key,
                               evidence_keys):
        keys = set(evidence_keys)
        for (t, _), d in sorted(self._d.items()):
            if (t == tenant_id and d["endpoint_id"] == endpoint_id and d["rule_id"] == rule_id
                    and d["rule_version"] == rule_version and d["scope_key"] == scope_key
                    and keys & set(d["evidence_keys"])):
                return copy.deepcopy(d)
        return None

    async def put(self, doc, expected_revision):
        k = (doc["tenant_id"], doc["detection_id"])
        cur = self._d.get(k)
        if (cur["revision"] if cur else None) != expected_revision:
            raise ConcurrencyConflict(doc["detection_id"])
        new = copy.deepcopy(doc)
        new["revision"] = (expected_revision or 0) + 1
        self._d[k] = new
        return new["revision"]

    def all(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return [copy.deepcopy(d) for (t, _), d in sorted(self._d.items())
                if tenant_id is None or t == tenant_id]


class MongoDetectionStore:
    """Motor-style async collection. Code path only; not exercised against a real Mongo here."""

    def __init__(self, collection: Any) -> None:
        self._c = collection

    async def get(self, tenant_id, detection_id):
        return await self._c.find_one({"tenant_id": tenant_id, "detection_id": detection_id},
                                      {"_id": 0})

    async def find_overlapping(self, *, tenant_id, endpoint_id, rule_id, rule_version, scope_key,
                               evidence_keys):
        return await self._c.find_one({"tenant_id": tenant_id, "endpoint_id": endpoint_id,
                                       "rule_id": rule_id, "rule_version": rule_version,
                                       "scope_key": scope_key,
                                       "evidence_keys": {"$in": list(evidence_keys)}},
                                      {"_id": 0}, sort=[("detection_id", 1)])

    async def put(self, doc, expected_revision):
        body = {k: v for k, v in doc.items() if k not in ("_id", "revision")}
        rev = (expected_revision or 0) + 1
        body["revision"] = rev
        if expected_revision is None:
            try:
                await self._c.insert_one(dict(body))
            except Exception as e:  # duplicate key on the unique index => concurrent insert
                if "duplicate key" in str(e).lower() or "E11000" in str(e):
                    raise ConcurrencyConflict(doc["detection_id"]) from None
                raise
            return rev
        res = await self._c.replace_one({"tenant_id": doc["tenant_id"],
                                         "detection_id": doc["detection_id"],
                                         "revision": expected_revision}, body)
        if getattr(res, "matched_count", 0) != 1:
            raise ConcurrencyConflict(doc["detection_id"])
        return rev


async def ensure_indexes(db: Any) -> None:
    """For E3 test/staging databases only."""
    for coll, specs in INDEXES.items():
        for keys, opts in specs:
            await db[coll].create_index(keys, **opts)
