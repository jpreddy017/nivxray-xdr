"""GATE 3 · the findings store.

A NEW collection (`edr_findings`). Nothing existing is migrated, mutated
or re-labelled — the raw and canonical evidence stores are not written to
by the fabric, which is the precondition for Gate 6 retrospection.

Writes are idempotent on the content-addressed `finding_id`, so
re-evaluating the same evidence with the same analyzer version and the
same features never duplicates a finding.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from deps import sync_collection

from edr_plane.fabric.contracts import Finding

COLLECTION = "edr_findings"


def persist(findings: Iterable[Finding]) -> Dict[str, Any]:
    coll = sync_collection(COLLECTION)
    inserted = existing = 0
    for f in findings:
        doc = f.to_mongo()
        res = coll.update_one({"finding_id": doc["finding_id"],
                               "tenant_id": doc["tenant_id"]},
                              {"$setOnInsert": doc}, upsert=True)
        if getattr(res, "upserted_id", None) is not None:
            inserted += 1
        else:
            existing += 1
    return {"inserted": inserted, "already_present": existing,
            "collection": COLLECTION,
            "note": ("a finding is content-addressed, so a repeated "
                     "evaluation is recognised rather than duplicated")}


def read(tenant_id: str, *, endpoint_ref: str | None = None,
         limit: int = 200) -> List[Dict[str, Any]]:
    """Tenant-partitioned read. The tenant is the caller's server-resolved
    tenant, never a value the client presented."""
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_ref:
        q["endpoint_ref"] = endpoint_ref
    return list(sync_collection(COLLECTION)
                .find(q, {"_id": 0})
                .sort("evaluation_time", -1)
                .limit(max(1, min(limit, 1000))))
