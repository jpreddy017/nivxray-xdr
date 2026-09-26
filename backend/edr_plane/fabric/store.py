"""GATE 3 + P0-C · the DURABLE findings store.

A NEW collection (`edr_findings`). Nothing existing is migrated, mutated
or re-labelled — the raw and canonical evidence stores are not written to
by the fabric, which is the precondition for Gate 6 retrospection.

P0-C adds durability with an explicit immutability guarantee:

* writes are idempotent on the content-addressed `finding_id`, so
  re-evaluating the same evidence with the same analyzer version, source
  and rule never duplicates a finding;
* every ANALYTIC field is written with `$ifNull`, so a re-evaluation can
  never overwrite the historical record of what was found and why. A
  changed analysis is a NEW finding (its identity changes) — never an
  edit of the old one. Re-evaluation/supersession semantics are Gate 6
  and are deliberately absent here;
* only the recurrence accounting moves: `last_seen`, `recurrence_count`
  and `last_recorded_at` — facts ABOUT the record, not the finding.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from deps import sync_collection

from edr_plane.fabric.contracts import Finding

COLLECTION = "edr_findings"

#: Fields the store owns. Everything else on the document is the
#: analytic body and is write-once.
_RECURRENCE_FIELDS = ("last_seen", "recurrence_count", "last_recorded_at")

IMMUTABILITY_CONTRACT = (
    "A persisted finding is write-once. A repeated evaluation updates only "
    "last_seen / recurrence_count / last_recorded_at; the analysis (label, "
    "severity, confidence, rule, detection_source, evidence_refs, features) "
    "is never rewritten. A different analysis has a different identity and "
    "is a NEW finding. Historical re-evaluation and supersession are Gate 6 "
    "and are NOT implemented here."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_indexes() -> None:
    coll = sync_collection(COLLECTION)
    coll.create_index([("tenant_id", 1), ("finding_id", 1)], unique=True)
    coll.create_index([("tenant_id", 1), ("first_seen", -1),
                       ("finding_id", -1)])
    coll.create_index([("tenant_id", 1), ("endpoint_ref", 1),
                       ("first_seen", -1)])
    coll.create_index([("tenant_id", 1), ("detection_source", 1)])
    coll.create_index([("tenant_id", 1), ("rule_id", 1)])


def persist(findings: Iterable[Finding]) -> Dict[str, Any]:
    coll = sync_collection(COLLECTION)
    inserted = existing = 0
    ids: List[str] = []
    for f in findings:
        doc = f.to_mongo()
        seen = f.observed_at or f.evaluation_time or _now()
        now = _now()
        write_once = {k: {"$ifNull": [f"${k}", {"$literal": v}]}
                      for k, v in doc.items()
                      if k not in _RECURRENCE_FIELDS}
        stage = {
            **write_once,
            "created_at": {"$ifNull": ["$created_at", now]},
            "first_seen": {"$ifNull": ["$first_seen", seen]},
            "last_seen": {"$cond": [
                {"$gt": [seen, {"$ifNull": ["$last_seen", ""]}]},
                seen, "$last_seen"]},
            "recurrence_count": {"$add": [
                {"$ifNull": ["$recurrence_count", 0]}, 1]},
            "last_recorded_at": now,
        }
        res = coll.update_one({"finding_id": doc["finding_id"],
                               "tenant_id": doc["tenant_id"]},
                              [{"$set": stage}], upsert=True)
        if getattr(res, "upserted_id", None) is not None:
            inserted += 1
        else:
            existing += 1
        ids.append(doc["finding_id"])
    return {"inserted": inserted, "already_present": existing,
            "finding_ids": ids, "collection": COLLECTION,
            "immutability": IMMUTABILITY_CONTRACT,
            "note": ("a finding is content-addressed, so a repeated "
                     "evaluation is recognised rather than duplicated")}


def _query(tenant_id: str, *, endpoint_ref: Optional[str] = None,
           severity: Optional[str] = None, rule_id: Optional[str] = None,
           detection_source: Optional[str] = None,
           since: Optional[str] = None,
           until: Optional[str] = None) -> Dict[str, Any]:
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_ref:
        q["endpoint_ref"] = endpoint_ref
    if severity:
        q["severity"] = severity
    if rule_id:
        q["rule_id"] = rule_id
    if detection_source:
        q["detection_source"] = detection_source
    window: Dict[str, Any] = {}
    if since:
        window["$gte"] = since
    if until:
        window["$lte"] = until
    if window:
        q["first_seen"] = window
    return q


def read(tenant_id: str, *, limit: int = 200,
         cursor: Optional[str] = None,
         **filters) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Tenant-partitioned read. The tenant is the caller's server-resolved
    tenant, never a value the client presented.

    Returns `(rows, next_cursor)`; the cursor is a keyset over
    `(first_seen, finding_id)` so a page boundary cannot drop or repeat a
    finding when new ones arrive.
    """
    q = _query(tenant_id, **filters)
    if cursor:
        try:
            c_seen, c_id = cursor.split("|", 1)
        except ValueError:
            c_seen, c_id = cursor, ""
        q["$or"] = [{"first_seen": {"$lt": c_seen}},
                    {"first_seen": c_seen, "finding_id": {"$lt": c_id}}]
    n = max(1, min(int(limit), 500))
    rows = list(sync_collection(COLLECTION)
                .find(q, {"_id": 0})
                .sort([("first_seen", -1), ("finding_id", -1)])
                .limit(n + 1))
    nxt = None
    if len(rows) > n:
        rows = rows[:n]
        nxt = f"{rows[-1].get('first_seen')}|{rows[-1].get('finding_id')}"
    return rows, nxt


def get(tenant_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
    return sync_collection(COLLECTION).find_one(
        {"tenant_id": tenant_id, "finding_id": finding_id}, {"_id": 0})


def counts(tenant_id: str, **filters) -> Dict[str, Any]:
    coll = sync_collection(COLLECTION)
    q = _query(tenant_id, **filters)
    by_severity = {r["_id"] or "NOT_RECORDED_BY_SOURCE": r["n"] for r in
                   coll.aggregate([{"$match": q},
                                   {"$group": {"_id": "$severity",
                                               "n": {"$sum": 1}}}])}
    by_source = {r["_id"]: r["n"] for r in
                 coll.aggregate([{"$match": q},
                                 {"$group": {"_id": "$detection_source",
                                             "n": {"$sum": 1}}}])}
    return {"total": coll.count_documents(q),
            "by_severity": by_severity,
            "by_detection_source": by_source}
