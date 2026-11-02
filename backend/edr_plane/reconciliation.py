"""Bounded, restartable reconciliation of explicitly owned raw evidence.

A fixed upper _id bounds each sweep. Cursor advancement happens only after
every job in the page is durably ensured. Competing scanners may repeat a
page, but a version comparison prevents stale progress from overwriting a
newer cursor. No raw records or existing jobs are changed.
"""
from typing import Any
from pymongo.errors import DuplicateKeyError

CURSORS = "edr_processing_reconciliation"
RAW = "edr_raw_events"


async def reconcile_page(db: Any, *, enqueue, contract: str, limit: int):
    limit = max(1, min(int(limit), 5000))
    counts = {"scanned": 0, "created": 0, "already_present": 0}
    cursors = db[CURSORS]
    key = {"_id": contract}
    try:
        await cursors.update_one(key, {"$setOnInsert": {
            "version": 0, "after": None, "upper": None}}, upsert=True)
    except DuplicateKeyError:
        # Only the fixed cursor identity can race here. A missing winner
        # below is an error, never permission to advance without a cursor.
        pass
    state = await cursors.find_one(key)
    if state is None:
        raise RuntimeError("reconciliation cursor could not be read")
    version = state["version"]
    after, upper = state.get("after"), state.get("upper")
    owned = {"processing_contract": contract, "trust_state": "AUTHENTICATED"}
    if upper is None:
        last = await db[RAW].find_one(owned, {"_id": 1}, sort=[("_id", -1)])
        if last is None:
            return counts
        upper = last["_id"]
        saved = await cursors.update_one(
            {**key, "version": version},
            {"$set": {"upper": upper}, "$inc": {"version": 1}})
        if not saved.modified_count:
            return counts
        version += 1
    bounds = {"$lte": upper}
    if after is not None:
        bounds["$gt"] = after
    page = db[RAW].find(
        {**owned, "_id": bounds},
        {"_id": 1, "tenant_id": 1, "raw_id": 1}
    ).sort("_id", 1).limit(limit)
    last_id = after
    async for row in page:
        tenant, raw_id = row.get("tenant_id"), row.get("raw_id")
        if not tenant or not raw_id:
            raise RuntimeError("owned raw evidence lacks tenant/raw identity")
        result = await enqueue(db, tenant_id=tenant, raw_id=raw_id)
        counts["scanned"] += 1
        counts["created" if result["created"] else "already_present"] += 1
        last_id = row["_id"]
    # A short/empty page finishes this finite sweep. The next sweep starts
    # from the beginning, including records inserted behind the cursor.
    progress = ({"after": None, "upper": None} if counts["scanned"] < limit
                else {"after": last_id, "upper": upper})
    await cursors.update_one(
        {**key, "version": version},
        {"$set": progress, "$inc": {"version": 1}})
    return counts
