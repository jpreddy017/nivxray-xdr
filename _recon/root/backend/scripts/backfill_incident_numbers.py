"""
Idempotent backfill · persisted human-facing incident numbers.

Owner-authorised 2026-09-05 ("APPROVE REAL INCIDENT NUMBERS").

  * Only ``doc_type == "xdr_incident"`` documents are numbered.
  * Deterministic order: ``created_at`` then ``id``, so the same corpus
    always produces the same assignment.
  * An incident that already has a number is NEVER renumbered.
  * The global counter is advanced to the highest number in use, so a
    later pipeline-created incident cannot collide with a backfilled one.
  * Re-running changes zero records.

Usage:
    python -m scripts.backfill_incident_numbers            # dry run
    python -m scripts.backfill_incident_numbers --apply
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.incident_numbering import (          # noqa: E402
    COUNTERS_COLLECTION, COUNTER_ID, INCIDENT_COLLECTION, INCIDENT_DOC_TYPE,
    ensure_incident_number_indexes, format_incident_number,
    parse_incident_number,
)


async def run(apply: bool) -> int:
    import deps
    deps.validate_config()
    deps.init_database()
    db = deps.db

    col = db[INCIDENT_COLLECTION]

    existing_max = 0
    already = 0
    cursor = col.find(
        {"doc_type": INCIDENT_DOC_TYPE,
         "incident_number": {"$type": "string"}},
        {"_id": 0, "incident_number": 1},
    )
    async for d in cursor:
        already += 1
        n = parse_incident_number(d.get("incident_number"))
        if n and n > existing_max:
            existing_max = n

    todo = []
    cursor = col.find(
        {"doc_type": INCIDENT_DOC_TYPE,
         "incident_number": {"$exists": False}},
        {"_id": 1, "id": 1, "created_at": 1},
    )
    async for d in cursor:
        todo.append(d)
    # Deterministic: oldest first, id as the tie-break.
    todo.sort(key=lambda d: (str(d.get("created_at") or ""), str(d.get("id") or "")))

    print(f"already numbered : {already} (max {format_incident_number(existing_max) if existing_max else '—'})")
    print(f"to number        : {len(todo)}")

    if not apply:
        for d in todo[:5]:
            print(f"  DRY  {d.get('id')} → "
                  f"{format_incident_number(existing_max + 1 + todo.index(d))}")
        print("dry run — nothing written (pass --apply)")
        return 0

    await ensure_incident_number_indexes(db)

    seq = existing_max
    written = 0
    for d in todo:
        seq += 1
        number = format_incident_number(seq)
        res = await col.update_one(
            # The `$exists: False` guard makes the write itself idempotent
            # even under a concurrent second run.
            {"_id": d["_id"], "incident_number": {"$exists": False}},
            {"$set": {"incident_number": number}},
        )
        written += res.modified_count

    # Park the counter above everything in use.
    await db[COUNTERS_COLLECTION].update_one(
        {"_id": COUNTER_ID},
        {"$max": {"seq": seq}},
        upsert=True,
    )
    print(f"written          : {written}")
    print(f"counter parked at: {seq} ({format_incident_number(seq)})")

    total = await col.count_documents({"doc_type": INCIDENT_DOC_TYPE})
    numbered = await col.count_documents(
        {"doc_type": INCIDENT_DOC_TYPE, "incident_number": {"$type": "string"}})
    leaked = await col.count_documents(
        {"doc_type": {"$ne": INCIDENT_DOC_TYPE},
         "incident_number": {"$exists": True}})
    print(f"incidents        : {numbered}/{total} numbered")
    print(f"non-incidents numbered (must be 0): {leaked}")
    return 0 if (numbered == total and leaked == 0) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(run(args.apply)))
