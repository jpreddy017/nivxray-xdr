#!/usr/bin/env python3
"""One-off, auditable cleanup of duplicated sensor evidence (P0-D).

Before the activity-identity guard existed, a sensor restart re-reported
the entire running process table, so ONE real process could be held as
many canonical evidence rows. This collapses those rows to one per
observed activity.

Nothing is lost: `edr_raw_events` retains every original payload
immutably, so any collapsed row is re-derivable. Only the derived
`v2_shadow_observations` projection is corrected, and every deletion is
printed.

    python3 /app/scripts/p0_d_sensor_evidence_dedupe.py [--apply]
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv                                  # noqa: E402
from motor.motor_asyncio import AsyncIOMotorClient              # noqa: E402

load_dotenv("/app/backend/.env")
APPLY = "--apply" in sys.argv
ADAPTER_PREFIX = "nivxforge-linux-sensor"


async def main() -> None:
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    coll = db["v2_shadow_observations"]
    groups: dict[tuple, list] = {}
    async for d in coll.find(
            {"adapter": {"$regex": f"^{ADAPTER_PREFIX}"}},
            {"event.iid": 1, "tenant_id": 1, "captured_at": 1}):
        key = (d.get("tenant_id"), (d.get("event") or {}).get("iid"))
        groups.setdefault(key, []).append(d)

    dupes = {k: v for k, v in groups.items() if len(v) > 1}
    removable = 0
    for key, rows in dupes.items():
        rows.sort(key=lambda r: str(r.get("_id")))
        removable += len(rows) - 1
        print(f"  {key[1]}  held {len(rows)}x  → keep {rows[0]['_id']}")
        if APPLY:
            await coll.delete_many({"_id": {"$in": [r["_id"]
                                                    for r in rows[1:]]}})

    print(f"\nsensor evidence rows      : {sum(len(v) for v in groups.values())}")
    print(f"distinct observed activity : {len(groups)}")
    print(f"duplicated activities      : {len(dupes)}")
    print(f"rows {'DELETED' if APPLY else 'that WOULD be deleted'}: {removable}")

    # Backfill the activity identity onto rows that predate the guard, so
    # a freshly-enrolled sensor re-reporting a long-running process cannot
    # create a second evidence row for it.
    from edr_plane.canonical_bridge import activity_identity  # noqa: E402
    import json
    backfilled = 0
    async for raw in db["edr_raw_events"].find(
            {"source_kind": "sensor"},
            {"payload": 1, "tenant_id": 1, "endpoint_ref": 1,
             "derivations": 1}):
        ev_ids = [d.get("event_id") for d in (raw.get("derivations") or ())
                  if d.get("parser_state") == "OK" and d.get("event_id")]
        if not ev_ids:
            continue
        try:
            act = activity_identity(json.loads(raw["payload"]),
                                    raw.get("endpoint_ref") or "")
        except (ValueError, TypeError):
            continue
        if APPLY:
            res = await coll.update_many(
                {"tenant_id": raw.get("tenant_id"),
                 "canonical_event_id": {"$in": ev_ids},
                 "activity_identity": None},
                {"$set": {"activity_identity": act}})
            backfilled += res.modified_count
        else:
            backfilled += await coll.count_documents(
                {"tenant_id": raw.get("tenant_id"),
                 "canonical_event_id": {"$in": ev_ids},
                 "activity_identity": None})
    print(f"activity_identity {'backfilled' if APPLY else 'to backfill'}: "
          f"{backfilled}")
    if not APPLY:
        print("\ndry run — re-run with --apply to correct the projection")


asyncio.run(main())
