"""Reset for P1.10a proof run."""
import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient


async def main():
    client = AsyncIOMotorClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    db = client[os.environ.get("DB_NAME", "test_database")]
    r = {}
    r["workspace_cases"] = (await db.workspace_cases.delete_many({"tenant_id": "nivx-live"})).deleted_count
    r["xdr_canonical_evidence"] = (await db.xdr_canonical_evidence.delete_many({"tenant_id": "nivx-live"})).deleted_count
    r["v2_shadow_observations"] = (await db.v2_shadow_observations.delete_many({"origin": "collector-live"})).deleted_count
    r["xdr_live_reasoning_audit"] = (await db.xdr_live_reasoning_audit.delete_many({})).deleted_count
    r["xdr_spread_watchlist"] = (await db.xdr_spread_watchlist.delete_many({})).deleted_count
    r["xdr_spread_sightings"] = (await db.xdr_spread_sightings.delete_many({})).deleted_count
    r["xdr_correlation_matches (SPREAD-WATCH-001)"] = (await db.xdr_correlation_matches.delete_many({"rule_id": "SPREAD-WATCH-001"})).deleted_count
    await db.xdr_collectors.update_one(
        {"id": "col_6551885c766a458ab315"},
        {"$set": {"events_received": 0, "events_parsed": 0, "events_normalized": 0, "events_error": 0, "state": "ADOPTED"}}
    )
    print("RESET:", r)

asyncio.run(main())
