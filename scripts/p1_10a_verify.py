"""Verify P1.10a proof state."""
import asyncio, os, json
from motor.motor_asyncio import AsyncIOMotorClient


async def main():
    client = AsyncIOMotorClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    db = client[os.environ.get("DB_NAME", "test_database")]

    print("=== xdr_live_reasoning_audit ===")
    async for r in db.xdr_live_reasoning_audit.find({}, {"_id": 0}).sort("at", 1):
        print(json.dumps(r, default=str)[:800])
        print("---")

    print("\n=== xdr_spread_watchlist ===")
    async for r in db.xdr_spread_watchlist.find({}, {"_id": 0}):
        print(f"  {r.get('indicator_type')}/{r.get('indicator_display')[:50]} status={r.get('status')} "
              f"endpoint_count={r.get('endpoint_count')} sightings={r.get('sighting_count')} "
              f"dup={r.get('duplicate_sightings')} unk={r.get('unknown_endpoint_sightings')} "
              f"thresholds={r.get('thresholds_emitted')} source={r.get('source')}")

    print("\n=== xdr_correlation_matches (SPREAD-WATCH-001) ===")
    async for r in db.xdr_correlation_matches.find({"rule_id": "SPREAD-WATCH-001"}, {"_id": 0}):
        s = r.get('spread', {})
        print(f"  claim={r.get('claim')!r}")
        print(f"    threshold={s.get('threshold')} indicator={s.get('indicator_type')}/{s.get('indicator_display')[:40]} "
              f"endpoints={s.get('endpoints')} unknown={s.get('unknown_endpoint_sightings')}")
        print(f"    evidence_level={r.get('evidence_level')} attack_techniques={r.get('attack_techniques')} engine_id={r.get('engine_id')}")

    print("\n=== workspace_cases (incidents) ===")
    n = 0
    async for r in db.workspace_cases.find({"tenant_id": "nivx-live"}, {"_id": 0, "case_id": 1, "title": 1, "status": 1, "created_at": 1}):
        print(" ", r); n += 1
    print("total incidents:", n)

    print("\n=== xdr_spread_sightings ===")
    n = 0
    async for r in db.xdr_spread_sightings.find({}, {"_id": 0, "indicator_type": 1, "indicator_value": 1,
                                                      "endpoint_identity": 1, "endpoint_identity_state": 1,
                                                      "counts_toward_spread": 1, "context": 1}):
        print(f"  {r.get('indicator_type')}/{r.get('indicator_value')[:20]} ident={r.get('endpoint_identity')} state={r.get('endpoint_identity_state')} counts={r.get('counts_toward_spread')} ctx.src={r.get('context',{}).get('src_ip')} ctx.user={r.get('context',{}).get('username')}")
        n += 1
    print("total sightings:", n)

asyncio.run(main())
