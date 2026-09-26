"""READ-ONLY · shape probe of stored canonical evidence for the G1 collector."""
import asyncio, json, os, sys
from collections import Counter
sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

TEN = "ten_f1a5479243e901cf159e230fa0"
COL = "col_d6b0b9e8172246f29be9"


async def main():
    cli = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = cli[os.environ["DB_NAME"]]
    for name in ("xdr_canonical_events", "xdr_canonical_evidence",
                 "canonical_ssot_store"):
        col = db[name]
        n = await col.count_documents({"tenant_id": TEN})
        print(f"\n=== {name} · tenant rows = {n} / total {await col.count_documents({})}")
        d = await col.find_one({"tenant_id": TEN})
        if d:
            d.pop("_id", None)
            print("keys:", sorted(d.keys()))
            print(json.dumps(d, default=str)[:2500])
        hist = Counter()
        async for x in col.find({"tenant_id": TEN},
                                {"source_type": 1, "dsm_id": 1,
                                 "provenance": 1, "channel": 1}):
            prov = x.get("provenance") or {}
            hist[(x.get("source_type"), x.get("dsm_id"),
                  (prov.get("routing") or {}).get("selected_dsm_id")
                  if isinstance(prov, dict) else None)] += 1
        for k, v in hist.most_common(15):
            print("   ", k, "->", v)
    cli.close()

asyncio.run(main())
