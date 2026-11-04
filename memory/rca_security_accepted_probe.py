"""READ-ONLY · did any Security-channel delivery from the G1 run get ACCEPTED?"""
import asyncio, json, os, sys
from collections import Counter
sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

TEN = "ten_f1a5479243e901cf159e230fa0"


async def main():
    cli = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = cli[os.environ["DB_NAME"]]
    names = await db.list_collection_names()
    print("collections with 'raw' or 'canonical':",
          sorted(n for n in names if "raw" in n or "canonical" in n))

    ev = db["xdr_canonical_events"]
    q = {"tenant_id": TEN, "provenance.routing.selected_dsm_id":
         "windows-security-evd"}
    print("\nACCEPTED canonical events routed to windows-security-evd:",
          await ev.count_documents(q))
    async for d in ev.find(q).limit(3):
        prov = d.get("provenance") or {}
        print("  event_id=", d.get("event_id"),
              "routing=", json.dumps(prov.get("routing"))[:300])

    dsm_hist = Counter()
    async for d in ev.find({"tenant_id": TEN},
                           {"provenance.routing.selected_dsm_id": 1,
                            "provenance.ingest.collection_method": 1}):
        prov = d.get("provenance") or {}
        dsm_hist[((prov.get("routing") or {}).get("selected_dsm_id"),
                  (prov.get("ingest") or {}).get("collection_method"))] += 1
    print("\ntenant canonical events by (dsm, collection_method):")
    for k, v in dsm_hist.most_common(20):
        print("   ", k, "->", v)

    for coll in ("xdr_raw_events", "xdr_raw_envelopes", "xdr_ingest_raw"):
        if coll in names:
            n = await db[coll].count_documents({"tenant_id": TEN})
            print(f"\n{coll} rows for tenant = {n}")
            async for d in db[coll].find({"tenant_id": TEN}).limit(2):
                d.pop("_id", None)
                print(json.dumps(d, default=str)[:1200])
    cli.close()

asyncio.run(main())
