"""READ-ONLY server-side RCA · Windows Security SOURCE_FORMAT_MISMATCH.

No writes. No endpoint contact. Reads stored G1 routing-block evidence only.
"""
import asyncio, json, os, sys
from collections import Counter

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient


async def main():
    cli = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = cli[os.environ["DB_NAME"]]
    col = db["xdr_ingest_routing_blocks"]

    total = await col.count_documents({})
    print(f"xdr_ingest_routing_blocks total = {total}")

    reasons = Counter()
    declared = Counter()
    async for d in col.find({}, {"routing": 1, "declared_payload_format": 1}):
        r = d.get("routing") or {}
        reasons[r.get("mismatch_reason")] += 1
        declared[(r.get("declared_source"), r.get("mismatch_reason"))] += 1
    print("\nreason histogram:", json.dumps({str(k): v for k, v in reasons.items()}, indent=2))
    print("\n(declared_source, reason) histogram:")
    for k, v in declared.most_common(40):
        print("   ", k, "->", v)

    q = {"routing.mismatch_reason": "SOURCE_FORMAT_MISMATCH"}
    n = await col.count_documents(q)
    print(f"\nSOURCE_FORMAT_MISMATCH rows = {n}")
    async for d in col.find(q).sort("nivx_received_at", -1).limit(5):
        d.pop("_id", None)
        print("\n--- BLOCK RECORD ---")
        print(json.dumps(d, indent=2, default=str)[:6000])

    cli.close()

asyncio.run(main())
