"""READ-ONLY · Security-channel accepted vs blocked EventID evidence."""
import asyncio, json, os, re, sys
from collections import Counter
sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

TEN = "ten_f1a5479243e901cf159e230fa0"


async def main():
    cli = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = cli[os.environ["DB_NAME"]]

    ev = db["xdr_canonical_events"]
    q = {"tenant_id": TEN, "source_event_id": {"$regex": r"\|Security\|"}}
    n = await ev.count_documents(q)
    print(f"xdr_canonical_events Security-channel rows = {n}")
    eids = Counter()
    recs = []
    async for d in ev.find(q):
        norm = d.get("normalized") or {}
        eids[str(norm.get("event_id"))] += 1
        recs.append((d.get("source_event_id"), norm.get("event_id"),
                     d.get("event_type"), d.get("parser_ok"),
                     d.get("normalized_ok")))
    print("accepted Security EventID histogram:", dict(eids))
    for r in recs[:10]:
        print("   ", r)

    ce = db["xdr_canonical_evidence"]
    q2 = {"tenant_id": TEN,
          "provenance.routing.selected_dsm_id": "windows-security-evd"}
    print(f"\nxdr_canonical_evidence routed windows-security-evd = "
          f"{await ce.count_documents(q2)}")
    async for d in ce.find(q2):
        print("   event_id=", d.get("event_id"), "type=", d.get("event_type"),
              "source_event_id=", d.get("source_event_id"),
              "time=", d.get("event_time"))

    # blocked Security record ids, to show the population and the gap
    bl = db["xdr_ingest_routing_blocks"]
    ids = []
    async for d in bl.find({"routing.mismatch_reason": "SOURCE_FORMAT_MISMATCH",
                            "routing.declared_source_resolved":
                            "windows-security-evd"},
                           {"source_event_id": 1, "payload_keys": 1,
                            "payload_excerpt": 1}):
        ids.append((d.get("source_event_id"), d.get("payload_keys"),
                    repr(d.get("payload_excerpt"))[:40]))
    print(f"\nblocked Security SOURCE_FORMAT_MISMATCH rows = {len(ids)}")
    for r in ids:
        print("   ", r)
    cli.close()

asyncio.run(main())
