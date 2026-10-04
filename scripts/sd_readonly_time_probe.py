"""§d READ-ONLY evidence probe. Classifies observation-time fields, lists indexes,
and captures real query plans for the newest-first contract. WRITES NOTHING."""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv  # noqa: E402

load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

CANON = "xdr_canonical_evidence"
SHADOW = "v2_shadow_observations"
RAW = "edr_raw_events"


def jd(x):
    return json.dumps(x, default=str, indent=2)


def stages(plan):
    """Flatten winningPlan stage names + index used."""
    out, cur = [], plan
    while isinstance(cur, dict):
        st = cur.get("stage")
        if st:
            out.append(st + (f"[{cur.get('indexName')}]" if cur.get("indexName") else ""))
        cur = cur.get("inputStage") or cur.get("inputStages") or None
        if isinstance(cur, list):
            cur = cur[0] if cur else None
    return " -> ".join(out)


async def main():
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    print("DB_NAME =", os.environ["DB_NAME"])

    print("\n=== A. COLLECTION COUNTS + INDEXES ===")
    for c in (CANON, SHADOW, RAW):
        n = await db[c].estimated_document_count()
        idx = await db[c].index_information()
        print(f"\n[{c}] estimated_docs={n}")
        for name, spec in idx.items():
            print(f"   idx {name}: {spec.get('key')}")

    print("\n=== B. OBSERVATION-TIME FIELD POPULATION ===")
    for c, fields in ((CANON, ["event_time", "ingest_time", "observed_at", "observed_ms",
                               "received_at", "created_at", "event_id", "tenant_id"]),
                      (SHADOW, ["event.ts", "captured_at", "ingest_time", "observed_ms",
                                "observation_id", "tenant_id"]),
                      (RAW, ["event_time", "ingest_time", "observed_ms", "raw_id", "tenant_id"])):
        total = await db[c].estimated_document_count()
        print(f"\n[{c}] total={total}")
        for f in fields:
            present = await db[c].count_documents({f: {"$exists": True, "$ne": None}}, maxTimeMS=60000)
            types = {}
            async for d in db[c].find({f: {"$exists": True, "$ne": None}}, {f: 1, "_id": 0}).limit(3):
                cur = d
                for part in f.split("."):
                    cur = (cur or {}).get(part) if isinstance(cur, dict) else None
                types[type(cur).__name__] = str(cur)[:40]
            pct = (100.0 * present / total) if total else 0.0
            print(f"   {f:<16} present={present:<8} ({pct:5.1f}%) sample_types={types}")

    print("\n=== C. KUSHU ENDPOINT RESOLUTION (read-only) ===")
    eps = [e async for e in db["edr_endpoints"].find(
        {"$or": [{"hostname": {"$regex": "KUSHU", "$options": "i"}},
                 {"computer_name": {"$regex": "KUSHU", "$options": "i"}}]},
        {"_id": 0, "endpoint_id": 1, "hostname": 1, "tenant_id": 1, "device_iid": 1,
         "collector_id": 1, "last_telemetry_at": 1, "status": 1, "lifecycle_state": 1})]
    print(jd(eps))

    if not eps:
        print("NO KUSHU ENDPOINT FOUND -> cannot run plan probe against real device")
        return
    ep = eps[0]
    tenant = ep.get("tenant_id")
    dev_candidates = [v for v in (ep.get("collector_id"), ep.get("device_iid"),
                                  ep.get("endpoint_id"), ep.get("hostname")) if v]
    print("tenant =", tenant, "device_candidates =", dev_candidates)

    print("\n=== D. REAL EVIDENCE VOLUME PER STORE FOR THIS DEVICE ===")
    probes = {
        CANON: {"tenant_id": tenant, "$or": [{"provenance.collector_id": {"$in": dev_candidates}},
                                             {"host.host_id": {"$in": dev_candidates}},
                                             {"host.hostname": {"$in": dev_candidates}}]},
        SHADOW: {"tenant_id": tenant, "$or": [{"event.device_iid": {"$in": dev_candidates}},
                                              {"collector_id": {"$in": dev_candidates}},
                                              {"event.computer": {"$in": dev_candidates}}]},
    }
    for c, flt in probes.items():
        n = await db[c].count_documents(flt, maxTimeMS=120000)
        print(f"   [{c}] matching docs = {n}")

    print("\n=== E. QUERY PLANS — OPTION A CONTRACT (newest-first + stable tie-breaker) ===")
    for c, flt, tkey, idkey in ((CANON, probes[CANON], "event_time", "event_id"),
                                (SHADOW, probes[SHADOW], "event.ts", "observation_id")):
        print(f"\n--- {c} sort({tkey} DESC, {idkey} DESC).limit(200) ---")
        try:
            ex = await db.command({
                "explain": {"find": c, "filter": flt,
                            "sort": {tkey: -1, idkey: -1}, "limit": 200},
                "verbosity": "executionStats"})
            w = ex["queryPlanner"]["winningPlan"]
            st = ex.get("executionStats", {})
            print("   winningPlan:", stages(w))
            print("   SORT_PRESENT:", "SORT" in stages(w))
            print("   nReturned=", st.get("nReturned"),
                  "totalKeysExamined=", st.get("totalKeysExamined"),
                  "totalDocsExamined=", st.get("totalDocsExamined"),
                  "executionTimeMillis=", st.get("executionTimeMillis"))
            print("   rejectedPlans:", [stages(p) for p in ex["queryPlanner"].get("rejectedPlans", [])])
        except Exception as ex:  # noqa: BLE001
            print("   EXPLAIN FAILED:", type(ex).__name__, str(ex)[:300])

    print("\n=== F. CURRENT §d BEHAVIOUR (what providers.py actually issues: no sort, no limit) ===")
    for c, flt in probes.items():
        try:
            ex = await db.command({"explain": {"find": c, "filter": flt},
                                   "verbosity": "executionStats"})
            st = ex.get("executionStats", {})
            print(f"   [{c}] plan={stages(ex['queryPlanner']['winningPlan'])} "
                  f"docsExamined={st.get('totalDocsExamined')} ms={st.get('executionTimeMillis')}")
        except Exception as ex:  # noqa: BLE001
            print(f"   [{c}] EXPLAIN FAILED:", str(ex)[:200])

    print("\n=== G. TIE-BREAKER VIABILITY: duplicate observation timestamps ===")
    for c, tkey in ((CANON, "event_time"), (SHADOW, "event.ts")):
        flt = probes[c]
        dup = [d async for d in db[c].aggregate([
            {"$match": flt}, {"$group": {"_id": f"${tkey}", "n": {"$sum": 1}}},
            {"$match": {"n": {"$gt": 1}}}, {"$sort": {"n": -1}}, {"$limit": 3}],
            allowDiskUse=True, maxTimeMS=120000)]
        print(f"   [{c}] top duplicate {tkey} buckets: {jd(dup)}")

    print("\n=== H. CHRONOLOGY SKEW: observation vs ingestion (backlog replay evidence) ===")
    rows = [d async for d in db[CANON].find(
        probes[CANON], {"_id": 0, "event_time": 1, "ingest_time": 1, "event_id": 1}).limit(5)]
    print(jd(rows))
    print("\nPROBE COMPLETE. WRITES PERFORMED: 0")


asyncio.run(main())
