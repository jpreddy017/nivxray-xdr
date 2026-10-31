"""STEP 34A preflight — READ ONLY. Explain + one bounded page + adapter dry run.

No writes, no engine, no frontier, no index creation. Runs against whatever
database MONGO_URL points at.
"""
import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
import sys

sys.path.insert(0, "/app/backend")
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

from edr_plane.behavior_evidence_adapter import to_evidence_record  # noqa: E402
from edr_trajectory.production_adapter import (OBSERVATION_TIME_KEY,  # noqa: E402
                                               _window_bounds, branches,
                                               page_device_evidence)

FETCH = 25 + 64


async def busiest(db):
    """The preview endpoint with the most canonical evidence."""
    pipe = [{"$group": {"_id": {"t": "$tenant_id", "h": "$host.host_id",
                                "n": "$host.hostname"},
                        "n": {"$sum": 1},
                        "newest": {"$max": "$event_time"}}},
            {"$sort": {"n": -1}}, {"$limit": 3}]
    return [d async for d in db.xdr_canonical_evidence.aggregate(pipe)]


async def main():
    c = AsyncIOMotorClient(os.environ["MONGO_URL"], serverSelectionTimeoutMS=5000)
    db = c[os.environ["DB_NAME"]]
    top = await busiest(db)
    print("TOP CANONICAL ENDPOINTS:")
    for t in top:
        print("  ", t)
    pick = top[0]
    tenant = pick["_id"]["t"]
    host_id, hostname = pick["_id"]["h"], pick["_id"]["n"]
    ep = await db.edr_endpoints.find_one(
        {"tenant_id": tenant, "$or": [{"hostname": hostname},
                                      {"device_iid": host_id},
                                      {"endpoint_id": host_id}]},
        {"_id": 0, "endpoint_id": 1, "hostname": 1, "device_iid": 1,
         "collector_id": 1, "tenant_id": 1})
    print("\nREGISTRY ENDPOINT:", ep)
    refs = sorted({str(v) for v in (host_id, hostname,
                                    (ep or {}).get("endpoint_id"),
                                    (ep or {}).get("device_iid"),
                                    (ep or {}).get("collector_id")) if v})
    newest = str(pick["newest"])
    end = datetime.fromisoformat(newest.replace("Z", "+00:00"))
    start = end - timedelta(minutes=10)
    print("REFS:", refs)
    print("WINDOW:", start.isoformat(), "->", end.isoformat())

    lo_us, hi_us, lo_s, hi_s = _window_bounds(start.isoformat(), end.isoformat())
    print("STRING BOUND:", lo_s, hi_s)

    print("\n=== P1 BRANCH EXPLAINS ===")
    rows = []
    for store in ("v2_shadow_observations", "xdr_canonical_evidence"):
        tkey = OBSERVATION_TIME_KEY[store]
        for flt in branches(store, refs, tenant):
            q = dict(flt)
            q[tkey] = {"$gte": lo_s, "$lte": hi_s}
            field = [k for k in flt if k != "tenant_id"][0]
            t0 = time.perf_counter()
            ex = await db.command({
                "explain": {"find": store, "filter": q,
                            "sort": {tkey: -1}, "limit": FETCH},
                "verbosity": "executionStats"})
            ms = (time.perf_counter() - t0) * 1000
            st = ex["executionStats"]
            plan = ex["queryPlanner"]["winningPlan"]

            def chain(p, acc=None):
                acc = acc or []
                acc.append(p.get("stage"))
                for key in ("inputStage", "queryPlan"):
                    if key in p:
                        chain(p[key], acc)
                if "inputStages" in p:
                    for s in p["inputStages"]:
                        chain(s, acc)
                return [a for a in acc if a]

            stages = chain(plan)
            idx = None
            def findidx(p):
                nonlocal idx
                if p.get("stage") == "IXSCAN":
                    idx = p.get("indexName")
                for key in ("inputStage", "queryPlan"):
                    if key in p:
                        findidx(p[key])
                for s in p.get("inputStages", []):
                    findidx(s)
            findidx(plan)
            rows.append({
                "store": store, "field": field, "stages": stages,
                "index": idx, "blocking_sort": "SORT" in stages,
                "keys": st["totalKeysExamined"], "docs": st["totalDocsExamined"],
                "nReturned": st["nReturned"],
                "executionTimeMillis": st["executionTimeMillis"],
                "wall_ms": round(ms, 1)})
            print(f'  {store:24s} {field:26s} idx={idx} stages={stages} '
                  f'keys={st["totalKeysExamined"]} docs={st["totalDocsExamined"]} '
                  f'n={st["nReturned"]} ms={st["executionTimeMillis"]}')

    print("\n=== P2 ONE BOUNDED PAGE ===")
    t0 = time.perf_counter()
    page = await page_device_evidence(db, tenant_id=tenant, refs=refs,
                                      page_size=25, cursor=None,
                                      time_start=start.isoformat(),
                                      time_end=end.isoformat())
    page_ms = (time.perf_counter() - t0) * 1000
    print("  latency_ms:", round(page_ms, 1), "state:", page["state"],
          "rows:", len(page["items"]), "has_more:", page["has_more"])
    print("  rows_per_store:", page["provenance"]["rows_per_store"])
    print("  branch_queries:", page["provenance"]["branch_queries"],
          "fetch:", page["provenance"]["branch_fetch_size"])
    print("  suppressed_duplicates:", page["suppressed_duplicates"])
    print("  unplaceable:", page["unplaceable_no_observation_time_count"])
    print("  excluded_outside_window:",
          page["window"]["excluded_outside_window"])

    print("\n=== P3 ADAPTER DRY CONVERSION ===")
    endpoint_id = (ep or {}).get("endpoint_id") or "ep_unresolved"
    okc, refusals, no_raw, kinds = 0, {}, 0, {}
    for row in page["items"]:
        raw = ((row.get("provenance") or {}).get("raw_ref")
               or (row.get("provenance") or {}).get("ref"))
        if not raw:
            no_raw += 1
        rec, why = to_evidence_record(row, tenant_id=tenant,
                                      endpoint_id=endpoint_id, raw_id=raw)
        if rec is None:
            refusals[why] = refusals.get(why, 0) + 1
        else:
            okc += 1
            kinds[rec.kind] = kinds.get(rec.kind, 0) + 1
    print("  rows:", len(page["items"]), "converted:", okc,
          "refusals:", refusals, "raw_ref_missing:", no_raw)
    print("  kinds:", kinds)
    if okc:
        sample = None
        for row in page["items"]:
            raw = ((row.get("provenance") or {}).get("raw_ref")
                   or (row.get("provenance") or {}).get("ref"))
            rec, _ = to_evidence_record(row, tenant_id=tenant,
                                        endpoint_id=endpoint_id, raw_id=raw)
            if rec:
                sample = rec
                break
        print("  sample fields:", json.dumps(sample.fields, default=str)[:400])
        print("  sample raw_id:", sample.ref.raw_id,
              "stable_key:", sample.stable_key[:24])

    worst = max((r["executionTimeMillis"] for r in rows), default=0)
    maxdocs = max((r["docs"] for r in rows), default=0)
    print("\n=== VERDICT ===")
    print("  blocking_sorts:", [f'{r["store"]}:{r["field"]}' for r in rows
                                if r["blocking_sort"]])
    print("  max_branch_ms:", worst, "max_docs_examined:", maxdocs,
          "page_ms:", round(page_ms, 1))


asyncio.run(main())
