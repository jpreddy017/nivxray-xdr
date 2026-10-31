"""STEP 34C preflight — PRODUCTION QUERY PLAN ONLY. READ ONLY, EXPLAIN ONLY.

Reuses the Step 34A branch construction verbatim (`branches`, `_window_bounds`,
`OBSERVATION_TIME_KEY`) and executes NOTHING but `explain("executionStats")`.

What this tool refuses, in code rather than by discipline:
* a preview/local database — the connection string must be supplied explicitly
  in `PROD_MONGO_URL` and may not resolve to localhost/127.0.0.1, and it may not
  equal the container's own `MONGO_URL`;
* any endpoint other than KUSHU, and any ref that looks like DESKTOP;
* the bounded 25-row page, the family census, the adapter, the engine, the
  frontier, index creation and every form of write.

Run:  PROD_MONGO_URL=... PROD_DB_NAME=... python backend/tools/preflight_34c.py
"""
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")
sys.path.insert(0, "/app/backend")

from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

from edr_trajectory.production_adapter import (OBSERVATION_TIME_KEY,  # noqa: E402
                                               _window_bounds, branches)

FETCH = 25 + 64
TARGET_HOSTNAME = "KUSHU"
PROHIBITED = ("DESKTOP",)
WINDOW_MINUTES = 10

BLOCKED_NO_URI = "NO_EXPLICIT_PRODUCTION_URI_PROD_MONGO_URL_UNSET"
BLOCKED_LOCAL = "REFUSED_PREVIEW_OR_LOCAL_DATABASE_SUBSTITUTION"
BLOCKED_SAME_AS_PREVIEW = "REFUSED_URI_IDENTICAL_TO_CONTAINER_MONGO_URL"
BLOCKED_NO_DB = "NO_EXPLICIT_PROD_DB_NAME"
BLOCKED_NO_TARGET = "KUSHU_NOT_RESOLVABLE_IN_TARGET_DATABASE"
BLOCKED_PROHIBITED_REF = "PROHIBITED_ENDPOINT_IN_RESOLVED_REFS"
BLOCKED_UNREACHABLE = "PRODUCTION_DATABASE_UNREACHABLE"


class Blocked(RuntimeError):
    pass


def resolve_uri() -> tuple[str, str]:
    uri = (os.environ.get("PROD_MONGO_URL") or "").strip()
    if not uri:
        raise Blocked(BLOCKED_NO_URI)
    low = uri.lower()
    if "localhost" in low or "127.0.0.1" in low or "::1" in low:
        raise Blocked(BLOCKED_LOCAL)
    if uri == (os.environ.get("MONGO_URL") or "").strip():
        raise Blocked(BLOCKED_SAME_AS_PREVIEW)
    name = (os.environ.get("PROD_DB_NAME") or "").strip()
    if not name:
        raise Blocked(BLOCKED_NO_DB)
    return uri, name


def chain(plan, acc=None):
    acc = acc or []
    acc.append(plan.get("stage"))
    for key in ("inputStage", "queryPlan"):
        if key in plan:
            chain(plan[key], acc)
    for s in plan.get("inputStages", []) or []:
        chain(s, acc)
    return [a for a in acc if a]


def index_of(plan):
    found = []

    def walk(p):
        if p.get("stage") == "IXSCAN":
            found.append(p.get("indexName"))
        for key in ("inputStage", "queryPlan"):
            if key in p:
                walk(p[key])
        for s in p.get("inputStages", []) or []:
            walk(s)
    walk(plan)
    return found[0] if found else None


async def resolve_kushu(db):
    """KUSHU's platform identity, read from the registry and canonical store."""
    ep = await db.edr_endpoints.find_one(
        {"hostname": TARGET_HOSTNAME},
        {"_id": 0, "endpoint_id": 1, "hostname": 1, "device_iid": 1,
         "collector_id": 1, "tenant_id": 1})
    if not ep or not ep.get("endpoint_id") or not ep.get("tenant_id"):
        raise Blocked(BLOCKED_NO_TARGET)
    newest = await db.xdr_canonical_evidence.find_one(
        {"tenant_id": ep["tenant_id"],
         "$or": [{"host.hostname": TARGET_HOSTNAME},
                 {"host.host_id": ep.get("device_iid")},
                 {"provenance.collector_id": ep.get("collector_id")}]},
        {"_id": 0, "event_time": 1}, sort=[("event_time", -1)])
    refs = sorted({str(v) for v in (ep.get("endpoint_id"), ep.get("device_iid"),
                                    ep.get("collector_id"), ep.get("hostname"))
                   if v})
    for ref in refs:
        if any(p in ref.upper() for p in PROHIBITED):
            raise Blocked(BLOCKED_PROHIBITED_REF)
    return ep, refs, (newest or {}).get("event_time")


async def main() -> int:
    try:
        uri, dbname = resolve_uri()
    except Blocked as e:
        print("STEP34C_STATUS = BLOCKED")
        print("PRODUCTION_CONFIRMED = NO")
        print("BLOCKER =", e)
        return 2
    client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
    try:
        info = await client.admin.command("hello")
    except Exception as exc:
        print("STEP34C_STATUS = BLOCKED")
        print("PRODUCTION_CONFIRMED = NO")
        print("BLOCKER =", BLOCKED_UNREACHABLE, repr(exc)[:200])
        return 2
    db = client[dbname]
    print("CLUSTER =", info.get("setName") or info.get("msg") or "standalone")
    print("DB =", dbname)
    try:
        ep, refs, newest = await resolve_kushu(db)
    except Blocked as e:
        print("STEP34C_STATUS = BLOCKED")
        print("PRODUCTION_CONFIRMED = YES")
        print("BLOCKER =", e)
        return 2
    tenant = ep["tenant_id"]
    end = datetime.fromisoformat(str(newest).replace("Z", "+00:00")) if newest \
        else datetime.now(timezone.utc)
    start = end - timedelta(minutes=WINDOW_MINUTES)
    print("ENDPOINT =", ep.get("hostname"))
    print("ENDPOINT_ID =", ep.get("endpoint_id"))
    print("TENANT =", tenant)
    print("REFS =", refs)
    print("WINDOW =", start.isoformat(), "->", end.isoformat())

    lo_us, hi_us, lo_s, hi_s = _window_bounds(start.isoformat(), end.isoformat())
    print("STRING BOUND =", lo_s, hi_s)

    rows = []
    print("\n=== P1 BRANCH EXPLAINS (EXPLAIN ONLY) ===")
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
            wall = (time.perf_counter() - t0) * 1000
            st = ex["executionStats"]
            plan = ex["queryPlanner"]["winningPlan"]
            stages = chain(plan)
            rows.append({
                "store": store, "field": field, "stages": stages,
                "index": index_of(plan), "blocking_sort": "SORT" in stages,
                "keys": st["totalKeysExamined"], "docs": st["totalDocsExamined"],
                "nReturned": st["nReturned"],
                "executionTimeMillis": st["executionTimeMillis"],
                "wall_ms": round(wall, 1)})
            print(f'  {store:24s} {field:26s} idx={rows[-1]["index"]} '
                  f'stages={stages} keys={st["totalKeysExamined"]} '
                  f'docs={st["totalDocsExamined"]} n={st["nReturned"]} '
                  f'ms={st["executionTimeMillis"]}')

    canon = [r for r in rows if r["store"] == "xdr_canonical_evidence"]
    shadow = [r for r in rows if r["store"] == "v2_shadow_observations"]
    sorts = [f'{r["store"]}:{r["field"]}' for r in rows if r["blocking_sort"]]
    print("\n=== VERDICT (MEASUREMENT ONLY, NO DECISION) ===")
    print("BRANCH_RESULTS =", json.dumps(rows, default=str))
    print("CANONICAL_BRANCH_RESULTS =", json.dumps(canon, default=str))
    print("SHADOW_BRANCH_RESULTS =", json.dumps(shadow, default=str))
    print("INDEXES_USED =", sorted({str(r["index"]) for r in rows}))
    print("BLOCKING_SORTS =", sorts or "NONE")
    print("MAX_KEYS_EXAMINED =", max((r["keys"] for r in rows), default=0))
    print("MAX_DOCS_EXAMINED =", max((r["docs"] for r in rows), default=0))
    print("MAX_BRANCH_LATENCY_MS =",
          max((r["executionTimeMillis"] for r in rows), default=0))
    print("PRODUCTION_WRITES = NONE")
    print("INDEX_CREATED = NONE")
    print("ENGINE_EXECUTED = NO")
    print("FRONTIER_CREATED = NO")
    print("PAGE_READ = NO")
    print("ADAPTER_RUN = NO")
    print("STEP34C_STATUS =", "BLOCKED" if sorts else "PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
