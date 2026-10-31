"""STEP 34E measurement — identity coverage census + TARGET contract proof.

Two parts, both read-only with respect to anything real:
  1) CENSUS over the preview canonical corpus — field PRESENCE and identity
     CLASSIFICATION counts only. No evidence content is printed, no endpoint is
     targeted, no DESKTOP lookup, no write.
  2) HERMETIC PROOF in a scratch database: the exact §d branch/time-window/
     paging shapes against the TARGET index set (one authoritative key + one
     legacy name branch), including coverage, boundedness, tenant isolation and
     newest-first ordering.
"""
import json
import random
import sys
from datetime import datetime, timedelta, timezone

from pymongo import DESCENDING, MongoClient

sys.path.insert(0, "/app/backend")
from edr_plane import canonical_identity_contract as idc  # noqa: E402
from edr_plane.canonical_index_contract import (  # noqa: E402
    CANONICAL_COLLECTION, REQUIRED_CANONICAL_INDEXES, TARGET_CANONICAL_INDEXES)

PREVIEW_DB = "test_database"
SCRATCH = "nivx_34e_hermetic_scratch"
FETCH = 25 + 64
T0 = datetime(2026, 6, 1, tzinfo=timezone.utc)
TENANTS = ["ten_a" + "0" * 20, "ten_b" + "0" * 20]
EPS = ["ep_" + f"{i:020x}" for i in range(4)]
HOSTS = [f"HOSTSYN{i}" for i in range(4)]


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def census(client):
    c = client[PREVIEW_DB][CANONICAL_COLLECTION]
    total = c.count_documents({})
    counts = {}
    for doc in c.find({}, {"_id": 0, "additional_fields.endpoint_id": 1,
                           "provenance.collector_id": 1, "host": 1}):
        _, reason = idc.classify(doc)
        counts[reason] = counts.get(reason, 0) + 1
    backfillable = 0
    for doc in c.find({"additional_fields.endpoint_id": {"$exists": False}},
                      {"_id": 0, "provenance.collector_id": 1,
                       "additional_fields.endpoint_id": 1, "host": 1}):
        if idc.backfill_candidate(doc):
            backfillable += 1
    print(f"CENSUS over preview corpus: {total} canonical rows")
    for reason, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {reason:46s} {n:7d}  {n/total*100:5.1f}%")
    print(f"  DETERMINISTICALLY_BACKFILLABLE                 {backfillable:7d}"
          f"  {backfillable/total*100:5.1f}%")
    return total, counts, backfillable


def rows():
    """The four identity populations the census found, in miniature."""
    rnd = random.Random(34)
    out = []
    for t_i, tenant in enumerate(TENANTS):
        for e_i in range(2):
            ep, host = EPS[t_i * 2 + e_i], HOSTS[t_i * 2 + e_i]
            for n in range(5000):
                when = T0 + timedelta(seconds=rnd.randint(0, 86400 * 7),
                                      microseconds=rnd.randint(0, 999999))
                base = {"tenant_id": tenant,
                        "event_id": f"cev_{tenant[-3:]}_{ep[-4:]}_{n}",
                        "event_time": iso(when), "ingest_time": iso(when),
                        "process": {"pid": n, "executable_path": "C:\\x.exe"},
                        "provenance": {"raw_ref": f"raw_{n}"},
                        "additional_fields": {"activity_type": "PROCESS",
                                              "operation": "start"}}
                shape = n % 20
                if shape == 19:          # authenticated boundary only (1,236-like)
                    base["provenance"]["collector_id"] = ep
                    base["host"] = {"host_id": host, "hostname": host}
                elif shape == 18:        # legacy name only
                    base["provenance"]["collector_id"] = "collector-snort-ref"
                    base["host"] = {"host_id": host, "hostname": host}
                elif shape == 17:        # not endpoint scoped at all
                    base["provenance"]["collector_id"] = "collector-snort-ref"
                else:                    # authoritative
                    base["additional_fields"]["endpoint_id"] = ep
                    base["provenance"]["collector_id"] = ep
                    base["host"] = {"host_id": ep, "hostname": host}
                out.append(base)
    return out


def chain(plan, acc=None):
    acc = acc or []
    acc.append(plan.get("stage"))
    for key in ("inputStage", "queryPlan"):
        if key in plan:
            chain(plan[key], acc)
    for s in plan.get("inputStages", []) or []:
        chain(s, acc)
    return [a for a in acc if a]


def idx_names(plan):
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
    return sorted(set(found))


def explain(db, field, values, tenant, lo, hi):
    flt = {field: {"$in": values}, "tenant_id": tenant,
           "event_time": {"$gte": lo, "$lte": hi}}
    ex = db.command({"explain": {"find": CANONICAL_COLLECTION, "filter": flt,
                                 "sort": {"event_time": -1}, "limit": FETCH},
                     "verbosity": "executionStats"})
    st, plan = ex["executionStats"], ex["queryPlanner"]["winningPlan"]
    stages = chain(plan)
    return {"field": field, "stages": stages, "indexes": idx_names(plan),
            "collscan": "COLLSCAN" in stages, "blocking_sort": "SORT" in stages,
            "keys": st["totalKeysExamined"], "docs": st["totalDocsExamined"],
            "nReturned": st["nReturned"], "ms": st["executionTimeMillis"]}


def main():
    client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=4000)
    census(client)

    client.drop_database(SCRATCH)
    db = client[SCRATCH]
    docs = rows()
    db[CANONICAL_COLLECTION].insert_many(docs)
    tenant, ep, host = TENANTS[0], EPS[0], HOSTS[0]
    end, = (T0 + timedelta(days=3),)
    lo = iso(end - timedelta(minutes=10) - timedelta(seconds=1))
    hi = iso(end + timedelta(seconds=1))
    wide_lo, wide_hi = iso(T0 - timedelta(days=1)), iso(T0 + timedelta(days=9))
    print(f"\nSCRATCH_DB = {SCRATCH}  docs = {len(docs)}")

    for spec in TARGET_CANONICAL_INDEXES:
        db[CANONICAL_COLLECTION].create_index(
            [(k, v) for k, v in spec["key"]], name=spec["name"])

    print("\n=== TARGET BRANCH PLANS (authoritative key + legacy name) ===")
    plans = [explain(db, idc.AUTHORITATIVE_FIELD, [ep], tenant, lo, hi),
             explain(db, idc.LEGACY_NAME_FIELD, [host], tenant, lo, hi)]
    for r in plans:
        print(f'  {r["field"]:34s} idx={r["indexes"]} stages={r["stages"]} '
              f'keys={r["keys"]} docs={r["docs"]} n={r["nReturned"]} ms={r["ms"]}')

    print("\n=== BOUNDEDNESS (wide window) ===")
    wide = [explain(db, idc.AUTHORITATIVE_FIELD, [ep], tenant, wide_lo, wide_hi),
            explain(db, idc.LEGACY_NAME_FIELD, [host], tenant, wide_lo, wide_hi)]
    for r in wide:
        print(f'  {r["field"]:34s} keys={r["keys"]} docs={r["docs"]} '
              f'n={r["nReturned"]} stages={r["stages"]}')
    print("  matching rows, authoritative branch, wide window =",
          db[CANONICAL_COLLECTION].count_documents(
              {idc.AUTHORITATIVE_FIELD: ep, "tenant_id": tenant,
               "event_time": {"$gte": wide_lo, "$lte": wide_hi}}))

    print("\n=== COVERAGE: does the target pair reach every endpoint row? ===")
    coll = db[CANONICAL_COLLECTION]
    by_old = coll.count_documents({"tenant_id": tenant, "$or": [
        {"provenance.collector_id": {"$in": [ep, host]}},
        {"host.host_id": {"$in": [ep, host]}},
        {"host.hostname": {"$in": [ep, host]}}]})
    by_new = coll.count_documents({"tenant_id": tenant, "$or": [
        {idc.AUTHORITATIVE_FIELD: {"$in": [ep]}},
        {idc.LEGACY_NAME_FIELD: {"$in": [host]}}]})
    only_old = coll.count_documents({"tenant_id": tenant,
                                     idc.AUTHORITATIVE_FIELD: {"$exists": False},
                                     idc.LEGACY_NAME_FIELD: {"$in": [None]},
                                     "$or": [
                                         {"provenance.collector_id": {"$in": [ep, host]}},
                                         {"host.host_id": {"$in": [ep, host]}}]})
    print("  rows reachable by the 3 legacy branches :", by_old)
    print("  rows reachable by the target pair       :", by_new)
    print("  rows ONLY reachable the legacy way      :", only_old,
          "(these are the rows the authenticated-boundary backfill covers)")
    backfillable = sum(1 for d in coll.find(
        {"tenant_id": tenant, idc.AUTHORITATIVE_FIELD: {"$exists": False}},
        {"_id": 0, "provenance.collector_id": 1, "host": 1,
         "additional_fields.endpoint_id": 1}) if idc.backfill_candidate(d))
    print("  deterministically backfillable rows     :", backfillable)

    print("\n=== TENANT ISOLATION ===")
    other = explain(db, idc.AUTHORITATIVE_FIELD, [ep], TENANTS[1], wide_lo, wide_hi)
    print("  other tenant: nReturned =", other["nReturned"], " docs =",
          other["docs"], " idx =", other["indexes"])

    print("\n=== ORDER + WINDOW ===")
    times = [d["event_time"] for d in coll.find(
        {idc.AUTHORITATIVE_FIELD: ep, "tenant_id": tenant,
         "event_time": {"$gte": lo, "$lte": hi}},
        {"_id": 0, "event_time": 1}).sort("event_time", DESCENDING).limit(FETCH)]
    print("  newest_first =", times == sorted(times, reverse=True),
          " inside_window =", all(lo <= t <= hi for t in times),
          " rows =", len(times))

    print("\n=== INDEX COST: target (2) vs 34D (3) ===")
    stats = db.command("collstats", CANONICAL_COLLECTION)
    target = sum(v for k, v in (stats.get("indexSizes") or {}).items()
                 if k.startswith("sd_canonical"))
    for spec in REQUIRED_CANONICAL_INDEXES:
        if spec["name"] not in [s["name"] for s in TARGET_CANONICAL_INDEXES]:
            db[CANONICAL_COLLECTION].create_index(
                [(k, v) for k, v in spec["key"]], name=spec["name"])
    stats2 = db.command("collstats", CANONICAL_COLLECTION)
    three = sum(v for k, v in (stats2.get("indexSizes") or {}).items()
                if k.startswith("sd_canonical"))
    data = stats2.get("size", 0) or 1
    print(f"  target 2 indexes = {target/1024:.1f} KiB ({target/data*100:.1f}% of data)")
    print(f"  34D set + target = {three/1024:.1f} KiB ({three/data*100:.1f}% of data)")
    print(f"  per-doc: target {target/len(docs):.1f} B/doc")

    print("\n=== VERDICT ===")
    print("TARGET_COLLSCANS =", [r["field"] for r in plans + wide if r["collscan"]])
    print("TARGET_BLOCKING_SORTS =", [r["field"] for r in plans + wide
                                      if r["blocking_sort"]])
    print("TARGET_MAX_KEYS =", max(r["keys"] for r in plans + wide))
    print("TARGET_MAX_DOCS =", max(r["docs"] for r in plans + wide))
    print("PLANS =", json.dumps(plans + wide))
    client.drop_database(SCRATCH)
    print("\nSCRATCH DROPPED. PRODUCTION_TOUCHED = NO. PREVIEW_WRITES = NONE")


if __name__ == "__main__":
    main()
