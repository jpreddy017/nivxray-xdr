"""STEP 34D measurement — HERMETIC. Scratch database, synthetic canonical rows.

Proves (or disproves) that the proposed canonical §d index specification serves
the three production branch SHAPES without a collection scan and without a
blocking in-memory sort. Nothing production is read, written or indexed: the
only database touched is a scratch DB created and dropped by this script on the
local mongod.
"""
import json
import random
import sys
from datetime import datetime, timedelta, timezone

from pymongo import DESCENDING, MongoClient

sys.path.insert(0, "/app/backend")
from edr_plane.canonical_index_contract import (  # noqa: E402
    CANONICAL_COLLECTION, REQUIRED_CANONICAL_INDEXES)

SCRATCH = "nivx_34d_hermetic_scratch"
TENANTS = ["ten_a" + "0" * 20, "ten_b" + "0" * 20, "ten_c" + "0" * 20]
EPS = ["ep_" + f"{i:020x}" for i in range(6)]
HOSTS = [f"HOSTSYN{i}" for i in range(6)]
N_PER = 6000
T0 = datetime(2026, 6, 1, tzinfo=timezone.utc)
FETCH = 25 + 64
WINDOW_MINUTES = 10


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def rows():
    """Three identity populations, mirroring what preview actually contains:
    authenticated rows where all three identity fields are the platform
    endpoint_id, rows with no hostname at all, and legacy rows whose host_id is
    not a platform id.
    """
    rnd = random.Random(34)
    out = []
    for t_i, tenant in enumerate(TENANTS):
        for e_i in range(2):
            ep, host = EPS[t_i * 2 + e_i], HOSTS[t_i * 2 + e_i]
            for n in range(N_PER):
                when = T0 + timedelta(seconds=rnd.randint(0, 86400 * 7),
                                      microseconds=rnd.randint(0, 999999))
                shape = n % 10
                doc = {"tenant_id": tenant,
                       "event_id": f"cev_{tenant[-3:]}_{ep[-4:]}_{n}",
                       "event_time": iso(when), "ingest_time": iso(when),
                       "process": {"pid": n, "executable_path": "C:\\x.exe"},
                       "additional_fields": {"activity_type": "PROCESS",
                                             "operation": "start",
                                             "endpoint_id": ep},
                       "provenance": {"collector_id": ep,
                                      "raw_ref": f"raw_{n}"}}
                if shape == 9:                     # legacy: host_id not a plat id
                    doc["host"] = {"host_id": host.lower(), "hostname": host}
                elif shape == 8:                   # no hostname observed
                    doc["host"] = {"host_id": ep, "hostname": None}
                else:                              # authenticated sensor row
                    doc["host"] = {"host_id": ep, "hostname": host}
                out.append(doc)
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


def indexes_of(plan):
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


def explain(db, field, refs, tenant, lo, hi):
    flt = {field: {"$in": refs}, "tenant_id": tenant,
           "event_time": {"$gte": lo, "$lte": hi}}
    ex = db.command({"explain": {"find": CANONICAL_COLLECTION, "filter": flt,
                                 "sort": {"event_time": -1}, "limit": FETCH},
                     "verbosity": "executionStats"})
    st, plan = ex["executionStats"], ex["queryPlanner"]["winningPlan"]
    stages = chain(plan)
    return {"field": field, "stages": stages, "indexes": indexes_of(plan),
            "collscan": "COLLSCAN" in stages,
            # SORT = blocking in-memory sort. SORT_MERGE is an index-ordered
            # merge of several index scans and is NOT blocking.
            "blocking_sort": "SORT" in stages,
            "sort_merge": "SORT_MERGE" in stages,
            "keys": st["totalKeysExamined"], "docs": st["totalDocsExamined"],
            "nReturned": st["nReturned"], "ms": st["executionTimeMillis"]}


def ordered(db, tenant, refs, lo, hi):
    """The rows actually come back newest-first, and inside the window."""
    cur = db[CANONICAL_COLLECTION].find(
        {"host.host_id": {"$in": refs}, "tenant_id": tenant,
         "event_time": {"$gte": lo, "$lte": hi}},
        {"_id": 0, "event_time": 1}).sort("event_time", DESCENDING).limit(FETCH)
    times = [d["event_time"] for d in cur]
    return (times == sorted(times, reverse=True),
            all(lo <= t <= hi for t in times), len(times))


def main():
    client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=4000)
    client.drop_database(SCRATCH)
    db = client[SCRATCH]
    docs = rows()
    db[CANONICAL_COLLECTION].insert_many(docs)
    print(f"SCRATCH_DB = {SCRATCH}  docs = {len(docs)}")

    tenant, ep, host = TENANTS[0], EPS[0], HOSTS[0]
    refs = sorted({ep, host})
    end = T0 + timedelta(days=3)
    start = end - timedelta(minutes=WINDOW_MINUTES)
    lo, hi = iso(start - timedelta(seconds=1)), iso(end + timedelta(seconds=1))
    print("REFS =", refs, "\nWINDOW =", lo, "->", hi)

    fields = [s["identity_field"] for s in REQUIRED_CANONICAL_INDEXES]

    print("\n=== A · BEFORE (production index set: _id_ + tenant_id/ingest_time) ===")
    db[CANONICAL_COLLECTION].create_index([("ingest_time", -1), ("tenant_id", 1)],
                                          name="tenant_id_1_ingest_time_-1")
    before = [explain(db, f, refs, tenant, lo, hi) for f in fields]
    for r in before:
        print(f'  {r["field"]:26s} idx={r["indexes"]} stages={r["stages"]} '
              f'keys={r["keys"]} docs={r["docs"]} n={r["nReturned"]} ms={r["ms"]}')

    print("\n=== B · AFTER (proposed canonical §d indexes) ===")
    for spec in REQUIRED_CANONICAL_INDEXES:
        db[CANONICAL_COLLECTION].create_index(
            [(k, v) for k, v in spec["key"]], name=spec["name"])
    after = [explain(db, f, refs, tenant, lo, hi) for f in fields]
    for r in after:
        print(f'  {r["field"]:26s} idx={r["indexes"]} stages={r["stages"]} '
              f'keys={r["keys"]} docs={r["docs"]} n={r["nReturned"]} ms={r["ms"]}')

    print("\n=== B2 · BOUNDEDNESS (wide window, thousands of matching rows) ===")
    wide_lo, wide_hi = iso(T0 - timedelta(days=1)), iso(T0 + timedelta(days=9))
    wide = [explain(db, f, refs, tenant, wide_lo, wide_hi) for f in fields]
    for r in wide:
        print(f'  {r["field"]:26s} stages={r["stages"]} keys={r["keys"]} '
              f'docs={r["docs"]} n={r["nReturned"]} ms={r["ms"]}')
    print("  matching rows in the wide window =",
          db[CANONICAL_COLLECTION].count_documents(
              {"host.host_id": {"$in": refs}, "tenant_id": tenant,
               "event_time": {"$gte": wide_lo, "$lte": wide_hi}}))

    print("\n=== C · NECESSITY (drop the hostname index, re-measure) ===")
    hostname_spec = [s for s in REQUIRED_CANONICAL_INDEXES
                     if s["identity_field"] == "host.hostname"][0]
    db[CANONICAL_COLLECTION].drop_index(hostname_spec["name"])
    without = explain(db, "host.hostname", refs, tenant, lo, hi)
    print(f'  host.hostname WITHOUT its index -> idx={without["indexes"]} '
          f'stages={without["stages"]} keys={without["keys"]} '
          f'docs={without["docs"]} ms={without["ms"]}')
    db[CANONICAL_COLLECTION].create_index(
        [(k, v) for k, v in hostname_spec["key"]], name=hostname_spec["name"])

    print("\n=== D · TENANT ISOLATION (same refs, other tenant) ===")
    other = explain(db, "host.host_id", refs, TENANTS[1], lo, hi)
    print(f'  other tenant nReturned={other["nReturned"]} '
          f'docs={other["docs"]} idx={other["indexes"]}')

    asc, inside, got = ordered(db, tenant, refs, lo, hi)
    print("\n=== E · ORDER + WINDOW ===")
    print("  newest_first =", asc, " all_inside_window =", inside, " rows =", got)

    print("\n=== F · INDEX COST (scratch sample) ===")
    stats = db.command("collstats", CANONICAL_COLLECTION)
    sizes = stats.get("indexSizes", {})
    data = stats.get("size", 0)
    for name, size in sorted(sizes.items()):
        print(f'  {name:34s} {size/1024:9.1f} KiB '
              f'{(size/data*100 if data else 0):5.1f}% of data size')
    proposed = sum(v for k, v in sizes.items() if k.startswith("sd_canonical"))
    print(f'  proposed three indexes total = {proposed/1024:.1f} KiB '
          f'({(proposed/data*100 if data else 0):.1f}% of data size) '
          f'for {len(docs)} docs')

    print("\n=== VERDICT ===")
    print("BEFORE_COLLSCANS =", [r["field"] for r in before if r["collscan"]])
    print("BEFORE_BLOCKING_SORTS =", [r["field"] for r in before
                                      if r["blocking_sort"]])
    print("AFTER_COLLSCANS =", [r["field"] for r in after if r["collscan"]])
    print("AFTER_BLOCKING_SORTS =", [r["field"] for r in after
                                     if r["blocking_sort"]])
    print("AFTER_MAX_KEYS =", max(r["keys"] for r in after))
    print("AFTER_MAX_DOCS =", max(r["docs"] for r in after))
    print("AFTER_MAX_MS =", max(r["ms"] for r in after))
    print("AFTER =", json.dumps(after))
    client.drop_database(SCRATCH)
    print("\nSCRATCH DROPPED. PRODUCTION_TOUCHED = NO")


if __name__ == "__main__":
    main()
