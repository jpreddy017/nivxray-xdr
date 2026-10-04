"""PREVIEW-ONLY index experiment for the §d canonical observation-time path.

Owner authorised: preview database ONLY, documented, reversible. Production untouched.
  create : python sd_preview_index_experiment.py create
  measure: python sd_preview_index_experiment.py measure
  drop   : python sd_preview_index_experiment.py drop        <- full rollback
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv  # noqa: E402

load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

CANON = "xdr_canonical_evidence"
SHADOW = "v2_shadow_observations"
PREFIX = "pvw_sd_"
# one index per DECLARED identity field of each store, tenant-prefixed, so the
# authoritative endpoint_predicate() $or is served by SORT_MERGE over ordered
# index scans instead of a blocking in-memory sort.
SPECS = {
    CANON: {
        f"{PREFIX}collector_eventtime": [("tenant_id", 1), ("provenance.collector_id", 1), ("event_time", -1)],
        f"{PREFIX}hostid_eventtime": [("tenant_id", 1), ("host.host_id", 1), ("event_time", -1)],
        f"{PREFIX}hostname_eventtime": [("tenant_id", 1), ("host.hostname", 1), ("event_time", -1)],
    },
    # v2_shadow_observations: MEASURED NOT REQUIRED. Its pre-existing obs_*_ts indexes already
    # serve every declared identity branch (LIMIT->FETCH->SORT_MERGE->IXSCAN, docs<=264). The
    # seven tenant-prefixed duplicates trialled here were dropped again; adding them would have
    # been index weight for no measured gain.
    SHADOW: {},
}
T, COL, DEV = "default", "ep_2d57cbe6f80152062109", "dev_42e8c6dc74b9"


def stages(p):
    out, cur = [], p
    while isinstance(cur, dict):
        st = cur.get("stage")
        if st:
            out.append(st + (f"[{cur.get('indexName')}]" if cur.get("indexName") else ""))
        nxt = cur.get("inputStage") or cur.get("inputStages")
        cur = nxt[0] if isinstance(nxt, list) and nxt else (nxt if isinstance(nxt, dict) else None)
    return " -> ".join(out)


async def main(cmd):
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    assert os.environ["DB_NAME"] == "test_database", "PREVIEW DB ONLY — refusing"

    if cmd == "create":
        for coll, specs in SPECS.items():
            for name, key in specs.items():
                print("created", await db[coll].create_index(key, name=name, background=True))
    elif cmd == "drop":
        for coll, specs in SPECS.items():
            have = await db[coll].index_information()
            for name in specs:
                if name in have:
                    await db[coll].drop_index(name)
                    print("dropped", coll, name)
                else:
                    print("absent", coll, name)
    elif cmd == "measure":
        for coll in SPECS:
            have = await db[coll].index_information()
            print(f"{coll} preview indexes:", [n for n in have if n.startswith(PREFIX)])
        or_canon = {"$and": [{"tenant_id": T}, {"$or": [
            {"provenance.collector_id": {"$in": [COL]}}, {"host.host_id": {"$in": [COL]}},
            {"host.hostname": {"$in": [COL]}}]}]}
        or_shadow = {"$and": [{"tenant_id": T}, {"$or": [
            {f: {"$in": [DEV, COL]}} for f in ("event.device_iid", "device_iid", "collector_id",
                                               "connector_id", "event.computer",
                                               "event.raw.computer", "event.raw.hostname")]}]}
        cases = [
            (CANON, "CANON authoritative $or sort(event_time -1) limit200", or_canon,
             {"sort": {"event_time": -1}, "limit": 200}),
            (CANON, "CANON authoritative $or + resume event_time<=X", {**or_canon,
             "event_time": {"$lte": "2026-02-25T14:00:00+00:00"}}, {"sort": {"event_time": -1}, "limit": 200}),
            (SHADOW, "SHADOW authoritative $or sort(event.ts -1) limit200", or_shadow,
             {"sort": {"event.ts": -1}, "limit": 200}),
            (SHADOW, "SHADOW authoritative $or + resume event.ts<=X", {**or_shadow,
             "event.ts": {"$lte": "2026-09-14T15:55:29.870000+00:00"}},
             {"sort": {"event.ts": -1}, "limit": 200}),
        ]
        for coll, label, flt, spec in cases:
            e = await db.command({"explain": {"find": coll, "filter": flt, **spec},
                                  "verbosity": "executionStats"})
            s = stages(e["queryPlanner"]["winningPlan"])
            st = e.get("executionStats", {})
            blocking = s.startswith("SORT ") or "-> SORT " in s or s.endswith("-> SORT")
            print(f"\n[{label}]\n   plan={s}\n   BLOCKING_IN_MEMORY_SORT={blocking} "
                  f"nReturned={st.get('nReturned')} keys={st.get('totalKeysExamined')} "
                  f"docs={st.get('totalDocsExamined')} ms={st.get('executionTimeMillis')}")
    else:
        print(__doc__)


asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "help"))
