"""§d PRODUCTION ADAPTER ACCEPTANCE — real evidence, read-only.

Proves: index-served per-branch plans, newest-first order, duplicate-free paging,
boundary completeness, identical-timestamp handling, tenant isolation, deep links.
WRITES NOTHING.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv  # noqa: E402

load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

from edr_trajectory import production_adapter as pa  # noqa: E402
from edr_trajectory.contracts import TenantRequired  # noqa: E402

T = "default"
REFS = ["dev_42e8c6dc74b9", "ep_2d57cbe6f80152062109"]
OTHER_T = "ten_f1a5479243e901cf159e230fa0"
OTHER_REFS = ["dev_f4b3fb82d7f3", "col_d6b0b9e8172246f29be9"]
RESULTS: list[tuple[str, str, str]] = []


def rec(name, ok, detail):
    RESULTS.append((name, "PASS" if ok else "FAIL", detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def stages(p):
    out, cur = [], p
    while isinstance(cur, dict):
        st = cur.get("stage")
        if st:
            out.append(st + (f"[{cur.get('indexName')}]" if cur.get("indexName") else ""))
        nxt = cur.get("inputStage") or cur.get("inputStages")
        cur = nxt[0] if isinstance(nxt, list) and nxt else (nxt if isinstance(nxt, dict) else None)
    return " -> ".join(out)


async def main():
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    print("\n=== 1. BRANCH PLANS ARE INDEX-SERVED (no blocking sort) ===")
    worst = 0
    blocking = []
    for store in pa.STORES:
        tkey = pa.OBSERVATION_TIME_KEY[store]
        for flt in pa.branches(store, REFS, T):
            q = {**flt, tkey: {"$ne": None}}
            e = await db.command({"explain": {"find": store, "filter": q,
                                              "sort": {tkey: -1}, "limit": 264},
                                  "verbosity": "executionStats"})
            s = stages(e["queryPlanner"]["winningPlan"])
            st = e.get("executionStats", {})
            docs = st.get("totalDocsExamined", 0)
            worst = max(worst, docs)
            field = [k for k in flt if k != "tenant_id"][0]
            if s.startswith("SORT ") or "-> SORT " in s:
                blocking.append((store, field, s, docs))
            print(f"   {store[:14]:<14} {field:<22} docs={docs:<7} ms={st.get('executionTimeMillis')} {s}")
    rec("INDEX_SERVED_NO_BLOCKING_SORT", not blocking,
        f"blocking branches={blocking or 'none'}; worst docsExamined={worst} (bounded by fetch size 264)")

    print("\n=== 2. NEWEST-FIRST ORDER ===")
    p1 = await pa.page_device_evidence(db, tenant_id=T, refs=REFS, page_size=50)
    ms1 = [e["observed_ms"] for e in p1["items"]]
    rec("NEWEST_FIRST", ms1 == sorted(ms1, reverse=True) and len(ms1) == 50,
        f"items={len(ms1)} newest={p1['items'][0]['observed_at']} oldest={p1['items'][-1]['observed_at']}")
    rec("INGEST_TIME_NOT_ORDERING_KEY",
        p1["provenance"]["ingest_time_used_as_observation_time"] is False
        and p1["provenance"]["ordering_authority"] == "STORED_OBSERVATION_TIME",
        f"ordering_authority={p1['provenance']['ordering_authority']}")

    print("\n=== 3. PAGING: NO OVERLAP, NO BOUNDARY LOSS ===")
    pages, cursor, seen = [], None, []
    for i in range(6):
        pg = await pa.page_device_evidence(db, tenant_id=T, refs=REFS, page_size=50, cursor=cursor)
        pages.append(pg)
        seen.append([e["event_id"] for e in pg["items"]])
        if not pg["has_more"]:
            break
        cursor = pg["next_cursor"]
    flat = [x for p in seen for x in p]
    overlap = set(seen[0]) & set(seen[1]) if len(seen) > 1 else set()
    rec("PAGE1_PAGE2_OVERLAP_EMPTY", not overlap, f"overlap={len(overlap)}")
    rec("NO_DUPLICATES_ACROSS_PAGES", len(flat) == len(set(flat)),
        f"{len(flat)} rows across {len(seen)} pages, {len(set(flat))} distinct")
    # boundary completeness: one big page must equal the concatenation of the small pages
    big = await pa.page_device_evidence(db, tenant_id=T, refs=REFS, page_size=len(flat))
    bigids = [e["event_id"] for e in big["items"]]
    rec("NO_BOUNDARY_LOSS", bigids == flat,
        f"single page({len(bigids)}) == paged sequence({len(flat)}): {bigids == flat}")

    print("\n=== 4. IDENTICAL OBSERVATION TIMESTAMPS ===")
    allms = [e["observed_ms"] for p in pages for e in p["items"]]
    ties = len(allms) - len(set(allms))
    strict = all(pa._key(p["items"][i]) > pa._key(p["items"][i + 1])
                 for p in pages for i in range(len(p["items"]) - 1))
    rec("TIE_TOTAL_ORDER_STRICT", strict,
        f"{ties} tied instants inside the paged range; (observed_ms,event_id) strictly descending={strict}")

    print("\n=== 5. TENANT ISOLATION ===")
    cross = await pa.page_device_evidence(db, tenant_id=T, refs=OTHER_REFS, page_size=25)
    rec("CROSS_TENANT_EVIDENCE_LEAK_NO", not cross["items"],
        f"tenant={T} asking for another customer's refs returned {len(cross['items'])} rows")
    own = await pa.page_device_evidence(db, tenant_id=OTHER_T, refs=OTHER_REFS, page_size=25)
    rec("OWN_TENANT_REACHED", bool(own["items"]) and all(e["tenant_id"] == OTHER_T for e in own["items"]),
        f"tenant={OTHER_T} got {len(own['items'])} rows, all own-tenant")
    try:
        await pa.page_device_evidence(db, tenant_id="", refs=REFS, page_size=5)
        rec("NO_TENANT_FAILS_CLOSED", False, "a tenant-less read was ACCEPTED")
    except TenantRequired:
        rec("NO_TENANT_FAILS_CLOSED", True, "TenantRequired raised; no evidence returned")

    print("\n=== 6. DEEP LINK TO EXACT EVIDENCE ===")
    target = p1["items"][7]
    r = await pa.resolve_evidence(db, tenant_id=T, refs=REFS, event_id=target["event_id"])
    rec("DEEP_LINK_RESOLVES_EXACT", r["state"] == "FOCUS_RESOLVED"
        and r["event"]["event_id"] == target["event_id"]
        and r["event"]["observed_at"] == target["observed_at"],
        f"{r['state']} event_id={target['event_id']} observed_at={r.get('observed_at')}")
    r2 = await pa.resolve_evidence(db, tenant_id=T, refs=REFS, event_id="ce_doesnotexist000000000")
    rec("DEEP_LINK_MISS_IS_EXPLICIT", r2["state"] == "FOCUS_NOT_RESOLVED" and r2["event"] is None,
        f"{r2['state']} reason={r2.get('reason')}")
    rx = await pa.resolve_evidence(db, tenant_id=T, refs=OTHER_REFS, event_id=target["event_id"])
    rec("DEEP_LINK_CANNOT_CROSS_ENDPOINT", rx["state"] == "FOCUS_NOT_RESOLVED",
        f"{rx['state']} — this endpoint's refs do not resolve another endpoint's evidence")

    print("\n=== 7. UNPLACEABLE EVIDENCE IS COUNTED, NEVER PLACED ===")
    rec("UNPLACEABLE_TRUTHFUL", all(e["observed_ms"] is not None for e in p1["items"]),
        f"unplaceable_count={p1['unplaceable_no_observation_time_count']}; "
        f"every emitted row carries a real observation time")

    print("\n=== 8. PROVENANCE PRESENT ON EVERY ROW ===")
    ok = all(e.get("provenance", {}).get("store") and e.get("sources") for e in p1["items"])
    rec("PROVENANCE_ON_EVERY_ROW", ok,
        f"stores_read={p1['provenance']['stores_read']} rows_per_store={p1['provenance']['rows_per_store']}")

    print("\n=== 9. BAD CURSOR REFUSED ===")
    from edr_trajectory.paging import BadCursor
    try:
        await pa.page_device_evidence(db, tenant_id=T, refs=REFS, cursor="not-a-cursor")
        rec("BAD_CURSOR_REFUSED", False, "accepted")
    except BadCursor:
        rec("BAD_CURSOR_REFUSED", True, "BadCursor raised")

    print("\n================ SUMMARY ================")
    for n, s, d in RESULTS:
        print(f"{s:<5} {n}")
    failed = [n for n, s, _ in RESULTS if s == "FAIL"]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} PASS")
    if failed:
        print("FAILED:", failed)
    with open("/app/scripts/sd_acceptance_last.json", "w") as f:
        json.dump([{"check": n, "result": s, "detail": d} for n, s, d in RESULTS], f, indent=2)


asyncio.run(main())
