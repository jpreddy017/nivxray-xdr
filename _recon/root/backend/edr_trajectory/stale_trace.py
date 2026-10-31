"""Stage-by-stage trace of ONE observation through the real trajectory read path (E1 code), reporting
the exact stage where it disappears, for E1's oldest-first page and for the E3 newest-first adapter."""
from __future__ import annotations

from typing import Any

from . import prodshape as ps


async def trace(db, ident: dict[str, Any], refs: list[str], *, observation_id: str | None, now_ms: int,
                window_ms: int = ps.D, limit: int = 500) -> dict[str, Any]:
    from edr_plane import trajectory_window as tw

    from .e1_shape_preview import trajectory, window_rows

    coll = db[tw.COLLECTION]
    if not observation_id:
        newest = max([d async for d in coll.find({}, {"_id": 0, "observation_id": 1, "event.ts": 1})],
                     key=lambda d: tw.instant_ms(d["event"]["ts"]) or 0)
        observation_id = newest["observation_id"]
    doc = await coll.find_one({"observation_id": observation_id}, {"_id": 0})
    stages: list[dict[str, Any]] = []
    add = lambda name, ok, detail: stages.append({"stage": name, "present": bool(ok), "detail": detail})
    add("1_events_api_store", doc, f"stored, event.ts={doc and doc['event']['ts']}, ingested={doc and doc.get('ingest_time')}")
    t0, t1 = ps._iso(now_ms - window_ms), ps._iso(now_ms)
    bounded = await tw._projected(db, ident=ident, refs=refs, docs_limit=tw.BOUNDED_DOCS)
    add("2a_e1_bounded_first_paint_text_sort", any(r.get("observation_id") == observation_id for r in bounded["rows"]),
        f"sort('event.ts', -1).limit({tw.BOUNDED_DOCS}) over {bounded['docs_read']} docs (string order)")
    proj = await tw._projected(db, ident=ident, refs=refs, docs_limit=None)
    row = next((r for r in proj["rows"] if r.get("observation_id") == observation_id), None)
    add("2b_normalization_projection_row", row, row and f"event_iid={row['event_iid']} lane_index={row['lane_index']}")
    total = len(proj["cat"]["lanes"])
    win = await window_rows(db, ident, time_start=t0, time_end=t1, lane_start=0, lane_end=total, kinds=None, q=None,
                            dispositions=None)
    add("3_window_filter", any(r.get("observation_id") == observation_id for r in win), f"{len(win)} rows in [{t0}, {t1}]")
    out: dict[str, Any] = {"observation_id": observation_id, "window": [t0, t1], "limit": limit, "stages": stages}
    for engine in ("e1", "e3"):
        r = await trajectory(engine, time_start=t0, time_end=t1, lane_start=0, lane_end=total, cursor=None, limit=limit,
                             kinds=None, q=None, dispositions=None, hist_day=None)
        page = r["events"]
        hit = any(e.get("observation_id") == observation_id for e in page)
        lane_ok = row is not None and any(ln["lane_index"] == row["lane_index"] for ln in r["lane_axis"]["lanes"])
        out[engine] = {"page_selection": {"present": hit, "returned": len(page), "matched_in_window": r["matched_in_window"],
                                          "first": page[0]["timestamp"] if page else None,
                                          "last": page[-1]["timestamp"] if page else None,
                                          "remaining_older": (r.get("e3_preview") or {}).get("remaining_older")},
                       "row_model": {"present": hit and lane_ok}}
    # The page's deep-link locate(): 6 pages x 2500 walked forward from the OLDEST observation (no time bound).
    cursor, found, seen = None, False, 0
    for _ in range(6):
        r = await tw.query_window(db, identity=ident, refs=refs, lane_start=0, lane_end=total, cursor=cursor, limit=2500)
        seen += len(r["events"])
        if any(e.get("observation_id") == observation_id for e in r["events"]):
            found = True
            break
        cursor = r.get("next_cursor")
        if not cursor:
            break
    out["e1_deep_link_locate"] = {"present": found, "observations_examined": seen, "all_time": proj.get("docs_read")}
    first_missing = next((s["stage"] for s in stages if not s["present"]), None)
    out["e1_disappears_at"] = first_missing or (None if out["e1"]["page_selection"]["present"] else "4_page_selection_oldest_first")
    out["e3_disappears_at"] = first_missing if first_missing and not first_missing.startswith("2a") else (
        None if out["e3"]["page_selection"]["present"] else "4_page_selection")
    return out
