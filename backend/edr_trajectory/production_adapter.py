"""§d PRODUCTION EVIDENCE ADAPTER — real E1 evidence → the E3 normalized event contract.

This is the ONLY bridge between E1's authoritative stores and E3's capability contracts.
It reads; it never writes, migrates, or re-stamps evidence.

OBSERVATION TIME AUTHORITY
--------------------------
Chronology comes from the store's own stored observation time and nothing else:

    v2_shadow_observations   -> event.ts
    xdr_canonical_evidence   -> event_time

`ingest_time` is NEVER an ordering key. Backlog replay is real on this platform, so placing a
replayed event at its ingestion instant would move it to the wrong place on the analyst's
timeline. A row whose observation time is absent or unparseable is UNPLACEABLE and is reported
as such — it is never given a time.

`observed_ms` IS A DERIVED REPRESENTATION, NOT A STORED FIELD
-------------------------------------------------------------
Measured: `observed_ms` exists in 0 of 277,684 canonical, 283,789 shadow and 287,447 raw
documents. E3 consumes it purely as a millisecond rendering of the authoritative stored time,
so it is derived here at the adapter boundary by `providers.from_*` → `contracts.parse_instant`.
Nothing is persisted and no second source of truth is created.

WHY THE MERGE IS IN THE ADAPTER AND NOT IN THE QUERY
----------------------------------------------------
Endpoint identity legitimately spans several declared fields (`ENDPOINT_KEYED_STORES`), so the
authoritative predicate is an `$or`. Measured on a real 275,902-observation endpoint:

  * `$or` + sort, few branches         -> LIMIT→FETCH→SORT_MERGE→IXSCAN   200 docs,     4 ms
  * `$or` + sort, more branches/refs   -> SORT→FETCH→OR→IXSCAN         276,031 docs, 4,401 ms

SORT_MERGE collapses into a blocking in-memory sort once branch×ref count passes the planner's
enumeration limit — i.e. the moment an endpoint acquires one more alias. A correctness and
latency cliff that depends on a planner heuristic is not a production foundation, so this
adapter asks each branch for its own newest page through that branch's index (measured
LIMIT→FETCH→IXSCAN, keys=200, docs=200, 1 ms) and performs the bounded merge itself. Work is
O(branches x page_size), never O(endpoint history).
"""
from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone
from typing import Any

from services.edr.endpoint_query import (
    ENDPOINT_KEYED_STORES,
    TENANT_PARTITIONED_STORES,
)

from .contracts import require_tenant
from .identity import dedupe
from .paging import PAGE_DEFAULT, PAGE_MAX, BadCursor
from .providers import (
    STORE_CANONICAL,
    STORE_SHADOW,
    finalize,
    from_canonical,
    from_shadow,
)

#: The store's OWN stored observation time. The one ordering authority per store.
OBSERVATION_TIME_KEY = {STORE_SHADOW: "event.ts", STORE_CANONICAL: "event_time"}
NORMALIZER = {STORE_SHADOW: from_shadow, STORE_CANONICAL: from_canonical}
STORES = (STORE_SHADOW, STORE_CANONICAL)

#: Headroom per branch so rows sharing an ordering position cannot straddle a page boundary.
TIE_MARGIN = 64
CURSOR_CONTRACT = "e3.dt.prod_cursor.v2"
ORDER = "NEWEST_FIRST"

UNPLACEABLE = "UNPLACEABLE_NO_OBSERVATION_TIME"
TIE_OVERFLOW = "TIE_GROUP_EXCEEDS_PAGE_SIZE"


def observation_us(value: Any) -> int | None:
    """The stored observation time at FULL SOURCE PRECISION, in epoch microseconds.

    E3's `observed_ms` is a millisecond REPRESENTATION, and the stores write microseconds:
    `...30.219438+00:00` and `...30.219516+00:00` are two distinct observations that both
    truncate to the same millisecond. Ordering and paging on the truncated value therefore
    manufactured ties that do not exist in the evidence, and because the resume boundary was
    expressed in that same truncated value, rows inside an artificial tie were skipped —
    measured as 16 observations returned at one page size and never returned at another.
    So ordering and the cursor use this value; `observed_ms` stays the rendering contract.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return int(value) * 1000
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(dt.replace(microsecond=0).timestamp()) * 1_000_000 + dt.microsecond
    s = str(value).strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.replace(microsecond=0).timestamp()) * 1_000_000 + dt.microsecond


def _encode(us: int, event_id: str, bounds: dict[str, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(
        {"v": CURSOR_CONTRACT, "us": int(us), "id": str(event_id), "b": bounds},
        separators=(",", ":")).encode()).decode()


def _decode(cursor: str) -> dict[str, Any]:
    try:
        d = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        if d.get("v") != CURSOR_CONTRACT:
            raise ValueError("wrong cursor contract")
        return {"us": int(d["us"]), "id": str(d["id"]),
                "b": {str(k): str(v) for k, v in (d.get("b") or {}).items()}}
    except Exception as ex:
        raise BadCursor("cursor is not a valid e3 production trajectory cursor") from ex


def _key(ev: dict[str, Any]) -> tuple[int, str]:
    """The total order: full-precision observation time, then stable evidence identity.

    `observed_us` is attached by the adapter from the store's own stored time. The identity
    tie-breaker stays because two stores can legitimately record the same activity at the same
    microsecond, and a page boundary inside such a pair must still be unambiguous.
    """
    return (int(ev["observed_us"]), str(ev["event_id"]))


def branches(store: str, refs: list[str], tenant_id: str) -> list[dict[str, Any]]:
    """One tenant-scoped, single-identity-field predicate per declared field.

    Each is individually index-servable, which is what keeps the sort out of memory. The field
    list is read from the authoritative `ENDPOINT_KEYED_STORES` contract, so this adapter can
    never address an undeclared identity field, and tenant partitioning is applied from the
    same contract rather than re-decided here.
    """
    fields = ENDPOINT_KEYED_STORES.get(store)
    if fields is None:
        raise KeyError(f"{store} is not a declared endpoint-keyed store")
    partition = TENANT_PARTITIONED_STORES.get(store)
    if partition and not tenant_id:
        return []                      # fail closed: no tenant, no evidence
    out = []
    for f in fields:
        flt: dict[str, Any] = {f: {"$in": refs}}
        if partition:
            flt[partition] = tenant_id
        out.append(flt)
    return out


async def _branch_page(coll: Any, flt: dict[str, Any], time_key: str,
                       upper_bound: str | None, fetch: int) -> list[dict[str, Any]]:
    """This branch's newest `fetch` rows THROUGH ITS OWN INDEX.

    `$lte` on the stored time is a range on the same index that provides the order, so resuming
    stays index-served. Rows with no observation time are excluded by the range itself — they
    are unplaceable and are reported separately instead of being ordered by something else.

    `_id` is projected because one document is legitimately matched by several identity
    branches and the store key is the only guaranteed-unique way to recognise it as the same
    document. It is an internal de-duplication key only: it is stripped before the contract is
    returned and is never presented as evidence identity.
    """
    q = dict(flt)
    q[time_key] = {"$lte": upper_bound} if upper_bound else {"$ne": None}
    cur = coll.find(q, {}).sort(time_key, -1).limit(fetch)
    return [d async for d in cur]


async def page_device_evidence(db: Any, *, tenant_id: str, refs: list[str],
                               page_size: int = PAGE_DEFAULT, cursor: str | None = None,
                               stores: tuple[str, ...] = STORES) -> dict[str, Any]:
    """One newest-first page of REAL evidence for one endpoint, in one customer.

    Returns the E3 normalized event contract plus the provenance needed to prove where every
    row came from. No store is promoted to canonical authority here: both are read and the
    same activity seen in both is collapsed by stable evidence identity.
    """
    tenant = require_tenant(tenant_id)
    size = max(1, min(int(page_size or PAGE_DEFAULT), PAGE_MAX))
    refs = [str(r) for r in (refs or []) if r]
    cur = _decode(cursor) if cursor else None
    if not refs:
        return _empty(size, "ENDPOINT_NOT_ADDRESSABLE_NO_VALIDATED_REFS")

    fetch = size + TIE_MARGIN
    jobs, plan = [], []
    for store in stores:
        tkey = OBSERVATION_TIME_KEY[store]
        bound = (cur or {}).get("b", {}).get(store)
        for flt in branches(store, refs, tenant):
            plan.append({"store": store, "time_key": tkey, "upper_bound": bound,
                         "fields": [k for k in flt if k != TENANT_PARTITIONED_STORES.get(store)]})
            jobs.append(_branch_page(db[store], flt, tkey, bound, fetch))
    raw_pages = await asyncio.gather(*jobs)

    rows: list[dict[str, Any]] = []
    per_store: dict[str, int] = {s: 0 for s in stores}
    #: event identity -> ordering position + the RAW stored time per store, kept at source
    #: precision so a resume bound is expressed in the exact value the store holds.
    order: dict[str, dict[str, Any]] = {}
    unplaceable = 0
    seen_docs: set[tuple[str, str]] = set()
    for spec, docs in zip(plan, raw_pages):
        store = spec["store"]
        tkey = spec["time_key"]
        for doc in docs:
            raw_t = _dig(doc, tkey)
            # one document is matched by several identity branches; recognise it by the
            # store's own unique key rather than by inferred fields, which can be absent.
            dk = (store, str(doc.get("_id")))
            if dk in seen_docs:
                continue
            seen_docs.add(dk)
            us = observation_us(raw_t)
            # never mutate the document the store handed us: strip the internal key on a copy.
            ev = finalize(NORMALIZER[store]({k: v for k, v in doc.items() if k != "_id"}))
            if ev.get("tenant_id") != tenant:     # defence in depth: never trust the filter alone
                continue
            if us is None or ev.get("observed_ms") is None:
                unplaceable += 1
                continue
            per_store[store] += 1
            eid = ev["event_id"]
            o = order.setdefault(eid, {"us": us, "raw": {}})
            o["us"] = min(o["us"], us)
            prev = o["raw"].get(store)
            o["raw"][store] = str(raw_t) if prev is None else min(prev, str(raw_t))
            rows.append(ev)

    merged, suppressed = dedupe(rows)
    merged = [finalize(e) for e in merged]
    for e in merged:
        # the full-precision observation time travels in the contract: `observed_ms` is the
        # millisecond RENDERING E3 consumes, this is the value the order and cursor use.
        e["observed_us"] = order[e["event_id"]]["us"]
    merged.sort(key=_key, reverse=True)

    tie_overflow = False
    if cur:
        bound_key = (cur["us"], cur["id"])
        before = len(merged)
        merged = [e for e in merged if _key(e) < bound_key]
        tie_overflow = before > 0 and not merged

    items = merged[:size]
    has_more = len(merged) > size
    nxt = None
    if has_more and items:
        last = items[-1]
        nxt = _encode(last["observed_us"], last["event_id"],
                      _next_bounds(items, order, stores, (cur or {}).get("b", {})))

    return {
        "order": ORDER,
        "contract": {"event": "e3.dt.event.v1", "cursor": CURSOR_CONTRACT},
        "page_size": size,
        "items": items,
        "has_more": has_more,
        "next_cursor": nxt,
        "suppressed_duplicates": suppressed,
        f"{UNPLACEABLE.lower()}_count": unplaceable,
        "state": TIE_OVERFLOW if tie_overflow else "PAGE_READY",
        "provenance": {
            "stores_read": list(stores),
            "rows_per_store": per_store,
            "observation_time_keys": {s: OBSERVATION_TIME_KEY[s] for s in stores},
            "order_key": "observed_us (full source precision), then stable evidence identity",
            "observed_ms_meaning": "MILLISECOND RENDERING of observed_us for the E3 event "
                                   "contract. It is lossy and is never the ordering key.",
            "session": ("a cursor FREEZES the session: every resumed page is bounded by the "
                        "stores own stored time, so evidence that arrives mid-session cannot "
                        "slip above an already-returned boundary. A fresh read with no cursor "
                        "deliberately shows the newest evidence."),
            "ordering_authority": "STORED_OBSERVATION_TIME",
            "ingest_time_used_as_observation_time": False,
            "canonical_authority": "NOT_SELECTED (E1 decision) — both stores read, "
                                   "duplicates collapsed on stable evidence identity",
            "identity_fields_addressed": sorted({f for p in plan for f in p["fields"]}),
            "addressed_by": refs,
            "tenant_id": tenant,
            "branch_queries": len(plan),
            "branch_fetch_size": fetch,
            "unplaceable_meaning": "the stored observation time is absent or unparseable, so "
                                   "this evidence has no provable position in time. It is "
                                   "counted, never placed at its ingestion instant.",
        },
    }


def _dig(doc: dict[str, Any], path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def _next_bounds(items: list[dict[str, Any]], order: dict[str, dict[str, Any]],
                 stores: tuple[str, ...], previous: dict[str, str]) -> dict[str, str]:
    """The resume bound per store: the OLDEST raw stored time this page emitted from that store.

    Kept per store and in the store's own representation, because the two stores write
    different formats and precisions — comparing one store's value against the other's is how
    a boundary row goes missing. A store that contributed nothing to this page keeps its
    previous bound rather than inheriting another store's: not advancing only re-reads, while
    advancing past unseen rows would drop them.
    """
    out: dict[str, str] = {}
    for store in stores:
        vals = [order[e["event_id"]]["raw"][store] for e in items
                if store in order.get(e["event_id"], {}).get("raw", {})]
        if vals:
            out[store] = min(vals)
        elif previous.get(store):
            out[store] = previous[store]
    return out


def _empty(size: int, reason: str) -> dict[str, Any]:
    return {"order": ORDER, "contract": {"event": "e3.dt.event.v1", "cursor": CURSOR_CONTRACT},
            "page_size": size, "items": [], "has_more": False, "next_cursor": None,
            "suppressed_duplicates": 0, f"{UNPLACEABLE.lower()}_count": 0, "state": reason,
            "provenance": {"stores_read": [], "reason": reason}}


async def resolve_evidence(db: Any, *, tenant_id: str, refs: list[str], event_id: str,
                           stores: tuple[str, ...] = STORES) -> dict[str, Any]:
    """Deep link: one evidence identity → its exact observation, or an explicit miss.

    Resolution is by the SAME stable event identity the page emitted, inside the same customer
    and the same endpoint, so a deep link can never reach another customer's evidence. A miss
    returns a reason; it never returns a different row that happens to be nearby in time.
    """
    tenant = require_tenant(tenant_id)
    refs = [str(r) for r in (refs or []) if r]
    if not refs or not event_id:
        return {"state": "FOCUS_NOT_RESOLVED", "reason": "ENDPOINT_OR_EVENT_IDENTITY_MISSING",
                "event_id": event_id, "event": None}
    cursor = None
    scanned = 0
    while True:
        page = await page_device_evidence(db, tenant_id=tenant, refs=refs,
                                          page_size=PAGE_MAX, cursor=cursor, stores=stores)
        for ev in page["items"]:
            if ev["event_id"] == event_id:
                return {"state": "FOCUS_RESOLVED", "event_id": event_id, "event": ev,
                        "observed_at": ev.get("observed_at"),
                        "position": {"scanned_newer_first": scanned,
                                     "basis": "NEWEST_FIRST_OBSERVATION_TIME_ORDER"},
                        "provenance": page["provenance"]}
            scanned += 1
        if not page["has_more"]:
            return {"state": "FOCUS_NOT_RESOLVED",
                    "reason": "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT",
                    "event_id": event_id, "event": None, "scanned": scanned}
        cursor = page["next_cursor"]
