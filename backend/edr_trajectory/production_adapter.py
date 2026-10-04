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
from datetime import datetime, timedelta, timezone
from typing import Any

from services.edr.endpoint_query import (
    ENDPOINT_KEYED_STORES,
    TENANT_PARTITIONED_STORES,
)
from edr_plane import temporal_authority as _ta

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

#: The store's OWN stored observation time. Evidence/compatibility value only.
OBSERVATION_TIME_KEY = {STORE_SHADOW: "event.ts", STORE_CANONICAL: "event_time"}

#: G-41 · the key chronological SELECTION uses. For the canonical store this is
#: the comparable integer `observation_us`, NOT the verbatim `event_time`:
#: production holds two valid `event_time` renderings of the same clock, and a
#: byte-wise string comparison put an event at 23:55 below one at 00:06 of the
#: same day on every date where both appear. Ordering was recoverable in memory;
#: SELECTION was not — a `LIMIT` under that sort fetched the wrong newest N, and
#: a resume bound expressed as a raw stored string excluded same-date rows that
#: belonged on a later page, permanently. Evidence never fetched cannot be
#: re-sorted into view.
TEMPORAL_SELECT_KEY = {STORE_SHADOW: "event.ts",
                       STORE_CANONICAL: _ta.OBSERVATION_US}

#: True where the selection key is a comparable scalar, so the bound may be an
#: exact value instead of a string prefix. Declared per store rather than
#: assumed, because the shadow store has no derived comparable value and keeps
#: its existing string behaviour until it does.
COMPARABLE_TEMPORAL = {STORE_SHADOW: False, STORE_CANONICAL: True}

#: The deterministic secondary order for a comparable store. Thousands of
#: endpoint events legitimately share one microsecond, so an index and a LIMIT
#: on time alone are not a total order — which is how a fix for string ordering
#: would otherwise introduce a fresh skip/duplicate bug at equal timestamps.
TEMPORAL_TIEBREAK_KEY = "_id"
NORMALIZER = {STORE_SHADOW: from_shadow, STORE_CANONICAL: from_canonical}
STORES = (STORE_SHADOW, STORE_CANONICAL)

#: Headroom per branch so rows sharing an ordering position cannot straddle a page boundary.
TIE_MARGIN = 64
CURSOR_CONTRACT = "e3.dt.prod_cursor.v2"
ORDER = "NEWEST_FIRST"

UNPLACEABLE = "UNPLACEABLE_NO_OBSERVATION_TIME"
TIE_OVERFLOW = "TIE_GROUP_EXCEEDS_PAGE_SIZE"

#: G-41 RETIREMENT · the canonical temporal-health verdict for THIS endpoint.
#: The comparable read now excludes an unstamped row at the database, so the
#: condition is stated explicitly rather than inferred from a counter that would
#: read as a clean zero.
TEMPORAL_HEALTHY = "ALL_COMPARABLE_EVIDENCE_TEMPORALLY_PLACEABLE"
TEMPORAL_UNSTAMPED = "UNSTAMPED_EVIDENCE_PRESENT_AND_EXCLUDED_FROM_SELECTION"
TEMPORAL_NOT_ASSESSED = "NOT_ASSESSED_NO_COMPARABLE_STORE_READ"

#: Deep-link search budget, in pages of PAGE_MAX. An unresolvable identifier would otherwise walk
#: the endpoint's entire retained history on every request — measured as an unbounded read on a
#: 279,554-observation endpoint. A budget that is REACHED is reported as reached, never as "not
#: found", because the two statements are not the same claim.
FOCUS_PAGE_BUDGET = 8


def observation_us(value: Any) -> int | None:
    """The stored observation time at FULL SOURCE PRECISION, in epoch microseconds.

    ONE parser, hosted in `edr_plane.temporal_authority`, so the value the
    writer stores and the value this adapter compares can never drift apart.

    E3's `observed_ms` is a millisecond REPRESENTATION, and the stores write
    microseconds: `...30.219438+00:00` and `...30.219516+00:00` are two distinct
    observations that both truncate to the same millisecond. Ordering and paging
    on the truncated value therefore manufactured ties that do not exist in the
    evidence, and because the resume boundary was expressed in that same
    truncated value, rows inside an artificial tie were skipped — measured as 16
    observations returned at one page size and never returned at another. So
    ordering and the cursor use this value; `observed_ms` stays the rendering
    contract.
    """
    return _ta.to_epoch_us(value)


def _encode(us: int, event_id: str, bounds: dict[str, str],
            unstamped: bool | None = None) -> str:
    d: dict[str, Any] = {"v": CURSOR_CONTRACT, "us": int(us),
                         "id": str(event_id), "b": bounds}
    if unstamped is not None:
        #: the session's temporal-health verdict, so a resumed page reports it
        #: without re-probing. One bit, no evidence and no identity in it.
        d["th"] = 1 if unstamped else 0
    return base64.urlsafe_b64encode(json.dumps(
        d, separators=(",", ":")).encode()).decode()


def _decode(cursor: str) -> dict[str, Any]:
    try:
        d = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        if d.get("v") != CURSOR_CONTRACT:
            raise ValueError("wrong cursor contract")
        th = d.get("th")
        return {"us": int(d["us"]), "id": str(d["id"]),
                "b": {str(k): str(v) for k, v in (d.get("b") or {}).items()},
                #: absent on a cursor minted before this field existed, which
                #: re-probes rather than asserting a verdict it never measured
                "th": None if th is None else bool(th)}
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


def branch_query(flt: dict[str, Any], time_key: str, *,
                 upper_bound: Any = None, lo: Any = None, hi: Any = None,
                 comparable: bool = False, tiebreak: str | None = None
                 ) -> tuple[dict[str, Any], list[tuple[str, int]]]:
    """The filter and sort this branch ACTUALLY executes.

    Extracted so an `explain` can prove the shape the read really uses rather
    than a hand-written imitation of it. A plan proof against a reconstructed
    query proves nothing about production.
    """
    q = dict(flt)
    rng: dict[str, Any] = {}
    ceiling = upper_bound
    if hi is not None:
        if comparable:
            if upper_bound is None or int(hi) < int(upper_bound):
                ceiling = hi
        else:
            a, b = observation_us(upper_bound), observation_us(hi)
            if upper_bound is None or (a is not None and b is not None and b < a):
                ceiling = hi
    if ceiling is not None:
        rng["$lte"] = ceiling
    if lo is not None:
        rng["$gte"] = lo
    q[time_key] = rng or {"$ne": None}
    sort = [(time_key, -1)] + ([(tiebreak, -1)] if tiebreak else [])
    return q, sort


async def _unstamped_probe(coll: Any, flt: dict[str, Any], time_key: str) -> bool:
    """Does this branch hold evidence with NO comparable temporal value?

    G-41 RETIREMENT · the comparable read excludes such a row AT THE DATABASE,
    so it can no longer be counted while being discarded. Reporting nothing
    would turn "we stopped looking" into an indistinguishable zero, which is the
    class of defect this platform refuses to ship — so the condition is probed
    EXPLICITLY instead.

    PRESENCE, not a count, and `_id` only: the predicate is satisfiable from the
    temporal index keys alone, it short-circuits on the first match, and it
    issues NO raw-string `event_time` selection, ordering or bound. It stays
    inside the collection contract this module already declares — `find` with a
    projection, bounded by `limit` — so no store or fixture grows a new method.
    It runs once per session; the verdict then travels in the cursor, so
    resuming a page never re-pays for it.
    """
    q = dict(flt)
    q[time_key] = {"$exists": False}
    async for _ in coll.find(q, {"_id": 1}).limit(1):
        return True
    return False


async def _branch_page(coll: Any, flt: dict[str, Any], time_key: str,
                       upper_bound: Any, fetch: int,
                       lo: Any = None, hi: Any = None,
                       comparable: bool = False,
                       tiebreak: str | None = None) -> list[dict[str, Any]]:
    """This branch's newest `fetch` rows THROUGH ITS OWN INDEX.

    FOR A COMPARABLE STORE the bound, the order and the LIMIT are all on
    an integer microsecond key, with `_id` as a deterministic secondary order so
    a tie group cannot shuffle between reads. That is what makes the LIMIT
    return the actual newest N: a byte-wise string comparison used to put an
    event at 23:55 below one at 00:06 of the same day, so the newest N by string
    were not the newest N in time, and a resume bound expressed as a raw stored
    string permanently excluded same-date rows that belonged on a later page.
    The resume bound stays INCLUSIVE (`$lte`) and exact exclusion is applied
    afterwards on `(observation_us, event_id)`; an inclusive integer bound can
    never drop a chronologically eligible row, which is the whole defect.

    A row carrying NO comparable value is excluded by the range itself. It is
    not reachable by a second string-ordered read any more — that transitional
    path is retired now the historical population is fully stamped — and its
    existence is reported by `_unstamped_probe` instead of being silently
    absent.

    FOR A NON-COMPARABLE STORE the previous behaviour is unchanged: `$lte` on
    the stored string is a BOUND, not the decision, and exact placement is
    applied afterwards by the same microseconds that provide the order. A string
    comparison never decides whether an observation is inside the analyst's
    window.

    Rows with no observation time are excluded by the range itself — they are
    unplaceable and are reported separately instead of being ordered by
    something else.

    `_id` is projected because one document is legitimately matched by several
    identity branches and the store key is the only guaranteed-unique way to
    recognise it as the same document. It is an internal de-duplication key
    only: it is stripped before the contract is returned and is never presented
    as evidence identity.
    """
    q, sort = branch_query(flt, time_key, upper_bound=upper_bound, lo=lo,
                           hi=hi, comparable=comparable, tiebreak=tiebreak)
    return [d async for d in coll.find(q, {}).sort(sort).limit(fetch)]


def _window_bounds(time_start: str | None, time_end: str | None
                   ) -> tuple[int | None, int | None, str | None, str | None]:
    """Exact microsecond window for placement, plus the string bounds for the query.

    THE BOUND MUST BE TIGHT. The first implementation widened it by an hour so a differing
    offset representation could not exclude a row — and that made the per-branch `limit` useless:
    on a busy endpoint the newest 69 rows of the widened range all sat ABOVE the window ceiling,
    so a ten-minute window holding evidence returned zero rows while reporting 138 rows excluded.
    A limit applied outside the window is not a window.

    The bound is therefore the window itself with one second of slack, which keeps the read inside
    the analyst's range while absorbing the sub-second and `Z`-versus-`+00:00` differences between
    the two stores. Exactness is still decided afterwards on microseconds, so the one-second slack
    can never widen what the analyst is shown.

    Known limitation, declared rather than hidden: a stored observation time written with a
    NON-UTC offset would sort outside this string bound. Three such corrupt strings are known to
    exist in this platform's evidence and are already reported as unplaceable.
    """
    lo_us = observation_us(time_start) if time_start else None
    hi_us = observation_us(time_end) if time_end else None
    if lo_us is None and hi_us is None:
        return None, None, None, None

    def prefix(us: int | None, slack_s: int) -> str | None:
        if us is None:
            return None
        dt = datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc) + timedelta(seconds=slack_s)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    return lo_us, hi_us, prefix(lo_us, -1), prefix(hi_us, 1)


async def page_device_evidence(db: Any, *, tenant_id: str, refs: list[str],
                               page_size: int = PAGE_DEFAULT, cursor: str | None = None,
                               time_start: str | None = None, time_end: str | None = None,
                               stores: tuple[str, ...] = STORES) -> dict[str, Any]:
    """One newest-first page of REAL evidence for one endpoint, in one customer.

    Returns the E3 normalized event contract plus the provenance needed to prove where every
    row came from. No store is promoted to canonical authority here: both are read and the
    same activity seen in both is collapsed by stable evidence identity.

    `time_start`/`time_end` are the analyst's window. They are OPTIONAL and default to absent,
    which means "the newest evidence, unbounded". When supplied they bound the read on the same
    field that provides the order, so the range the UI claims to be showing is the range it
    actually read — and a deep link can bring an observation older than the newest page into
    view instead of resolving correctly and then never appearing.
    """
    tenant = require_tenant(tenant_id)
    size = max(1, min(int(page_size or PAGE_DEFAULT), PAGE_MAX))
    refs = [str(r) for r in (refs or []) if r]
    cur = _decode(cursor) if cursor else None
    if not refs:
        return _empty(size, "ENDPOINT_NOT_ADDRESSABLE_NO_VALIDATED_REFS")

    lo_us, hi_us, lo_s, hi_s = _window_bounds(time_start, time_end)
    fetch = size + TIE_MARGIN
    jobs, plan = [], []
    probes: list[Any] = []
    #: probed once per session; a resumed page inherits the verdict
    inherited = (cur or {}).get("th")
    comparable_read = False
    for store in stores:
        tkey = TEMPORAL_SELECT_KEY[store]
        comparable = COMPARABLE_TEMPORAL[store]
        tiebreak = TEMPORAL_TIEBREAK_KEY if comparable else None
        comparable_read = comparable_read or comparable
        # G-41 · a comparable store resumes on the cursor's exact microsecond,
        # which is store-independent; only a non-comparable store still needs a
        # per-store raw-string bound.
        bound = (cur or {}).get("us") if comparable \
            else (cur or {}).get("b", {}).get(store)
        w_lo, w_hi = (lo_us, hi_us) if comparable else (lo_s, hi_s)
        for flt in branches(store, refs, tenant):
            plan.append({"store": store, "time_key": tkey, "upper_bound": bound,
                         "comparable_temporal": comparable,
                         "fields": [k for k in flt if k != TENANT_PARTITIONED_STORES.get(store)]})
            jobs.append(_branch_page(db[store], flt, tkey, bound, fetch,
                                     w_lo, w_hi, comparable, tiebreak))
            if comparable and inherited is None:
                probes.append(_unstamped_probe(db[store], flt, tkey))
    raw_pages = await asyncio.gather(*jobs)
    unstamped_present = (inherited if inherited is not None
                         else (any(await asyncio.gather(*probes)) if probes
                               else None))

    rows: list[dict[str, Any]] = []
    per_store: dict[str, int] = {s: 0 for s in stores}
    #: event identity -> ordering position + the RAW stored time per store, kept at source
    #: precision so a resume bound is expressed in the exact value the store holds.
    order: dict[str, dict[str, Any]] = {}
    unplaceable = 0
    outside_window = 0
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
            us = int(raw_t) if (spec["comparable_temporal"]
                                and isinstance(raw_t, int)) else observation_us(raw_t)
            # never mutate the document the store handed us: strip the internal key on a copy.
            ev = finalize(NORMALIZER[store]({k: v for k, v in doc.items() if k != "_id"}))
            if ev.get("tenant_id") != tenant:     # defence in depth: never trust the filter alone
                continue
            if us is None or ev.get("observed_ms") is None:
                unplaceable += 1
                continue
            # EXACT window placement, on microseconds. The string range above is only a bound.
            if (lo_us is not None and us < lo_us) or (hi_us is not None and us > hi_us):
                outside_window += 1
                continue
            per_store[store] += 1
            eid = ev["event_id"]
            o = order.setdefault(eid, {"us": us, "raw": {}})
            o["us"] = min(o["us"], us)
            # only a NON-COMPARABLE store still needs a raw-string resume bound;
            # a comparable store resumes on the exact microsecond instead.
            if not spec["comparable_temporal"]:
                prev = o["raw"].get(store)
                o["raw"][store] = str(raw_t) if prev is None \
                    else min(prev, str(raw_t))
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
                      _next_bounds(items, order, stores, (cur or {}).get("b", {})),
                      unstamped_present)

    return {
        "order": ORDER,
        "contract": {"event": "e3.dt.event.v1", "cursor": CURSOR_CONTRACT},
        "page_size": size,
        "items": items,
        "has_more": has_more,
        "next_cursor": nxt,
        "suppressed_duplicates": suppressed,
        f"{UNPLACEABLE.lower()}_count": unplaceable,
        # G-41 RETIREMENT · the canonical read selects ONLY stamped evidence, so
        # an unstamped row is no longer fetched-then-discarded and cannot show
        # up in the counter above. The condition is therefore stated here. A
        # clean verdict is a MEASURED clean verdict, never the absence of a read.
        "temporal_health": _temporal_health(unstamped_present, comparable_read),
        "window": {"time_start": time_start, "time_end": time_end,
                   "applied": lo_us is not None or hi_us is not None,
                   "excluded_outside_window": outside_window,
                   "basis": ("exact microsecond placement against the stored observation time; "
                             "the query bound is the window itself with one second of slack and "
                             "never decides membership")},
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


def _temporal_health(unstamped: bool | None, comparable_read: bool) -> dict[str, Any]:
    """The canonical temporal-health statement, as a claim this read can prove.

    Three distinct answers, never collapsed into one reassuring number:
    assessed-and-clean, assessed-and-unstamped-evidence-exists, and not
    assessed because no comparable store was read.
    """
    if unstamped is None:
        return {"state": TEMPORAL_NOT_ASSESSED, "assessed": False,
                "unstamped_evidence_present": None,
                "basis": ("no comparable store was read in this request"
                          if not comparable_read else
                          "the comparable store was read but not probed"),
                "meaning": ("this read makes NO claim about unplaceable "
                            "evidence. It is not a statement that there is "
                            "none.")}
    return {
        "state": TEMPORAL_UNSTAMPED if unstamped else TEMPORAL_HEALTHY,
        "assessed": True,
        "unstamped_evidence_present": bool(unstamped),
        "selection_authority": f"{_ta.OBSERVATION_US} DESC, {TEMPORAL_TIEBREAK_KEY} DESC",
        "basis": ("an index-supported presence probe for evidence matching this "
                  "endpoint's declared identity branches that carries no "
                  f"{_ta.OBSERVATION_US}. It performs no raw-string "
                  f"{OBSERVATION_TIME_KEY[STORE_CANONICAL]} selection, ordering "
                  "or bound, and runs once per paging session."),
        "meaning": ("true means this endpoint holds evidence whose stored "
                    "observation time is absent or unparseable. The comparable "
                    "read EXCLUDES it rather than placing it at an invented "
                    "time, so it is not in `items` and is not counted in "
                    f"{UNPLACEABLE.lower()}_count — this flag is the only "
                    "signal that it exists."),
    }


def _dig(doc: dict[str, Any], path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def _next_bounds(items: list[dict[str, Any]], order: dict[str, dict[str, Any]],
                 stores: tuple[str, ...], previous: dict[str, str]) -> dict[str, str]:
    """The resume bound per store: the OLDEST raw stored time this page emitted from that store.

    G-41 · a COMPARABLE store no longer needs one: it resumes on the cursor's
    exact microsecond, which is representation-independent, so its bound is
    omitted rather than carried as a string that could exclude an eligible row.
    A non-comparable store keeps its own representation, because comparing one
    store's value against the other's is how a boundary row goes missing. A
    store that contributed nothing keeps its previous bound rather than
    inheriting another store's: not advancing only re-reads, while advancing
    past unseen rows would drop them.
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
            "suppressed_duplicates": 0, f"{UNPLACEABLE.lower()}_count": 0,
            # no store was read, so no temporal claim is made. An endpoint that
            # could not be addressed is NOT an endpoint proven clean.
            "temporal_health": _temporal_health(None, False), "state": reason,
            "provenance": {"stores_read": [], "reason": reason}}


async def resolve_evidence(db: Any, *, tenant_id: str, refs: list[str],
                           event_id: str | None = None,
                           match: Any = None,
                           max_pages: int = FOCUS_PAGE_BUDGET,
                           stores: tuple[str, ...] = STORES) -> dict[str, Any]:
    """Deep link: one evidence identity → its exact observation, or an explicit miss.

    Resolution is by the SAME stable event identity the page emitted, inside the same customer
    and the same endpoint, so a deep link can never reach another customer's evidence. A miss
    returns a reason; it never returns a different row that happens to be nearby in time.

    `match` is an optional predicate for identifiers that are not the evidence identity itself —
    e.g. a store's own `observation_id` carried in `provenance.ref`. It walks the SAME ordered
    pages through the SAME tenant- and endpoint-scoped adapter, so an alternative identifier can
    never widen the authorized scope or reach a row the identity path could not reach.
    """
    tenant = require_tenant(tenant_id)
    refs = [str(r) for r in (refs or []) if r]
    if not refs or not (event_id or match):
        return {"state": "FOCUS_NOT_RESOLVED", "reason": "ENDPOINT_OR_EVENT_IDENTITY_MISSING",
                "event_id": event_id, "event": None}
    hit = match if match else (lambda ev: ev["event_id"] == event_id)
    cursor = None
    scanned = 0
    pages = 0
    while True:
        page = await page_device_evidence(db, tenant_id=tenant, refs=refs,
                                          page_size=PAGE_MAX, cursor=cursor, stores=stores)
        pages += 1
        for ev in page["items"]:
            if hit(ev):
                event_id = ev["event_id"]
                return {"state": "FOCUS_RESOLVED", "event_id": event_id, "event": ev,
                        "observed_at": ev.get("observed_at"),
                        "position": {"scanned_newer_first": scanned,
                                     "basis": "NEWEST_FIRST_OBSERVATION_TIME_ORDER"},
                        "provenance": page["provenance"]}
            scanned += 1
        if not page["has_more"]:
            return {"state": "FOCUS_NOT_RESOLVED",
                    "reason": "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT",
                    "event_id": event_id, "event": None, "scanned": scanned,
                    "search": {"pages_searched": pages, "page_size": PAGE_MAX,
                               "state": "EXHAUSTED_SEARCH_COMPLETED"}}
        if pages >= max_pages:
            # A BUDGET IS NOT AN ABSENCE. Walking an endpoint's whole history for a deep link
            # that does not exist is an unbounded read, so the walk is capped — but reporting a
            # capped walk as "not found" would assert something this resolver did not establish.
            return {"state": "FOCUS_NOT_RESOLVED",
                    "reason": "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE",
                    "event_id": event_id, "event": None, "scanned": scanned,
                    "search": {"pages_searched": pages, "page_size": PAGE_MAX,
                               "state": f"PAGE_BUDGET_REACHED_{max_pages}"},
                    "meaning": ("the newest " + str(scanned) + " observations do not carry this "
                                "identifier. This is NOT proof that the endpoint never held it.")}
        cursor = page["next_cursor"]
