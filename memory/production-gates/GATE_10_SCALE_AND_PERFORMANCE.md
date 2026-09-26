# GATE 10 · SCALE & PERFORMANCE — **IN_PROGRESS**

Owner target: a *useful* initial Device Trajectory in **≤2 s** on the
defined representative benchmark, followed by progressive deeper-history
loading, **without weakening evidence semantics**.

## Benchmark subject

`dev_42e8c6dc74b9` · tenant `default` · **208,754 observations** and
growing (the live Linux sensor keeps writing). Measured against the
external preview edge with a real analyst JWT and the authoritative
tenant header — the same path the SPA takes, edge included.

## Baseline (start of this session)

| call | runs | time |
|---|---|---|
| meta / first paint (`lane 0-1, limit 1`) | 3 | 2.58 · 1.52 · 1.82 s |
| viewport slice (`lane 0-14, limit 2500`) | 2 | 1.94 · 1.26 s |
| legacy `/api/edr/device-trajectory` | 3 | 6.14 · 6.06 · 6.17 s |

Server-side breakdown from the route's own log line showed where it
went: `resolve=0.34-1.87 s · projection=0.54-1.39 s`, i.e. **identity
resolution was a comparable cost to the projection itself**, and the
projection cost was being paid on cache HITS too.

## Three isolated fixes (no evidence semantics touched)

1. **Identity resolution off the event loop.**
   `eq.resolve_endpoint` is a SYNC pymongo path (deliberately — it is the
   one resolver, shared with the sync surfaces) and was called inline in
   an async route on a single-worker backend, so it blocked the loop for
   its full duration and every concurrent trajectory read queued behind
   it. It now runs via `asyncio.to_thread`. Same function, same scope,
   same result.
2. **A covered index for the identity facts.**
   Resolution aggregates the tenant / collector / connector facts over
   EVERY observation of the device — that is deliberate, because tenancy
   must be decided over all of them and not over the one document that
   happened to be read first. With only `(event.device_iid, event.ts)`
   available the `$group` had to fetch documents. New index
   `obs_device_identity_facts`
   `{event.device_iid, tenant_id, collector_id, connector_id}`, declared
   in the startup index bootstrap (`server.py`), keeps it inside the
   index: measured **0.33 s → 0.22 s**, identical result.
3. **Derived aggregates moved onto the projection.**
   `event_type_counts`, the activity bands, the observed extent and the
   lane lookup were recomputed on EVERY read — four more full passes over
   208k rows even when the projection itself was a cache hit. They are
   now computed once by `_with_derived()` and travel with the cached
   projection, and an unfiltered viewport read serves its rows from
   per-lane buckets instead of scanning the whole history. A filtered,
   searched or history-pinned read still computes its own, because a
   filter legitimately changes the population.

**A real defect was introduced and caught by measurement, not by luck:**
there are TWO projection builders (`_projected` in the loop and
`_project_all_sync` off the loop) filling the SAME cache, and the first
version of fix 3 only taught one of them about the derived keys — the
next read raised `KeyError: 'by_lane'` and returned HTTP 500. Both now go
through `_with_derived()`, and
`tests/edr/test_gate10_trajectory_window_fast_paths.py::
test_both_projection_builders_carry_the_derived_aggregates` is a
structural guard so the two paths can never diverge again.

## After (same host, same endpoint, same day)

| call | runs | time |
|---|---|---|
| meta / first paint | **8** | 1.17 · 1.19 · 1.34 · **1.06** · 1.82 · 1.17 · 1.77 · 1.15 s |
| viewport slice (2500 events) | 3 | 2.11 (cold) · **0.41** · 0.43 s |
| filtered read `q=bash` (recompute path) | 1 | 0.79 s |
| real SPA · navigate → trajectory painted | 1 | **1.26 s** |

Server-side after: `resolve=0.22-0.40 s · projection=0.6-0.8 s`.

Truth preserved (verbatim from the responses):

```
meta      projection.state=BOUNDED_RECENT  projected=4000  all_time=208623
slice     projection.state=COMPLETE        projected=208623  lanes=8342
filtered  after_filters=1396  in_window=132   (q=bash)
```

and the SPA still states *"Showing the most recent 4,000 of 208,754
recorded observations. The complete endpoint-wide axis is being built and
will replace this view automatically — counts shown are exact, not
estimated."*

## Verdict

**8 of 8 meta reads are now under 2 s (1.06-1.82 s, mean 1.33 s)** and
the warm slice is ~0.42 s. The gate is still **NOT** claimed as PASS,
because "≤2 s" for production means p95 under concurrency on a defined
fleet, and that has not been measured.

## Remaining work before this gate can be claimed

1. p50/p95/p99 under concurrency (4 concurrent meta reads currently
   measure 2.3-4.2 s — the single-worker backend is the constraint, not
   the projection).
2. The **legacy** `/api/edr/device-trajectory` route is still ~6.1 s and
   is reachable from the XDR console: optimise or retire it.
3. Fleet-scale reads — 222 computers is not a scale test.
4. Failure injection: Mongo unavailable, the warm worker killed
   mid-projection, an ingest storm during a projection.
5. A defined, repeatable benchmark harness so these numbers are
   reproducible rather than hand-timed curls.
