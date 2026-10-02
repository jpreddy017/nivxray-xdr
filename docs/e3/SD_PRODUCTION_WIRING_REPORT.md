# §d PRODUCTION WIRING — CONSOLIDATED REPORT

NOTHING DEPLOYED. NO PRODUCTION DB/SCHEMA/INDEX CHANGE. KUSHU AND DESKTOP-A9HGFJJ UNTOUCHED.

## A. SOURCE STATE
```
CURRENT_BRANCH   = integration/e3-dt
STARTING_HEAD    = 1da71197
WORKTREE         = modified: backend/routers/edr.py, 3 E3 test files
                   new:      backend/edr_trajectory/production_adapter.py
                             backend/edr_trajectory/production_service.py
                             backend/tests/edr_trajectory/test_sd_production_adapter.py
E1_FOUNDATION    = 1800aeea (merge-base, confirmed)
FINAL_E3_SOURCE  = 258c8854 (present via da4c9098)
GATE16_STATUS    = PASS (5/5)
PRODUCTION_DEPLOYMENT_PERFORMED = NO
```

## B. OBSERVED_MS / TIME DECISION  (§9-§11)

```
PURPOSE                   = DERIVED_INDEX_KEY + VIEW_MODEL_FIELD (NOT authoritative stored time)
AUTHORITATIVE_SOURCE      = v2_shadow_observations.event.ts | xdr_canonical_evidence.event_time
IMPLEMENTATION            = OPTION A (existing authoritative stored time) at the query layer
                          + OPTION B (derive at the adapter boundary) for the representation
PERSISTED?                = NO
SCHEMA_CHANGE?            = NO
BACKFILL_REQUIRED?        = NO
CANONICAL_AUTHORITY_CHANGED? = NO
OPTION C / D              = NOT IMPLEMENTED, NOT PRE-AUTHORISED
```

Measured population (read-only), proving `observed_ms` is not a stored field anywhere:

| store | docs | `event_time`/`event.ts` | `ingest_time` | `observed_ms` |
|---|---|---|---|---|
| xdr_canonical_evidence | 277,684 | 100.0% | 100.0% | **0** |
| v2_shadow_observations | 283,789 | 100.0% (`event.ts`) | 0% | **0** |
| edr_raw_events | 287,447 | 0% | 100.0% | **0** |

`observed_ms` is produced by `providers.from_*` → `contracts.parse_instant(stored time)`. E3 consumes it
only as a millisecond rendering, so Option B needed no new field and no second source of truth.

## C. WHY THE MERGE IS IN THE ADAPTER (query-plan evidence)

Real endpoint, 275,902 observations (`default` / `dev_42e8c6dc74b9` / `ep_2d57cbe6f80152062109`):

| query shape | winning plan | docsExamined | ms |
|---|---|---|---|
| authoritative `$or`, few branches | LIMIT→FETCH→SORT_MERGE→IXSCAN | 200 | 4 |
| authoritative `$or`, more branch×ref | **SORT→FETCH→OR→IXSCAN** | **276,031** | **4,401** |
| per-branch resolved + bounded | LIMIT→FETCH→IXSCAN | 200 | 1 |

SORT_MERGE collapses into a blocking in-memory sort once branch×ref passes the planner's
enumeration limit — i.e. the moment an endpoint gains one more alias. A correctness/latency cliff
governed by a planner heuristic is not a production foundation, so the adapter issues one bounded
index-served query per declared identity branch and merges them itself: O(branches × page_size).

## D. PREVIEW INDEX EXPERIMENT (owner-authorised, preview only)

```
REQUIRED  : 3 on xdr_canonical_evidence — it has NO event_time index at all, so any
            observation-time sort was a blocking sort over 273,988 docs (610 ms).
            pvw_sd_collector_eventtime  (tenant_id, provenance.collector_id, event_time -1)
            pvw_sd_hostid_eventtime     (tenant_id, host.host_id,            event_time -1)
            pvw_sd_hostname_eventtime   (tenant_id, host.hostname,           event_time -1)
NOT REQUIRED: v2_shadow_observations — 7 tenant-prefixed duplicates were trialled, measured to add
            nothing (its pre-existing obs_*_ts already serve every branch), and DROPPED again.
PRODUCTION : OWNER_DECISION_REQUIRED — 3 indexes on xdr_canonical_evidence. Not created.
ROLLBACK   : python /app/scripts/sd_preview_index_experiment.py drop
```

## E. DEFECT FOUND AND FIXED — SUB-MILLISECOND EVIDENCE LOSS

The stores record **microseconds**; `observed_ms` is **milliseconds**. `...30.219438+00:00` and
`...30.219516+00:00` are two distinct observations that truncate to one millisecond. Ordering and
paging on the truncated value manufactured ties that do not exist in the evidence, and because the
resume boundary used that same truncated value, members of the fake tie were **skipped**.

```
MEASURED BEFORE FIX : 16 observations returned at page_size=3 and NEVER returned at page_size=7
AFTER FIX           : missing=0 at page sizes 3 / 7 / 25 / 100
FIX                 : production_adapter.observation_us() — order and cursor use full source
                      precision; `observed_ms` remains the E3 rendering contract and is documented
                      as lossy and never an ordering key. `observed_us` now travels in the contract.
```

Two further defects fixed in the same module: the branch-overlap key relied on fields that are
frequently absent (now the store's own unique key), and the adapter mutated the document the store
handed it (now a copy).

## F. CORRECTNESS PROOFS

`/app/scripts/sd_production_adapter_acceptance.py` — **16/16 PASS on real evidence**
(index-served no blocking sort · newest-first · ingest_time not an ordering key · page1∩page2=∅ ·
no duplicates · no boundary loss · strict total order under ties · cross-tenant leak NO · own tenant
reached · no-tenant fails closed · deep link exact / explicit miss / cannot cross endpoint ·
unplaceable truthful · provenance on every row · bad cursor refused).

`backend/tests/edr_trajectory/test_sd_production_adapter.py` — 24 hermetic invariant tests.

```
SORT_TUPLE                = (observed_us DESC, event_id DESC)
CURSOR                    = e3.dt.prod_cursor.v2, opaque, per-store raw bound at source precision
PAGE1_PAGE2_OVERLAP       = 0
BOUNDARY_LOSS             = NONE
IDENTICAL_TIMESTAMP       = strict total order preserved
ORDER DETERMINISM         = identical at page sizes 3/7/25/100/300 from a fixed cursor, on
                            SHADOW-only, CANONICAL-only and the UNION
LIVE CORPUS NOTE          = the preview corpus is actively ingesting (+4 docs / 6 s in both stores),
                            so a cursor-less read legitimately shows newly arrived evidence; a
                            cursor freezes the session.
```

## G. TEST MATRIX

```
tests/edr/              2051 passed,  3 skipped, 0 failed
tests/edr_trajectory/     78 passed,  9 skipped, 0 failed
combined                2129 passed, 12 skipped, 0 failed
Gate 16                    5 passed
ruff (new files)           clean
```

Pre-existing TEST_HARNESS_FAILURE repaired (test-only, no product code): 8 tests in
`test_kushu_import.py`, `test_stale_trace.py`, `test_platform_seed.py` ERRORED at setup because they
requested an async fixture without the asyncio marker the rest of the suite uses. They were
reporting as "no coverage" while actually never executing — they now run and pass.

## H. REMAINING BLOCKERS

### BLOCKER 1 — the active analyst path still hides the newest evidence
```
WHY   : /edr/device-trajectory -> DeviceTrajectoryEntry. VITE_E3_DT_V3 is OFF, so the analyst gets
        EdrDeviceTrajectoryPage, which reads the V1 contract of
        GET /api/edr/endpoints/{id}/trajectory. V1 builds a bounded projection then slices the page
        OLDEST-FIRST (pinned by E3's own stale_trace characterisation test as
        e1_disappears_at = 4_page_selection_oldest_first).
MEASURED: V1 page newest row 2026-10-02T14:17:47 while the endpoint's newest real observation is
        14:37:33 — roughly 20 minutes of the most recent real evidence is not reachable in the UI.
        The new e3 contract on the same request returns it correctly.
SMALLEST SAFE NEXT ACTION: owner picks ONE —
        (A) make V1 page selection newest-first. Smallest change, fixes the existing UI with no
            frontend work, but it alters an established shared contract (dt2 + other surfaces read
            it) and rewrites a characterisation test that currently documents the defect.
        (B) adopt the proven `e3` contract in the EDR Device Trajectory page. Architecturally
            correct per §4/§13 (adapter, no foundation rewrite), no V1 semantics touched, but it is
            real frontend work across Grid/Navigator/Activity/Artifacts.
        Recommendation: (B), with (A) rejected as a shared-contract change at this stage.
OWNER_DECISION_REQUIRED = YES
```

### BLOCKER 2 — A–T cannot be validated against real KUSHU evidence from this pod
```
WHY   : KUSHU is a PRODUCTION endpoint. The preview database (test_database) holds ZERO KUSHU rows:
        edr_endpoints 0, v2_shadow_observations 0, xdr_canonical_evidence 0, edr_raw_events 0.
        Production confirms KUSHU exists with 258 observations (owner screenshot), but this pod has
        no authorised production Mongo connection and §6 forbids production DB operations.
EFFECT: every A–T row that requires real KUSHU telemetry is INSUFFICIENT_REAL_EVIDENCE / NOT_TESTED.
        No other endpoint was substituted to manufacture a PASS, per your instruction.
        What IS proven is the adapter against a REAL 275,902-observation Windows sensor corpus.
SMALLEST SAFE NEXT ACTION: owner supplies a read-only production path, or accepts A–T validation
        after (and only after) KUSHU delivery resumes into an environment this pod may read.
OWNER_DECISION_REQUIRED = YES
```

### BLOCKER 3 — FIXED · EDR route was served by an XDR component and redirected into XDR
```
WAS   : src/App.jsx:75 imported EdrTrajectoryResolver from @/xdr/pages/ and bound it to
        src/App.jsx:367 <Route path="/edr/trajectory">. That component rendered XdrShell and then
        redirected to the XDR route /xdr/endpoints/:device/trajectory. SEVEN EDR surfaces link to
        /edr/trajectory, so every one of them carried the analyst out of NivXForge EDR and into
        NivXRay XDR. This is the mechanism behind XDR chrome on an EDR investigation path.
NOW   : resolver moved to @/nivxforge/pages/EdrTrajectoryResolver.jsx; renders NivXForgeConsole
        (activeTab="device-trajectory"); redirects to /edr/device-trajectory?device=<ref>;
        unresolved-state links now go to /edr/computers and /edr/detections.
        The explicit "Investigate in NivXRay XDR" pivot is untouched and remains legitimate.
GATE  : Gate 16 widened from 5 to 7 tests. test_no_edr_route_is_served_by_an_xdr_component starts
        from the ROUTE TABLE (the sibling test only scanned files already under the EDR directory,
        so a component sitting in the XDR layer was invisible to it whatever route it served).
        Proven to catch the regression: restoring the old import makes it FAIL with
        "/edr/trajectory -> EdrTrajectoryResolver from @/xdr/pages/EdrTrajectoryResolver".
VERIFIED LIVE (EDR path only, no XDR pivot used): /edr/trajectory?device=... stays on /edr/*,
        renders NivXForge EDR chrome and the EDR sidebar, breadcrumb "NivXForge EDR > Device
        Trajectory (legacy)", and no "PLANE XDR investigation". The CAPABILITY UNAVAILABLE /
        TENANT_REQUIRED panel shown is CORRECT fail-closed behaviour: the PLATFORM principal had
        no customer selected, so tenant authority refuses instead of defaulting. Auth and tenant
        checks were NOT weakened and routing was NOT changed to make automation pass.
STATUS = RESOLVED (Class B, reversible). `yarn build` clean. 2131 passed / 12 skipped / 0 failed.
```

### RESIDUAL (recorded, not fixed)
```
- 11 EDR pages import `apiErrorText` from `@/xdr/nx/apiError`. Gate 16 classifies `@/xdr/nx` as
  SHARED_*_SAFE, so this is sanctioned shared-library use rather than a product dependency. Moving
  it to a neutral shared layer would be cleaner but touches 11+ files; out of this slice's scope.
- `apps/nivxray-xdr/.git` is a NESTED git repository inside the outer repo, while the same files
  are also tracked by the outer repo. `git mv` run from inside it silently fails. Pre-existing
  repository hygiene debt, flagged for the owner, deliberately not altered.
```

## I. VALIDATION PATH CONSTRAINT (recorded, binding)

EDR validation must stay inside EDR:
`NivXForge EDR → EDR auth/authorized customer → Computers/Endpoint → Device Trajectory →
/edr/device-trajectory → EDR trajectory API → real endpoint evidence`.

MUST NOT be used as proof of EDR: the "Investigate in NivXRay XDR" pivot, XDR workspace routes, XDR
Device Trajectory, or the standalone E3 preview shell (`/e3shell-*/index.html`, customer "Synthetic
Preview Customer", host `SYN-LT-0427`, footer "Synthetic data · Debug"), which is FIXTURE DATA.
Routing and auth/tenant checks must never be weakened to make automation pass.

## J. SECURITY GATES
```
AUTH                              = PASS (unchanged; route still Depends(get_current_user)+edr_tenant)
TENANT_ISOLATION                  = PASS (adapter fails closed with no tenant; cross-tenant refs -> 0 rows)
DURABLE_ACK                       = PASS (untouched)
GATE16                            = PASS (7/7) — widened; EDR-route/XDR-component gap closed
RESPONSE_AUTHORITY                = PASS (untouched; adapter is read-only)
PRODUCTION_MOCK_DATA_REACHABLE    = NO (`mock_data_reachable: false`; no fixture path in the adapter)
CROSS_TENANT_EVIDENCE_LEAK        = NO
INGEST_TIME_USED_AS_OBSERVATION_TIME = NO
SYNTHETIC_DATA_USED_AS_REAL_PROOF = NO
CANONICAL_EVIDENCE_SILENTLY_REWRITTEN = NO
CANONICAL AUTHORITY DECIDED       = NO (both stores read; duplicates collapsed on stable identity)
```

## K. ROLLBACK
```
ROLLBACK_SHA            = 1da71197
ROLLBACK_METHOD         = git checkout backend/routers/edr.py backend/tests/edr_trajectory/ &&
                          rm backend/edr_trajectory/production_{adapter,service}.py
                          (the `e3` key is additive and inside try/except; V1 and dt2 are untouched)
DATA_ROLLBACK_REQUIRED  = NO
INDEX_ROLLBACK          = python /app/scripts/sd_preview_index_experiment.py drop  (preview only)
CONFIG_ROLLBACK         = NONE (no .env, deps, CI, sensor or supervisor change)
```

## L. VERDICT

**NOT_PRODUCTION_READY** — on Blockers 1 and 2 above. Blocker 3 is RESOLVED.

The §d production evidence path itself is complete and proven on real evidence: authoritative
observation time, newest-first, deterministic duplicate-free and loss-free cursor paging, exact
deep links, tenant fail-closed, truthful UNKNOWN/NOT_COLLECTED, and no reachable mock data.
What is not yet proven is that an analyst SEES it (Blocker 1) and that it holds on real KUSHU
evidence (Blocker 2).
