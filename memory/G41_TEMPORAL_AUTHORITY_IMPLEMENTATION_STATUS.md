# G41_TEMPORAL_AUTHORITY_IMPLEMENTATION_STATUS

**Implemented and tested locally. Nothing applied to production, nothing pushed, nothing deployed.**
No KUSHU, no DESKTOP-A9HGFJJ, no sensors, no TI, no STEP 35 identity data, no historical identity
provenance, no response plane, no unrelated UI. No production data mutation.

---

## 1. FILES CHANGED

| File | Change |
|---|---|
| `backend/edr_plane/temporal_authority.py` | **NEW** · the one derivation of `observation_us`, the writer stamp and the writer invariant |
| `backend/edr_plane/observation_us_migration.py` | **NEW** · bounded historical backfill + read-only verify, registered, `apply` structurally impossible until an expectation is declared |
| `backend/edr_trajectory/production_adapter.py` | selection/ordering/LIMIT/cursor moved onto `observation_us` + `_id`; one parser (delegates to `temporal_authority`); transitional legacy read; `pending_temporal_migration` counter |
| `backend/detection_content/xdr_pipeline.py` | `stamp()` + `assert_stamped()` immediately before the single canonical `insert_one` |
| `backend/edr_plane/canonical_index_contract.py` | `TARGET_TEMPORAL_INDEXES` declared (declaration only — **no index created anywhere**) |
| `backend/edr_plane/migration_control.py` | two operations merged into the existing closed registry |
| `backend/tests/edr/test_g41_temporal_authority.py` | **NEW** · 37 tests incl. the production-inversion regression |
| `backend/tests/edr/test_g41_transitional_read.py` | **NEW** · 6 tests proving unmigrated evidence is not lost |
| `backend/tests/edr_trajectory/test_sd_production_adapter.py` | test double's `sort()` now models the driver's list form and numeric keys |
| `backend/tests/edr/test_34h_a_migration_control.py` | registry assertion derived from the registry instead of enumerated |

No route added. No `.env` change. No dependency change. No frontend change.

## 2. WRITER IMPLEMENTATION

`observation_us` — **signed int, UTC epoch microseconds**, derived at the single canonical writer
boundary (`xdr_pipeline`, immediately before the only `insert_one`), then asserted.

* **Same instant → same value**, from any representation. Proven for space-vs-`Z`, `Z`-vs-`+00:00`,
  `+02:00`-vs-UTC and `-05:00`-vs-UTC.
* **`event_time` is never rewritten.** Only `observation_us` and two declarations
  (`additional_fields.observation_us_state` / `observation_us_basis`) are added.
* **`ingest_time` is never a source.** Backlog replay is real here; an absent source time stays
  absent.
* **Fail closed.** An unreadable value leaves the field ABSENT with state
  `UNPLACEABLE_UNPARSEABLE_OBSERVATION_TIME`. Nothing is manufactured. Ingestion still succeeds —
  evidence durability must never depend on this derivation.
* **One parser.** `production_adapter.observation_us` now delegates to
  `temporal_authority.to_epoch_us`; a test reads the source and fails if a second
  `fromisoformat` appears there.
* **Invariant.** `assert_stamped()` raises if a document reaches the writer unstamped, or if the
  declared state and the stored value disagree. A test asserts stamp → assert → insert in that
  order.

## 3. QUERY / PAGINATION IMPLEMENTATION

`TEMPORAL_SELECT_KEY[canonical] = "observation_us"` while `OBSERVATION_TIME_KEY` keeps `event_time`
as the evidence value. Raw timestamp strings no longer drive range selection, newest/oldest
ordering, the LIMIT, or the resume cursor for the canonical store.

* Range, sort and LIMIT run on the integer key with `_id` as a second sort key.
* The resume bound is the cursor's exact microsecond, **store-independent** and **inclusive**
  (`$lte`); exact exclusion is then applied in memory on `(observation_us, event_id)`. An inclusive
  integer bound cannot drop a chronologically eligible row — which was the entire defect.
* The shadow store is declared non-comparable (`COMPARABLE_TEMPORAL`) and keeps its existing
  behaviour. It has no derived value yet; this is stated as a declared residual, not assumed away.
* **Behavior consumes the identical path.** `SdEvidenceProvider` already calls
  `page_device_evidence`; a test asserts it contains no timestamp parsing of its own.

### 3.1 A design gap the first implementation exposed — and how it is handled
Making selection depend on `observation_us` made **140 existing tests fail**, because every
historical fixture — and all 122,369 production rows — predate the field. Shipping that would have
made every historical row **vanish** from Device Trajectory and from Behavior's window: far worse
than the ordering defect being fixed.

So `_branch_page` now issues a **bounded transitional second read**, scoped strictly to rows with no
comparable value, selected by the legacy string path, and merged by the same microsecond order as
everything else. It carries the old limit-under-a-string-sort weakness **only for unmigrated rows**,
and the page response exposes `pending_temporal_migration` so the remaining exposure is counted
rather than silent. It returns nothing — and can be deleted — once the backfill completes.

## 4. CURSOR DESIGN

The total order is `(observation_us, event_id)`; the database order is
`(observation_us desc, _id desc)`.

Thousands of endpoint events legitimately share one microsecond, so time alone is not a total order
— fixing string ordering without a tiebreaker would have introduced a fresh skip/duplicate bug at
equal timestamps. `_id` makes the database sort and therefore the LIMIT deterministic; `event_id`
remains the in-memory tiebreaker because two stores can record the same activity at the same
microsecond. `TIE_MARGIN = 64` gives headroom so a tie group cannot straddle a page, and
`TIE_GROUP_EXCEEDS_PAGE_SIZE` still reports the case where it would.

## 5. PROPOSED INDEX — declared, **not created**

```
sd_canonical_endpointid_observationus
  (tenant_id 1, additional_fields.endpoint_id 1, observation_us -1, _id -1)
sd_canonical_hostname_observationus
  (tenant_id 1, host.hostname 1, observation_us -1, _id -1)
```

Equality prefix → identity → descending comparable time → deterministic tiebreak, matching the
query the adapter actually issues; a test asserts the key list and directions against the contract.
`[PROD]` **no index on `observation_us` exists today** (4 indexes present). Creating these is a
separate owner-authorized action, and the no-COLLSCAN / no-blocking-SORT proof must be taken by the
authenticated `explain_canonical_identity_read_plan` **after** the field exists — before then the
plan would prove nothing.

## 6. REGRESSION RESULTS

| Suite | Result |
|---|---|
| `test_g41_temporal_authority.py` | **37 passed** |
| `test_g41_transitional_read.py` | **6 passed** |
| `tests/edr_trajectory` (full) | **401 passed, 9 skipped** |
| `tests/edr` + `tests/edr_investigation` + `tests/edr_trajectory` | **2,724 passed, 12 skipped, 16 failed** |

The 16 are **pre-existing xdist-isolation failures, not regressions**: `test_34h_a_migration_control.py`
passes **19/19 in isolation**, and `test_p0_f13_5_detection_handoff.py` fails **4/7 on a stashed
(unmodified) tree** with `RuntimeError: deps.db accessed before init_database()`. Measured baseline
on the same combined run earlier in this session was 18 failures; it is now 16.

Coverage against the required matrix: space-vs-`Z` representations · timezone-equivalent instants ·
fractional precision to the microsecond · ordering across second/minute/hour/day boundaries · equal
timestamps paginating deterministically and repeatably · forward page boundaries at sizes
1/2/3/5/7/20/24 · no duplicate across pages · no missing event across pages · resume cursor cannot
skip eligible evidence · LIMIT returns the actual newest N · tenant isolation · endpoint isolation ·
malformed timestamp fails closed · Device Trajectory chronological selection · Behavior window
selection · writer invariant · single-parser guard.

**The production-inversion fixture** uses the literal confirmed values
`"2026-09-27 23:55:38.144"` and `"2026-09-27T00:06:30.7557375Z"`. One test asserts that the string
comparison still says the wrong thing (`PROD_LATE_SPACE < PROD_EARLY_Z`), so the fixture cannot
silently stop reproducing the bug; the others prove correct order, that `limit=1` returns 23:55, and
that a cursor landing on the space-format row no longer excludes the same-date `Z` rows from any
later page.

## 7. PRODUCTION HISTORICAL CENSUS `[read-only, snapshot]`

| | |
|---|---|
| total | **122,369** |
| migration candidates (`observation_us` absent ∧ `event_time` string non-empty) | **122,369 — the entire corpus** |
| `observation_us` already present | **0** |
| no source value (`event_time` absent / empty / non-string) | **0 / 0 / 0** |
| candidate format classes | space 43,521 · `Z` 78,849 · offset 0 |
| unaccounted representation | **none** — no shortfall |
| index on `observation_us` | **none** |
| `e3_migration_runs` for the two new operations · `e3_migration_row_ledger` | 0 · 0 · absent |

The deployer flagged a **+1 excess** in the format sum (122,370 vs 122,369) and correctly refused to
reconcile it. Dual-match is 0, so it is live-ingestion skew across non-atomic counts, not an overlap.
That it is **excess rather than shortfall** is the safe direction: every candidate maps to a known
parseable class.

## 8. MIGRATION READINESS — and why it is NOT ready

`EXPECTED_CANDIDATES` is **deliberately `None`**, so `apply` cannot run: an undeclared expectation
is not an expectation, and a test pins it.

**The STEP 35 exact-ceiling discipline cannot be applied yet, and this is the important finding.**
There, the population was closed: STEP 34F/34G meant no new row could join it. Here the population
is **open and growing** — the writer is not deployed, so every row ingested from now until it is
deployed becomes another candidate. A census taken today is stale by the next write.

Correct sequence, and the reason `SAFE_TO_MIGRATE_HISTORY = NO` today:
1. deploy the writer → new evidence is stamped at ingest, so the candidate set **closes**;
2. re-census → the number is now monotonically non-increasing;
3. declare `EXPECTED_CANDIDATES` in a reviewed commit, with an explicit drift decision;
4. owner takes a point-in-time recovery position;
5. production `report` → review gate board;
6. owner-run `apply`, then `verify_canonical_observation_us` (read-only: recomputes
   `observation_us` from the stored `event_time` for every ledgered row and re-checks the collateral
   digest);
7. create the two indexes, then take the `explain` proof;
8. the transitional legacy read reports `pending_temporal_migration = 0` and can be deleted.

Eligibility is already exactly as required: valid existing `event_time`, successful deterministic
parse, no conflicting `observation_us`; `event_time` never rewritten; guarded `update_one`;
prior-state ledger; audited; and it fails closed on an undeclared or drifting population.

## 9. DEVICE TRAJECTORY VALIDATION

Order and page membership proven correct against the production inversion and across the full
mixed-representation corpus at six page sizes, with no duplicate and no missing event. The window
still applies exactly, on microseconds, to both migrated and unmigrated rows. A row with no
readable time is **reported** as unplaceable, never placed and never dropped silently.

## 10. BEHAVIOR-PROVIDER VALIDATION

`SdEvidenceProvider.window()` returns both sides of the inversion through the corrected path, and a
guard test asserts Behavior holds no timestamp parsing of its own. No separate Behavior time
implementation exists.

## 11. PARALLEL RELEASE READINESS `[read-only — nothing pushed or deployed]`

* **Repo/branch/HEAD:** branch `integration/e3-dt`, HEAD `14884069` (2026-10-03).
* **Frontend:** `apps/nivxray-xdr` (Vite + Vercel). `vercel.json` already routes host
  `edr.nivxforge.com` → `/edr` (and `xdr.nivxforge.com` → `/xdr`), SPA rewrite in place,
  `outputDirectory: dist`, build via `scripts/vercel-build.sh`.
* **E3 Device Trajectory integration:** `src/nivxforge/trajectory_amp/DeviceTrajectoryEntry.jsx`
  switches on `E3_DT_V3` → lazy `trajectory_v3/DeviceTrajectoryPage`; otherwise the legacy
  `EdrDeviceTrajectoryPage`.
* **Feature/config state:** `E3_DT_V3` is a **build-time** flag (`VITE_E3_DT_V3 === "1"`) and is
  **NOT set** in `apps/nivxray-xdr/.env` (which carries only `REACT_APP_NIVXRAY_API_URL`).
  **Publishing today therefore ships the LEGACY Device Trajectory, not V3.** Enabling V3 requires
  setting `VITE_E3_DT_V3=1` in the Vercel build environment.
* **Isolation from this migration:** **YES.** The temporal fix is backend-only; the frontend
  consumes `page_device_evidence` through the API and has no knowledge of `observation_us`.
  Publishing cannot be made worse by the migration, and the migration cannot be made worse by
  publishing.
* `dist/` is a stale local build (Oct 2 21:32) and is not the artifact Vercel would ship.

## 12. GATES

**TEMPORAL_AUTHORITY_GATE = PASS**
Writer derivation, writer invariant, single parser, comparable selection, deterministic
`(observation_us, _id)` cursor, index contract, Device Trajectory and Behavior validation, and the
production-inversion regression are all implemented and green, with no regression attributable to
the change.

**SAFE_TO_MIGRATE_HISTORY = NO — sequencing, not safety.**
The migration code is ready and fails closed, but the candidate population is still **open**: all
122,369 rows are candidates and more join with every write until the writer is deployed. Deploy the
writer first, then re-census, then declare the expectation in a reviewed commit. Migrating against
an open population is how a bounded migration stops being bounded.

**SAFE_TO_PUBLISH_EDR_UI = YES, with one disclosure.**
Publication is isolated from the temporal work and the routing is already in place. But with
`VITE_E3_DT_V3` unset the published site shows the **legacy** Device Trajectory. If the intent is to
publish *with* E3 V3, the flag must be set at build time — and my recommendation is to do that
**after** the backfill, so V3 is not the first thing an analyst uses while
`pending_temporal_migration` is still 122,369.

**STOPPED** before historical APPLY, GitHub push and production deployment.
