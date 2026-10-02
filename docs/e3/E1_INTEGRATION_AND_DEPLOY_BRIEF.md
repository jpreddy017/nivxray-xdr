# E1 Integration & Deploy Brief — E3 (feature/e3-edr-engines → feature/rc2-alignment)

Paste this into the E1 workspace as-is. Author: E3 agent. The E3 agent has no access to production, the live Mongo, KUSHU or the E1 environment. Every file, line and test count below comes from the E3 clone.

## 0. Hard rules for E1
- **E3 never deployed anything.** This brief asks E1 to integrate, test in E1's real environment, and roll out behind flags.
- **Protected areas stay untouched unless E1 explicitly owns the change:**
  - durable ACK / `edr_plane/processing_queue.py`
  - Gate-4 (`tests/edr/test_processing_queue_worker.py`, `test_p0_reconcile_contract_ownership.py`)
  - canonical authority
  - sensor ACK semantics (`SENT ≠ ACCEPTED`)
- **Truth rules apply to every surface:**
  - UNKNOWN is never shown as benign.
  - A detection is not a malicious verdict.
  - No inferred edges.
  - UTC instants only; place events by `observed_at`, never `ingested_at`.

## 1. Source, target, merge
| | |
|---|---|
| Source | GitHub `feature/e3-edr-engines` @ **`eab566a9a5f32f29c1260d5880dfddf12e56122e`**. The owner pushes it from the bundle as a fast-forward from `6185974b`. |
| Base | `1800aeea8af699786b93961621cf1fca97382b95` (`feature/rc2-alignment` when E3 forked) |
| Target | `feature/rc2-alignment` |
| Commits | 26 (`git log --oneline 1800aeea..eab566a9`) |
| Strategy | Branch `integrate/e3-into-rc2` from the **current** `origin/feature/rc2-alignment`. Run `git merge --no-ff origin/feature/e3-edr-engines`, so E3 history stays intact and the merge can be reverted with `git revert -m 1`. No squash, no force-push. |

**E1 must check its own changes since `1800aeea` first.** E3 cannot see them:
```bash
git fetch origin
git log --oneline 1800aeea..origin/feature/rc2-alignment
git diff --name-only 1800aeea origin/feature/rc2-alignment > /tmp/e1.txt
git diff --name-only 1800aeea origin/feature/e3-edr-engines > /tmp/e3.txt
comm -12 <(sort /tmp/e1.txt) <(sort /tmp/e3.txt)      # = files BOTH sides changed → expected conflicts
```

E3 **modified** (M) only these existing files, so conflicts can only appear here:
- `apps/nivxray-xdr/src/nivxforge/trajectory/AmpNavigator.jsx`
- `apps/nivxray-xdr/src/nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx`
- `apps/nivxray-xdr/src/nivxforge/trajectory/RelationshipCanvas.jsx`
- `apps/nivxray-xdr/src/nivxforge/trajectory/dt2/__tests__/dt2_3c_rev2_parity.test.js`
- `frontend/src/v2/pages/DeviceTrajectoryV2.jsx`
- `frontend/src/v2/canvas_engine/InvestigationCanvas.jsx`. **It is shared with IRG.** The DT-I1 Step 1 change (`57218ac3`) alters IRG's date strip. **Owner decision is pending:** keep it, or revert that hunk for IRG only.

Everything else is **added** (A). Check with `git diff --name-status 1800aeea origin/feature/e3-edr-engines | grep -v '^A'`; it should list only the six files above.

## 2. Package inventory (all additive)
| Package | Purpose | Runtime prereqs | Flag (default OFF) | Storage / indexes (as migrations) | Tests | Rollback |
|---|---|---|---|---|---|---|
| `backend/edr_behavior/` | Deterministic behavioral + sequence engine: contracts, predicates, matcher, suppression, store, replay, starter rule pack | Python ≥3.11, motor (already in E1). No new pip deps. | **`E3_BEHAVIOR_ENABLED`** (new; read once at startup, then passed as `BehaviorIntegration(enabled=…)`). Off means `on_canonical` returns `{"evaluated": False, "reason": "DISABLED"}`. | `e3_behavior_detections`. `store.INDEXES` (unique `tenant_id, detection_id, revision` + query indexes). `ensure_indexes()` is "for E3 test/staging only", so **E1 must write a migration** in its migration runner that applies `INDEXES`. | `backend/tests/edr_behavior` (58) | Flag off. The collection is inert. Drop it only with owner approval. |
| `backend/edr_ml/` | Explainable ML foundation: features, baselines, models, signals; `safe.py` guards | stdlib + numpy only if already present (see imports). No network. | **`E3_ML_ENABLED`** (new) | None persisted by E3 (pure). E1 decides persistence later. | `backend/tests/edr_ml` | Flag off |
| `backend/edr_investigation/` | DT view-model builders: `builder.py` (15-section Activity view), `causal.py` (PROVEN/SUPPORTED/CORRELATED/UNKNOWN), `ti.py` + `ti_contracts.py` (`dt-i1e.ti.v1` normalization; `adapt_ioc_intelligence`) | None (pure; no providers, no network) | **`E3_DT_VIEWMODELS_ENABLED`** (new) | None | `backend/tests/edr_investigation` (incl. `test_dt_ti_contracts.py`) | Flag off. The API omits the fields. |
| `frontend/src/v2/investigation/*.mjs/.jsx` | `activityView`, `causalView`, `navigatorDates`, `timeWindow` + `ActivityDetailsSections.jsx`, `CausalContextPanel.jsx` | none | `frontend/src/v2/flags.js` registry (3-state, default **disabled**). Add a `DT_I1_VIEWS` entry. | none | `node --test frontend/src/v2/investigation/*.node-test.mjs` (32) + component test (8) | Flag off, or revert the merge |
| DT time model `apps/.../trajectory/dt2/timeWindow.mjs` (+ vendored copy in `frontend/src/v2/investigation/`) | Rolling/calendar/evidence/linked/analyst windows; RC8 disclosure | none | **None.** This is a bug fix on the served page and should ship unflagged. If E1 wants a kill switch, use `VITE_DT_LEGACY_WINDOW=1`, but E3 recommends against it. | none | `node --test …/dt2/__tests__/timeWindow.node-test.mjs` (18) + dt2 suites (159) | Revert `eab566a9` |
| `docs/e3/*` | Designs, handoffs, `DT_HOTFIX_TIME_WINDOW.md` | — | — | — | — | — |

## 3. Wiring that needs E1-owned changes (none applied by E3)
1. **Behavior engine hook.**
   - Where: `backend/edr_plane/canonical_bridge.py::bridge` (def at :499). Call it **after** the `CANONICAL_EVIDENCE_CREATED` derivation is appended (`add_derivation(...)` at :521-545).
   - What:
     ```python
     if BEHAVIOR.enabled:
         await BEHAVIOR.on_canonical(canonical_dict, BridgeContext(tenant_id, endpoint_id, raw_id,
               canonical_event_id=..., generation=..., store="v2_shadow_observations", record_id=...))
     ```
   - `BEHAVIOR` is built once at startup (`server.py` lifespan) from `SequenceEngine(load starter pack)` plus the `edr_behavior.store` sink.
   - The adapter **never raises** into the bridge. Keep it outside the durable-queue transaction, so a behavior fault can't fail the derivation or the queue job.
   - Behaviour must be identical with the flag off (golden test: same derivations and queue states).
2. **TI broker over `ioc_intelligence`.**
   - A new E1 service, `services/ti_broker.py`, reads cached `ioc_intelligence` cards. No new provider calls are in scope.
   - It normalizes through `edr_investigation.ti.normalize_ioc_card` and `ti_contracts.adapt_ioc_intelligence`.
   - Rules: provider errors become `UNKNOWN/ERROR`, never benign. Respect provider TTL and stamp `fetched_at`.
3. **Trajectory API serving the view models.**
   - Where: `backend/routers/edr.py:996` `GET /edr/endpoints/{id}/trajectory`, right after `dt2.augment` / `build_graph` (:1068-1076).
   - When `E3_DT_VIEWMODELS_ENABLED`, add `out["dt2"]["views"] = {"activity": builder.build(...), "causal": causal.build(...), "ti": ti_broker.lookup(observables)}`. These are additive keys only.
   - The client ignores missing keys, and the response size budget must hold. Compute per returned page, never per endpoint history.
4. **Freshness contract REPORTING → STALE → OFFLINE (from `KUSHU_TELEMETRY_GAP_DIAGNOSIS.md` §2-A).**
   - Where: Enrolment read path, plus `EdrEnrollmentBody.jsx:293`.
   - Compute at **read time** from `last_telemetry_at`, `last_heartbeat_at`, `report_interval_seconds` and the latest post-trust rejection, using `services/edr/endpoint_health.py` thresholds:
     - stale = `max(3×interval, 60 s)`
     - offline = `max(20×interval, 900 s)`
   - States: REPORTING / ALIVE_NO_RECENT_TELEMETRY / STALE / OFFLINE / NEVER_REPORTED. Return `age_s`, `threshold_s` and `basis`.
   - Stop treating stored `sensor_state=REPORTING` (`store.mark_reported`, store.py:550) as truth (defect **D-ENR-1**).
5. **Counter labels (D-ENR-2).** `edr_endpoints.event_count` is `$inc` **per accepted delivery/batch** (store.py:560). Relabel it "Accepted deliveries" and show the real raw-event count separately (from `edr_raw_events`). Also fix **D-EVT-1** (`EdrEventsPage` ignores `?device=`). That's E1's decision; it's outside DT scope.
6. **Branding copy defect:** "WRONG PRODUCT HOST — This deployment serves **NivXRay EDR**" should read **NivXForge EDR**. Recorded only.

## 4. Port DT-I1 onto the DEFAULT page (no duplicate implementation)
The served `/edr/device-trajectory` is `apps/nivxray-xdr/src/nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx` (+ `dt2/`). DT-I1 A–D landed in `frontend/src/v2/pages/DeviceTrajectoryV2.jsx` (case-scoped, separate `frontend/` app, not built for edr.nivxforge.com).
1. Create **one** shared package (e.g. `packages/dt-views/`, or an alias `@nivx/dt-views`) that holds `activityView.mjs`, `causalView.mjs`, `navigatorDates.mjs`, `timeWindow.mjs`, the verdict helpers, and the two JSX panels. Both apps import it. Delete the vendored copy and its byte-parity test once imports resolve in both builds.
2. Add an adapter `dt2/viewAdapter.js` that maps the default page's rows (`/edr/endpoints/{id}/trajectory` `events[]` + `dt2.graph` nodes/edges) onto the frame shape the view-models expect. Keep it pure and unit-tested.
3. Render `ActivityDetailsSections` / `CausalContextPanel` from `AmpEventDetails` / `AmpActivityPanel` behind `DT_I1_VIEWS`. The dates come from `timeWindow` (already on the default page).
4. Run the DT-I1 suites against **both** adapters. Then retire the case-scoped duplicates, or keep V2 as a thin consumer.

## 5. RC8 server fix (oldest-first page cap)
- **Defect:**
  - `backend/edr_plane/trajectory_window.py:1463` does `page = in_lane[:limit]` on ascending rows, so it returns the **oldest** `limit` rows.
  - `routers/edr.py:1073-1076` builds `dt2.graph` from that page.
  - On dense windows the **newest** evidence is not drawn.
  - The client now discloses this and auto-narrows the rolling view, but the server should fix it.
- **Option A (preferred):** a new query param `order=newest|oldest` (default `oldest`, so existing consumers are unchanged).
  - `newest` takes the last `limit` rows of `in_lane`, returns them **ascending**, and sets `next_cursor` for paging backwards (`before=` cursor).
  - The DT client passes `order=newest`.
  - Tests: dense window > limit returns the newest `limit`; cursors don't overlap; `has_more`/`matched_in_window` are exact; graph nodes come only from returned rows.
- **Option B:** build `dt2.graph` from `in_time` (the full window) with a node cap, and keep events paged. Tests: graph contains the newest process lifelines even when events are capped; response-size ceiling.
- **Also:** `trajectory_window.py:605` `sort("event.ts", -1)` sorts **strings**. On mixed `"YYYY-MM-DD hh:mm"` / ISO stores, "most recent" is mis-ordered. Sort on a parsed-instant field, or document it.
- Put the tests in `backend/tests/edr/test_trajectory_window_order.py`.

## 6. Staged rollout
1. **Preview** (E1 staging): merge, run §7, flags all OFF → confirm byte-identical API responses for existing consumers. Turn the flags ON in staging only and run the E3 suites plus a manual DT check.
2. **KUSHU canary:** in production, set the flags ON **only for tenant `ten_e759b7288598bd882e3dcac49d`** (tenant-scoped flag check in each hook). Check after 24 h:
   - no change in ingest latency, `edr_processing_queue` RETRY/DONE rates, or Gate-4 metrics;
   - `e3_behavior_detections` rows each carry evidence refs;
   - DT default page shows current-day evidence;
   - the freshness state matches the KUSHU readings.
3. **Verify:** the owner signs off on the canary evidence.
4. **Wider:** enable tenant by tenant. The kill switch is the flag; full rollback is `git revert -m 1 <merge>`.
- ACK, queue and Gate-4 code stay **unchanged** throughout. Any change there is a separate E1-owned PR with its own Gate-4 run.

## 7. Acceptance tests E1 must run before deploy (in E1's real environment)
```bash
cd backend && pip install -r requirements.txt            # includes pytest-asyncio==1.4.0 (missing it made Gate-4 show 22 false failures in E3)
python -m pytest tests/edr -q -m 'slow or not slow'      # FULL edr suite incl. Gate-4 (34 in E3: test_processing_queue_worker + test_p0_reconcile_contract_ownership)
python -m pytest tests/edr_behavior tests/edr_ml tests/edr_investigation -q   # E3: 136 passed
cd .. && for f in frontend/src/v2/investigation/*.node-test.mjs; do node --test "$f"; done   # 32
node --test apps/nivxray-xdr/src/nivxforge/trajectory/dt2/__tests__/timeWindow.node-test.mjs # 18
(cd apps/nivxray-xdr && yarn vitest run src/nivxforge/trajectory)                           # dt2 suites: 179 under real vitest 2.1.9 in E3
python -m pytest tests/edr_trajectory -q                                                   # E3 Phase 1 contracts: 31
(cd apps/nivxray-xdr && yarn build) && (cd frontend && yarn build)                          # both apps compile
```
Gate: everything green, plus the flags-OFF byte-identical response check (§6.1), plus the RC8 tests once §5 lands.

## 8. Decisions after eab566a9 (owner, 2026-10-02) — binding for E1
1. **DT frontend tests before prod.**
   - Run the dt2 suites under **real vitest**: `cd apps/nivxray-xdr && yarn vitest run src/nivxforge/trajectory`.
   - E3 ran them with vitest 2.1.9, installed outside the repo in `/tmp/vt` with an alias config: **179/179 passed** (9 files).
   - The earlier "159" count came from a node:test shim that **did not run `test.each`/`it.each`** parametrised cases (20 tests). Treat 179 as the baseline.
   - Also run the node-test suites (32 view-model + 18 time model) and the 8 component tests.
2. **RC8: newest-first paginated retrieval that preserves all history.**
   - The reference contract is `backend/edr_trajectory/paging.py` (`e3.dt.paging.newest_first.v1`).
   - Total order `(observed_ms DESC, event_id DESC)`.
   - Opaque cursor carrying `as_of` (an ingest-time session freeze), so pages have no loss or duplication.
   - Page size bounded at 500.
   - Older pages are reachable down to the start of retention.
   - E1 implements it in `trajectory_window.py` (§5) or serves `edr_trajectory` over the authoritative store.
3. **IRG isolation.**
   - A raw backend verdict must never render as "ASSESSED MALICIOUS" on IRG or anywhere else.
   - The shared `InvestigationCanvas.jsx` hunk from `57218ac3` needs an owner decision before merge.
4. **TI authority trace before any live VirusTotal / AbuseIPDB / OTX switch-on.**
   - E1 documents which collection is authoritative for reputation (`ioc_intelligence`), its TTL, and its failure states.
   - Then it maps them onto `edr_trajectory.ti` states: PROVIDER_ERROR / RATE_LIMITED / OUTAGE / NO_HIT / UNKNOWN / CLEAN-with-evidence / MALICIOUS-with-evidence.
   - Provider keys live only in E1's secret store. E3 never holds keys and makes no network calls (netguard enforced).
5. **Freshness fix** `REPORTING → ALIVE_NO_RECENT_TELEMETRY → STALE → OFFLINE` (§3.4), computed at read time with basis and age. Stored `sensor_state` is not truth.
6. **KUSHU backlog drain** (`KUSHU_REALTIME_CATCHUP_PLAN.md`): first the read-only checks K1–K11. Then:
   - concurrent upload (sensor);
   - **server write batching** (`insert_many ordered=False` + bulk enqueue). This is a protected path, E1-owned, and needs a Gate-4 run.
   - No evidence is dropped or reordered.
7. **Canonical store authority** (`v2_shadow_observations` vs `xdr_canonical_evidence`) is **E1's decision**, backed by read-only production evidence. E3's `EvidenceProvider` reads both and selects neither (`authority: NOT_SELECTED`).
   - E1's read-only proof: for one KUSHU day, count both stores by `activity_identity`, then compare overlap, store-only rows, and field completeness.
8. **Response actions are approval-only from E3.**
   - `edr_trajectory.actions.ApprovalStore` creates `APPROVAL_REQUESTED` records (tenant-scoped, idempotent, audited) and executes nothing.
   - E1 wires approved requests through its **hardened response boundary**, which owns ACCEPTED → EXECUTED → CONTAINED → VERIFIED. These states are never inferred from each other.
   - Read-only pivots (copy hash, search hash/name, open File Trajectory) need no approval record.
9. **New E3 package `backend/edr_trajectory/` (Phase 1).**
   - Contracts `e3.dt.*.v1`.
   - Router `edr_trajectory.api.build_router()` at `/api/e3/trajectory/*`. It isn't mounted by E1's server.
   - Mounting is flag-gated by `E3_TRAJECTORY_ROUTER=1` (see §9.4). It is **OFF unless the flag is set**, and no E1/prod config sets it. **E1 decides whether to strip or keep it.**
   - Fixtures are SYNTHETIC, plus one `kushu_shape` labelled **SHAPE-FAITHFUL / NOT PRODUCTION DATA**.
   - The `/seed` endpoint writes only to the E3-namespaced collections `e3_dt_seed_shadow_observations` and `e3_dt_seed_canonical_evidence`. **Never enable `/seed` in production.**
   - Tests: `backend/tests/edr_trajectory` (31, including mount-off-by-default).
   - Gap audit: `docs/e3/DT_AMP_PARITY_GAP_AUDIT.md` (telemetry items S-1..S-7 are sensor work and are not faked).

## 9. New items from E3 Phase 1 (2026-10-02). E1-owned; none of these is applied by E3
1. **Production trajectory ordering defects.** These are in `backend/edr_plane/trajectory_window.py`; see §5.
   - `:1463` `page = in_lane[:limit]` on ascending rows returns the **oldest** `limit` rows, and `dt2.graph` is built from that page.
   - `:605` `sort("event.ts", -1)` sorts **strings**. On mixed `"YYYY-MM-DD hh:mm"` / ISO stores, "most recent" is mis-ordered.
   - Fix by sorting on a parsed-instant field (`observed_ms`) with the total order `(observed_ms DESC, event_id DESC)` from `edr_trajectory.paging` (§8.2).
   - Tests go in `backend/tests/edr/test_trajectory_window_order.py`.
2. **Persist the status log and approvals.**
   - `edr_trajectory.actions.StatusLog` (append-only retrospective status) and `ApprovalStore` (APPROVAL_REQUESTED) are **in-memory** in E3.
   - E1 provides tenant-scoped durable collections. Requirements:
     - Insert-only, with no update/delete path; `AppendOnlyViolation` semantics must hold.
     - A unique index on `(tenant_id, idempotency_key)` for approvals.
     - An audit trail.
     - Approved requests route through the hardened response boundary (§8.8).
   - The retro-scan producer that emits status events is also E1's.
3. **Per-endpoint gap/heartbeat feed.**
   - `edr_trajectory.timeline.coverage` needs `heartbeats_ms[]` and `declared_gaps[{from_ms,to_ms,kind,basis}]` per endpoint and window.
   - E1 exposes them from the sensor journal's `integrity`/gap accounting and from heartbeats.
   - Until then, coverage can only report `NO_TELEMETRY_RECEIVED` from event spacing. That describes delivery, not endpoint activity.
4. **Router mounting.**
   - `edr_trajectory.preview_mount.mount_if_enabled(app, get_db)` is called right after `app.include_router(api)` in `backend/server.py`.
   - It mounts `/api/e3/trajectory/*` **only** when `E3_TRAJECTORY_ROUTER=1`. Read-only, apart from `/seed` (E3-namespaced synthetic collections) and `/approvals` (in-memory, executes nothing).
   - No auth, ingest or durable-ACK code is touched. No E1/prod config sets the flag.
   - The change is its own commit, labelled `preview-mount(e3)[E1: STRIP]`. To strip it, revert that commit; the rest of `edr_trajectory` doesn't depend on it.
   - If E1 keeps it, put it behind E1 auth and tenant middleware first, and **never** enable `/seed` in production.
5. **Sensor telemetry gaps S-1..S-7.** These are sensor work and are not faked in E3; details are in `docs/e3/DT_AMP_PARITY_GAP_AUDIT.md` §3.
   - **S-1:** No true-creator field, so the `parent_spoof` flag can't fire from Sysmon 1. Needs ETW/kernel creator telemetry.
   - **S-2:** No file write/modify, delete or rename events. Sysmon 2/23/26 aren't admitted, and Security 4663 isn't collected.
   - **S-3:** No hash on file events (Sysmon 11), so file lanes have `sha256=None`, never an invented value.
   - **S-4:** No boot/session id. PID reuse across reboots relies on start time.
   - **S-5:** No image-load, remote-thread or process-access events (Sysmon 7/8/10).
   - **S-6:** Processes seen only through 4688 have no GUID and no start time, so identity is `PID_ONLY_NOT_AUTHORITATIVE` and lineage is at best CORRELATED.
   - **S-7:** Process end needs the Sysmon config to emit EventID 5. Otherwise lanes show `continues_after`.
6. **Store authority (E1-1)** and **Mongo aggregation push-down for viewport/density (E1-2)**. These restate §8.7 and the gap audit row 10.
