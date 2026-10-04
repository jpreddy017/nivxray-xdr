# E3 DT HOTFIX — Current-Day / Rolling-Window Visibility

Branch `feature/e3-edr-engines`, local only. No push, no deploy, no production contact.
Scope: Device Trajectory only.

## 0. Which page is served

| Route | App / file | Status |
|---|---|---|
| `edr.nivxforge.com/edr/device-trajectory` | `apps/nivxray-xdr/src/App.jsx:372` → `apps/nivxray-xdr/src/nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx` | **SERVED** page (Vercel root `apps/nivxray-xdr`, `NIVX_PRODUCT_SCOPE=edr`, `scripts/vercel-build.sh`) |
| `/xdr/edr/device-trajectory` | `EdrTrajectoryRedirect.jsx` → `/edr/device-trajectory` | redirect to the same page |
| `/edr/trajectory` (target of the old "Use Legacy Device Trajectory" link) | `EdrTrajectoryResolver` → `/xdr/endpoints/:ref/trajectory` → `XdrEntity360Page` | separate XDR surface |
| `/v2/trajectory/:caseId` | `frontend/src/v2/pages/DeviceTrajectoryV2.jsx` (legacy NivXray app `frontend/`) | case-based DT; this is where DT-I1 Steps 1–4 landed |

The "Use Legacy Device Trajectory" link (`data-testid="amp-legacy-link"`, href `/edr/trajectory`) was **removed from source in `18c381a2` (DT2-3a, 2026-09-28)**. It is not in HEAD. If the owner's production screenshot shows it, production is running a build that is **older than `18c381a2`**. I can't confirm the production build from here: I have no production access, by design.

**Divergence finding:** the DT-I1 work (dates, verdict separation, causal context) changed `frontend/src/v2/pages/DeviceTrajectoryV2.jsx`. That page is **not** the one served at `/edr/device-trajectory`. This needs an owner decision. This hotfix fixes the served page and brings the V2 page into line on the time model (§3).

## 1. Root cause (recorded BEFORE patching; line numbers at HEAD `98513e26`)

The served page never had a reference-time ("now") model. Every window was derived from the **newest delivered observation** or from **evidence/retention bounds**, then labelled as if it were a day or the "last 24 h".

| # | File:line (HEAD) | Defect | Effect |
|---|---|---|---|
| RC1 | `EdrDeviceTrajectoryPage.jsx:275-293` | The first view is `startOfDayUTC(observed_end)` → `+24h`, where `observed_end` is the newest *delivered* observation. | The window is anchored to evidence, not to the reference time. When delivery lags (backlog, or the sensor stopped), it opens on a historical day. |
| RC2 | `EdrDeviceTrajectoryPage.jsx:326-346` + `dt2/navigation.js:118,152-156` | Auto-focus replaces the view with `evidenceWindow(graph min,max,{dayStart})`. When evidence spans more than `MAX_WINDOW_MS` = 6 h, it centres a 6 h window on the **midpoint** of the evidence. | On a live endpoint with evidence from 00:00 to now, the first view is a 6 h window around midday. **The latest hours (the current activity) are outside the window.** This is the primary "current-day hidden" mechanism. |
| RC3 | `EdrDeviceTrajectoryPage.jsx:435-436` | Pan/zoom clamp `max = retention.max ?? obsEnd`, the last evidence or the retention `available_range.to` snapshot. | The analyst cannot pan to "now". Observations newer than a stale snapshot are unreachable. |
| RC4 | `EdrDeviceTrajectoryPage.jsx:671-680` | The presets `1d/7d/…` compute `obsEnd - days*DAY`. | An evidence-bounded window is presented as "last N days". |
| RC5 | `AmpNavigator.jsx:63-64` | The 30-day strip is anchored to `observedEnd`. | The current day's cell is **missing** whenever the newest delivered observation is from an earlier day. |
| RC6 | `AmpNavigator.jsx:77-85` | The hour band domain is always the calendar day of `selectedDay`, whatever the view. | The navigator, canvas and query interval disagree whenever the view is not exactly one UTC day. |
| RC7 | `EdrDeviceTrajectoryPage.jsx:349-353` + `AmpNavigator.jsx:291-320` | Bins are fetched for **one** UTC day (`hist_day=selectedDay`) and drawn by bin index on a day axis. | A window that crosses UTC midnight (any rolling 24 h, and every IST working day) loses one side's bins. |
| V2 | `frontend/src/v2/pages/DeviceTrajectoryV2.jsx:550-555, 770` | "24 Hours" = `caseBounds.end - 24h` (case evidence end). | An evidence-bounded range is labelled as a rolling "24 Hours". |

Placement: the backend `timestamp` is `ev.ts` (sensor observed time) with a `captured_at` fallback (`backend/edr_plane/trajectory_window.py:163-164`), plus `timestamp_instant_ms`. The frontend never reads `ingested_at`. The `captured_at` fallback is backend semantics: noted here, not changed (out of scope).

## 2. Fix (served page)

New pure module `apps/nivxray-xdr/src/nivxforge/trajectory/dt2/timeWindow.mjs` (`dt.time.v1`). It uses UTC instants only; timezone is presentation only.

- **Rolling** (default): `[ref-24h, ref]`. `ref` = reference time (wall clock, re-read every 60 s). A rolling view advances with the clock.
- **Calendar day**: only after an explicit day-cell click. `[00:00Z, 24:00Z)`. Any part after `ref` is drawn as *not yet occurred*.
- **Evidence-bounded**: only from the explicit "Fit to evidence" control or the "all" preset. It is labelled `Evidence-bounded … (not "last 24 h")`.
- **Linked**: from a deep link (`from/to`, or `at`).
- **Analyst**: any pan or zoom.
- The day strip ends at the **reference day** (RC5). Bins are fetched for every UTC day the navigator domain touches and placed by absolute observed time (RC6, RC7).
- Pan/zoom bound: `max = ref + 120 s` skew tolerance (RC3). A future observation never stretches a window. It is counted and labelled.
- Query interval = view ± prefetch, always ⊇ view. The canvas renders the view. The Activity pane lists the view's observations. All three are exposed as `data-window-*` / `data-query-*` (RC6).
- Placement by `observedAt(e)`: `timestamp_instant_ms`, then `observed_at`, then `timestamp`. **Never** `ingested_at` / `received_at`.

## 3. V2 page (`frontend/src/v2`)

The same module is vendored at `frontend/src/v2/investigation/timeWindow.mjs`. A byte-identity parity test fails if the two copies diverge. In V2, DT-only props (IRG is unchanged):
- range options are relabelled `Entire case (evidence-bounded)`, `Last 24 h of case evidence`, and so on
- a time-model chip states the evidence-bounded case window against the reference time

## 4. Contributor found during the hotfix: per-request count cap (RC8)

| # | File:line | Defect |
|---|---|---|
| RC8 | `backend/edr_plane/trajectory_window.py:1463` `page = in_lane[:limit]` (rows sorted ascending) + `backend/routers/edr.py:1073-1076` `build_graph(out …)` | Each request returns the **OLDEST** `limit` rows of the window, and `dt2.graph` (the default Relationships canvas) is built **from that page only**. The served page asks for `limit=2500` and never follows `next_cursor`. The 30% left prefetch spends the budget on *older* evidence. On a dense window (or during a backlog replay) the **newest hours are silently not drawn**. |
| (note) | `trajectory_window.py:101,605` `BOUNDED_DOCS=4000` with `sort("event.ts", -1)` | First paint (untimed reads only) uses a bounded most-recent projection, labelled `BOUNDED_RECENT`. `event.ts` is a **string** sort over mixed formats (`"YYYY-MM-DD hh:mm"` vs `"…T…Z"`), so "most recent" may be mis-ordered on mixed-format stores. Not changed. |

**Fix (served page, frontend only, no backend change):** `capOf`/`truncationOf` mark a capped window as `TRUNCATED_OLDEST_FIRST`. The undelivered tail is shaded in the navigator (`amp-nav-unloaded`) and stated as *"NOT drawn (not absent)"*.

The default **rolling** view auto-narrows to its newest part that fits one page (`tailWindow` + `pageBudget`), still ending at the reference time, and says so (`dt-window-narrowed`). Every other mode stays where the analyst put it and offers an explicit **Show newest** button.

**Recommended backend follow-up (owner decision, not executed):** add a newest-first page order, or build `dt2.graph` from `in_time` rather than the page.

## 5. DT implementation map (answers to the owner's questions)

| Route (edr.nivxforge.com) | Shell | File | Data / retention model | Count cap |
|---|---|---|---|---|
| **`/edr/device-trajectory` — DEFAULT** | NivXForge console, AMP navigator | `apps/nivxray-xdr/src/nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx` | `GET /edr/endpoints/{id}/trajectory`: time-windowed over the complete per-endpoint projection of `v2_shadow_observations` (all retained history; retention boundary reported, not assumed) | **YES**: 2500/request (server `MAX_LIMIT` 4000), oldest-first (RC8). **Fixed here.** |
| `/edr/trajectory` — "Device Trajectory (legacy)" (`XdrContextBar.jsx:63`) | NIVXRAY XDR shell | `apps/nivxray-xdr/src/xdr/pages/EdrTrajectoryResolver.jsx`. With no params it **refuses** (CAPABILITY UNAVAILABLE, kept as is). With a device it navigates to `/xdr/endpoints/:ref/trajectory` → `XdrEntity360Page.jsx` (trajectory tab) | `GET /edr/device-trajectory?hours=N`: `since = server now − N h` (rolling to now), or `all_time`. Reads `device_identity.observations()` plus case-derived detections | **No count cap found** (`device_identity.py:474-520`: unbounded read). It is a performance risk, not a visibility one. Its window is already rolling to server-now. **Left unchanged**; its limits are recorded here. |
| `/v2/trajectory/:caseId` | legacy NivXray app (`frontend/`, separate CRA build) | `frontend/src/v2/pages/DeviceTrajectoryV2.jsx` | **case-scoped**: `GET /v2/cases/{id}/trajectory/device?limit=1000` | **YES**: 1000 frames per case. Ranges are now labelled evidence-bounded. |

**Explicit answer: `DeviceTrajectoryV2.jsx` is NEITHER the default page NOR the "(legacy)" page.** It belongs to the separate `frontend/` NivXray app. That app is not built by the edr.nivxforge.com Vercel project (root `apps/nivxray-xdr`; the repo root `vercel.json` runs `refuse-root-deployment.sh`). **None of the DT-I1 A–D work (navigator dates, detection ≠ malicious, full row labels, Activity Details 15-section view, causal context) is on the page the owner uses.**

The "Use Legacy Device Trajectory" link was removed in `18c381a2` (2026-09-28). A production build that still shows it predates `18c381a2`.

**"3 endpoint entities projected" vs "1 reporting computer":** these come from different sources.
- "3" is `GET /edr/endpoints` (`routers/edr.py:846`). It groups **investigation cases** (`workspace_cases`, ≤500 most recent) by extracted hostname, so it counts every host named by any case (uploaded/analysed evidence included), not live agents.
- "1" is `edr_events.facets` (`routers/edr_events.py:330-385`). It counts endpoints that **reported observations** in the selected hours.

**Branding defect (recorded, NOT fixed, outside DT scope):** "WRONG PRODUCT HOST — This deployment serves **NivXRay EDR**…" on `/xdr/endpoints` should read NivXForge EDR.

**Proposal (not executed): bring DT-I1 to the default page without duplicating it.**
1. Lift the pure DT-I1 modules (`frontend/src/v2/investigation/{navigatorDates,verdict,activityView,causalView,ti}.mjs`) into one shared package. `timeWindow.mjs` already shows the pattern: one source plus a byte-parity test, or better, a workspace package both apps import.
2. Map the default page's row shape (`/edr/endpoints/{id}/trajectory` events + `dt2.graph`) onto those view-models through a thin adapter, so `AmpActivityPanel`/`AmpEventDetails` render the same contracts.
3. Port the DT-I1 tests to run against both adapters, then retire the case-scoped duplicates.

## 6. Results

| Suite | Result |
|---|---|
| `timeWindow.node-test.mjs` T1–T17 + parity P1 | **18/18** |
| DT-I1 view-model (`frontend/src/v2/investigation/*.node-test.mjs`) | **32/32** |
| DT-I1 component (react-dom/server) | **8/8** |
| Served-page dt2 suites (vitest files, run via node:test shim): compromise, engine, viewport, cisco, filetype, lifeline, parity, detection, graph | **159/159** at HEAD and at worktree. One parity assertion was rewritten to the new invariant: no auto-focus; a linked window carries mode `LINKED`. |
| Backend `edr_investigation + edr_behavior + edr_ml` | **136 passed** |
| Gate-4 (`test_processing_queue_worker` + `test_p0_reconcile_contract_ownership`) | **34 passed**. The env was missing the pinned `pytest-asyncio==1.4.0`; I installed it in the environment only. |
| Testing agent (iteration_1) | TW-A..TW-F, Fit-to-evidence, analyst pan, V2 regression and IRG-unchanged: **all PASS, 0 issues** |

The RC8 work (TW-G, 18/18 incl. T16/T17) was verified by unit tests and screenshots, not by the testing agent.

Preview screenshots are in `/app/.e3ui-harness/shots_tw/`: TW-A … TW-G, TW-G2 (capped calendar day + Show newest), and BEFORE (HEAD) TW-A / TW-G. All use synthetic fixtures, reference time 2026-10-02T04:30:00Z.

Additional finding: a lifeline that began before the window drew into the row-label gutter. Fixed with a presentation clip (`RelationshipCanvas.jsx`, `dt2-plot-clip`); no data moved.

Nothing committed, pushed or deployed. No production endpoint contacted.
