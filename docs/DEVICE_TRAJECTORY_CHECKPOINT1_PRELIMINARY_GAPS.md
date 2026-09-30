# DEVICE TRAJECTORY · CHECKPOINT 1 — PRELIMINARY READ-ONLY GAP LIST

**Read-only. `DEVICE_TRAJECTORY_CODE_CHANGED = NO`,
`DEVICE_TRAJECTORY_FIXES_APPLIED = NO`, `PRODUCTION_UI_DEPLOYED = NO`.**
No JSX, CSS, trajectory-model, backend or fixture change was made. No
screenshots were taken: real KUSHU evidence does not exist yet, and the
active gate remains the B5-GAP-1 canary. This document exists so
Checkpoint 1 starts from a known list instead of a blank page.

Scope, per owner decision: **structural / evidence-presentation parity
only.** Intelligence that depends on E3–E6 is classified
`NOT_EVALUABLE_YET — ENGINE NOT PRESENT` and is **not** a renderer defect.

Classification used here:

| Class | Meaning |
|---|---|
| `PASS_PENDING_VISUAL` | the mechanism exists in code and is wired to real evidence; only the owner's visual comparison can confirm parity |
| `DIVERGES` | proven divergence from the Cisco reference, readable in the code today |
| `NOT_EVALUABLE_YET` | depends on an engine (E3–E6) or evidence that does not exist |

Divergence class: `UI` (presentation) · `DATA` (evidence substrate) ·
`ENGINE` (missing analytical engine) · `CONTRACT` (server contract).

Sources of truth used: `memory/AMP_TRAJECTORY_CONFORMANCE.md`,
`memory/production-gates/CISCO_AMP_TRAJECTORY_ENGINEERING.md` (sourced
Cisco research), `DEVICE_TRAJECTORY_V2_GAP_ANALYSIS.md`,
`DEVICE_TRAJECTORY_V2_PUBLIC_REFERENCE_ADDENDUM.md`,
`DEVICE_TRAJECTORY_V2_DT2_0_IMPLEMENTATION.md`, and direct inspection of
`apps/nivxray-xdr/src/nivxforge/trajectory/*` + `dt2/*` +
`apps/nivxray-xdr/src/xdr/lib/trajectoryModel.js`.

---

## A · STRUCTURAL ROWS — expected to pass, confirm visually

Each row's mechanism was located in code. Nothing here is asserted as
parity; the owner's side-by-side decides.

| # | Cisco reference behaviour | NivXForge mechanism (code) | Class |
|---|---|---|---|
| A1 | Page title + `Use Legacy Device Trajectory` + fullscreen | `dt-heading`, `amp-legacy-link`, `amp-fullscreen-toggle` | `PASS_PENDING_VISUAL` |
| A2 | Collapsed computer strip "`<host>` in group `<g>` · N compromise events" | `amp-computer-header`, collapsed by default | `PASS_PENDING_VISUAL` |
| A3 | Expanded computer attribute table | `AmpComputerHeader.jsx`; uncollected fields render `◇ not collected` with a reason, never zero | `PASS_PENDING_VISUAL` |
| A4 | `Filters ⌄` + `Search Device Trajectory` strip above the navigator | `amp-filters-button` / `amp-filters-menu` / `amp-filter-search` / `amp-apply-filters` | `PASS_PENDING_VISUAL` |
| A5 | Activity sparkline + 30-day navigator, red compromise dots, click a day to move | `amp-nav-day-band`, log-scaled density curve, per-day red strip | `PASS_PENDING_VISUAL` |
| A6 | 24-hour band with dual handles, drag/centre, out-of-window hatched | `amp-nav-hour-band`, `amp-nav-band`, `amp-nav-window-region`, hatch `#amp-nav-hatch` | `PASS_PENDING_VISUAL` |
| A7 | Vertical axis: processes `[ System ]` then `[ Files & Network ]` | `dt2-section-system`, `dt2-section-files-network`, `amp-gutter-system` follows the top visible section | `PASS_PENDING_VISUAL` |
| A8 | Row labels right-aligned with type tag, PID, lineage guides | `amp-lane-label-<row>` → `name (pid) [Tag]` + one guide tick per ancestor | `PASS_PENDING_VISUAL` |
| A9 | Horizontal time axis with ticks + gridlines | `amp-time-axis`, `amp-tick-<t>` | `PASS_PENDING_VISUAL` |
| A10 | Process lifelines, child/file activity stemming from the line | `AmpCanvas.jsx` lifelines + elbow connectors with junction nodes from authoritative `process_iid`/`parent_iid` | `PASS_PENDING_VISUAL` |
| A11 | Activity icons per event type, aggregated when overlapping | `amp-event-<event_iid>` + count badge | `PASS_PENDING_VISUAL` |
| A12 | Right-hand **Activity** master list | `amp-activity-panel`, `amp-activity-list`, `amp-activity-up/down` | `PASS_PENDING_VISUAL` |
| A13 | Click an event → **Activity Details** in place with a back arrow, no navigation away | `amp-details-panel`, `amp-details-back`; viewport preserved | `PASS_PENDING_VISUAL` |
| A14 | Event Details: timestamp, severity chip, description, observables, observed activity | `amp-details-timestamp`, `amp-details-disposition`, `amp-details-description`, observables/observed-activity sections | `PASS_PENDING_VISUAL` |
| A15 | Side-to-side scroll through time + activity scroll | `amp-hscroll`, `amp-vscroll`, pointer drag, `dt2-time-earlier/later`, `dt2-rows-up/down` | `PASS_PENDING_VISUAL` |
| A16 | Filters de-noise the graph, applied with a button | `amp-apply-filters`, activity/disposition/file-type groups with counts | `PASS_PENDING_VISUAL` |
| A17 | Explicit zoom / step controls, jump to next-previous event | `dt2-zoom-in/out`, `dt2-prev-event/next-event`, `dt2-return-to-event/row`, `dt2-window-label/state` | `PASS_PENDING_VISUAL` (exceeds the published Cisco control set) |
| A18 | Selection keeps time window, filters and context | selection is state-only; no scroll hijack | `PASS_PENDING_VISUAL` |

---

## B · PROVEN DIVERGENCES — readable in the code today

| # | Cisco reference | NivXForge observed | Evidence | Exact divergence | Class | Proposed correction | Priority |
|---|---|---|---|---|---|---|---|
| B1 | Inspector column is a resizable/collapsible investigation surface | fixed-width column | `EdrDeviceTrajectoryPage.jsx:65` `DETAILS_W = 394` | not resizable, no overlay mode; on a narrow viewport the canvas is crushed | `UI` | drag handle + overlay mode under a width threshold; per-session only, no preference store | P1 (usability at real viewports) |
| B2 | Coverage of the timeline is visibly qualified | `CoverageInterval` is published by the server and `dt2/density.js::coverageOf` exists, but **nothing renders it**; only a canvas label `no sensor coverage` | `coverageOf` has no consumer outside `dt2/`; `AmpCanvas.jsx:241` | per-interval bands (OBSERVED / NOT_COLLECTED / NOT_CANONICALIZED / PARSE_FAILURE) are not drawn, so "no visibility" and "nothing happened" look alike outside the single hatched region | `UI` (contract already exists) | render coverage bands under the time axis, legend-labelled | **P0 for an evidence-truth product** |
| B3 | Analyst keyboard operation of the timeline | no keyboard handling anywhere in the trajectory folder | zero `keydown` handlers in `nivxforge/trajectory/**` | every navigation action is pointer-only | `UI` | minimal set: ←/→ time, ↑/↓ rows, `+`/`-` zoom, `n`/`p` next/prev event, `Esc` close details | P2 |
| B4 | Search narrows and the analyst walks the matches | match **count** only (`amp-search-match-count`, `meta.matched_after_filters`) | `EdrDeviceTrajectoryPage.jsx:869` | no `MATCH n OF m` cursor, no prev/next match, no field scoping (hash, IP, domain, PID are one substring) | `UI` + `CONTRACT` | match cursor in the contract + prev/next controls; field-scoped `q` | P2 |
| B5 | Event Details exposes the underlying record | no byte-preserved RAW payload surface in the inspector, although `GET /api/edr/events/{raw_id}` exists | no `raw_payload`/RAW tab in `AmpEventDetails.jsx` | the analyst cannot see the original record behind a canonical observation | `UI` (pure wiring) | RAW section/tab fed by the existing endpoint, labelled byte-preserved | P1 |
| B6 | Filters can de-select individual **processes**, not only event types | filters are activity-type / disposition / file-type | `AmpFilterBar.jsx` | a noisy single process cannot be removed from the graph | `UI` | process de-selection list sourced from the lane axis | P2 |
| B7 | Per-file event cache suppresses repeats at ingest (Clean 7 d / Unknown 1 h / Malicious 1 h) | `dt2/repeatCache.js` exists but has **no consumer**; all repeats are shown | grep: `repeatCache` referenced only inside `dt2/` | Cisco's graphs are sparse because the repeats never exist; ours shows every observation, which is denser than the reference | `DATA`/`CONTRACT` | **owner ruling required** — suppressing at display would hide observations we hold; prefer an explicit "N repeats collapsed" affordance over silent suppression | P1 decision, not code |
| B8 | Parent/child resolved by file identity (SHA-256) | resolved by canonical process identity, with a declared PID surrogate when the sensor sends no hash (`authority: DERIVED`, `downgraded: true`) | `CISCO_AMP_TRAJECTORY_ENGINEERING.md` §5 | weaker identity than the reference; already declared, not hidden | `DATA` | widen sensor hash coverage (coverage expansion, separate task) | P2 |
| B9 | Lifelines are solid because terminations are collected | lifelines dash open when no `process_exit` was observed | `AMP_TRAJECTORY_CONFORMANCE.md` difference #9 | **deliberate and correct** — a closed lifeline would assert a termination nothing observed. Note: EID 5 is now enabled, so KUSHU should produce genuinely closed lifelines for the first time — Checkpoint 1 is the first chance to see that path exercised | `DATA` | none; verify closure renders correctly with KUSHU's EID 5 | P1 verification |
| B10 | Browser Back steps through investigation states | URL writes use `replace: true`; filters/search/zoom are not in the URL | gap analysis §23 | Back leaves the investigation instead of stepping it | `UI` | push vs replace rules + fuller URL state | P2 |

---

## C · NOT EVALUABLE YET — engine not present

These are **not** renderer defects and must not be "fixed" with fixtures.

| # | Surface | Depends on | Current truthful state |
|---|---|---|---|
| C1 | Detection markers on lifelines, red "Detected `<name>`" line | **E3** deterministic detection | `amp-details-detection-flag`, `amp-detection-none`, `amp-detected-by-none` render the absence; no marker is drawn when nothing detected |
| C2 | Disposition colouring (clean / malicious) | **E4** reputation | nothing is ever labelled CLEAN; unassessed activity is `UNKNOWN_NOT_ASSESSED` (deliberate epistemic difference) |
| C3 | Cloud IOC panel, yellow IOC highlight, compromise event rows | **E4/E5** | `dt2-ioc-panel` + `dt2-ioc-not-observed`, `dt2-section-compromise`, `dt2-compromise-band` exist and correctly show not-observed |
| C4 | Blue halo over contributing events of a compromise | **E5** contributor set published server-side | not drawn — must never be inferred from proximity (`FORBIDDEN_BASES`) |
| C5 | MITRE \| ATT&CK tactics/techniques box | **E6** attribution (today: deterministic keyword mapper, `AUTHORITY_DERIVED`) | `amp-mitre-box` / `amp-mitre-none` / `amp-mitre-tactics-none` |
| C6 | Typed relationship edges "what did THIS process touch" | `relationships[]` (**built** in DT2-0 contract) + rendering | `dt2-relationship-canvas` with `dt2-relationships-empty`; evaluable only with evidence that has real artefact edges — KUSHU file/DNS/network activity should provide the first real test |
| C7 | Retrospective 7-day re-evaluation, forensic snapshot, file trajectory | post-E6 capabilities | absent rather than faked |

Per owner decision, **no label is added to the UI for these**; the absence
is recorded here, and the product continues to represent backend truth.

---

## D · WHAT CHECKPOINT 1 STILL NEEDS BEFORE IT CAN RUN

1. **B5-GAP-1 canary PASS on KUSHU** — the active gate.
2. **A declared CANARY/VALIDATION density pass on KUSHU** (benign only:
   EID 1 / 5 / 3 / 11 / 22), run *after* the canary result is recorded so it
   cannot contaminate the acceptance measurements. Zero fabricated
   detections, IOCs, ATT&CK mappings or contributor claims.
3. **Preview-only evaluation** against the real backend, no production
   deployment.
4. **Screenshot pairs** (Cisco reference from `memory/production-gates/`
   vs NivXForge preview at the same structural moment) for every row in §A
   and §B.
5. The two questions only real KUSHU evidence can answer:
   * do **closed** lifelines render correctly now that EID 5 is enabled
     (B9)? Every previous dataset was 100 % `END_NOT_OBSERVED`;
   * does the `[ System ]` band look legitimate rather than empty when the
     host's vocabulary is genuinely process-heavy? The previous endpoint
     was 3731 `network_connect` vs 262 `process_create`, which made the
     System band look broken when it was telling the truth.

---

## E · STOP

Preliminary list ends here. Nothing was changed, nothing was deployed,
nothing was fabricated. The active engineering gate remains
**KUSHU → B5-GAP-1 disposable canary**; this document is not a reason to
delay it.

```
DEVICE_TRAJECTORY_CODE_CHANGED  = NO
DEVICE_TRAJECTORY_FIXES_APPLIED = NO
PRODUCTION_UI_DEPLOYED          = NO
FIXTURES_ADDED                  = NO
CANARY_STARTED                  = NO
DESKTOP_A9HGFJJ_TOUCHED         = NO
```
