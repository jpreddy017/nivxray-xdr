# DT2 · CISCO AMP DEVICE TRAJECTORY — STRICT UI/UX CLONE · ACCEPTANCE RECORD

Reference (authoritative, user-supplied): `cisco_ref/CISCO_DEMO_UPATRE_REFERENCE.png`
(cropped from `cisco_ref/USER_SUPPLIED_COMBINED.jpeg`, 1366px wide figure).

Subject: NivXForge EDR Device Trajectory · endpoint `WS-W1-1789575060`
/ `dev_0e10780f2c86`, customer `default`. REAL evidence only, no fixtures.

Artefacts
- `cisco_ref/DT2_CISCO_CLONE_SIDE_BY_SIDE.png` — full page A vs B.
- `cisco_ref/DT2_TRAJECTORY_PANE_SIDE_BY_SIDE.png` — trajectory pane A vs B.
- `cisco_ref/DT2_TRAJECTORY_PANE_1TO1.png` — pane at 1:1 pixels, B NOT rescaled.
- `cisco_ref/DT2_NIVXFORGE_REAL_PAGE.png` — B alone.

## Metrics taken from the reference and coded as absolute px

| element | reference | implemented |
|---|---|---|
| gutter rule (x) | 238 | `LEFT = 238` |
| date header height | 38 | `DATE_H = 38` |
| rotated time scale height | 48 | `TICK_H = 48` |
| System band height | 32 | `SYS_H = 32` |
| Files & Network band height | 40 | `FN_H = 40` |
| row pitch | 18 | `ROW = 18` (`ampModel.ROW_H = 18`) |
| Activity pane width | ~394 | `DETAILS_W = 394` |
| 24-hour navigator band | 72 (ticks in the top 30) | `HOUR_H = 72` |
| day cell height | 28 | 28 |
| section / row / tag type | 14·700 / 12 / 11 | same |

The reference is a fixed-metric layout; NivXForge renders the same absolute
metrics at a 1684px content width, so the composites scale B by ~0.77. The
1:1 artefact is the geometry-accurate comparison.

## Visual acceptance matrix

| component | state | note |
|---|---|---|
| Search Device Trajectory | MATCH | left, full width, magnifier inside, Enter submits, `at:<ts>` grammar retained |
| Filters control | MATCH | right, borderless, glyph + chevron, 5 Cisco categories, Apply Filters |
| Day navigator (30 cells) | MATCH | bordered cells, selected cell outlined, day numbers + month under the cells |
| Navigator event markers | MATCH | red = compromise, blue = search hits, radius log-scaled by the day's real count |
| Selected-day treatment | MATCH | outlined cell + tinted column through the labels |
| 24-hour navigator ribbon | MATCH | solid tinted band, hour rules, hour scale and date inside the band |
| Selected-hour / window treatment | MATCH | white window region with blue border, draggable, event dots on top |
| Timeline / Activity split | MATCH | two panes, one border, Activity 394px, independent scrolling |
| Timeline header | MATCH | right-aligned in the gutter, 14·700 |
| Date columns (`Jul 25`/`Jul 26`) | MATCH | one label per observed day + a rule at each day boundary |
| Vertical time axis + grid | MATCH | hour reference marks across the day + event-anchored ticks, rotated labels, grid to the pane bottom |
| System band | MATCH | permanent, full width, tinted, label right-aligned |
| Files & Network band | MATCH | permanent, label right-aligned, rows beneath |
| Trajectory rows | MATCH | real rows only, right-aligned `name [PE]` |
| Process lifelines | MATCH | pale green line; observed-evidence span, dashed continuation where no exit was observed |
| `[PE]` notation | MATCH | derived from the observed path extension (declared derivation, not file identification) |
| Event glyphs | PARTIAL | same size/shape/placement; artwork is original — Cisco's glyph assets are proprietary |
| Detection / warning indicators | MATCH | amber triangle in Activity, red mark on the row, tinted label for an implicated row |
| Activity pane + rows + icons | MATCH | actor · glyph · target, hairline separators, ▲▼ scroll track |
| Pane borders / grid lines | MATCH | single outer border, gutter rule, axis rule, band rules |
| Typography | MATCH (absolute) | equal to the reference's absolute sizes; appears smaller in any composite that downscales B |
| Spacing / density | MATCH | metrics table above |
| Scrolling | MATCH | ▲▼ rows, ◀ ▶ time with a thumb over the retained period, return-to-selection |
| Cloud-query line graph over the day cells | NOT PRESENT | DATA GAP — Cisco defines it as per-day cloud-query volume (p.403); NivXForge collects no such metric. Substituting our own activity curve under Cisco's meaning would be false parity. |
| `Inbox status: Requires attention` | NOT PRESENT | DATA GAP — no NivXForge inbox/triage state exists behind this control. |

Structural items PARTIAL/NOT PRESENT: 1 PARTIAL (glyph artwork, proprietary)
and 2 NOT PRESENT, both because the underlying NivXForge datum does not exist.
No structural item is missing for want of implementation.

## Content differences that are NOT UI defects

The reference figure shows a 13-hour Upatre chain. This endpoint's real
evidence is 15 observations, all stamped `2026-06-01T10:00:00Z`, over 17 rows
(16 process nodes + 1 canonical FILE row). The layout is therefore identical
while the drawn content differs. No timestamp was moved, spread or collapsed
and no row was removed to make the screenshots agree.

## `Unknown process` diagnostic inventory (defect, not fixed here)

- Count: **3** rows — `pnode:proc_fc0d47fd87eb` (12 children),
  `pnode:proc_86dd9e202435` (1), `pnode:proc_fdfa3b97d40a` (1).
- Underlying event type: `process_create` (Sysmon EID 1), adapter
  `sysmon-normalizer`.
- Fields present on the node: `node_id`, `process_iid`, `lifeline`,
  `evidence_ref` (RAW_EVENT / CANONICAL_EVENT / OBSERVATION), `child_node_ids`.
- Fields absent: `image`, `pid`, `process_guid`, `user`, `command_line`;
  `label` falls back to the `process_iid`.
- Server's own grading: `identity_authority: UNKNOWN`,
  `identity_basis: IDENTITY_NOT_PRESENT_IN_EVIDENCE`,
  `presence: REFERENCED_BY_CHILD_EVIDENCE_ONLY`, `downgraded: true`,
  `provenance.has_own_observation: false`. No observation exists whose
  `process_iid` is the parent (`v2_shadow_observations` count = 0).
- **Origin: normalization / graph builder (dt2-2a), NOT telemetry and NOT
  frontend mapping.** The child's persisted canonical evidence DOES name the
  parent — `event.process.parent_name = "explorer.exe"` and
  `event.raw.parent_image = "explorer.exe"` on
  `observation evt_27fede4a71241c77` / `process_iid proc_836bad7d4aa3`. The
  graph builder does not propagate that name onto the synthesized parent node,
  so the API response contains no field the UI could map.
- Action required (backend, separate step): emit the parent's display name on
  the synthesized parent node with an explicit basis, e.g.
  `identity_basis: PARENT_NAME_FROM_CHILD_EVIDENCE`, keeping
  `identity_authority: UNKNOWN`. Until then the row correctly reads
  `Unknown process`; the UI must not guess.

## Regression

- `yarn vitest run` → 122/122 passing (4 files).
- Route loads with real evidence: 17 rows, 25 time ticks, 15 Activity rows,
  1 detection row (`regedit.exe`), 1 canonical FILE row
  (`C:\Users\Public\payload.exe`).
- Page theme choice removed from Device Trajectory only. No other EDR page and
  no global console theme was changed.

## DT2-3a.2 · TIME DOMAIN / VIEWPORT PROJECTION — acceptance run (valid)

Harness failure of the previous run: **FAILURE_CLASS = A (authentication did
not complete)**. Console evidence:
`POST /api/auth/login → 502` (transient preview gateway), so the harness never
left `/login`; every trajectory selector was absent and the instrumentation
read null. Not a trajectory-engine failure. Fixed by a deterministic readiness
gate (retry login until the URL leaves `/login`, `wait_for_selector` on the
canvas, then poll `data-dt2-view-from` until populated).

AUTH_OK yes · TENANT_CONTEXT_OK yes (`default`) · ENDPOINT_LOAD_OK yes ·
TRAJECTORY_API_OK yes · CANVAS_MOUNTED yes · INSTRUMENTATION_OK yes

Endpoint `dev_0e10780f2c86` (WS-W1-1789575060):

| measurement | BEFORE | AFTER |
|---|---|---|
| VIEWPORT_START | 2026-06-01T00:00:00Z | 2026-06-01T09:59:00.000Z |
| VIEWPORT_END | 2026-06-02T00:00:00Z | 2026-06-01T10:01:00.000Z |
| VIEWPORT_DURATION_MS | 86 400 000 | 120 000 |
| EVIDENCE_MIN / MAX | 10:00:00.000Z / 10:00:00.000Z | unchanged (never mutated) |
| EVIDENCE_SPAN_MS | 0 | 0 |
| EVIDENCE_PERCENT_OF_VIEWPORT | 0 % | 0 % |
| DRAWABLE_LEFT_PX / WIDTH_PX | 238 / 1000 | 238 / 1000 |
| EVIDENCE_PIXEL_SPAN | 0 px | 0 px |
| VISIBLE_ROW_COUNT | 17 | 17 (all 17 have evidence in the window) |
| tick scale | 00:00…23:00 hours | 09:59:00 … 10:01:00, 15s steps |

NUMERIC_TIMESTAMP_X_PROOF (rendered DOM, 5 of 15):

| event | timestamp | row | x | y |
|---|---|---|---|---|
| certutil.exe start | 2026-06-01T10:00:00.000Z | pnode:proc_836bad7d4aa3 | 738.00 | — |
| payload.exe FILE activity | 2026-06-01T10:00:00.000Z | proc_836bad7d4aa3::FILE | 738.00 | 203.00 |
| wmic.exe start | 2026-06-01T10:00:00.000Z | pnode:proc_19f187c8c8ea | 738.00 | — |
| powershell.exe start | 2026-06-01T10:00:00.000Z | pnode:proc_2926e8542ed7 | 738.00 | — |
| cmd.exe start | 2026-06-01T10:00:00.000Z | pnode:proc_3b6b312b60a2 | 738.00 | — |

Mapping check: `238 + ((10:00:00 − 09:59:00) / 120 000) × 1000 = 738.00` — the
rendered value for every event. **The renderer projects X from the timestamp.**

- TIME_DOMAIN_BUG_FOUND: **YES** → FIXED (full-day primary viewport replaced by
  `evidenceWindow`; ticks now derive from the current viewport).
- PROJECTION_BUG_FOUND: **NO** → proven above; `projectX` is the only
  horizontal mapping and the DOM agrees with it to 0.01px.
- ROW_ASSIGNMENT_BUG_FOUND: **YES (partial)** → every process was promoted
  regardless of the window; `rowsInWindow` now keeps only rows with evidence in
  the viewport plus the evidenced parents needed to explain them.

**T1 < T2 < … < T5 CANNOT BE DEMONSTRATED ON THIS ENDPOINT: the timestamps are
EQUAL.** All 15 persisted observations carry `event.ts = captured_at =
2026-06-01T10:00:00Z` (sequences 0–14, `raw.utc_time` absent). `EVIDENCE_SPAN_MS
= 0`, therefore equal X is the mathematically correct result and no viewport can
separate them. The remaining vertical appearance on
`dev_0e10780f2c86` is a **TELEMETRY / NORMALIZATION defect**, not a geometry
defect:

> NEW BLOCKER — `TELEMETRY_TIMESTAMP_COLLAPSE`: the Sysmon path stamps every
> event of an ingest batch with one time. No per-event `UtcTime` reaches
> `v2_shadow_observations`. Until the collector/normalizer preserves per-event
> time, NivXForge cannot render horizontal progression for this endpoint
> without fabricating time, which is forbidden.

Diagnostic endpoint with real distinct times (`dev_42e8c6dc74b9`): process
starts at `00:16:19.730 / .810 / .820` — an 90ms span that the old full-day
viewport rendered as 1px and the new window renders across the canvas.

FOCUSED_TESTS: `dt2/__tests__/dt2_3a2_viewport.test.js` (15) — helper layer.
Renderer-level DOM proof supplied above; a jsdom renderer test is still TO DO.
FILES_CHANGED: `dt2/navigation.js` (evidenceWindow/projectX/tickStepFor),
`dt2/graphModel.js` (rowsInWindow), `RelationshipCanvas.jsx` (projectX, viewport
ticks, row relevance, DOM instrumentation), `EdrDeviceTrajectoryPage.jsx`
(auto-focus to the evidence window, once per device+day+filter).

DT2_3A_2_VERDICT: time-domain and row-relevance defects FIXED and proven;
projection proven correct; **horizontal progression blocked by
TELEMETRY_TIMESTAMP_COLLAPSE, not by the trajectory engine.**
