# Cisco AMP / Secure Endpoint Device Trajectory — clone conformance

NivXForge EDR · `/xdr/edr/device-trajectory` · updated 2026-06-06

Reference baseline: Cisco Secure Endpoint User Guide (Device Trajectory)
plus the owner-supplied reference pack of real console screens (classic
AMP light console, newer Secure Endpoint console, Secure Endpoint
Japanese console).

Legacy `/edr/trajectory` is untouched and remains operational.

## Reproduced (observable Cisco behaviour, real evidence only)

| Cisco element | NivXForge clone |
|---|---|
| Page header: title, Use Legacy Device Trajectory, fullscreen | `dt-heading`, `amp-legacy-link`, `amp-fullscreen-toggle` |
| Collapsed computer strip "<host> in group <g> · N compromise events" | `amp-computer-header` (collapsed by default, as Cisco) |
| Expanded computer attribute table | Hostname/OS/Connector/First Observed/Device IID/Endpoint ID/Enrollment/Sensor/Observations · Group/Policy/Internal IP/External IP/Last Seen/Definitions/Identity/Tenant/Rows |
| Isolation state row | `amp-isolation-row` → links to the response plane |
| Related Compromise Events · Vulnerabilities | `amp-related-compromise`, `amp-vulnerabilities` |
| Device action row | Forensic Snapshot, Live Query, Events, Process Tree, Campaign Story, Response; Scan/Diagnose/Move-to-Group disabled with a stated reason |
| Filters ⌄ + Search Device Trajectory | `amp-filters-button` / `amp-filters-menu` / `amp-filter-search` (activity type with counts, disposition, timeframe, legend) |
| Activity sparkline | `amp-nav-sparkline` |
| 30-day Navigator band, click a day to move the trajectory | `amp-nav-day-band`, `amp-nav-day-<YYYY-MM-DD>` |
| Red compromise markers in the band | `amp-nav-day-red-<day>` |
| 24-hour Navigator band, click to centre | `amp-nav-hour-band`, `amp-nav-bin-hit-<n>` |
| Sliding window with dual handles | `amp-nav-band`, `amp-nav-handle-left/right` |
| Vertical axis: processes ("[ System ]") then files & network | `amp-gutter-system`, `amp-section-<name>` |
| Row labels right-aligned with a type tag | `amp-lane-label-<row>` |
| Horizontal time axis with tick labels + gridlines | `amp-time-axis`, `amp-tick-<t>` |
| Process lifelines | `amp-lifeline-<row>` (solid green process, dotted grey file/network) |
| Parent → child connectors | `amp-connector-<row>` with `data-parent-lane-index` |
| Activity icons per event type, aggregated when overlapping | `amp-event-<event_iid>` + count badge |
| Compromise treatment: red icons, red axis markers, amber band | `amp-compromise-marker-*`, `amp-compromise-band-*` |
| Hover tooltip | `amp-tooltip` |
| Right-hand **Activity** master list | `amp-activity-panel`, `amp-activity-row-<event_iid>`, `amp-activity-count` |
| Click an event → **Activity Details** in place, with a back arrow | `amp-details-panel` (header "Activity Details"), `amp-details-back` — no modal, no navigation away, viewport preserved |
| Dark console (current Secure Endpoint) and light console (classic AMP) | `amp-theme-toggle`, default dark, persisted |
| Activity quick filters | `amp-activity-tabs`: All / Processes / Files / Network / Detections with counts |
| **Show details** endpoint drawer | `amp-show-details` → `amp-details-drawer` (right-side, never navigates away) |
| **Actions** endpoint command menu | `amp-actions-button` → `amp-actions-menu`: Events, Process Tree, Campaign Story, Live Query, Take System Snapshot, Start Isolation; Scan / Diagnose Connector / Move to Group / Device Audit Log disabled with a stated reason |
| Row labels carry the PID and lineage guides | `amp-lane-label-<row>` renders `name (pid) [Tag]` with one guide tick per ancestor level |
| Detection → Trajectory: open at the right endpoint, time and event | `?device=&at=<ISO>[&process_iid=]` centres the window on that instant and selects the nearest observation once; `?event=<event_iid>` selects exactly |
| Timestamp + severity chip | `amp-details-timestamp`, `amp-details-disposition` |
| "Detected <name>" in red | `amp-details-detected-line` (only when something detected it) |
| Description | `amp-details-description` |
| MITRE \| ATT&CK box with Tactics / Techniques | `amp-mitre-box` |
| Observables (File + hash, expandable) | `amp-observables`, `amp-observable-expand-<i>` |
| Observed Activity | `amp-observed-activity` |
| **Detected By** | `amp-detected-by` / `amp-detected-by-<i>` / `amp-detected-by-none` |
| Time + activity scrollbars over the retained period | `amp-hscroll`, `amp-vscroll` |
| Fullscreen | `amp-fullscreen` |
| Drag to move through time and activity | pointer drag on `amp-canvas` |

## Declared DIFFERENCES (not Cisco-verifiable, or not reproducible)

1. **Icon artwork** is original. Cisco's glyph assets are proprietary;
   each activity type has a functionally equivalent shape carrying the
   same information (type by shape, disposition by colour).
2. **File-type tags** — Cisco shows its own file identification
   (`[PE]`, `[OLE2]`, `[Graph]`). NivXForge does not run file
   identification, so the tag is DERIVED from the observed path
   extension and falls back to the row's group (`[Proc]`, `[File]`,
   `[Net]`). It is a derivation, never an identification.
3. **Wheel mapping** (per the owner's final instruction): wheel scrolls
   the activity axis, shift/horizontal wheel scrubs time, ctrl or cmd +
   wheel zooms the window. Attached natively and non-passively so no
   ancestor scrolls the page instead. Dragging, `amp-vscroll`,
   `amp-hscroll`, the Navigator bands, the window controls, search and
   event selection all remain.
4. **Take a Tour / Share** are Cisco product features with no
   NivXForge equivalent, so they are absent rather than faked.
5. **Dispositions** — Cisco has a file reputation service. NivXForge
   has none, so nothing is ever labelled CLEAN; unassessed activity is
   `UNKNOWN_NOT_ASSESSED`. This is a deliberate epistemic difference.
6. **Vulnerabilities / Kenna risk / connector GUID / policy / groups /
   internal + external IP / definitions version** are not collected by
   the NivXForge sensor. They render as an explicit "◇ not collected"
   with the reason on hover, never as empty or zero.
7. **Scan / Diagnose / Move to Group** are unimplemented and rendered
   disabled with a stated reason rather than hidden or faked.
8. **Exact pixel metrics, zoom ratios and colour hex values** are not
   published by Cisco; functional equivalents are used, tokenised in
   `ampModel.js` from `design_guidelines.json`.
9. **Process lifelines are dashed to the right edge** when no
   `process_exit` was observed. Cisco draws solid lifelines because it
   collects process termination; drawing a closed lifeline here would
   assert a termination nothing observed.
10. **Open a detection's full description** — Cisco renders the
    detection's authored prose. Our detections carry a rule label but
    no authored description, so the description states what is known
    and names the collector instead of inventing text.

## Data path (no mock, no parallel store)

    edr_raw_events → v2_shadow_observations (canonical evidence)
                   → edr_plane/trajectory_window.py (projection)
                   → GET /api/edr/endpoints/{id}/trajectory
                   → the page

The projection creates no store of its own; it caches its own derived
projection for 90 s per endpoint purely to keep panning fluid.

## Resolved defects

* **Deep activity rows rendered empty.** The lane catalogue was built
  only from documents inside the requested time window, so lane indices
  were renumbered per window and a request for rows 300–324 could
  address rows that did not exist in that window. The axis is now built
  over the endpoint's whole history and is invariant to the viewport
  (`axis_scope: ENDPOINT_WIDE_INVARIANT_TO_VIEWPORT`), with
  `lane_axis_version` so a client can detect real catalogue growth.
* **The trajectory read as disconnected independent rows.** The axis was
  ordered `(group, depth, first_seen)`, which put every root first and
  its children hundreds of rows away. It is now a depth-first lineage
  pre-order over observed `process_iid`/`parent_iid`, so a process is
  immediately followed by what it spawned.
* **"parent not observed" was a blanket fallback.** Three distinct
  truths are now named: `OBSERVED`, `PARENT_NOT_REPORTED_BY_SENSOR`
  (the sensor reported no parent at all) and
  `PARENT_NOT_OBSERVED_VISIBILITY_GAP` (a parent was reported but never
  observed). A parent outside the viewport still resolves, because
  `parent_lane_index` is computed on the full axis.
* **The sensor's display label was rendered as a detection.**
  `raw.rule_label` ("bash · process create") is a display label, not a
  rule. It is now carried as `display_label`; `rule_label` is populated
  only when `raw.rule_id` exists, and "Detected …" is stated only when
  something actually detected the observation.
* **Event identity collisions.** `event.iid` is reused across
  observations (8 duplicates in 406 during Stage 1). `event_iid` is now
  a composite of the canonical id plus a digest of the distinguishing
  fields, so merged pages de-duplicate exactly.

## Proof

`python3 /app/scripts/p0_f12_amp_trajectory_proof.py` — 17/17 PASS
against live evidence (deep rows under a narrow window · axis
invariance · time navigation · lifelines and end state · real
parent→child→grandchild chain · pre-order adjacency · distinct parent
states · activity types · dispositions · 30-day band · 24-hour bins ·
Detected By · uncollected fields declared · unique event identity ·
filters · digest separation · epistemic state).

Frontend interaction coverage: `/app/test_reports/iteration_96.json`,
`iteration_97.json`, `iteration_98.json`.
