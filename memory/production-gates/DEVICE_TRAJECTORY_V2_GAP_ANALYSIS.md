# DEVICE TRAJECTORY V2 — PHASE A GAP ANALYSIS (READ-ONLY)

Owner directive: Phase A only. **No code change, no deployment, no DB write,
no response action.** Nothing in this document was implemented.

Production gate status recorded as the owner instructed:
**S1-S5 PASSED · S6 (functional trajectory acceptance) HELD.**

## Method

Read-only inspection of:

| Layer | Files |
|---|---|
| Trajectory projection | `backend/edr_plane/trajectory_window.py` (1155 L) |
| Trajectory routes | `backend/routers/edr.py` — `/endpoints/{id}/trajectory` :995, `_computer_header` :1066, `/device-trajectory` :1103, `/endpoints/{id}/trajectory/focus` :1540, `/process-tree` :718, `/file-trajectory` :795 |
| Events read path | `backend/routers/edr_events.py` — list :180, facets :329, single raw event :393 |
| Canonical / identity | `backend/edr_plane/windows_eventlog.py`, `backend/edr_plane/canonical_bridge.py` (`bind_process_identity` :396), `backend/v2/ingestion/canonical.py` (`ces_to_cem_dict` :213-345), `backend/v2/ingestion/telemetry_bridge.py` (`observation_doc` :118) |
| Trajectory UI | `apps/nivxray-xdr/src/nivxforge/trajectory/` — `EdrDeviceTrajectoryPage.jsx` (984 L), `AmpCanvas.jsx` (587), `AmpNavigator.jsx` (429), `AmpEventDetails.jsx` (451), `AmpComputerHeader.jsx` (278), `AmpFilterBar.jsx` (221), `AmpActivityPanel.jsx` (144), `ampModel.js` (267) |
| Events UI | `apps/nivxray-xdr/src/nivxforge/pages/EdrEventsPage.jsx` (509 L) |

## Headline: V1 is much closer than the screenshots suggest

The existing trajectory is **not** a chart bolted onto a list. It already has a
windowed cursor-paged projection, an endpoint-wide invariant lane axis ordered
by **observed lineage in depth-first pre-order**, process lifelines, parent→
child elbow connectors, a 30-day sparkline plus a draggable 24-hour band, a
bounded merge cache with lane/time prefetch, server-side filters, a
right-click pivot menu, an event-details pane with MITRE / observables /
detection / provenance sections, and a deep-link **focus handoff** endpoint
that resolves a detection or raw/canonical event id to an exact observation.

So V2 is mostly **completion and interaction work**, not a rewrite. The
honest deficits cluster in five places: no Events→Trajectory entry point, no
first-class relationship/detection/density contract, no search-match
navigation, no raw-evidence tab, and no keyboard / resizable-inspector
ergonomics.

## Parity report — per dimension, no aggregate score

| Dimension | State | Why |
|---|---|---|
| **UI parity** | PARTIAL | Three surfaces exist (header+navigator, canvas, details) but the inspector is a fixed 348 px column (`EdrDeviceTrajectoryPage.jsx` `DETAILS_W = 348`, :47) and is neither resizable nor collapsible-to-overlay |
| **Navigation parity** | PARTIAL | Wheel = rows, shift+wheel = time, ctrl+wheel = zoom, drag = pan (`AmpCanvas.jsx` :122-157, :89-104); **no** explicit zoom-in/out/reset buttons, **no** jump-prev/next event, **no** jump-prev/next detection, **no** keyboard shortcuts (zero `keydown` handlers in the whole folder) |
| **Timeline parity** | GOOD | 30-day activity band + 24-hour band with triangle handles and window drag (`AmpNavigator.jsx` :221-370); day pinning via `hist_day`; time window drives the request (`time_start`/`time_end`) |
| **Relationship parity** | PARTIAL | Process→process lineage is real and evidence-derived (`build_lane_catalogue` :614-700, lineage pre-order :678-700, `parent_state` PENDING / PARENT_NOT_REPORTED_BY_SENSOR / PARENT_NOT_IN_FILTERED_VIEW). Process→file/registry/DNS/network is **implied by lane grouping only** — there is no typed edge list, so "what did THIS process touch" is not directly answerable |
| **Search / filter parity** | PARTIAL | Server-side `q`, `kinds`, `dispositions` with a filter-scoped axis rebuild (:980-1010); **no** match-of-N navigation, no field-scoped search (hash, IP, domain, PID, canonical id are all matched as one substring) |
| **Evidence parity** | PARTIAL | Inspector shows canonical fields, detection attribution, MITRE, observables, provenance ids (`AmpEventDetails.jsx` :216-425). **No byte-preserved RAW payload tab**, although `GET /api/edr/events/{raw_id}` already exists (`edr_events.py` :393) — pure wiring |
| **Telemetry coverage** | HONEST, NARROW | Exactly 8 Windows families canonicalised; everything else retained raw and reported as an explicit gap. Verified in production (S1-S5). Coverage is a *header* statement, not a timeline band |

## Requirement-by-requirement

Legend — **OK** already satisfied · **FE** frontend work only · **BE** backend
work needed · **FE+BE** both · **TEL** limited by telemetry, not by code.

| § | Requirement | State | Evidence / what is missing |
|---|---|---|---|
| 0 | Never fabricate; UNKNOWN ≠ ABSENT | **OK** | The codebase is already built on this: `DISPOSITION_UNKNOWN = "UNKNOWN_NOT_ASSESSED"` (:76), `assessment_state` NO_DETECTION_CLAIMED_THIS_OBSERVATION (:827), `process_state` OBSERVED/UNKNOWN, `NOT_COLLECTED` header objects (`edr.py` :1073), `exit_observed` instead of an invented end |
| 1 | Analyst workflow event→focus→relations→time→pivot | **FE+BE** | Focus handoff exists (`trajectory_focus` :1540, consumed at `EdrDeviceTrajectoryPage.jsx` :334-371); the loop breaks at "show me this process's files/DNS/network" because there is no relationship query |
| 2 | Three coordinated surfaces | **OK** (layout) / **FE** (proportions) | Present; inspector width fixed |
| 3 | Time navigation: density, handles, pan, zoom ±, reset, jump event/detection, fit | **FE** | Density + handles + pan + wheel-zoom exist; the six explicit controls and both jump families do not |
| 3 | Preserve selection + context across a window change | **FE** | Filter change clears cache, rows, lanes and selection by design (:113-120). Correct for a *filter*; too aggressive for a *time* change |
| 4 | Relationship model with evidence-backed edges | **BE** | `relationships[]` does not exist in the response. Substrate is available: every row carries `process_iid`, `parent_process_iid`, `artefacts_iids`, `file_artefacts`, and file/registry/DNS/network lanes are keyed on the real object (`_group_and_key` :138) |
| 5 | Process lifelines with full identity | **OK** / **TEL** | Lifelines drawn (`AmpCanvas.jsx` :421-426) from `first_seen`/`last_seen`/`exit_observed`. Windows identity is genuinely strong: `ProcessGuid`→`process_iid` (`canonical_bridge.py` :414, `canonical.py` :214-220). **TEL**: no signer/signature/integrity for Windows yet; Sysmon 1 gives hashes + command line, 4688 gives neither guid nor hashes (documented downgrade `windows_eventlog.py` :613-637) |
| 6 | Expand / collapse density control | **FE+BE** | Not present at all — the axis is a flat virtualised list. Needs a collapsed/expanded lineage model on the axis (BE) plus carets (FE) |
| 7 | Selection keeps timeline, filters, zoom, context | **OK** | `onSelect` sets state only (`AmpCanvas.jsx` :259); no scroll hijack |
| 7 | Inspector docked, resizable, independently scrollable, collapsible | **FE** | Docked and independently scrollable; not resizable, no overlay mode |
| 8 | Inspector tabs SUMMARY/PROCESS/RELATIONSHIPS/EVIDENCE/DETECTION/RAW/PROVENANCE | **FE** (+**BE** for RELATIONSHIPS) | Today it is one scrolling column with sections (`AmpEventDetails.jsx` :216-425). RAW needs only `GET /api/edr/events/{raw_id}`; RELATIONSHIPS needs §4 |
| 9 | Deep-linking event→exact trajectory context | **PARTLY OK / FE** | URL already carries `device`, `at`, `event`, `process_iid`, `detection`, `raw_event_id`, `canonical_event_id`, `incident` (:182, :325-347, :444-448) and `trajectory_focus` resolves them. **The Events page never links to it** — zero `device-trajectory` references in `EdrEventsPage.jsx`. Detections page does (`EdrDetectionsPage.jsx` :129) |
| 10 | Field-scoped search + match navigation | **FE+BE** | `q` is one case-insensitive substring over a row projection (`_matches` :855). No `MATCH n OF m`, no prev/next, no field scoping |
| 11 | Filter groups (activity / detection / evidence status) | **PARTIAL** | `kinds` + `dispositions` exist; evidence-status filters (canonicalised / raw-only / unsupported / parse failure) do not, though `parser_state` is already carried in provenance (:846) |
| 12 | Investigation path highlighting, focus vs show-all | **FE** | Lineage connectors are drawn but there is no dimming of unrelated rows and no focus/show-all toggle |
| 13 | Navigable detection markers | **PARTIAL FE** | Markers are rendered per row (`AmpCanvas.jsx` :414) and rows are clickable, but there is no detection-marker navigation (next/prev detection, jump-to-time-and-select) |
| 14 | Context menu pivots | **OK** | Right-click menu with sectioned actions and `onPivot` (`AmpCanvas.jsx` :159-178, :529-575; handler `EdrDeviceTrajectoryPage.jsx` :481). Response actions correctly absent |
| 15 | Scroll isolation + sticky controls | **PARTIAL FE** | Canvas owns its own wheel semantics and declares them (`data-wheel-navigation="rows\|shift-time\|ctrl-zoom"` :176); the page-level stickiness of header/toolbar and the inspector's independent scroll region need auditing at real viewport sizes |
| 16 | Large datasets: windowing, cursor, virtualization, abort, prefetch | **MOSTLY OK** | Opaque `(timestamp, event_iid)` cursor (:104), `MAX_LIMIT 4000`, bounded first paint then background warm of the complete projection (:944-960), per-lane bucketing (:1028), TTL'd projection cache, client merge cache `CACHE_MAX 28` with `LANE_PREFETCH 14` / `TIME_PREFETCH 0.3`. **Gap**: no stale-request abort (no `AbortController` in the folder) |
| 17 | Backend contract: observations / relationships / detections / density / coverage | **BE** | Response has observations (`events`), `lane_axis`, `activity`, `event_type_counts`, `projection`, `time_range`, `provenance`, `epistemic_state`. **Missing as first-class**: `relationships[]`, `detections[]`, `density[]`, `coverage[]` |
| 18 | Coverage bands on the timeline | **BE+FE** | Only a canvas label "no sensor coverage" (`AmpCanvas.jsx` :211) and the header epistemic message. There is no per-interval band distinguishing OBSERVED / NOT_COLLECTED / NOT_CANONICALIZED / PARSE_FAILURE / EVALUATION_FAILED |
| 19 | Unsupported Windows events stay raw + explicit | **OK** | Proven in production S5 and enforced in `windows_eventlog.py`; nothing in the trajectory path promotes them |
| 20 | Do not regress the 8 supported classes | **OK** | Sysmon 1/3/11/12/13/22 + Security 4688/4624; trajectory lanes already recognise REGISTRY / DNS / AUTHENTICATION groups (`trajectory_window.py` :52, :64-70) |
| 21 | Natural before/after investigation loop | **FE+BE** | Depends on §3 jumps, §4 relationships, §6 expansion |
| 22 | Keyboard operations | **FE** | None exist |
| 23 | URL/session state survives refresh and Back | **PARTIAL** | Device/lane/at/event are written with `replace: true` (:322, :371) — Back therefore does **not** step through investigation states; filters, search, zoom and disposition are not in the URL |
| 24 | Responsive width, resizable/collapsible inspector | **FE** | Fixed 348 px; small screens crush the canvas |
| 25 | Events↔Trajectory integration, richer event table | **FE** | Events page has saved views + copy-link (:139-190) but **no** per-event actions (open details / open trajectory / open process tree / copy canonical id / hunt). Column config and CSV export also absent — owner flagged these as out of scope for this gate |
| 26 | Security invariants | **OK** | Every trajectory route is `Depends(get_current_user)` + `Depends(edr_tenant)`; scope resolved server-side via `_tenant_scope` / `endpoint_predicate`; projection creates no store (`creates_no_store: True`); no response action reachable from the canvas |
| 27 | Performance against the real endpoint | **TO PROVE** | The code is written for scale (bounded first paint, background warm) and comments cite a 205k-observation endpoint, but no measured evidence exists for the Windows endpoint at DT2 interaction rates |
| 28 | 23-step analyst acceptance story | **BLOCKED** | Steps 4-6, 14-17 and 23 cannot pass today (no Events entry point, no match navigation, no detection navigation, no raw tab, Back does not step) |
| 29 | No parity claim from visual similarity | **ACK** | This document reports per-dimension state and no aggregate percentage |

## Backend contract delta (the only truly structural work)

```
TrajectoryWindow  today                     needed
  events[]        ✓ observations            keep
  lane_axis       ✓ lanes + lineage order   keep
  activity        ✓ day/type buckets        promote to density[] per interval
  projection      ✓ state + basis           keep
  —                                          relationships[]  (typed, evidence_ref)
  —                                          detections[]     (navigable markers)
  —                                          coverage[]       (per-interval bands)
```

`relationships[]` must be **derived server-side from canonical evidence**, never
assembled in the client from display strings. The inputs already exist per
observation: `process_iid`, `parent_process_iid`/`parent_iid`,
`artefacts_iids`, `file_artefacts`, and object-keyed lanes for FILE / REGISTRY
/ DNS / NETWORK.

## What telemetry cannot do today (TEL — not a UI bug)

1. Process **end** time on Windows: Sysmon 5 (process terminated) is not in the
   supported set, so lifelines legitimately end in `exit_observed: false`.
2. Signer / signature status / integrity level: not canonicalised
   (`windows_eventlog.py` :90 lists them as not-supported for PROCESS).
3. Security 4688 has no `ProcessGuid` and no hashes — identity is a documented
   downgrade, so its lineage is weaker than Sysmon 1's.
4. File **read** activity, module loads, process access, WMI, scheduled tasks:
   not collected → must render as NOT COLLECTED bands, never as silence.
5. `ATT&CK` mapping comes from a deterministic keyword mapper
   (`v2/ingestion/mitre_map.py`), so the inspector must label it as derived,
   not as an authored detection claim.

Widening any of these is **coverage expansion — a separate task**, per §19.

## Proposed slice plan (for Phase B approval, not implementation)

| Slice | Content | Layer |
|---|---|---|
| DT2-0 | `relationships[]` + `detections[]` + `density[]` + `coverage[]` contract, with tests asserting every edge carries an evidence ref | BE |
| DT2-1 | Explicit time controls: zoom ±/reset/fit, jump prev/next event, jump prev/next detection, selection-preserving window change, request abort | FE |
| DT2-2 | Events page → Trajectory entry point (row action + inspector action) using the existing focus handoff; URL push (not replace) so Back steps | FE |
| DT2-3 | Relationship rendering: object edges, focus-relationship dimming, show-all, expand/collapse carets | FE (+BE axis collapse) |
| DT2-4 | Inspector V2: tabs incl. RAW via `/api/edr/events/{raw_id}`, resizable, overlay mode on narrow screens | FE |
| DT2-5 | Field-scoped search + `MATCH n OF m` prev/next navigation | FE+BE |
| DT2-6 | Coverage bands + evidence-status filters (`parser_state`) | FE+BE |
| DT2-7 | Keyboard operations, sticky controls, scroll-isolation audit | FE |
| DT2-8 | Performance proof against `ep_1989031c8c1d0085812f` at interaction rates | Test |
| DT2-9 | The 23-step analyst acceptance story, captured | Test |

## Stop

Phase A ends here. No file under `backend/` or `apps/` was modified. Awaiting
owner review before producing `DEVICE_TRAJECTORY_V2_ARCHITECTURE.md` (Phase B).
