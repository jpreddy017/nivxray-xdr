# DT2-3b · CISCO SEMANTICS CLOSE-OUT (A-D) · 2026-09-29

Owner decision: display-side suppression · sensor content-identity task ·
both parity gaps before DT2-3c. Real Windows corpus dev_2adbb41a04a4.

## A · REPEAT-EVENT SUPPRESSION

`apps/nivxray-xdr/src/nivxforge/trajectory/dt2/repeatCache.js`, applied in the
TRAJECTORY PROJECTION only (`graphModel.axisRowsOf`).

Documented windows, User Guide p.401 verbatim: *"When a file triggers an
event, the file is cached for a period of time before it will trigger another
event… Clean files – 7 days · Unknown files – 1 hour · Malicious files – 1
hour."*

```
CLEAN      604800000 ms   documented
UNKNOWN      3600000 ms   documented
MALICIOUS    3600000 ms   documented
SUSPICIOUS        none    NOT DOCUMENTED → NO SUPPRESSION
*_NOT_ASSESSED    none    NOT DOCUMENTED → NO SUPPRESSION
null / conflicting none   NOT DOCUMENTED → NO SUPPRESSION
```

**CACHE_IDENTITY_KEY = REFERENCE BEHAVIOR NOT VERIFIED.** No Cisco source
states the key. The connector is documented to compute a SHA-256 and check a
local cache with it (Operations Guide), but that is the SCAN cache, not
provably the event-trigger cache. NivXForge therefore declares its own:

```
sha256 present            → CONTENT_IDENTITY   · CONTENT_SHA256              · downgraded false
file identity present     → FILE_IDENTITY      · AUTHORITATIVE_FILE_IDENTITY · downgraded false
otherwise                 → PATH_SURROGATE     · OBSERVED_PATH_PLUS_ACTOR_NOT_CONTENT · downgraded TRUE
```

A pathname is never silently equated with content identity.

Suppressed = NOT DRAWN AGAIN. Every suppressed observation is returned on the
surviving event as `suppressed[]`, counted in `suppressedCount`, shown on the
row as `+N suppressed`, and still listed by the Activity pane and the API.
Nothing is deleted, dropped or deduplicated from canonical evidence.

Live result on this corpus: **0 suppressed.** Every observation is
`UNKNOWN_NOT_ASSESSED` — which is NOT Cisco's "Unknown" disposition, it means
no verdict was ever sought — so the rule cannot be established and the
projection fails to no suppression. Correct by the owner's rule.

## B · FILE CONTENT IDENTITY

Raised as P1 sensor work in `DT2_PARITY_BACKLOG.md`. `CLASS_BASIS =
PATH_EXTENSION_DERIVED_NOT_CONTENT_IDENTIFIED` is exposed in the File Type
filter. 0 of 3298 observations carry a SHA-256.

## C · PROCESS DE-SELECTION

Sixth filter category `Processes`, one entry per observed process trajectory
(`amp-filter-proc-<node_id>`). De-selecting removes the row from the graph
only.

Relationship truth after de-select, proven by test and live run:
- the child keeps its own row, its own lifeline and its own
  `parentNodeId` claim — it is NEVER re-parented onto a surviving ancestor
- `data-row-parent-hidden="true"` declares the hidden parent
- no stem is drawn to a row that is not present, so nothing unrelated is
  visually reconnected
- the hidden process's file rows go with it rather than being orphaned onto
  the axis
- observations, edges, children, files, network, DNS and canonical evidence
  are untouched

Live: 8 rows → 7 rows after de-selecting one process; evidence unchanged.

## D · COMPROMISE NAVIGATION

Backend now separates a telemetry kind from a compromise claim:

```
is_detection          kind == "detection" or attribution   (unchanged)
compromise_authority  DETECTION_FABRIC_ATTRIBUTION | MITRE_ATTRIBUTED_EVIDENCE | null
```

Navigator red dots (day band and 24-hour bins) now require
`malicious + compromises`, never `detections`. A compromise bin focuses on
`first_compromise_at` / `first_compromise_iid` — Cisco's "Compromise Events"
jump — instead of the bin's first telemetry observation.

**This removed a FABRICATION.** Before: 3102 Sysmon registry events carried
`kind=detection`, so the navigator drew compromise markers for them. After:
`compromises = 0`, `redDayDots = 0`. The underlying normalizer mis-mapping is
raised as a P1 defect; presentation no longer depends on it.

Also fixed here: `AmpNavigator` parsed `first_timestamp` with `Date.parse`,
which reads Sysmon's space form as the analyst's LOCAL time. Now `msUTC`.

## E · IOC CONTRIBUTORS

`IOC_CONTRIBUTOR_PROVENANCE = MISSING`. Blue halo stays disabled. No
contributor is derived from proximity, process, SHA, user, window or adjacency.

## TESTS

```
dt2_3b_cisco_semantics.test.js   10 · windows, identity hierarchy, fail-closed,
                                      de-select truth, no re-parenting
dt2_3b_filetype.test.js           5
dt2_3b_lifeline.test.js           8
dt2_3a2_viewport.test.js         15
graphModel.test.js               31
dt2_1_engine.test.js             52
                            total 121 vitest passed
backend edr suite                923 passed (6 pre-existing live-API failures,
                                 unrelated, verified pre-existing by stash)
```

DATA_CHANGED: NO · DEPLOYED: NO.
