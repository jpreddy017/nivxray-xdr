# DT2-3b · PROCESS / FILE TRAJECTORY PROOF (real Windows corpus)

Device: dev_2adbb41a04a4 · DESKTOP-A9HGFJJ · tenant ten_f1a5479243e901cf159e230fa0
Corpus: genuine NivXForge Windows collector telemetry (Sysmon EVTX retained).
DATA_CHANGED: NO · TIMESTAMPS ALTERED: NONE.

## 1 · PROCESS node evidence bounds

```
PROCESS nodes in window                 42
with first_evidence_at + last_evidence_at 38
observed span > 0                        10   (max 36m 05s, chrome.exe)
observed span == 0                       28   → truthful point glyph, no line
no evidence bound at all                  4   → no glyph, no line
```

## 2 · Canonical relationships

```
PROCESS_FILE     74   derivation_basis CANONICAL_ACTOR_PROCESS_BINDING
PROCESS_PROCESS  10   derivation_basis CANONICAL_PARENT_PROCESS_IDENTITY
PROCESS_NETWORK   7
PROCESS_DNS       1
inferred / proximity-derived   0
```

## 3 · Five rendered relationships (viewport 15:30:54.046Z → 16:32:14.416Z,
left 238, drawable 1234, span 3 680 369.1 ms)

PROCESS `chrome.exe` · proc_4d4d505a2431 · pid 976 · DESKTOP-A9HGFJJ\jpred
row Y = 167.00 · START_X 492.06 · END_X 1217.94 · TERMINATED false

| FILE | file_write time | REL_X | file row Y | evidence_ref (OBSERVATION / CANONICAL) |
|---|---|---|---|---|
| 001425.log | 2026-09-22 15:48:36.697 | 594.30 | 185 | evt_0dfccf4768bc4eeb / sysmon-11-dfd2276b08a84aed9261a4f252d837e8 |
| 001426.ldb | 2026-09-22 15:48:36.697 | 594.30 | 203 | evt_d7a71e56ea71e68a / sysmon-11-d0f07815f8d0451f883033381d09093a |
| Local State41c0c39f-….tmp | 2026-09-22 15:49:07.503 | 604.63 | 221 | evt_de02ff72a0190762 / sysmon-11-bd846d5f7c474ea595260bd2af699b63 |
| ef1443cf-9fa8-….tmp | 2026-09-22 15:49:07.521 | 604.63 | 239 | evt_2b406ec960de4604 / sysmon-11-2e690897fa274b02b25ae10238f4488d |
| Local State06790e1c-….tmp | 2026-09-22 15:49:17.517 | 607.99 | 257 | evt_c5408e5dd858d140 / sysmon-11-f73429eb07b744f1ab26a0bfcc4b2f2e |

Second span on another row: PROCESS `msedgewebview2.exe` · proc_bb4b60331fdf ·
Y 455.00 · 15:46:45.819Z → 15:53:24.767Z · START_X 557.12 · END_X 690.89 ·
TERMINATED false · 33 PROCESS_FILE stems.

Independent check of the projection:
`492.06 = 238 + ((15:43:31.770 − 15:30:54.046) / 3 680 369.1) × 1234`
`1217.94 = 238 + ((16:19:36.693 − 15:30:54.046) / 3 680 369.1) × 1234`

## 4 · Lifeline rendering

`RelationshipCanvas.jsx` line 341 renders
`<line x1={xOf(lifeline.startMs)} x2={xOf(lifeline.endMs)} y1={mid} y2={mid}>`,
i.e. first observed evidence → last observed evidence, labelled
`OBSERVED_EVIDENCE_SPAN` and `terminated=false` unless real termination
evidence exists (`data-lifeline-semantics`, `data-row-terminated`).

Why the lines were invisible before, and what changed — NO line-drawing code
was touched:

1. `build_lane_catalogue` appended every FILE/NETWORK/DNS lane after ALL 46
   process lanes, so a windowed client holding lanes 0-36 received the
   process rows and none of their artefacts. With no activity evidence the
   server's process lifeline collapsed to the single process-lane instant,
   so `x2 == x1` and the row correctly drew a point. Each non-process lane
   now follows the process lane its OWN evidence names
   (`actor_process_iid`, from the observation's canonical process identity).
2. The client parsed server timestamps with `Date.parse`, which reads
   Sysmon's `2026-09-22 15:43:31.770` as the ANALYST's local time. Replaced
   with `dt2/instant.js` `msUTC`, mirroring `backend/edr_plane/instant.py`.
3. Added `data-row-end-iso`, `data-row-end-x`, `data-row-terminated`,
   `data-row-y` instrumentation so the span is measurable from the DOM.

No row is full width. No line runs viewport-edge to viewport-edge. No
duration is invented. A zero-span row stays a glyph (28 of them in this
window).

## 5 · Stems

`RelationshipCanvas.jsx` line 270-289 draws a stem only when an edge exists:
`r.activityEdge` (server `PROCESS_FILE`) or `edgeFor(graph, parent, child)`
(server `PROCESS_PROCESS`). `activityEdgeFor` matches on `edge_id` alone.
No stem is derived from proximity, filename, PID, user or adjacency —
`graphModel.js` `axisRowsOf` keeps a FILE activity on its process row when
the server published no edge for it.

Stem X = the activity's own authoritative time
(`times.ordering_time ?? source_time`), not the row start.

## VERDICT

```
PROCESS_FILE_RELATIONSHIP_EVIDENCE   SUFFICIENT (74 canonical edges)
HORIZONTAL_OBSERVED_EVIDENCE_SPANS   RENDERED (10 in window)
X = AUTHORITATIVE TIME               PASS (0.00 px deviation)
Y = PROCESS/FILE ROW                 PASS
INFERRED RELATIONSHIPS               NONE
```

Crop: `/app/artifacts/dt2_3b_proof_full.png` (native 1:1).
