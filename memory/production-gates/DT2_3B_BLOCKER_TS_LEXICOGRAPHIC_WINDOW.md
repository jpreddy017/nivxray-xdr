# DT2-3b BLOCKER · `TS_LEXICOGRAPHIC_WINDOW_EXCLUSION`

Found while starting DT2-3b against the REAL Windows corpus
(dev_2adbb41a04a4 / DESKTOP-A9HGFJJ, tenant ten_f1a5479243e901cf159e230fa0).

CODE_CHANGED: **NO** · DATA_CHANGED: **NO** · STOPPED FOR OWNER REVIEW.

## Symptom

`GET /api/edr/endpoints/dev_2adbb41a04a4/trajectory?time_start=2026-09-22T15:40:00.000Z&time_end=2026-09-22T16:50:00.000Z`

```
observations_all_time  : 3298
matched_after_filters  : 3298
matched_in_time_range  : 4          ← should be ~3298
matched_in_window      : 0
events                 : []
dt2.graph.process_nodes: 0
epistemic_state        : NO_ACTIVITY_IN_RANGE
lane_axis.total_lanes  : 155        ← the SAME read lists 155 lanes whose
                                      first_seen/last_seen are inside the
                                      requested window (15:43 → 16:20)
```

The endpoint reports "no activity observed in this time range" for a window
that demonstrably contains 3294 observations it is simultaneously describing in
its own lane axis.

## Root cause (exact)

`/app/backend/edr_plane/trajectory_window.py` lines 1021–1026 filter the time
window by **lexicographic string comparison**:

```python
in_time = (filtered if no_time_bound
           else [r for r in filtered
                 if (not time_start or (r["timestamp"] or "") >= time_start)
                 and (not time_end or (r["timestamp"] or "") <= time_end)])
```

`r["timestamp"]` comes from `_ts()` (line 134) = `event.ts` verbatim.

Genuine Sysmon telemetry stores its own instant in Sysmon's native
`EventData/UtcTime` format — **space separated, no zone designator**:

```
stored event.ts : "2026-09-22 15:43:31.770"
query bound     : "2026-09-22T15:40:00.000Z"
"2026-09-22 15:43:31.770" >= "2026-09-22T15:40:00.000Z"  →  False
```

because `' '` (0x20) sorts before `'T'` (0x54). Every space-format timestamp is
therefore excluded from every windowed read. The 4 records that DID match are
the Windows Security Log events, which happen to carry
`2026-09-22T16:46:06.3636853Z`.

The raw string enters the pipeline unnormalised at
`/app/backend/edr_plane/windows_eventlog.py:553`:

```python
activity_time = (_s(data.get("UtcTime")) or _s(system.get("time_created")) ...)
```

`_s()` preserves the source string; nothing converts it to RFC 3339 before it
becomes `event.ts`. (The investigation-pipeline normalizer
`normalizers/base.py` DOES understand `"%Y-%m-%d %H:%M:%S.%f"`, so the two
paths disagree.)

## Blast radius (measured, nothing modified)

```
v2_shadow_observations total                 : 252834
space-separated event.ts (no 'T', no 'Z')    : 3333   — 100% adapter=sysmon-normalizer
devices affected                             : 13
  dev_2adbb41a04a4 (ten_f1a5479243e901cf159e230fa0)  3294
  12 further devices in tenant `default`                39
```

Every genuine Sysmon observation in this environment is invisible to windowed
Device Trajectory reads. Sorting and cursor paging use the same string tuple
(`(r["timestamp"], r["event_iid"])`), so ordering is also wrong whenever the
two formats mix on one endpoint.

This is NOT the same defect as the W1 fixture single-instant issue. That one
was truthful data. This one silently hides real evidence.

## Why it blocks DT2-3b

DT2-3b is process/file vertical-axis relationship parity. The only real
time-diverse Windows corpus available (101 FILE lanes, 46 PROCESS lanes, 107
real `file_write` events) cannot be read through the windowed endpoint at all,
so no process→file relationship parity can be demonstrated on real evidence.
Per the owner's rule this qualifies as a canonical timestamp / evidence-contract
defect affecting trajectory correctness.

```
BLOCKS_DT2_3B: YES — TS_LEXICOGRAPHIC_WINDOW_EXCLUSION
```

## Candidate fixes (NOT applied — owner decision required)

- **B (read-side, no data change, recommended first):** in
  `trajectory_window.query_window`, compare **parsed instants** instead of raw
  strings (one canonical parse helper, applied to the bound and to
  `r["timestamp"]`), and sort on the parsed value. Fixes all 3333 existing
  records immediately, changes no stored evidence, changes no timestamp value.
- **A (write-side, prevents recurrence):** normalise `EventData/UtcTime` to
  RFC 3339 UTC at `edr_plane/windows_eventlog.py:553` so `event.ts` is always
  `…Z`. Value-preserving (Sysmon's field name declares UTC), but it only
  affects NEW ingestion; the 3333 existing records would need a backfill, which
  IS a data change and needs explicit owner authorisation.
- **C:** both — B now for correctness, A to stop the divergence recurring.

## Correction to an earlier record

`memory/PRD.md` (DT2-3a.2 entry) states: *"NEW BLOCKER
`TELEMETRY_TIMESTAMP_COLLAPSE`: … no per-event UtcTime survives ingestion.
Needs a collector/normalizer fix."* That conclusion is **WRONG** and is
corrected by `DT2_3A2_TIMESTAMP_PROVENANCE.md`: per-event UtcTime survives
ingestion exactly as sent; the W1 fixture simply sent one hardcoded UtcTime for
all 15 records. No collector/normalizer timestamp-collapse defect exists.
