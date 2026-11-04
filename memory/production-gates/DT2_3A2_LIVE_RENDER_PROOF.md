# DT2-3a.2 · LIVE RENDER PROOF (owner acceptance submission)

Captured 2026-06 (session rerun) against the CURRENT BUILD.
ZERO React/trajectory code changes were made to produce this proof.

Device: dev_0e10780f2c86 (WS-W1-1789575060, tenant `default`)

## Viewport (read from rendered DOM instrumentation)

| Metric | Value |
|---|---|
| VIEWPORT_START | 2026-06-01T09:59:00.000Z (`data-dt2-view-from`) |
| VIEWPORT_END | 2026-06-01T10:01:00.000Z (`data-dt2-view-to`) |
| VIEWPORT_DURATION_MS | 120000 (`data-dt2-view-ms`) |
| DRAWABLE_LEFT_PX | 238 (`data-dt2-left`) |
| DRAWABLE_WIDTH_PX | 1000 (`data-dt2-drawable-width`) |
| VISIBLE_ROW_COUNT | 17 rendered / 17 total (`data-dt2-rendered-lanes` / `data-dt2-lane-count`) |

## Evidence span (authoritative, storage + API)

| Metric | Value |
|---|---|
| EVIDENCE_MIN_TIMESTAMP | 2026-06-01T10:00:00Z |
| EVIDENCE_MAX_TIMESTAMP | 2026-06-01T10:00:00Z |
| EVIDENCE_SPAN_MS | 0 |
| EVIDENCE_PERCENT_OF_VIEWPORT | 0.00 % |
| EVIDENCE_PIXEL_SPAN | 0.00 px |

Storage ground truth: all 15 `v2_shadow_observations` records for this device
carry `event.ts == "2026-06-01T10:00:00Z"` verbatim. They differ only by
`event.sequence` (0..14). This is not API truncation — the corpus itself has a
single instant.

## Rendered proof (expected X computed independently)

expectedX = 238 + ((t − 09:59:00.000Z) / 120000) × 1000

| EVENT | TIMESTAMP | ROW | X | Y | EXPECTED_X | DELTA_PX |
|---|---|---|---|---|---|---|
| activity FILE C:\Users\Public\payload.exe | 2026-06-01T10:00:00.000Z | pnode:proc_836bad7d4aa3 | 738.00 | 203.00 | 738.00 | 0.00 |
| row start certutil.exe | 2026-06-01T10:00:00.000Z | pnode:proc_836bad7d4aa3 | 738.00 | row 2 | 738.00 | 0.00 |
| row start payload.exe [FILE] | 2026-06-01T10:00:00.000Z | pnode:...::payload.exe | 738.00 | row 3 | 738.00 | 0.00 |
| row start wmic.exe | 2026-06-01T10:00:00.000Z | pnode:proc_19f187c8c8ea | 738.00 | row 5 | 738.00 | 0.00 |
| row start powershell.exe | 2026-06-01T10:00:00.000Z | pnode:proc_2926e8542ed7 | 738.00 | row 6 | 738.00 | 0.00 |

Five same-row activity events: **NOT OBSERVED IN ACCEPTANCE CORPUS**
(the corpus contains exactly ONE activity node; 11 rows carry a row-start
instant, 4 rows are "Unknown process" with no observed time and therefore draw
no glyph).

## Classification

- TIME_DOMAIN_BUG: **FIXED**
- TIMESTAMP_TO_X_PROJECTION: **PASS** (delta 0.00 px on every measured event)
- ROW_Y_ASSIGNMENT: **PASS** (one row per node, 17 distinct Y bands)
- VERTICAL_STACK_CAUSE: **C — real timestamps are genuinely identical**
  (EVIDENCE_SPAN_MS = 0). Secondary: D, the marks sit on different trajectory
  rows, which is correct.

## Owner decision required

Horizontal spread is arithmetically impossible for this corpus without
fabricating time. No spacing, jitter, minimum-separation or synthetic duration
will be introduced.
