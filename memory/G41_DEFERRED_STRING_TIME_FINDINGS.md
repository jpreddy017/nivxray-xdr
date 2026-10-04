# G-41 · RECORDED, DEFERRED: remaining raw-string time behaviour

Recorded 2026-06, at owner instruction, when the canonical transitional legacy
reader was retired. **NOT in scope of that task and NOT changed.** These are
recorded so they cannot be forgotten, and so a future reader does not mistake
"G-41 canonical boundary closed" for "this platform no longer selects on a
stored time string".

The canonical Device Trajectory evidence read (`production_adapter`) is now
exclusively `(observation_us DESC, _id DESC)`. The three items below are
separate code paths that were never part of the G-41 canonical boundary.

## 1 · `GET /api/edr/endpoints/{id}/trajectory/hours`
`backend/routers/edr_trajectory_v3.py:100`

Selects with a lexicographic ISO prefix range on the raw stored time
(`OBSERVATION_TIME_KEY[store]`), widened one day each side, then
`.sort(tkey, -1).limit(CAP)` with `CAP = 200_000`, and places exactly in
Python on `observation_us`.

Not the G-41 defect in its acute form: the widening plus a 200k cap plus exact
Python placement means a normal day cannot be mis-attributed. The latent risk is
the same family — the LIMIT is applied under a string sort, so on an endpoint
whose retained history inside the widened window exceeds `CAP`, which rows are
dropped is decided by byte order, and `truncated: true` reports it as a lower
bound rather than hiding it.

## 2 · `GET /api/edr/endpoints/{id}/trajectory/file-facts`
`backend/routers/edr_trajectory_v3.py:181`

`.sort(tkey, 1).limit(5_000)` on the raw stored time, ascending, to find the
first observation of a hash or path. A string ascending sort with a 5,000 limit
can return a "first seen" that is not the earliest in time when both stored
representations are present for that file, because every space-format row sorts
below every `Z`-format row within a calendar date.

This is the clearest residual correctness exposure of the three.

## 3 · the shadow store `v2_shadow_observations`
`COMPARABLE_TEMPORAL[STORE_SHADOW] = False`

It has no `observation_us` at any row. Selection, ordering, LIMIT and the cursor
resume bound all remain on the raw `event.ts` string (the cursor's per-store `b`
map now exists solely for this store). The adapter still applies exact
microsecond placement afterwards, so ORDER is right; SELECTION under a LIMIT
carries the same weakness G-41 removed from canonical — but only if this store
ever holds two representations of the same clock. That has not been measured.

## 4 · cursor-interface roughness on the production trajectory route
Found 2026-06 while taking the authenticated resume proof. Neither is a G-41
temporal defect; both are client-contract issues.

a. An **empty** `e3_cursor` silently restarts from page 1. `routers/edr.py:1101`
   evaluates `cursor=e3_cursor or before`, so `""` is falsy, falls through to
   `before`, and `production_adapter.py:347` skips `_decode` entirely. A client
   that reads the cursor from the wrong property path therefore receives a
   perfectly valid FIRST page that looks like a successful resume. That is
   exactly how a false resume was produced during the G-41 proof.

b. A **malformed non-empty** cursor raises `BadCursor` at
   `production_adapter.py:347`, which propagates to the route's blanket
   `except` at `routers/edr.py:1103` and degrades the whole `e3` block to
   `E3_PRODUCTION_CONTRACT_UNAVAILABLE`. A client input error is thus presented
   as a backend capability outage instead of a clean 400.

c. Related shape note for whoever writes the UI client: the paging envelope
   (`items`, `has_more`, `next_cursor`, `state`, `temporal_health`) is nested
   under `e3.page` (`production_service.py:150`), NOT directly under `e3`.

## 5 · two production findings surfaced by the retirement validation
NOT caused by the retirement, NOT in its scope, must not be forgotten.

a. **403 storm on `POST /api/edr/agent/session`** — 46 in one sampled page
   (truncated), only occasional 200s. Agents rejected at session
   establishment. Unreconciled alongside it: `telemetry/batch` showed 1 request
   in a 1440-minute window and `agent/commands` 0, yet `xdr_canonical_evidence`
   grew +308 over the same period. Either ingest arrives by a path those greps
   do not cover, or the log sampling is badly truncated. Not guessed at.

b. **Stale migration lock, pre-dating the deploy by ~90 minutes** —
   `e3_migration_locks` holds `verify_canonical_observation_us`, acquired
   2026-10-04T00:01:52Z, heartbeat dead since 00:09:24Z, actor
   `admin@nivxray.com`, run `mig_d74da541e339403d` still in state RUNNING.
   Root cause is the 30-second gateway timeout: the client disconnected, the
   worker died without releasing, the audit row was never closed. The
   heartbeat/progress liveness logic should make this lock TAKEABLE rather than
   permanently blocking — dead heartbeat plus no observable progress is the
   exact case it was built for — but that remains UNPROVEN until an operation
   actually attempts takeover. The stuck RUNNING row is an audit inaccuracy
   that will mislead the next reader of that collection.

## Sequencing note
Each of these is its own gate and its own proof. None should be bundled with a
feature. Measure the representation space of `event.ts` before deciding whether
item 3 needs a shadow-side `observation_us` at all.
