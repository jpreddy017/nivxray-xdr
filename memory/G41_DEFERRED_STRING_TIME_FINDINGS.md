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

## Sequencing note
Each of these is its own gate and its own proof. None should be bundled with a
feature. Measure the representation space of `event.ts` before deciding whether
item 3 needs a shadow-side `observation_us` at all.
