# Queue claim ownership repair — 2026-11-01

## Production checkpoint

Read-only production viewer checks around 08:43 UTC (14:13 IST) returned
2,350,491 PENDING and 206,482 DONE jobs for the Internal Validation customer.
The filters were sampled sequentially, not as an atomic snapshot. The latest
creation-ordered completed job shown was created October 3 at 05:35:06 UTC and
completed November 1 at 08:43:36 UTC. KUSHU's October 31 trajectory still showed
zero loaded events. The incident remains open. Its endpoint header was SILENT,
last seen about two hours earlier; sensor availability is a separate observation.

## Reproduced correctness defect

Baseline: phase2/edr-production at 4d1f4f653863956807fbc5905373554c8c16b375.
In a UUID-named localhost-only Mongo fixture, worker A claimed a job at attempt 1;
its lease expired; worker B reclaimed it at attempt 2. A could then call either
mark_done or mark_retry and overwrite B's PROCESSING state. Both stale transitions
returned True on the baseline. Production evidence was not modified by this test.

## Bounded change

The atomic claim already increments attempts. Pass that returned claim generation
to completion/retry and require tenant, raw ID, PROCESSING state, matching attempts,
and an unexpired lease in the update predicate. No new fields, indexes, queue scan,
claim-order change, worker-count increase, or raw-data migration is introduced.
The normal process_one path passes its claimed generation on both transitions.
Missing/expired ownership cannot complete or release another claim.

This fences queue-state transitions only. It does not make canonical/detection
side effects idempotent, cancel an old worker, renew long-running leases, or fix
the bridge's lookup-then-insert race. It is not the backlog throughput repair.
Do not enable extra workers or workstation processing on the strength of this
change alone. A rolling deployment with old workers still alive is not fully
fenced: old code does not send or enforce the generation check. Stop/drain old
workers before treating the new ownership rule as universal.

## Verification

- check_queue_lease_ownership.py: reassigned success/failure rejected with the
  replacement job unchanged; current owner accepted; tenant isolation; exact
  lease expiry rejected; delayed retry and reclaim; completed-state protection.
- check_queue_claim_indexes.py: 50,000 synthetic jobs; pre-index 40,000 docs/77 ms
  with SORT; post-index one doc/1 ms without blocking SORT; FIFO, readiness,
  expired lease recovery, 24 concurrent claims, completion and retry all pass.
- Eight existing worker unit tests pass (0.15 s) with the candidate explicitly
  imported from /root/edr-lease-release, not the running /app copy.
- SHA256 of the tested processing_queue.py:
  c1a88ac97928d33d8d6e0cf131d2c5a295cff8138c8df0a36e9b692b822e8baa.

All Mongo fixtures use localhost and delete only their own synthetic UUID database.
No application environment files or production database credentials are used.

## Next bounded work

Profile production stage costs and establish bridge-side idempotency before
increasing concurrency. The isolated six-event full-worker profiler previously
measured about 6–8 ms after warmup; that is not a production capacity estimate.
The workstation connector, local raw store and remote result publication remain
proposals, not deployed components. Keep raw evidence retained and purge disabled.
