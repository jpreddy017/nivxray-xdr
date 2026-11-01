# Durable queue freshness repair

Production evidence on 2026-11-01: a KUSHU raw log observed 2026-10-31 and retained at 09:25 UTC has no derivations; its exact queue record is PENDING with attempts=0. Historical trajectory for the same device and customer renders 200 observations. The previous FIFO index and expired-owner repairs are deployed, but the oldest-first queue is still processing October 3 arrivals.

## Scheduling change

Each existing worker alternates a newest-ready claim with an oldest-ready claim. Selection remains one atomic find-and-update, using the same readiness predicates, attempt generation and lease fencing. The first turn after worker startup is newest-ready. No worker, index, database, ingestion contract or evidence timestamp is added or changed. Direct callers retain oldest-first by default.

This reserves half of successful processing turns for recovery and half for fresh arrivals. When only historical work exists, both turns consume it. Future retries and active leases remain ineligible. All jobs remain durable. This is intentionally a scheduling change rather than a throughput claim; chronological FIFO across all jobs no longer holds. Under sustained overload, middle-age jobs can wait until the recovery side reaches them. Per-tenant fairness and sufficient processing capacity remain separate work.

## Validation

- Real Mongo 50,000-job fixture: oldest query examines one key/document in 1 ms; newest query examines three keys and one document in 0 ms, with no blocking SORT.
- Repeated startup, retry readiness, active/expired leases, atomic concurrent claims and stale-owner fencing pass.
- Continuous-arrival fixture: twenty fresh jobs are claimed on fresh turns while twenty oldest historical jobs are claimed on recovery turns; eighty remaining historical jobs are retained.
- Worker regression verifies six consecutive turns alternate fresh/recovery.

These are local synthetic checks, not production throughput measurements. Acceptance requires recent normalized events visibly appearing in production Device Trajectory and Activity. Do not treat a successful deployment as acceptance.

## Rollback

Restore processing_queue.py from production merge 763f1b73e4649c11544e929c095ace892ed8c237 and republish the backend. No data/index rollback is required; existing jobs and lease generations are unchanged.
