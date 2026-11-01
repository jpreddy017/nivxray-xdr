# Device Trajectory recovery tracker — 2026-11-01

## Acceptance

Recent and historical accepted activity must be queryable and visible in Device Trajectory, Activity Details and process relationships. Successful deployment, a connected badge or ingestion counters alone are insufficient. Preserve raw evidence, tenant isolation and existing products. Production database inspection remains read-only through the approved viewer.

## Completed production work

- Queue claim index removes the blocking FIFO sort (PR 33).
- Attempt-generation and live-lease completion fencing prevents an expired owner from finishing a reclaimed queue job (PR 34). This does not make bridge side effects idempotent.
- Existing worker alternates newest/oldest ready jobs (PR 35, source merge 1b2e71327f55d604ebad9e45acbec17e225d5a65, Emergent d892870). This changes scheduling, not capacity. Middle-age starvation under overload and tenant fairness remain unresolved.

## Step 1: exact inserted canonical record update

The full pipeline inserted a canonical document, then updated its evaluation timestamps with only event_id. That predicate could update another tenant's same-identifier record and can require a linear scan when a suitable event_id index is absent. The correction uses the insert result's _id plus tenant_id. No index, schema, ACK, worker count, retention or evidence migration changes.

Local synthetic real-Mongo A/B fixture: 50,000 seed rows, another tenant's same-event-id row inserted before the intended row. External HTTP is disabled. Baseline: 50,001 documents examined, zero keys, foreign row changed and intended row unstamped. Candidate: one key/document examined, foreign row unchanged and intended row stamped. Timings (25.520 ms vs 4.506 ms whole fixture pipeline) are synthetic, not production throughput. Current production index availability is not verified; do not claim a measured production collection scan.

Run the retained regression with tools/edr/check_canonical_write_identity.py. It forces localhost Mongo, uses UUID-named synthetic databases, and drops only those fixture databases. Optional --baseline accepts a frozen pre-fix pipeline for A/B verification.

Compatibility: 83 tests passed with candidate module loaded and pytest xdist disabled: test_xdr_round11_pipeline.py, edr/test_phase0_windows_canonical_bridge.py, edr/test_p1_10a_spread_watchlist.py and edr/test_c1_canonical_event_identity.py. No test expectations changed. Preview /app sources remain unchanged while testing the isolated candidate.

## Remaining ordered work

1. Release the exact-document backend update; verify source hash and backend health, then compare queue progress and trajectory coverage.
2. Finish existing frontend regression/build checks and release the prepared 10-second refresh candidate. Ten isolated mounted tests pass; it advances live bounds, preserves fixed historical bounds, avoids overlapping polls and pauses during details/older-page inspection. Not yet deployed.
3. Trace recent, missing October and visible historical samples through raw record, job, shadow/canonical evidence, query and rendered result. Keep occurrence, receipt and processing time separate.
4. Measure stage duration, arrival/completion rate, oldest pending age and database/CPU utilization. Additional workers require bridge retry/concurrency side effects to become safe first.
5. If capacity remains insufficient, implement durable handoffs separating activity publication and analysis, with separate completion status and resumable idempotent stages. Do not bypass tenant attribution or discard pending work.
6. Verify multiple historical dates, current activity, details and process relationships. Full AMP capability parity remains a separate, unfinished product objective.

## Endpoint delivery observation

Fresh production Overview inspection during this step: KUSHU ep_a67be48d5b4e01d4d9e8 in Internal Validation is SILENT; authenticated telemetry approximately 4,849 seconds old, no recent heartbeat, 52,370 received events. Last-reported sensor queue is 248,308; it is not a current locally measured queue depth. The page reports 8,709 evaluated events in its last-24h projection. Backend processing progress does not establish current sensor delivery. Endpoint service/network diagnostics remain needed if silence persists; workstation access has not been established.

## Earlier path transition

Commit aaaeb8995a2842466ae7adb1372729ec1a1b762e (2026-10-01 15:07:52 UTC; deployment date unverified) changed raw append -> synchronous bridge -> ACK into raw append -> durable enqueue -> ACK, with one processing worker started by server.py. Preserve that durability boundary; repair capacity and stage recovery rather than returning to an ACK path that awaits full analysis.

## Rollback

Restore only backend/detection_content/xdr_pipeline.py from 1b2e71327f55d604ebad9e45acbec17e225d5a65 and republish. No evidence/index rollback is required. Do not revert unrelated preview changes or shared product files.
