# Device Trajectory normalization backlog repair — 2026-11-01

## Observed production behavior

KUSHU (`ep_a67be48d5b4e01d4d9e8`) has raw Windows telemetry in
`edr_raw_events`, but its October 31 trajectory window returns zero projected
events. A September 30 window renders 200 events with zero compromise indicators.
Normal activity is therefore not intentionally gated by compromise status.

Read-only inspection of the production database viewer showed about 2.70 million
raw records and 2.54 million queue documents. The customer-scoped DONE filter
returned 184,161 jobs at sampling time. Jobs created October 3 were completing on
November 1, approximately 15–19 seconds apart. A sampled recent raw event,
`raw_7beaecb01e37ef32e5bc2c52`, was PENDING with zero attempts. The worker is
advancing through old work; it is not simply absent. These are sampled observations,
not an exhaustive production query profile or a guaranteed backlog-clearance ETA.

## Current architecture and failure

Authenticated sensor ingestion durably stores immutable raw evidence and enqueues
a reference. A leased worker invokes `canonical_bridge`, which writes normalized
shadow/canonical evidence. Trajectory reads those normalized stores; Events can
display raw evidence before derivation completes. The bridge is still present.

`claim()` atomically selects the oldest eligible job across PENDING, ready RETRY,
and expired PROCESSING leases. The previous indexes put eligibility range fields
before `created_at`. On a disposable 50,000-document Mongo fixture, the actual
claim predicate required scanning 40,000 ready jobs and a blocking SORT to select
one. Repeating that work for each job makes a growing backlog increasingly costly.

The bridge's tenant/activity-identity duplicate lookup already has a startup
index declaration in `server.py`; this patch does not alter that lookup.

## Target and implementation

Keep the existing durable pipeline and atomic claim semantics. Add the non-unique
`fifo_work` index with fields `state, created_at, available_at, lease_until`.
Equality branches can merge creation-ordered index streams and stop after finding
one eligible job. Existing indexes remain for compatible rollback. No query hint
is required by the tested planner. There is no raw-evidence fallback, fabricated
activity, replay, purge, deletion, change to tenant boundaries, or change to FIFO,
lease and retry rules.

Flow after deployment remains: raw retained → durable queue → indexed atomic claim
→ canonical bridge → normalized stores → trajectory timeline/activity/details.
Only the claim access path changes. Historical jobs still need to drain.

## Verification

`python tools/edr/check_queue_claim_indexes.py` uses only a uniquely named local
Mongo fixture, never application environment files or a production connection.
It exercises the actual `claim()` predicate/update through `explain(findAndModify)`
and executes real claims. It verifies planner work, oldest eligible selection,
future retry exclusion, active lease exclusion, expired lease recovery, 24
concurrent claims without duplicate assignment, completion, retry delay, and
idempotent startup index creation. It removes only its own synthetic fixture.

The initial read-query probe improved from 40,000 examined documents / 73 ms to
one document / 1 ms without a hint. The actual atomic-write query improved from
40,000 documents / 76 ms with SORT to one document / 1 ms with SORT_MERGE.
The readiness, FIFO, lease, completion, retry and concurrent-claim checks passed.
Fixture latency is not a production throughput promise.

## Deployment and production acceptance

This is a backend repair. A Vercel frontend deployment alone cannot apply it.
Emergent must publish the reviewed backend containing the new index declaration.
Startup creates the additive index before starting the durable workers. Building
an index on a large production collection consumes resources and can extend startup;
watch deployment/index logs and avoid overlapping publishes.

After publication, confirm the index exists, completed-job throughput rises, the
oldest pending creation time advances, retry/error rates remain acceptable, and
arrival rate is below sustained processing capacity. Then verify KUSHU's October
31 and current windows, event details, older loading and deep links. Zero findings
must continue to allow ordinary normalized activity. Keep purge disabled.

If processing still cannot catch up after the index exists, profile the complete
worker/bridge path and measure ingestion versus service rate before choosing a
bounded worker-capacity change. Do not silently prioritize recent work by dropping
or skipping historical evidence. Report the remaining lag explicitly.

Rollback uses the preceding Emergent backend version; the additive index can
remain. No index deletion or evidence rollback is necessary.

## Reference behavior

Cisco describes Device Trajectory as a view of endpoint activity and telemetry,
including benign and malicious activity, rather than a list limited to compromise
detections. MongoDB's ESR guidance explains the equality/sort/range ordering used
by the added index.

- https://blogs.cisco.com/security/stopping-attacks-early-the-power-of-endpoint-telemetry-in-cybersecurity
- https://www.mongodb.com/docs/v7.0/tutorial/equality-sort-range-guideline/
