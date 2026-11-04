# P0 · DEDUPE PRODUCTION HARDENING — 2026-06 (preview only)

Preview only. No production deploy. No campaign folding, no Retry Visibility
UI, no key rate limiting, no production auth deploy.
Owner-approved counter semantics kept: `events_received` = unique accepted
deliveries, `events_duplicate` = duplicate/retried deliveries.

---

## FAILURE SEMANTICS
The idempotency store is now a **correctness dependency of machine ingestion,
not a best-effort optimisation**. Every path that previously continued without
protection now refuses the request.

| Condition | Before | Now |
|---|---|---|
| store unbound (`MONGO_URL` missing) | processed WITHOUT dedupe | **503 `INGEST_IDEMPOTENCY_UNAVAILABLE`**, `retryable: true` |
| unique-index creation fails | processed without index | **503** (`IdempotencyUnavailable` raised from `_coll()`) |
| claim `insert_one` / resolve raises `PyMongoError` | n/a | **503** |
| cannot record the raw-persisted marker | n/a | **503** with `stage: raw_persisted_marker` |
| claim vanished mid-resolution | n/a | **503** |

- `_coll()` **raises** instead of returning `None`, so no caller can silently
  proceed unprotected. `release()` was deleted outright.
- Nothing is written on the 503 path — verified by asserting the raw count is 0.
- **Authentication is untouched and still evaluated first**: an anonymous
  caller gets `403 ACCESS_DENIED` and the response contains no hint about
  store health (`test_auth_is_not_weakened_by_the_idempotency_gate`).
- The only remaining soft path is `complete()` / `needs_review()` swallowing a
  write error *after* the work is done. Worst case is a **refused retry**,
  never a duplicate — the safe direction.

## CLAIM STATE MODEL
Durable states in `xdr_ingest_dedupe`, with a lease. **No claim is ever
deleted to let a retry through** — that was the mechanism that permitted the
extra raw row. No in-memory lock exists anywhere.

```
CLAIMED        lease held, NOTHING persisted yet
RAW_PERSISTED  raw row written (id recorded), reasoning pending
COMPLETED      fully processed · terminal · retention armed
NEEDS_REVIEW   evidence already persisted but reasoning did not finish ·
               terminal for auto-retry · flagged with review_reason
```

Retry resolution is decided against persisted state, never a wall-clock guess:

| Existing state | Decision | Effect |
|---|---|---|
| `COMPLETED` / legacy `PROCESSED` | `DUPLICATE` | original chain reported back |
| `NEEDS_REVIEW` | `DUPLICATE_NEEDS_REVIEW` | refused; operator must requeue |
| `CLAIMED`/`RAW_PERSISTED`, **live** lease | `IN_FLIGHT` | concurrent copy, no work started |
| `CLAIMED`, **expired** lease | `RESUME_FULL` | nothing persisted → reprocess fully |
| `RAW_PERSISTED`, **expired** lease | `RESUME_FROM_RAW` | reason only, raw row NOT rewritten |

Provenance distinguishes all four owner-required cases: *never processed*
(`stage=NONE`), *partially processed* (`RAW_PERSISTED` / `REASONING_INCOMPLETE`
+ `review_reason`), *successfully processed* (`COMPLETED` + trace/canonical/
incident ids), *safely retryable* (expired lease + `attempt` counter).

Lease takeover is a **single conditional `find_one_and_update`**, so exactly
one worker can own a claim. `LEASE_SECONDS=300` (env-tunable) exceeds
worst-case single-envelope pipeline latency. A record with **no** lease field
(pre-hardening schema) is treated as expired so it can never deadlock as
permanently `IN_FLIGHT`.

`TelemetryReceipt` gained `resumed`; `ReasoningOutcome.status` gained
`DUPLICATE` / `DUPLICATE_NEEDS_REVIEW` / `IN_FLIGHT` plus
`duplicate_of_trace_id`, `delivery_count`, `dedupe_key`.

## TTL / RETENTION POLICY
- **Dedicated field**: `retention_at` (BSON date), TTL index
  `ttl_retention_at` with `expireAfterSeconds: 0`.
- **Set ONLY on a terminal claim** (`complete()` / `needs_review()`). An
  active or in-progress claim carries `retention_at: null`, and MongoDB's TTL
  monitor ignores documents whose field is missing or not a date — therefore
  **an in-flight claim can never be expired out from under a retry**
  (`test_active_claims_are_never_ttl_eligible`).
- **Horizon: 14 days** (`INGEST_DEDUPE_RETENTION_DAYS`). Justification:
  `nivxray-xdr-collector` spools and replays for at most 7 days, so the window
  is **double the supported replay horizon** — a compliant forwarder can never
  outlive its own claim.
- **Replay after the window (documented, tested)**: the claim has been
  reclaimed, so the delivery is indistinguishable from a first delivery and is
  processed as a new event — new raw, canonical, detection and (if the gate is
  met) a new incident. This is only reachable by a collector replaying older
  than 14 days, i.e. outside the supported contract
  (`test_replay_after_retention_window_is_a_new_delivery`).
- **Upgrade guard**: legacy `PROCESSED` claims from the first implementation
  are honoured as terminal and get `retention_at` armed on first contact, so
  they are neither re-claimable nor immortal. Production has no
  `xdr_ingest_dedupe` collection yet (never deployed), so there is no
  production migration to run; the 4 preview leftovers were armed.

## EXACT FILES CHANGED
| File | Change |
|---|---|
| `backend/services/ingest_idempotency.py` | **Rewritten.** `IdempotencyUnavailable`; `_coll()` raises and builds unique + TTL + lookup indexes; `claim()` returns FRESH / RESUME_FULL / RESUME_FROM_RAW / DUPLICATE / DUPLICATE_NEEDS_REVIEW / IN_FLIGHT with atomic lease takeover; `mark_raw_persisted()`, `complete()`, `needs_review()`; `release()` **removed**; `LEASE_SECONDS`, `RETENTION_DAYS`, `TERMINAL`. |
| `backend/routers/xdr_ingest.py` | 503 `INGEST_IDEMPOTENCY_UNAVAILABLE` on claim failure and on marker failure; batch partitioned into fresh / resume / duplicate; raw-persisted marker written per row before reasoning; resumed envelopes reasoned without re-persisting raw; per-envelope `complete()` / `needs_review()` (no release); post-canonical fault also flagged; `TelemetryReceipt.resumed`. |
| `backend/tests/test_p0_dedupe_hardening.py` | **NEW** — 19 fault-injection tests. |
| `backend/tests/test_p0_dedupe_upgrade_guard.py` | **NEW** — 4 upgrade-path tests. |
| `backend/tests/test_p0_ingest_idempotency.py` | 3 assertions updated to the new lifecycle field names. |
| `scripts/restart_retry_proof.py` | **NEW** — real supervisor restart + retry proof. |

**Not changed**: `detection_content/xdr_incident.py` (campaign folding),
`xdr_veee.py`, `xdr_pipeline.py`, `xdr_rbac.py`, any rule or threshold.

## FAULT-INJECTION TEST MATRIX — 23/23 PASS
| Required condition | Test | Result |
|---|---|---|
| dedupe store unavailable | `test_unbound_store_refuses_ingest_with_retryable_503` | **PASS** 503, 0 rows written |
| unique-index/claim write failure | `test_claim_write_failure_refuses_ingest`, `test_index_creation_failure_is_unavailable_not_unprotected`, `test_store_error_during_claim_is_translated` | **PASS** |
| auth not weakened by the gate | `test_auth_is_not_weakened_by_the_idempotency_gate` | **PASS** 403, no leak |
| crash **before** raw persistence | `test_crash_before_raw_persistence_is_fully_retryable` | **PASS** `RESUME_FULL`, exactly 1 chain after retry |
| failure **immediately after** raw persistence | `test_failure_after_raw_persistence_resumes_without_a_second_raw_row` | **PASS** `resumed=1`, raw count unchanged |
| failure **after canonical creation** | `test_pipeline_fault_flags_needs_review_and_never_releases_the_claim` | **PASS** `NEEDS_REVIEW`; retry → `DUPLICATE_NEEDS_REVIEW`, raw & incident counts unchanged |
| concurrent duplicate requests | `test_concurrent_duplicate_is_refused_while_the_lease_is_live` | **PASS** `IN_FLIGHT`, lease not stolen |
| terminal claim never taken over | `test_completed_claim_is_never_taken_over_even_with_a_dead_lease` | **PASS** |
| resume does not inflate counters | `test_resume_does_not_inflate_the_locked_received_counter` | **PASS** |
| TTL/index behaviour | `test_ttl_index_is_on_a_dedicated_field_with_expire_zero`, `test_active_claims_are_never_ttl_eligible`, `test_terminal_claims_arm_retention_in_the_future`, `test_retention_horizon_exceeds_the_collector_replay_horizon`, `test_replay_after_retention_window_is_a_new_delivery` | **PASS** |
| normal distinct-event processing | `test_distinct_source_event_id_is_still_a_new_delivery`, `test_no_payload_only_suppression` (3 identical payloads, 3 distinct ids → 3 chains) | **PASS** |
| upgrade path | 4 tests in `test_p0_dedupe_upgrade_guard.py` | **PASS** |
| lifecycle happy path | `test_successful_delivery_reaches_completed_with_retention_armed` | **PASS** |

## RESTART/RETRY RESULT (real process restart, not simulated)
`scripts/restart_retry_proof.py` — **VERDICT PASS**
(`test_reports/restart_retry_proof.json`)

1. Delivery 1 over the machine-auth path → `REASONED`, incident
   `inc_4e65e911753d4ec9ae34`, trace `live_ba1e0fbffacf4097`;
   counts `raw 1 / canonical 1 / incidents 1`.
2. `supervisorctl restart backend` — process killed and restarted, health
   re-polled.
3. Byte-identical envelope replayed → `http 200`, `duplicates=1`,
   `status=DUPLICATE`, `incident_created=false`,
   `incident_id == inc_4e65e911753d4ec9ae34`,
   `duplicate_of_trace_id == live_ba1e0fbffacf4097`, `delivery_count=2`,
   `reasoned=0`, `incidents_promoted=[]`, claim `status=COMPLETED`,
   `attempt=1` (no takeover).
4. Counts after restart+retry: **`raw 1 / canonical 1 / incidents 1` —
   unchanged.**

## DUPLICATE RAW / CANONICAL / DETECTION / INCIDENT COUNTS
| Scenario | raw | canonical | detection | incident |
|---|---|---|---|---|
| identical retry | 1 → 1 | 1 → 1 | not re-run (`reasoned=0`) | 1 → 1 |
| 5 consecutive retries | 1 | 1 | not re-run | 1 |
| retry after **real** process restart | 1 → 1 | 1 → 1 | not re-run | 1 → 1 |
| retry after failure **post-raw** | 1 → 1 | +1 (first canonical, correctly) | re-run once | 1 |
| retry after failure **post-canonical** | 1 → 1 | unchanged | refused | unchanged |
| concurrent duplicate | 1 | 1 | not started | 1 |
| store unavailable | 0 | 0 | 0 | 0 (request refused) |
| distinct `source_event_id` | +1 | +1 | run | +1 (correct) |

**All duplicate raw/canonical/detection/incident chains are prevented.** The
partition runs before the raw writer and before `_reason_batch`, so a
recognised retry never reaches the raw writer, the canonical writer,
`evaluate_detection`, VEEE or `materialise_incident`.

## REGRESSION RESULTS
- `test_p0_dedupe_hardening.py` **19/19 PASS** (new)
- `test_p0_dedupe_upgrade_guard.py` **4/4 PASS** (new)
- `test_p0_ingest_idempotency.py` **13/13 PASS**
- `test_collector_api_key_auth.py` + `test_p0sec_rbac_fail_closed.py`
  **54/54 PASS** — auth and P0-SEC fail-closed untouched
- non-endpoint campaign behaviour **2/2 PASS** — folding unchanged as directed
- **Full preview collector proof re-run: VERDICT PASS**, 0 failures — auth
  matrix 11/11, chain rule `DET-EX-001` → VEEE SUSPICIOUS 70 → incident
  `inc_3237ef62a05947abb5d1`, tenant isolation PASS, replay deduped, distinct
  event not suppressed.
- Pre-existing failures, unchanged and **not** caused by this work (all the
  legacy `X-Principal-Id` header-seeding pattern that P0-SEC intentionally
  stopped honouring — refused at the RBAC gate, so the ingest handler never
  runs): `test_xdr_data_sources_collectors.py`,
  `tests/edr/test_p1_10_live_contract.py`,
  `tests/edr/test_cross_tenant.py::test_v11_body_tenant_id_never_trusted`,
  `test_xdr_api_keys.py`, `test_xdr_rbac_enforcement.py`.

## RESIDUAL TRADE-OFFS (disclosed, none block deploy)
1. A fault that may have written canonical evidence yields `NEEDS_REVIEW`:
   auto-retry is refused, so that event needs an **operator requeue**. Chosen
   deliberately — never duplicate evidence, never silently drop, always
   surface. There is currently **no UI** for that queue (deliberately out of
   scope this session); it is visible as
   `db.xdr_ingest_dedupe.find({status:"NEEDS_REVIEW"})`.
2. A retry arriving within the 300 s lease of a still-running first attempt is
   answered `IN_FLIGHT` rather than processed. Correct (no second chain) but
   the collector must treat it as "already accepted", not as a failure.
3. `complete()` swallowing a write error can leave a claim non-terminal until
   its lease expires; the retry then resumes rather than duplicating.
4. Replay older than 14 days is treated as a new event (documented above).

## FINAL GO / NO-GO FOR PRODUCTION DEPLOY
**GO.** Both gaps the owner flagged are closed and proven:
fail-open is gone (503 `INGEST_IDEMPOTENCY_UNAVAILABLE`, nothing written,
auth unaffected), and the claim lifecycle no longer releases a claim — a real
process restart plus retry produced zero duplicate raw/canonical/detection/
incident records. Retention is bounded on a dedicated field that cannot touch
an active claim.

Recommended deploy note: production has no `xdr_ingest_dedupe` collection yet,
so the indexes are created on first ingest — the first request after deploy
pays the index build and any failure there is a safe 503, not an unprotected
ingest.

## CLEANUP
All **21** proof API keys across the three throwaway tenants revoked
(0 usable); all **6** proof collectors DISABLED — verified in the datastore.
No non-terminal claims left behind; every terminal claim has retention armed.
Retained for review: 12 raw events, 12 canonical docs, 12 incidents under
`p0f-collector-auth-proof` / `p0f-restart-retry-proof`. Nothing outside the
throwaway tenants was written.
