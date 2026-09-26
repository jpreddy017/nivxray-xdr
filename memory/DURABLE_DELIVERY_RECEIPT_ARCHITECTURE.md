# Durable Delivery Receipt / Reconciliation · permanent architecture

**Status:** implemented and tested (2026-06). Not deployed, not merged.
**Branch:** `feature/rc2-alignment`.

## The invariant

> No delivery is DELIVERED until an authoritative backend disposition is
> durably evidenced AND locally verified.

HTTP success/failure alone cannot establish whether an endpoint event was
durably committed and evidenced. That is the gap R5 and R6 repaired by hand;
this architecture removes the need for that class of recovery.

## Lifecycle

```
LOCAL JOURNAL DURABLE (Outbox.record)
  -> READY (queued / retrying, next_attempt_at elapsed)
  -> DISPATCHING (delivering + dispatch_started_at + delivery_key persisted)
  -> BACKEND CLAIMED (2xx: a CLAIM, never a receipt)
  -> BACKEND DISPOSITION (idempotency claim / canonical evidence / B4
     retained raw / routing refusal, written by the ingest boundary)
  -> AUTHORITATIVE RECEIPT (POST /api/xdr/ingest/delivery/receipts)
  -> LOCAL RECEIPT VERIFIED (tenant + collector + delivery_key bound)
  -> DELIVERED (one statement, with the receipt stored on the row)
```

Anything sent whose outcome is not proven:

```
DISPATCHING -> UNKNOWN_COMMIT_STATE -> RECONCILE(stable delivery_key)
    DELIVERED_CANONICAL      -> DELIVERED / VERIFIED (canonical=true)
    DELIVERED_RETAINED_RAW   -> DELIVERED / VERIFIED (canonical=false, B4)
    NOT_FOUND (proven absence) -> RETRYABLE (bounded backoff)
    TERMINAL_REFUSED / TERMINAL_NEEDS_REVIEW -> TERMINAL_ACCOUNTED
    SERVER_IN_PROGRESS / ACCOUNTED_WITHOUT_EVIDENCE / unavailable
                             -> stays UNKNOWN_COMMIT_STATE
```

## Commit-state classification (`framework/delivery.py · CommitState`)

| Attempt outcome | commit_state | local effect |
|---|---|---|
| 2xx | `COMMIT_CLAIMED` | UNKNOWN until a receipt proves it |
| timeout / read / write / protocol error | `UNKNOWN` | UNKNOWN, reconcile |
| 5xx, 408, unattributed 4xx (incl. 404) | `UNKNOWN` | UNKNOWN, reconcile |
| ConnectError / ConnectTimeout / proxy / bad URL / not configured / 429 | `NOT_SENT` | bounded retry, no receipt asked for |
| app-attributed 4xx refusal | `TERMINAL_CLAIMED` | UNKNOWN until the receipt confirms the refusal |

`NOT_SENT` is the only class that may be retried without asking the
authoritative plane, because it provably never reached the application.

## Stable identity

`framework/receipts.delivery_key()` is byte-identical to the backend's
`services.ingest_idempotency.event_identity()`:

```
sha256( tenant_id \x1f collector_id \x1f source \x1f
        (source_event_id | "__no_source_event_id__") \x1f sha256(raw) )
```

It is persisted on the row (`delivery_key`, written with `COALESCE` so it can
never be re-issued) and is the identity used by the initial send, every retry,
every restart and every reconciliation. Duplicate delivery therefore lands on
the same backend claim and cannot create duplicate canonical evidence.

## Receipt contract (`nivx.delivery.receipt/1`)

Stored verbatim on the row in `receipt_json`. Fields: `basis`, `authority`
(`surface`, `tenant_id`, `collector_id`, `at`, `read_only`), `delivery_key`,
`ref`, `source_event_id`, `connector_id`, `disposition`, `bucket`,
`bucket_basis`, `matched_by`, `canonical`, `retained_raw`, `evidence_ref`,
`canonical_event_id`, `retained_raw_id`, `retained_raw_reason`, `claim`
(status/stage/trace_id/delivery_count/duplicate_count/raw_row_id/
review_reason), `routing_block`, `local_action`, `local_action_basis`,
`verified_at`.

`Outbox.mark_receipt_verified()` refuses anything that is not a verified
delivery receipt, so a `delivered` row without evidence is unreachable.

## Verification (fail closed)

Hard failure — never converted into success — when the receipt's authority
tenant, authority collector, row `ref`, `delivery_key`, row `collector_id` or
`source_event_id` do not match the local delivery, or the bucket is unknown.

## Backend surface

`POST /api/xdr/ingest/delivery/receipts`
(`backend/routers/xdr_delivery_receipts.py`)

* requires `collectors.enroll` (the permission delivery already needs);
* tenant = the CREDENTIAL's tenant via the existing tenant authority, never a
  header claim, never cross-tenant;
* the named collector must exist and belong to that tenant; every identity
  must belong to that collector;
* accounting comes from `services.delivery_reconciliation` — the SAME
  implementation the analyst surface uses — so there is one definition of what
  the authoritative plane did. Read-only: it writes nothing and re-decides
  nothing.

`_ENDPOINT_STILL_OPEN` now includes `unknown_commit_state`, so a dispatched
delivery with no server-side record is `RETRYABLE_STILL_QUEUED` (proven
absence) instead of `UNEXPLAINED`.

## B4 truth

`DELIVERED_CANONICAL` and `DELIVERED_RETAINED_RAW` are both durable and are
NOT the same fact. The receipt carries `canonical` / `retained_raw` flags, the
retained-raw id and the mismatch reason; a retained-raw receipt has no
`evidence_ref`. Retained raw is never collapsed into canonical evidence.

## R3.1 delivery-health gate

Unchanged semantics. OPEN prevents dispatch entirely (nothing is claimed, no
budget consumed). A gate that opens mid-batch releases the unclaimed rows.
Reconciliation is a READ on the authoritative plane, spends no delivery
budget, and therefore runs while the gate is OPEN — without bypassing tenant
or credential authority.

## Restart correctness and the constructor hazard

`Outbox(restart_recovery=...)` is now explicit:

* `RESET_TO_QUEUED` — legacy at-least-once behaviour (unchanged default, so
  every existing test and deployment behaves exactly as before);
* `RECONCILE` — the permanent protocol: DELIVERING → UNKNOWN_COMMIT_STATE;
* `NONE` — open and mutate nothing (forensic/bounded tooling no longer has to
  avoid the real component to stay safe).

`restart_recovery_result` reports the policy and the rows moved.

Acquisition is untouched: `AcquisitionState` advances a bookmark only for
rows that are `DELIVERED`, which now means receipt-verified. A backend outage
cannot lose already-durable acquisition.

## Files

| File | Change |
|---|---|
| `framework/receipts.py` | NEW · identity, receipt contract, verification, disposition→action |
| `framework/receipt_client.py` | NEW · machine-authenticated receipt client |
| `framework/durable_delivery.py` | NEW · `DurableDeliveryWorker` (dispatch + automatic reconciliation + loop) |
| `framework/outbox.py` | `UNKNOWN_COMMIT_STATE`, `RestartRecovery`, receipt columns/index, receipt writers, `rows_by_status`, `stale_dispatching` |
| `framework/delivery.py` | `CommitState` classification on every outcome |
| `framework/runtime.py` | `NIVX_DURABLE_DELIVERY` selects the protocol and the restart policy |
| `backend/routers/xdr_delivery_receipts.py` | NEW · machine receipt surface |
| `backend/services/delivery_reconciliation.py` | `unknown_commit_state` is an open endpoint outcome |
| `backend/server.py` | router registration |

Schema additions are additive and nullable (`delivery_key`, `receipt_json`,
`receipt_basis`, `receipt_verified_at`, `dispatch_started_at`,
`unknown_since`, `reconcile_attempts` + `ix_env_delivery_key`), so an older
database upgrades in place and no existing column changes.

## Deployment switch

`NIVX_DURABLE_DELIVERY=1` selects the durable worker and the RECONCILE
restart policy. Default OFF: nothing about a running fleet changes until a
deployment says so.
