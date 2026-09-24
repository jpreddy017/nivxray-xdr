# G1-R5 · Bounded Delivery Drain — PLAN (authored; NOTHING executed)

Status: **READY for owner review · NOT executed on DESKTOP-A9HGFJJ**
Scope of this turn: plan + implementation + tests + execution procedure + evidence
contract. No endpoint execution. No deploy. No merge.

R4 is **CLOSED / FROZEN**. Nothing in this phase modifies, replays, reinterprets
or extends R4 recovery.

---

## 1. Frozen starting state (owner-confirmed)

| fact | value |
|---|---|
| dead_letter | 0 |
| queued | 122,393 |
| delivered | 2,884 |
| delivering | 50 |
| retrying | 125 |
| total | 125,452 |
| recovered rows (R4) | 14,868, all `queued`, attempts 0 |
| bookmarks | unchanged |
| acquisition/delivery since R4 | none |

---

## 2. Architecture path used — delivery WITHOUT acquisition

Two separations already exist in the runtime and were verified by reading the
code, not assumed:

1. `main.py` starts connectors only when `XDR_AUTO_START_CONNECTORS=1`, and
   starts the delivery worker separately
   (`XDR_DISABLE_DELIVERY_WORKER != "1"`). So the service CAN run
   delivery-only today, with no code change.
2. The delivery path itself does not depend on any connector:
   `Outbox → DeliveryWorker → IngestClient`.

For the FIRST real drain we do **not** use the uvicorn service, for three
reasons:

* the standalone collector control plane **fails closed** — every
  `/api/xdr/outbox/*` route answers `403 COLLECTOR_AUTH_UNAVAILABLE`
  (`framework/authz.py`), so a drain cannot be operator-paced or inspected
  over HTTP on the endpoint; only `/health` is readable;
* the background worker loop drains continuously at `poll_interval=2s` with no
  row ceiling — that is not a bounded proof;
* the service constructs `CollectorRuntime`, which rehydrates connector
  records and attaches `AcquisitionState` to the outbox connection.

Chosen path (owner-approved): **bounded in-process delivery-only driver**

```
scripts/g1_r5_delivery_drain.py
  Outbox(path=XDR_STATE_DIR)         # durable rows + R3.1 durable gate state
  IngestClient()                      # R1/R2 classification, unchanged
  DeliveryWorker(outbox, ingest)      # R3/R3.1 health gate, unchanged
```

The driver **never** imports `framework.windows_eventlog`, never constructs
`WindowsEventLogConnector`, never calls `EvtSubscribe`, never reads an Event
Log, never constructs `CollectorRuntime`/`AcquisitionState`, and never writes a
bookmark. That is asserted at runtime, not merely intended:
`invariants.windows_connector_never_imported` and
`invariants.no_acquisition` (byte-identical fingerprints of
`windows_channel_state`, `acquisition_batch`, `acquisition_window`,
`acquisition_terminal_record`).

---

## 3. Exact 500-row bounding mechanism

`--max-rows` is a hard ceiling on the **attempted population**, not a
best-effort limit:

* each tick computes `limit = min(batch_size, max_rows - attempted)` and
  **resizes the worker batch to that limit** before the tick runs;
* the candidate rows for the tick are read first
  (`Outbox.next_batch(limit)`, deterministic
  `ORDER BY next_attempt_at ASC, created_at ASC`), so the attempted rows are
  known by identity, not inferred from counters;
* `attempted += result["drained"]` uses the worker's own claim count, so a
  short tick is counted short.

Therefore `attempted <= max_rows` always, and
`invariants.row_ceiling_respected` states it.

Secondary ceilings (reaching ANY ceiling stops the run):

| ceiling | first-drain value | effect |
|---|---|---|
| `--max-rows` | **500** | `MAX_ROWS_REACHED` → eligible for PASS |
| `--max-ticks` | 40 | `MAX_TICKS_REACHED` → **not** PASS |
| `--max-seconds` | 600 | `MAX_SECONDS_REACHED` → **not** PASS |
| queue empty | — | `QUEUE_EMPTY` → eligible for PASS |
| gate OPEN | — | hard stop → **not** PASS |

There is no silent retry beyond the bounded proof: the driver exits after the
stop condition, and the persisted retry/backoff state is left exactly as the
production machinery wrote it.

---

## 4. The pre-existing 50 `delivering` rows

Constructing `Outbox` runs R3.1 restart recovery
(`_reset_stuck_delivering()`: `delivering → queued`). This is **measured, not
hidden**:

* the status histogram is read FIRST over a `mode=ro` sqlite connection,
  before the `Outbox` object exists;
* a second snapshot is taken immediately after construction;
* the driver reports
  `delivering_before`, `delivering_after`, `queued_before`, `queued_after`,
  `delivering_reset_to_queued`, `queued_delta`, and `consistent`
  (`queued_delta == delivering_reset_to_queued`).

Expected on the endpoint:
`delivering_before = 50`, `delivering_after = 0`,
`delivering_reset_to_queued = 50`, `queued_delta = +50`
(`queued 122,393 → 122,443`), `consistent = true`.
`consistent = false` is a FAIL and aborts the accounting.

The **dry run does not perform this recovery at all**: it never constructs the
`Outbox`, reads its candidate rows over a `mode=ro` connection, and reports
`state = NOT_APPLIED_IN_DRY_RUN` with `would_reset_to_queued = 50`. So stage 4
of the procedure writes nothing whatsoever — the first write in this phase
happens only under `--execute`.

Those 50 rows become normal queue members; some of them may be inside the
first 500 attempted, which is correct and accounted — the ingest boundary is
idempotent on the delivery identity.

---

## 5. R3.1 OPEN behaviour (owner directive)

For this first proof the gate is **not** allowed to self-recover:

* gate `OPEN` **before** a tick → stop (`GATE_OPEN_BEFORE_TICK`);
* gate refuses the tick → stop (`GATE_BLOCKED_DELIVERY`);
* gate opens **during** a tick → stop (`GATE_OPENED_DURING_DRAIN`);
* in all three cases: `pass=false`, `gate_opened=true`, the full durable gate
  row and gate status are captured in evidence, and the driver exits with
  code 2.

No cooldown is waited out and no HALF_OPEN probe is attempted, so the FIRST
failure condition of the production delivery path is preserved as evidence
instead of being obscured by automatic recovery. Mid-batch, the worker's own
R3 behaviour still applies: unattempted claimed rows are released back to
`queued` with their retry budget untouched.

---

## 6. Endpoint ↔ server identity reconciliation

**HTTP 2xx is acceptance by the destination, not canonical ingestion.** Inside
one accepted batch a delivery can still be routing-refused (D15), retained
under B4, duplicate-suppressed, or left mid-flight.

### 6.1 Gap found, and the smallest read-only capability added

Existing read-only surfaces were **not sufficient**:

* `GET /api/xdr/ingest/routing/deliveries` reports accepted rows with
  `source_event_id: null` — the collector's envelope id is deliberately not
  carried onto the evidence row, so ACCEPTED deliveries could not be
  reconciled by identity (only counted in aggregate);
* `xdr_canonical_events` (the raw row that DOES carry the envelope
  `source_event_id`) has no read API at all;
* only refusals (`xdr_ingest_routing_blocks`) and B4 retained raw expose the
  envelope `source_event_id`.

Smallest missing capability, now implemented (read-only, no new authority):

```
POST /api/xdr/ingest/routing/reconcile        ≤ 500 identities per request
routers/xdr_delivery_reconciliation.py        its own router, see below
services/delivery_reconciliation.py           pure read; writes nothing
```

It lives in its own router module on purpose: D21
(`routers/xdr_ingest_routing.py`) holds a contract test that the routing
visibility surface exposes **GET only**, so no endpoint on it can alter a
routing decision. Reconciliation is semantically a read but needs a request
body for a 500-identity population, so the D21 contract is kept literal
instead of being relaxed. Tenant scope, the scope resolver and the read-only
note are imported from D21, not redefined.

It reads only what the ingest boundary already wrote:
`xdr_ingest_dedupe` (the per-delivery claim), `xdr_canonical_events`,
`xdr_canonical_evidence`, `xdr_ingest_routing_blocks`,
`xdr_ingest_raw_retained`. Tenant scope comes from the **authenticated
principal** (`deps.get_current_user` → `resolve_tenant_scope`); `X-Tenant-Id`
is ignored; a record outside scope is reported as not found and never
described.

### 6.2 The identity bridge

The authoritative per-delivery claim key is
`services.ingest_idempotency.event_identity`:

```
sha256( tenant_id \x1f collector_id \x1f source \x1f source_event_id
        \x1f sha256(canonical_json(raw)) )
```

Every input is a field the collector already holds, so the endpoint computes
the SAME key locally (`delivery_key()` in the driver). Parity is pinned by a
test that computes both sides and asserts equality
(`test_the_collector_derives_the_same_delivery_identity`).

Resolution order per identity (and the basis is always reported):

1. claim by `delivery_key` → `matched_by=DELIVERY_KEY`
2. claim by identity tuple (`collector_id + source_event_id [+ payload_digest]`)
   → `matched_by=IDENTITY_TUPLE`
3. B4 retained raw by `retained_identity_key`, else by
   `tenant + collector + source_event_id`
4. routing refusal by `tenant + collector + source_event_id`
5. canonical evidence via `claim.canonical_event_id → evidence.event_id`

Aggregate count equality is never relied on: each row reports its own match
basis, and a row that could not be identified is refused by the API rather
than assumed to have landed.

---

## 7. Required accounting

| bucket | condition |
|---|---|
| `DELIVERED_CANONICAL` | claim terminal-successful **and** its canonical evidence row resolves |
| `DELIVERED_RETAINED_RAW` | B4 retained raw exists (NOT canonical, NOT evaluated) |
| `TERMINAL_ACCOUNTED` | authoritative routing refusal, or claim `NEEDS_REVIEW` |
| `RETRYABLE_STILL_QUEUED` | live non-terminal server claim, or endpoint still `queued`/`retrying`/`delivering` with no server record |
| `UNEXPLAINED` | endpoint says `delivered` and the server has no record; endpoint `dead_letter` with no server accounting; claim completed but evidence unresolvable |

Equations required for PASS:

```
attempted (endpoint)  = DELIVERED_CANONICAL + DELIVERED_RETAINED_RAW
                      + RETRYABLE_STILL_QUEUED + TERMINAL_ACCOUNTED
                      + UNEXPLAINED
UNEXPLAINED           = 0
attempted             = delivered + retrying + dead + released_unattempted   (endpoint side)
attempted             <= 500
total rows            unchanged (125,452)
delivering_reset_to_queued == queued_delta == 50
acquisition tables    byte-identical
gate                  never OPEN
```

---

## 8. Evidence artifacts

Written by the driver to `<state-dir>\g1_r5_evidence\`:

| file | content |
|---|---|
| `r5-drain-pre-snapshot.json` | status histogram, durable gate row, acquisition-table fingerprints — read BEFORE the Outbox is constructed |
| `r5-drain-identities.json` | one record per attempted row: `ref` (outbox id), tenant, connector, collector, source, `source_event_id`, `payload_digest`, `delivery_key`, `endpoint_outcome`, attempts before/after, last error, failure classification/status code |
| `r5-drain-run.json` | ceilings, per-tick accounting, gate status, stop reason, all invariants, endpoint PASS/FAIL |
| `r5-drain-post-snapshot.json` | post histogram, gate row, acquisition fingerprints |
| `r5-server-reconciliation.json` | the reconcile API response: per-row disposition/bucket/basis + bucket totals + `pass` |
| `r5-final-reconciliation.json` | the combined endpoint ↔ server verdict |
| `outbox.db.r5-pre.bak` + `.sha256` | mandatory pre-drain backup |

---

## 9. PASS / FAIL

### Prerequisites checked by the procedure before ANY delivery

1. elevated shell, venv python present, tool fresh (option probe);
2. `NIVX_TENANT_ID` and `NIVX_COLLECTOR_ID` set — the collector id is part of
   the delivery identity, so a drain under the `collector-local` fallback is
   refused by the driver itself;
3. no collector process holds `outbox.db`; SHA-256-verified backup taken;
4. ingest authentication + tenant binding probed (`HTTP 400` on an empty
   batch = authenticated, creates no evidence);
5. **reconciliation surface probed**: `POST /api/xdr/ingest/routing/reconcile`
   must answer `401/403` (present, fail-closed). `404` aborts — the drain will
   not deliver rows it cannot reconcile afterwards.
   Verified live on the acquisition plane
   (`https://greeting-app-5782.preview.emergentagent.com`) — the same plane
   the G1 acquisition delivered to, so no deploy is required for this phase;
6. dry run must show `consistent = true`, acquisition tables unchanged, and a
   gate that is not already `OPEN`.

**PASS** requires ALL of:

1. `stop_reason ∈ { MAX_ROWS_REACHED, QUEUE_EMPTY }`
2. `attempted <= 500` and the endpoint accounting equation holds
3. `delivering_reset_to_queued == queued_delta == 50`, `consistent = true`
4. acquisition tables byte-identical; total rows unchanged; Windows connector
   module never imported
5. gate never OPEN (`gate_opened = false`)
6. server reconciliation `pass = true` with `UNEXPLAINED = 0` and no
   cross-tenant record in the response
7. all evidence artifacts present and internally consistent

**FAIL / HARD STOP** on any of: gate OPEN, `consistent = false`, any
acquisition table changed, total row count changed, `UNEXPLAINED > 0`, a
secondary ceiling reached, or a missing/inconsistent artifact.

---

## 10. Changed files

| file | change |
|---|---|
| `apps/nivxray-xdr-collector/scripts/g1_r5_delivery_drain.py` | **new** · bounded delivery-only driver (dry-run by default) |
| `apps/nivxray-xdr-collector/tests/test_g1_r5_delivery_drain.py` | **new** · 11 tests |
| `backend/services/delivery_reconciliation.py` | **new** · read-only reconciliation service |
| `backend/routers/xdr_delivery_reconciliation.py` | **new** · `POST /api/xdr/ingest/routing/reconcile` (read-only, own router so the D21 GET-only contract stays literal) |
| `backend/routers/xdr_ingest_routing.py` | two reconciliation lookup indexes only |
| `backend/server.py` | registers the new router |
| `backend/tests/test_g1_r5_delivery_reconciliation.py` | **new** · 17 tests |
| `memory/G1_R5_DELIVERY_DRAIN_PLAN.md` | this plan |
| `memory/G1_R5_DELIVERY_DRAIN_EXECUTION_COPY.ps1` | the bounded endpoint procedure |

No existing behaviour was modified: no change to `Outbox`, `DeliveryWorker`,
`DeliveryHealthGate`, `IngestClient`, routing, B4, or any R4 artifact.

### Test results (this pod, synthetic only)

```
apps/nivxray-xdr-collector · tests/test_g1_r5_delivery_drain.py ........ 15 passed
apps/nivxray-xdr-collector · full collector suite ..................... 325 passed
backend · tests/test_g1_r5_delivery_reconciliation.py ................... 17 passed
backend · tests/test_d21_routing_visibility.py (contract regression) .... 15 passed
backend · tests/test_b4_raw_forensic_retention.py ....................... 25 passed
backend · tests/test_d15_declared_source_routing.py + P0 idempotency .... passed
```

CLI behaviour exercised end-to-end against a throwaway synthetic outbox:

* dry run → `pass=true`, exit `0`, four artifacts written, **zero writes**
  (a row left in `delivering` stayed `delivering`);
* `--execute` against an unreachable destination → gate `OPEN`,
  `stop_reason=GATE_OPENED_DURING_DRAIN`, `pass=false`, exit `2`, and the
  population fully accounted (5 `retrying` + 1 released to `queued` + 1
  untouched = 7, nothing lost, nothing stranded in `delivering`).

Live checks: `POST /api/xdr/ingest/routing/reconcile` is registered in the
served OpenAPI, answers `403` unauthenticated (fail-closed), and with an
admin session returns a correct partition
(`RETRYABLE_STILL_QUEUED=1, UNEXPLAINED=0, pass=true`) for a synthetic
not-found identity whose endpoint outcome was `queued`.

---

## 11. Remaining risks

1. **Gate may open on the first real batch.** The destination is a real
   production ingest under a 500-row burst; a 5xx/timeout run of 5 consecutive
   destination failures opens the gate. That is a hard stop by design — it is
   evidence, not a defect.
2. **`delivery_key` depends on `raw` being byte-stable through JSON.**
   Parity is pinned by test, but if the ingest boundary ever enriched `raw`
   before computing identity, the key lookup would miss and reconciliation
   would fall back to the identity tuple. The response states `matched_by`, so
   a fallback is visible rather than silent.
3. **B4 retained raw is expected for some historical records**
   (`SOURCE_RECORD_NOT_SUPPORTED`). It is accounted in its own bucket and must
   not be read as canonical coverage.
4. **Retention growth**: a large retained-raw population from the full drain
   still has no rotation policy (P1, `xdr_ingest_raw_retained`). Not triggered
   by 500 rows; must be decided before the full 122k drain.
5. **`NEEDS_REVIEW` claims** (if any appear) are accounted as terminal but
   need a deliberate operator decision afterwards.
6. Backend reconciliation requires a valid owner JWT at execution time
   (`memory/OWNER_JWT_REFRESH_PROCEDURE.md`).

---

## 12. Verdict

**READY** for the first 500-row execution, pending owner authorization.
Execution procedure: `memory/G1_R5_DELIVERY_DRAIN_EXECUTION_COPY.ps1`
(dry run first; the execute step is explicitly gated inside the block).
