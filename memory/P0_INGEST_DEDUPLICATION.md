# P0 · INGEST/INCIDENT DEDUPLICATION — 2026-06 (preview only)

Preview only. No production deploy. No rate limiting, no UI work.
Detection, VEEE and incident-creation logic were **not** weakened or altered.

---

## ROOT CAUSE
Replaying an identical collector envelope created a full second chain because
the ingest endpoint had **no delivery identity at all**:

1. `routers/xdr_ingest.py::ingest_telemetry` inserted one row into
   `xdr_canonical_events` per envelope unconditionally.
2. It then handed every envelope to `_reason_batch` →
   `process_event_through_pipeline`, which inserted a fresh canonical event,
   re-ran detection, re-ran VEEE and called `materialise_incident`.
3. The **only** duplicate protection anywhere was
   `detection_content/xdr_incident.py::_consolidate`, whose key is
   `(tenant_id, endpoint_id)` inside a rolling window. `_endpoint_scope()`
   returns `None` for any source without a platform-minted `ep_…` id, so for
   CEF/LEEF/syslog/cloudtrail telemetry consolidation was skipped entirely by
   design ("non-endpoint sources unchanged") and a new incident was written.

So the defect was **delivery-retry semantics**, not campaign logic: nothing in
the system could tell "the same event delivered twice" from "two events".

## DEDUP DESIGN
Two explicitly separate mechanisms, per the directive:

| Mechanism | Question it answers | Where |
|---|---|---|
| **Ingest idempotency** (new) | is this the same **DELIVERY** of one event? | `services/ingest_idempotency.py`, applied in `ingest_telemetry` before ANY persistence |
| Campaign consolidation (untouched) | do these **DISTINCT** events belong to one campaign? | `detection_content/xdr_incident.py::_consolidate` |

Idempotency is an **explicit claim record under a UNIQUE index**, not a timing
heuristic and not an in-memory cache:

- The batch is partitioned **before** anything is written. Each envelope's
  identity is claimed with an atomic `insert_one`; a `DuplicateKeyError` *is*
  the proof of a retry.
- A duplicate produces **no** raw row, **no** canonical event, **no**
  detection, **no** VEEE run and **no** incident. The receipt returns the
  ORIGINAL `trace_id`, `canonical_event_id`, `observation_id` and
  `incident_id` with `status="DUPLICATE"`, plus `delivery_count`.
- Provenance is preserved, never fabricated: the claim record carries
  `delivery_count` / `retry_count` / `first_seen_at` / `last_seen_at`, and the
  original incident gets additive `duplicate_delivery_count` +
  `last_duplicate_delivery_at`. No state, priority or verdict is changed.
- `events_received/parsed/normalized` (the LOCKED evidence for the CONNECTED
  gate) count **unique** telemetry only; retries land in a new
  `events_duplicate` counter, so redelivery can never inflate the state
  machine.
- A **transient** pipeline fault releases the claim so the collector's next
  retry is reprocessed — a real security event is never permanently swallowed.
  A **deterministically blocked** payload (`NO_DSM`/`BLOCKED`) keeps its claim.
- If the dedupe store is unbound, ingest processes normally: availability of
  security telemetry outranks de-duplication (fail-open on *dedupe* only,
  never on *auth*).

## DEDUP KEY
```
sha256( tenant_id | collector_id | source | source_event_id | sha256(raw) )
```
- `tenant_id`, `collector_id` → the same `source_event_id` from another tenant
  or another collector is a **different** event.
- `source_event_id` → the same payload with a new id is a **new** event and is
  never suppressed.
- `sha256(raw)` covers the **semantic** event only. Volatile transport fields
  (`collection_timestamp`, `received_at`) are excluded, so a retry is still
  recognised after its transport metadata moves on; and a collector that
  reuses one id for two different payloads never has an event silently lost.
- Missing `source_event_id` falls back to `__no_source_event_id__` + payload
  digest, so collectors that do not emit ids are still protected.
- `endpoint_id` is **not** part of the key — the mechanism is endpoint-agnostic,
  which is exactly why it fixes the non-endpoint case.

## EXACT FILES CHANGED
| File | Change |
|---|---|
| `backend/services/ingest_idempotency.py` | **NEW** — `event_identity()`, `claim()`, `record_outcome()`, `release()`; collection `xdr_ingest_dedupe` with a UNIQUE index on `key`. |
| `backend/routers/xdr_ingest.py` | Partition batch into fresh/duplicate before persistence; raw persist, counters and reasoning run on fresh only; `events_duplicate` counter; retry provenance on the original incident; `TelemetryReceipt.duplicates`; `ReasoningOutcome.status="DUPLICATE"` + `duplicate_of_trace_id` / `delivery_count` / `dedupe_key`; claim outcome recorded / released per envelope. |
| `backend/tests/test_p0_ingest_idempotency.py` | **NEW** — 13 tests. |
| `scripts/preview_collector_auth_proof.py` | Replay section now asserts dedupe instead of merely observing it; added a "distinct event not suppressed" check. |

**Not changed**: `detection_content/xdr_incident.py`, `xdr_veee.py`,
`xdr_pipeline.py`, `xdr_rbac.py`, any rule or threshold.

## TEST MATRIX — 13/13 PASS (`tests/test_p0_ingest_idempotency.py`)
| # | Case | Required | Result |
|---|---|---|---|
| 1 | identical retry, same `source_event_id` | no second chain | **PASS** — raw/canonical/incident counts unchanged; retry points at the original incident and trace |
| 2 | 5 consecutive retries | exactly one incident, one raw row | **PASS** |
| 3 | retry provenance | `duplicate_delivery_count=2`, claim `delivery_count=3`/`retry_count=2` | **PASS** |
| 4 | same payload, **different** `source_event_id` | NOT suppressed | **PASS** — 2 distinct chains |
| 5 | same event, **different tenant** | NOT deduped | **PASS** — distinct incidents |
| 6 | same `source_event_id`, **different collector** | NOT deduped | **PASS** |
| 7 | **non-endpoint** CEF firewall telemetry | deduped | **PASS** |
| 8 | **endpoint-shaped** LEEF process telemetry | deduped | **PASS** |
| 9 | restart / persistence | claim durable, unique index enforced | **PASS** — record read over a separate connection; `uniq_event_key` asserted unique |
| 10 | identity stability | same key across repeat computation | **PASS** |
| 11 | identity separation | tenant / collector / sei / payload all change the key | **PASS** |
| 12 | claim atomicity | 2nd claim → DUPLICATE with incremented counters | **PASS** |
| 13 | locked counters | retry does not raise `events_received`/`events_normalized`; raises `events_duplicate` | **PASS** |

## PREVIEW REPLAY RESULT (full proof re-run — VERDICT **PASS**)
Auth matrix still 11/11. Chain still real: collector
`col_8defc6f93d3e49ce95c0` → canonical `b8496a4b-5129-40ca-a20a-416ebaf3c3e6`
→ rule **DET-EX-001** → VEEE **SUSPICIOUS 70** → incident
`inc_cc66368611ca49a0ba78` (trace `live_d904285cbc584eb0`).

Replay of the identical envelope:
`duplicates=1`, `status=DUPLICATE`, `incident_created=false`,
`incident_id == original`, `duplicate_of_trace_id == original trace`,
`reasoned=0`, `observations_created=0`, `incidents_promoted=[]`,
**raw 7→7 · canonical 8→8 · incidents 8→8**,
`collector.events_received=1` (unchanged), `events_duplicate` incremented.

A new `source_event_id` in the same session still produced a genuine new
incident (`inc_f5f61996896a4354ba41`) — nothing legitimate is suppressed.

## ARE RAW / CANONICAL / DETECTION / INCIDENT DUPLICATES ALL PREVENTED?
**Yes — all four.** The partition happens before the raw insert and before
`_reason_batch` is called, so a retry never reaches the raw writer, the
canonical writer, `evaluate_detection`, VEEE or `materialise_incident`.
Proven by count assertions at every layer (test 1 and the live replay), not by
inspection.

## TRADE-OFFS
1. **`events_received` now counts unique deliveries, not HTTP arrivals.** The
   CONNECTED gate stays honest and un-inflatable; the raw arrival count lives
   in `events_duplicate`. Anyone reading `events_received` as "packets seen"
   must now add both.
2. **A transient pipeline fault releases the claim.** The retry is then
   reprocessed, which can leave one extra raw row for that rare path. Chosen
   deliberately: losing a real security event is worse than an extra audit row.
3. **Dedupe fails open if its store is unbound** (duplicates possible, ingest
   never blocked). Auth is unaffected and still fails closed.
4. **Same `source_event_id` + different payload is treated as two events.**
   Safe direction (never drops evidence), but a badly-behaved collector that
   mutates a payload between retries will still create two chains.
5. **Unbounded growth** of `xdr_ingest_dedupe`. It needs a TTL/retention sweep
   before high-volume production ingest — see blockers.

## DELIBERATELY NOT DONE — needs an owner decision
The directive said *"do not use `(tenant_id, endpoint_id)` as the only incident
dedupe key for non-endpoint telemetry"*. That is now satisfied: the retry
protection is endpoint-agnostic and sits at the ingest layer.

I did **not** additionally extend *campaign folding* to non-endpoint sources,
because doing so would:
- reverse an owner-ratified P0-F.2 decision that is explicitly locked by
  `tests/edr/test_p0_f_endpoint_detection.py::test_non_endpoint_sources_keep_their_existing_behaviour`
  ("CEF/LEEF and snort must be untouched: no campaign scope, no
  consolidation"), and
- fold **genuinely distinct** events with different `source_event_id`s into one
  incident, which conflicts with *"do not suppress legitimate repeated
  security events that have different source event IDs."*

The retry defect is fixed without it. **Decision needed**: should distinct
non-endpoint events from the same device (e.g. `host.host_id=HYD-FW01`, which
IS present in the canonical) fold into one campaign incident within the
30-minute window? That changes incident volume for all syslog/CEF/cloud
sources and should be your call, not mine.

## GO / NO-GO FOR PRODUCTION AUTH DEPLOY
**GO — conditional.** The auth design and the dedup fix are both proven in
preview. Two things to settle first:
1. **Retention for `xdr_ingest_dedupe`** (TTL index or sweeper). Without it the
   collection grows one document per unique event forever.
2. Confirm the trade-off on `events_received` semantics above, since it is the
   evidence behind the CONNECTED state.

Neither blocks the auth code itself; both are operational. After deploy:
first isolated production collector → then rate limiting / key health /
issuance UX.

## REGRESSION STATUS
- `test_p0_ingest_idempotency.py` 13/13 PASS (new)
- `test_collector_api_key_auth.py` + `test_p0sec_rbac_fail_closed.py` 54/54 PASS
- non-endpoint campaign behaviour unchanged: 2/2 PASS
- Pre-existing failures, unchanged and **not** caused by this work (all are the
  legacy `X-Principal-Id` header-seeding pattern that P0-SEC intentionally
  stopped honouring — the requests are refused at the RBAC gate with
  `ACCESS_DENIED/unauthenticated`, so the ingest handler never runs):
  `test_xdr_data_sources_collectors.py` (20 errors before and after — verified
  by stashing), `tests/edr/test_p1_10_live_contract.py` (5 failed),
  `tests/edr/test_cross_tenant.py::test_v11_body_tenant_id_never_trusted`,
  `test_xdr_api_keys.py`, `test_xdr_rbac_enforcement.py`.

## CLEANUP
All **16** proof API keys across both proof tenants revoked (0 usable) and all
**4** proof collectors DISABLED — verified in the datastore. Retained for
review under `p0f-collector-auth-proof`: 9 raw events, 9 canonical docs,
9 incidents, 4 dedupe records. Nothing outside the two throwaway tenants was
written.
