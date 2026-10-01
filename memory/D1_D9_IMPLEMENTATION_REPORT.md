# D1 + D9 — IMPLEMENTATION REPORT (owner review gate)

Date: 2026-09-14 · Scope: endpoint (sensor) path only · **D8 NOT started.**

Reproduce with:
```
cd /app/backend && python3 /app/scripts/p0_real_loop_readonly_proof.py 8
```

---

## A · Exact files changed

| File | Lines | What |
|---|---|---|
| `backend/services/provenance_timestamps.py` | **NEW**, 78 | The stamp shape and the four statuses. One definition, used by both writers |
| `backend/detection_content/xdr_pipeline.py` | +33 | Stamps `parsed_at`, `normalized_at`, `nivx_received_at`, `rule_evaluated_at`, `verdict_at` at the real boundaries |
| `backend/edr_plane/canonical_bridge.py` | +40 | Seeds source-side stamps in `parse()`; `event_time_basis` (D9); carries the receipt time into the pipeline |
| `backend/routers/edr_enrollment.py` | +1 | Passes the genuine raw-row `ingest_time` into the bridge |
| `scripts/p0_real_loop_readonly_proof.py` | ~90 | Reads the new block; pre/post cohort split; real per-stage latencies |

Nothing else touched. No UI, no Cisco parity, no reporting, no refactors, no
auditd DSM change.

## B · Exact behaviour changed

1. **Four statuses, never a bare value.** `AVAILABLE` / `NOT_APPLICABLE` /
   `NOT_OBSERVED` / `MISSING`, each with its own `source` or `reason`.
   `pts.stamp()` **raises** if asked to record a value-less `AVAILABLE`, so an
   uncaptured boundary cannot be dressed up as a measured one.
2. **Stamps are taken at the real boundaries, separately:** `parsed_at` the
   instant `parser.parse()` returns; `normalized_at` after
   `normalizer.normalize()`; `rule_evaluated_at` after `evaluate_detection()`;
   `verdict_at` after the **authoritative** verdict — deliberately after the
   spread re-evaluation, so it never marks a superseded provisional verdict.
3. **`nivx_received_at` is only ever copied from the producer that observed
   it** — `edr_raw_events.ingest_time`, carried through the authenticated
   ingest envelope. Absent producer ⇒ stays `MISSING`.
4. **`collector_received_at = NOT_APPLICABLE`** on the sensor path with the
   reason recorded. **A batch-send time was never substituted.**
5. **D9:** `additional_fields.event_time_basis` is now `ACTIVITY_TIME` or
   `OBSERVATION_TIME`. `event_time` itself is unchanged — the meaning is
   declared rather than the value rewritten, so no rule or timeline shifts.
6. Detection/verdict stamps are **appended** to the already-persisted
   canonical row (`$set` on `provenance.timestamps.*` only). The row is
   written before detection on purpose, so evidence survives a detection
   fault. **No evidence field is ever rewritten.**

## C · Before / after test results

Harness **unchanged in gate logic and in the 8-stamp list**; it now reads the
persisted block and reports both cohorts in one run.

| Cohort | Events | No MISSING stamp | Verdict |
|---|---|---|---|
| PRE-PATCH | 3 | 0/3 | **FAIL** |
| POST-PATCH | 10 | 10/10 | **PASS** |

All other gates: **PASS 13/13** — real telemetry, raw persistence, parsing,
normalization, canonical evidence, detection, verdict traceability, tenant
attribution, end-to-end traceability.

**Genuinely measured stages** (both endpoints real stamps, no proxy):

| Stage | n | min | median | max |
|---|---|---|---|---|
| `sensor_observed_at` → `nivx_received_at` | 13 | 51.3 ms | 6852.3 ms | 12700.6 ms |
| `nivx_received_at` → `parsed_at` | 10 | 100.3 ms | 104.1 ms | 114.8 ms |
| `parsed_at` → `normalized_at` | 10 | 0.1 ms | 0.1 ms | 0.1 ms |
| `normalized_at` → `rule_evaluated_at` | 10 | 1.3 ms | 1.4 ms | 1.4 ms |
| `rule_evaluated_at` → `verdict_at` | 10 | 1.1 ms | 1.3 ms | 7.8 ms |

No p95/p99 claimed — sample far too small.

Two of these numbers are worth reading as findings, not achievements:

- **`sensor → nivx` median 6.9 s** is the sensor's ~15 s polling cycle, not
  processing cost. It dominates end-to-end time by three orders of magnitude.
- **`parsed → normalized` 0.1 ms** truthfully reveals that on this path
  "normalize" only stamps provenance — `canonical_bridge.parse()` already
  produced the canonical shape. The stage is real but nearly empty. That is
  an honest measurement of a thin stage, not a padded one.

## D · Real-event provenance example (verbatim from storage)

`cev_raw_...` · LinuxSensor · NETWORK/CONNECTION_OBSERVED:

| Stamp | Status | Value / reason | Source |
|---|---|---|---|
| `activity_occurred_at` | NOT_OBSERVED | this collection method observes a state, not the instant it began | — |
| `sensor_observed_at` | AVAILABLE | 2026-09-14T14:31:40.975499+00:00 | `sensor:observed_at` |
| `collector_received_at` | NOT_APPLICABLE | no collector boundary exists on the sensor path | — |
| `nivx_received_at` | AVAILABLE | 2026-09-14T14:31:43.207646+00:00 | `ingest:raw row ingest_time` |
| `parsed_at` | AVAILABLE | 2026-09-14T14:31:43.313979+00:00 | `pipeline:parser:nivxforge-linux-sensor-parser` |
| `normalized_at` | AVAILABLE | 2026-09-14T14:31:43.314054+00:00 | `pipeline:normalizer:nivxforge-linux-sensor-normalizer` |
| `rule_evaluated_at` | AVAILABLE | 2026-09-14T14:31:43.315439+00:00 | `pipeline:detection:nivxray::detection_content::nivxray_native_sigma` |
| `verdict_at` | AVAILABLE | 2026-09-14T14:31:43.316706+00:00 | `pipeline:verdict:nivxray::xdr::veee` |

PROCESS rows differ in exactly one place, correctly:
`activity_occurred_at = AVAILABLE` from `sensor:/proc start_time`, and
`event_time_basis = ACTIVITY_TIME`.

## E · AVAILABLE / NOT_APPLICABLE / NOT_OBSERVED / MISSING

Across 10 post-patch events:

| Stamp | Result |
|---|---|
| `activity_occurred_at` | 2× AVAILABLE (PROCESS) · 8× NOT_OBSERVED (NETWORK) |
| `sensor_observed_at` | 10× AVAILABLE |
| `collector_received_at` | 10× NOT_APPLICABLE |
| `nivx_received_at` | 10× AVAILABLE |
| `parsed_at` | 10× AVAILABLE |
| `normalized_at` | 10× AVAILABLE |
| `rule_evaluated_at` | 10× AVAILABLE |
| `verdict_at` | 10× AVAILABLE |

**Zero MISSING.** Six stamps carry real values, one is structurally
not-applicable, one is genuinely unobservable for NETWORK activity and real
for PROCESS activity.

## F · Regressions

**None attributable to the patch — established by running the identical
command on a clean tree, not by assertion.**

```
patched : 19 failed, 377 passed
clean   : 19 failed, 377 passed      ← identical failure set (diff = empty)
```

The 19 pre-existing failures: `test_p0_ingest_idempotency` (10),
`edr/test_p1_10_live_contract` (5), `edr/test_p0_f4_endpoint_process_tree` (3),
`edr/test_cross_tenant` (1).

Worth flagging: `tests/test_p0_ingest_idempotency.py` **passes 13/13 when run
alone, with the patch applied.** Its 10 failures appear only when it runs after
`tests/edr` — cross-file state pollution that exists independently of this
work. It is a real problem for anyone trusting a combined run, and it is not
mine to fix in this step.

## G · Is D1 now PASS, PARTIAL or FAIL?

**PARTIAL overall · PASS for every event produced after the patch.**

- POST-PATCH: **PASS**, 10/10, zero MISSING.
- PRE-PATCH: **FAIL**, 0/3 — and deliberately left that way. Backfilling
  provenance onto historical events would mean inventing the very timestamps
  this work exists to stop inventing. Old events stay honestly incomplete.
- Not yet covered: the **XDR-ingest path** (auditd and every other
  collector-delivered source) is untouched, so it still has no stamps. D1 is
  PASS on the endpoint path only.
- The strict "literal value on all 8" reading is reported in the harness as
  **FAIL 0/13**, unhidden, because `collector_received_at` must never be
  given a value here.

## H · D9 status

**PARTIAL — the ambiguity is now declared, not removed.**

11/13 sampled events have `event_time == sensor_observed_at`; 8/11 (all
post-patch) now carry `event_time_basis: OBSERVATION_TIME`, so a consumer can
tell the two meanings apart. `event_time` itself was intentionally not
re-pointed: that would shift rule and timeline semantics platform-wide, which
is not a minimum patch. **Remaining risk:** a consumer that reads `event_time`
and ignores `event_time_basis` still cannot tell. Closing that properly means
a schema decision (a distinct `observed_at` field on canonical evidence), which
I have not taken.

## I · Recommended minimum D8 implementation (NOT started)

Persist what the evaluator already computes and currently discards. The
library evaluator returns match objects; only `rule_id` survives today.

Minimum shape, one new collection `xdr_detection_matches`, one row per
(canonical event × matched rule):

```
tenant_id, canonical_event_id, raw_ref, trace_id,
rule_id, rule_version, rule_name, engine_id,
matched_fields: [ {field_path, observed_value, predicate_note} ],
evidence_refs:  [ "xdr_canonical_evidence/<event_id>" ],
severity, confidence, mitre_attack[], evaluated_at
```

Two changes to reach it:
1. `detection_content/library` match objects must return the field paths and
   observed values they matched on. Today the predicates are opaque lambdas
   (`predicate=lambda ev: ...`), so **the matched field is not recoverable
   even in principle** — each rule must declare its evaluated fields
   (`telemetry_requirements` already lists them; the values must be captured
   at evaluation time).
2. `xdr_pipeline.evaluate_detection()` writes one row per match, with
   `evidence_refs` pointing at canonical evidence.

Honest constraint: for rules whose predicate is a closure, the matched field
list can only be as accurate as the rule's own declaration. I would not infer
it — a wrong citation is worse than none.

---

## Production actions completed (owner-approved, verified)

| Action | Result | Audit ref |
|---|---|---|
| Revoke unused live credential `key_dd92dd232f434bbba88b` ("nivx-prod-2") | `enabled=False`, `revoked_at=2026-09-14T14:49:56Z` · re-read confirms | `aud_1799328621f54e1caf61` |
| Delete stray `default` collector `col_c7147fd01df2438cbe08` | HTTP 200, re-read → **404** | `aud_aee47e7e16954319b312` |

Preconditions were verified and printed **before** each action: the key was
`enabled=True` with `last_used_at=None` in `nivx-prod-1`; the collector was in
`default`, `0/0/0` events, `last_event_at=None`, state `STARTING`, with **zero
enabled credentials in that tenant** to depend on it.

`col_a3e09eddb0544a31882e` (`nivx-prod-1`, DISABLED) was **left untouched**, as
instructed. **Production now holds no active ingest credential** — exactly one
will be minted when genuine onboarding begins, and it will not be printed.

---

## STOP — awaiting review before D8.
