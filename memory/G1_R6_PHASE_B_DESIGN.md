# G1-R6 PHASE B — DESIGN / READINESS (exact 28 only)

**Status: DESIGN ONLY. Nothing implemented, nothing executed.**
Phase A is PASS / CLOSED / FROZEN and is neither rerun nor reinterpreted here.

Population after Phase A:

```
delivered 3306 · delivering 28 · queued 121993 · retrying 125 · dead_letter 0 · total 125452
```

The 28 are exactly the `RETRYABLE_STILL_QUEUED` refs in
`C:\nivx\g1-proof\r5\r5-inflight-50-server-reconciliation.json`.
Phase B touches those 28 and nothing else — not the 22 repaired rows, not the
121 993 queued, not the 125 retrying.

---

## 1. Two blocking facts discovered during this review

These decide the whole design, so they come first.

### 1.1 Constructing `Outbox` would mutate the 28 before we are ready

`framework/outbox.py:170 Outbox.__init__` calls `_init_schema()` and then
**`_reset_stuck_delivering()` (line 207)**, whose body is:

```sql
UPDATE envelopes SET status='queued', updated_at=? WHERE status='delivering'
```

Merely opening the real `Outbox` therefore flips all 28 `delivering` rows to
`queued` — an uncontrolled mutation *and* it makes them eligible for the
general backlog worker, which is exactly what must not happen. This is why the
exact-50 tool and the Phase A repair both refuse to import it.

**Decision: Phase B never constructs `Outbox`.** It owns its own `sqlite3`
connection (read-only in dry run, `BEGIN IMMEDIATE` per bounded step in
apply), and imports only the pure `Envelope` dataclass for payload shaping.
Importing the module is safe; instantiating the class is not. A test asserts
both: no `Outbox(` call, and `delivering` count unchanged after import.

### 1.2 There is no non-mutating liveness probe for the collector's credential

`IngestClient.deliver()` authenticates to `POST /api/xdr/ingest/telemetry`
with `X-XDR-API-Key` + `X-Tenant-Id`, and that route requires the
`collectors.enroll` permission (`routers/xdr_ingest.py:798-800`).

Credential inventory for the collector's tenant `ten_f1a5479243e901cf159e230fa0`
(read-only, PREVIEW): **7 keys, 6 revoked, exactly 1 live** —
`key_1318617827ee44ada0f7` / prefix `nvx_5866032d`, `enabled: true`,
`revoked_at: null`, scope `['collectors.enroll']`, `last_used_at
2026-09-24T06:19:40Z` (i.e. during the R5 window). Scope matches the ingest
route, so **delivery is possible** — no blocker.

But a `collectors.enroll`-scoped key can call nothing read-only, so there is
**no way to prove the credential is alive without delivering something**.

**Decision: a canary of exactly 1, then the remaining 27.** This is not an
invention — `DeliveryHealthGate.probe_limit()` already returns exactly 1 in
`HALF_OPEN`, so Phase B adopts the same discipline unconditionally for its
first attempt. An auth failure then costs one classified, idempotent,
reconciled attempt instead of 28.

---

## 2. State machine

Per-row, and the run as a whole. Every transition is justified by evidence;
none is inferred.

```
                    ┌─────────────────────────────────────────┐
                    │ 0 · LOAD AUTHORITY + FREEZE PRECONDITIONS│
                    └───────────────────┬─────────────────────┘
                                        │ all 28 present, locally `delivering`
                                        │ the 22 excluded and untouched
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 1 · GATE CHECK (R3.1, persisted state)  │
                    └───────────────────┬─────────────────────┘
                         allow_delivery()│false → HARD STOP (no attempt)
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 2 · CANARY: exactly 1 identity          │
                    └───────────────────┬─────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 3 · RECONCILE the canary (authoritative)│
                    └───────────────────┬─────────────────────┘
              canary not canonical/retained → HARD STOP, 27 never attempted
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 4 · REMAINDER: the other 27, bounded    │
                    └───────────────────┬─────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 5 · RECONCILE all 28 (single request)   │
                    └───────────────────┬─────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 6 · LOCAL ACCOUNTING (transactional)    │
                    └───────────────────┬─────────────────────┘
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │ 7 · IDENTITY EQUATION + EVIDENCE        │
                    └─────────────────────────────────────────┘
```

Per-row terminal classes, taken **only** from the authoritative reconciliation
in step 5 — never from the HTTP response of step 2/4:

| server bucket | local action | local status after |
|---|---|---|
| `DELIVERED_CANONICAL` | accounting repair, same marker discipline as Phase A | `delivered` |
| `DELIVERED_RETAINED_RAW` | accounting repair, **B4 preserved**: recorded as retained-raw, never as canonical | `delivered` + `retained_raw` provenance |
| `RETRYABLE_STILL_QUEUED` | **no local change** — attempts/next_attempt_at/last_error untouched | `delivering` (still) |
| `TERMINAL_ACCOUNTED` | **no local change**, reported for owner decision | `delivering` (still) |
| `UNEXPLAINED` | **FAIL / HARD STOP**, whole run rolled back | unchanged |

A row is marked `delivered` **only** when the authoritative backend proves
canonical or retained-raw evidence exists. An ambiguous wire outcome
(`UNATTRIBUTED_FAILURE`, timeout, edge refusal, no `X-Request-ID`
attribution) is classified retryable and sent to reconciliation — never
guessed as delivered.

---

## 3. Exact 28-selection mechanism

1. Read the authority JSON. Refuse it if `VERDICT` is present (the
   FAILED-UNTRUSTED sibling), if `pass != true`, or if `rows` is absent.
2. Require exactly 50 rows, 22 `DELIVERED_CANONICAL`, 28
   `RETRYABLE_STILL_QUEUED`, 0 other.
3. `target = the 28 retryable refs`; `excluded = the 22 canonical refs`.
   Assert `target ∩ excluded = ∅` and `|target| = 28`.
4. Hard bound: `len(target) > 28` → refuse. There is no `--limit` and no
   `--all`; the population is not parameterised.
5. For each of the 28, read the local row and require:
   - it exists, and `status == 'delivering'`;
   - `recovery_json` carries **no** `G1-R6-A` marker (it must not be one of
     the repaired 22);
   - the locally recomputed delivery identity equals the authority's
     `delivery_key` for that ref.
6. Assert the local `delivering` set is **exactly** these 28 (Phase A's
   post-state), and that each of the 22 excluded refs is locally `delivered`
   **and** carries the `G1-R6-A` marker — positive proof Phase A is intact.
7. Assert `queued == 121993`, `retrying == 125`, `dead_letter == 0`,
   `total == 125452`, and fingerprint those populations so step 7 can prove
   they never moved.

---

## 4. Delivery mechanism

- `IngestClient` from `framework/delivery.py` — unchanged, hardened, already
  carries G1-R1 classification and G1-R2 bounded redacted failure detail.
- Payload built via the pure `Envelope` dataclass from the local row, so
  `tenant_id / source / source_event_id / connector_id / collector_id / raw`
  are identical to the original attempt. **Identity is preserved, not
  regenerated.**
- Two bounded steps only: canary (1), then remainder (27). Batch size for the
  remainder is capped small (default 7) so a mid-run failure leaves a
  reconcilable boundary rather than 27 unknowns.
- Strictly no `DeliveryWorker`, no scheduler, no acquisition, no
  `EvtSubscribe`, no bookmark write, no `next_batch()` (which would claim
  arbitrary rows from the 121 993 backlog).
- `NIVX_INGEST_*` configuration is read as-is. If unconfigured,
  `deliver()` already returns `RETRYABLE / ingest_not_configured` — Phase B
  hard-stops on that **before** the canary rather than recording a fake
  attempt.

## 5. Idempotency protections

1. Server-side `ingest_idempotency.event_identity` is the same deterministic
   hash used by the exact-50 tool (tenant + collector + source + event_id +
   payload_digest). Re-delivering a row the server already holds is a
   **no-op de-duplicated write**, which is precisely why redelivering the 28
   is safe and why the 22 were repaired locally instead of resent.
2. Identity is recomputed from the row and asserted equal to the authority's
   `delivery_key` before the row is eligible — a payload that would land under
   a *different* identity is refused, not delivered.
3. Local `delivering` status is never pre-flipped to `queued`, so no other
   process can claim these rows concurrently, and `_reset_stuck_delivering`
   is never invoked.
4. The writer guard refuses to run while any collector process is alive.
5. Apply mode takes an exclusive `BEGIN IMMEDIATE` only for the accounting
   step, after all evidence is in hand.

## 6. R3.1 delivery-health gate interaction

- The gate is constructed as `DeliveryHealthGate(store=<phase-b adapter>,
  destination_key=<same key the worker uses>)`, so the persisted
  `delivery_health_gate` row is **restored**, not rediscovered
  (`restored_from` provenance is recorded in the evidence).
- `allow_delivery() == False` (OPEN, cooldown unexpired) → **HARD STOP with no
  attempt**. Phase B does not override an open gate.
- `HALF_OPEN` → `probe_limit() == 1`, which is already the canary shape.
- `record_success()` / `record_destination_failure(reason)` are called with
  real destination evidence, exactly as the worker does, so the gate's memory
  stays truthful.
- **Dry run** passes a read-only store adapter whose `save_health_gate` raises,
  proving the readiness pass cannot mutate gate state.

## 7. Expected local-state transitions

Only these are possible, and only in apply mode:

```
delivering → delivered        for each row the server proves canonical
delivering → delivered        for each row the server proves retained-raw (B4 flagged)
delivering → delivering       for retryable / terminal (NO change at all)
```

If all 28 land canonically, post-state is:

```
delivered 3334 (+28) · delivering 0 (-28) · queued 121993 · retrying 125 · dead_letter 0 · total 125452
```

A partial outcome is legitimate and is **not** a failure: e.g. 20 canonical
and 8 still retryable → `delivered 3326 · delivering 8`. Bookmarks, queued,
retrying, dead_letter and total must be unchanged in **every** case.

## 8. Failure / rollback semantics

- Dry run: read-only. No wire call, no gate write, no SQLite write.
- Any precondition failure → HARD STOP before the canary; nothing attempted.
- Canary not accounted for → HARD STOP; the 27 are never attempted.
- Any `UNEXPLAINED` row in the final reconciliation → FAIL; the accounting
  transaction is rolled back in full. Nothing may vanish from accounting.
- Accounting is all-or-nothing: one transaction, per-row `rowcount != 1` →
  rollback.
- A failed delivery attempt **leaves the row exactly as it was**
  (`delivering`, same attempts, same last_error) and is recorded as evidence.
  Phase B deliberately does not consume the retry budget of these rows.
- Every failure path returns a non-zero process exit code.
- A pre-execution backup of `outbox.db` (+ `-wal`/`-shm`) is written before
  the first mutating operation, as in Phase A.
- **No schema change.** `recovery_json` already exists (Phase A wrote 22
  markers through it). If any further column were ever needed it would be
  raised for separate approval, never added silently.

## 9. Evidence artifacts

Written to `C:\ProgramData\NivXForge\state\g1_r6_evidence\`:

| file | when |
|---|---|
| `r6-phaseB-readiness.json` | dry run — selection proof, gate state, preconditions, planned canary/remainder, non-mutation proof |
| `r6-phaseB-delivery.json` | apply — per-attempt classification + bounded redacted failure detail, gate transitions |
| `r6-phaseB-reconciliation.json` | apply — the complete authoritative per-row response for all 28 |
| `r6-phaseB-final.json` | apply — per-row provenance, the identity equation, pre/post snapshots, PASS/FAIL |
| `outbox-pre-r6b-<stamp>.db` | apply — backup before the first mutation |

Per-row provenance records: ref, delivery identity, wire classification,
server bucket, evidence_ref, canonical_event_id or retained_raw_id, local
action taken, and `network_delivery_performed: true/false`.

**Identity equation, asserted:**

```
canonical + retained_raw + retryable + terminal + unexplained = 28
required: unexplained = 0
```

## 10. Files to add / change

| file | change |
|---|---|
| `apps/nivxray-xdr-collector/scripts/g1_r6_phase_b_exact28_recovery.py` | **new** — the only new logic |
| `apps/nivxray-xdr-collector/tests/test_g1_r6_phase_b_exact28.py` | **new** — focused tests |
| `apps/nivxray-xdr-collector/tests/test_g1_r6_phase_b_execution_copy.py` | **new** — static guards on the PS block |
| `memory/G1_R6_PHASE_B_EXECUTION_COPY.ps1` | **new** — dry-run-by-default wrapper |
| `framework/*` | **unchanged** — no collector redesign |
| `backend/*` | **unchanged** — reconciliation API already sufficient |

## 11. Focused tests (planned)

1. Selection: exactly the 28 retryable refs chosen; the 22 canonical excluded;
   a 27- or 29-row authority refused; the FAILED-UNTRUSTED sibling refused.
2. Phase A integrity: refuses if any of the 22 is not `delivered` with a
   `G1-R6-A` marker, or if the local `delivering` set ≠ the 28.
3. **`Outbox` is never constructed**: import the module, assert the
   `delivering` count is still 28 and that no `Outbox(` call exists.
4. Gate: OPEN + unexpired cooldown → hard stop, zero wire calls;
   `HALF_OPEN` → canary limit 1; dry-run store refuses writes.
5. Canary: an auth failure on row 1 stops the run with 27 unattempted.
6. Ambiguity: `UNATTRIBUTED_FAILURE` / timeout / missing `X-Request-ID` is
   classified retryable and reconciled, never marked delivered.
7. Full success: 28 canonical → `delivered 3334 · delivering 0`, queued /
   retrying / total / bookmarks unchanged, 28 markers written.
8. Partial: 20 canonical + 8 retryable → `delivered 3326 · delivering 8`, and
   the 8 keep status, attempts, next_attempt_at and last_error byte-for-byte.
9. B4: a `DELIVERED_RETAINED_RAW` row is accounted as retained-raw, never
   relabelled canonical.
10. `UNEXPLAINED` ⇒ FAIL + full rollback + non-zero exit.
11. Idempotency: a row whose recomputed identity ≠ the authority's
    `delivery_key` is refused, not delivered.
12. Blast radius: the 121 993 queued and 125 retrying rows are fingerprinted
    before and after and must be identical.
13. Second run is a no-op / refusal; no double counting.

## 12. Acceptance criteria

**PASS requires all of:**
- authority file validated; exactly 28 selected; the 22 excluded and proven
  intact;
- gate permitted the attempt and its persisted state was restored, not
  rediscovered;
- every attempt bounded (1 canary, then ≤ 7 per step, ≤ 28 total);
- final reconciliation covers all 28 with strict 1:1 refs;
- `unexplained = 0` and the identity equation sums to 28;
- every row marked `delivered` carries server-proven canonical or retained-raw
  evidence;
- retryable/terminal rows unchanged in status, attempts, next_attempt_at,
  last_error;
- queued 121 993, retrying 125, dead_letter 0, total 125 452, bookmarks
  unchanged;
- all four evidence artifacts written; exit code 0.

**FAIL (hard stop, rollback, non-zero exit) on any of:** unexplained > 0,
ref mismatch, gate open, canary unaccounted, identity mismatch, blast-radius
drift, `Outbox` construction detected, or a `delivered` mark without server
evidence.

---

**Not included by design:** no general backlog drain, no acquisition restart,
no `DeliveryWorker`, no scheduler, no schema change, no collector redesign,
no Phase A rerun. After the 28 close, the ~122k backlog still waits on the
permanent durable receipt / reconciliation mechanism — that is the next
design task, not this one.
