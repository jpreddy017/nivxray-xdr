# STEP 35 — Bounded Deterministic Identity Backfill · DESIGN ONLY

**Status:** DESIGN — awaiting owner review. No code wired. Nothing executed.
**Scope boundary:** no Behavior run, no shadow run, no KUSHU, no DESKTOP, no
production write of any kind in this step.
**Predecessor:** STEP 34H-D closed **PASS** — `sd_canonical_endpointid_eventtime`
and `sd_canonical_hostname_eventtime` both reported `ALREADY_PRESENT_VERIFIED`
on `xdr_canonical_evidence` in production.

---

## 1. Why this step exists

The §d canonical read is to be narrowed to ONE authoritative identity key,
`additional_fields.endpoint_id`, plus one bounded legacy NAME branch
(`host.hostname`). Three derived branches (`provenance.collector_id`,
`host.host_id`, `host.hostname`) are to be retired.

Retiring `provenance.collector_id` as an *addressing* branch is only safe if the
evidence it currently reaches is reachable through the authoritative field
instead. Measurement (STEP 34E, 299,771-row corpus) found exactly one class of
row where that is not yet true:

> **1,236 rows** have NO `additional_fields.endpoint_id` but DO carry a
> `provenance.collector_id` that is platform-minted (`ep_…`) — the authenticated
> ingest boundary supplied the identity while a non-sensor DSM normalized the
> event, so the value is *authenticated*, not observation-derived.

Those 1,236 rows are the entire backfill population. Everything else is
deliberately left alone (§3.3).

**Goal of STEP 35:** make the authoritative field present on exactly those rows,
by copying an already-authenticated value, with per-row provenance that keeps a
backfilled identity permanently distinguishable from a boundary-stamped one —
and with no change to any other field of any document.

**Non-goal:** resolving the name-only population. Those rows stay explicitly
UNRESOLVED and remain addressable only through the legacy NAME branch.

---

## 2. Where it lives

A **second registered operation** inside the existing closed registry
(`edr_plane/migration_control.py`), along
`ensure_canonical_identity_indexes`:

```
OP_BACKFILL_IDENTITY = "backfill_authoritative_endpoint_identity"
```

It inherits, unchanged, every property that was already built and tested for the
index operation — and this is the reason for reusing it rather than writing a
script:

| Inherited property | Consequence for the backfill |
|---|---|
| Closed registry | the operation name is compiled in; an unknown name is refused + audited |
| Zero caller parameters | the caller supplies **only** `mode`; no filter, no collection, no limit, no update document can be injected |
| `require_admin` | authenticated admin principal recorded as `actor`; no credential in, no credential out |
| Single-writer lock (`e3_migration_locks`) | a concurrent second request CONFLICTs (409) instead of racing; lock released even on failure; a stale lock is reported, never stolen |
| Durable audit (`e3_migration_runs`) | REQUESTED / RUNNING / COMPLETED / FAILED / REFUSED, with `migration_run_id` |
| `report` vs `apply` | report mode performs **zero writes** |
| Secret-free results | counts, states, reasons and ids only |

A **third** registered operation is declared for inverse/rollback (§6):

```
OP_REVERT_IDENTITY_BACKFILL = "revert_authoritative_endpoint_identity_backfill"
```

Registering it is a code change, reviewed like any other. It is *not*
auto-invoked by a failure.

---

## 3. Eligibility rule — for review

### 3.1 The single source of truth
Eligibility is **not** restated in the migration. It is
`canonical_identity_contract.backfill_candidate(row)` — already written, already
tested, already the only deterministic backfill the contract permits:

```
authoritative field absent
AND provenance.collector_id is platform-minted ("ep_" + suffix)
  → {set: {additional_fields.endpoint_id: <collector_id>},
     source: "provenance.collector_id",
     basis:  "AUTHENTICATED_INGEST_BOUNDARY_SUPPLIED_PLATFORM_ID"}
→ otherwise None
```

If the migration and the contract ever disagree, the migration is wrong. A guard
test asserts the migration calls the contract and contains no independent
predicate of its own.

### 3.2 The database-side selector
The server-side filter is a compiled constant, never caller-supplied, and is a
*superset* of eligibility used only to bound the scan:

```
{ "additional_fields.endpoint_id": {"$exists": False},
  "provenance.collector_id": {"$regex": "^ep_"} }
```

Every candidate returned by that selector is then re-validated **in Python by
the contract** before anything is written. The regex is a narrowing device, not
the rule. (Shape-only `^ep_`: registry membership is an authorization question
answered elsewhere, and is explicitly NOT re-litigated here — the value was
already accepted at an authenticated boundary.)

### 3.3 Explicitly NOT eligible (must be 0 writes)
| Population | Measured | Why untouched |
|---|---|---|
| Authoritative field already present | 294,107 | nothing to do; never overwritten |
| Authoritative field present but NOT platform-minted | — | a fallback leaked in; contract returns UNRESOLVED, a defect to investigate, never silently fixed |
| Name-only (`host.hostname`, no minted id anywhere) | 3,557 / 3,558 | a NAME is never promoted to an identity |
| No `host` object at all (collector/network sensor) | 2,049 | not endpoint-scoped evidence; must never be associated with an endpoint |
| `host.host_id` present, authoritative absent | — | `host.host_id` is in `NEVER_IDENTITY`; it is a copy or a hostname, never a source |

---

## 4. The 1,236-row boundary — for review

The count is treated as a **declared expectation with a hard ceiling**, not as a
limit to fill.

```
EXPECTED_CANDIDATES = 1236          # STEP 34E preview measurement
CANDIDATE_HARD_CEILING = 2000       # refuse above this, do not truncate
```

Behaviour:

1. **Census first.** Both modes begin with a `count_documents` on the compiled
   selector. The number is recorded in the run record *before* any write.
2. **Drift is a refusal, not a trim.** If the census exceeds
   `CANDIDATE_HARD_CEILING`, the run is `REFUSED` with reason
   `CANDIDATE_POPULATION_DRIFT` and **zero writes occur**. It is never truncated
   to the first 1,236 — a silent partial migration is worse than no migration.
3. **Drift below/above expectation but within ceiling is reported, not blocked.**
   Production is a different corpus from the preview measurement, and the
   population legitimately shrinks over time (the STEP 34F boundary stamping
   means no *new* row can join it). The delta is surfaced as
   `expected_candidates` / `observed_candidates` / `drift` so the reviewer
   decides.
4. **Per-row, not bulk.** Writes are `update_one` per document, guarded (§5.2).
   There is no `update_many` and no `bulk_write`, so the ceiling is a true
   bound on documents touched and the ledger can be per-row.
5. **Bounded cursor.** The candidate cursor is read with an explicit
   `.limit(CANDIDATE_HARD_CEILING)` and `batch_size`, with `no_cursor_timeout`
   NOT set, so a long pause cannot pin a server cursor.

**Review question for the owner:** is `CANDIDATE_HARD_CEILING = 2000` the right
headroom, or should the ceiling be exactly `1236` and any drift a refusal?

---

## 5. Per-row write and provenance — for review

### 5.1 The update document
Exactly two paths are set. Nothing else in the document is read-modify-written,
so `tenant_id`, `host.*`, `event_time`, `ingest_time`, every raw reference and
every other provenance stamp are untouched by construction:

```
$set:
  additional_fields.endpoint_id     = <platform-minted provenance.collector_id>
  provenance.endpoint_identity      = {
      state:            "RESOLVED",
      authority:        "BACKFILL_DETERMINISTIC",     # NOT the boundary
      source:           "provenance.collector_id",
      basis:            "AUTHENTICATED_INGEST_BOUNDARY_SUPPLIED_PLATFORM_ID",
      migration_run_id: "mig_…",
      backfilled_at:    "<ISO8601 Z>",
      contract_version: "G-26"
  }
```

`authority` is deliberately **`BACKFILL_DETERMINISTIC`**, distinct from the
`AUTHENTICATED_INGEST_BOUNDARY` written by live stamping. Consequences:

* a backfilled identity is forever auditable and separable in any query;
* the inverse operation (§6) has an exact, self-describing target;
* no reader can mistake a migrated row for one that arrived with its identity.

### 5.2 Guarded write (no blind overwrite)
Each `update_one` carries the eligibility *in its own filter*, so a row that
changed between census and write is **skipped**, never overwritten:

```
filter = { _id: <row _id>,
           additional_fields.endpoint_id: {$exists: False},
           provenance.collector_id: <the exact value re-validated> }
```

`matched_count == 0` is recorded as `SKIPPED_CHANGED_UNDER_RUN`, not an error,
and not a retry. This makes the operation safe against concurrent live ingest.

### 5.3 Durable per-row ledger
A new collection `e3_migration_row_ledger`, one document per row touched:

```
{ migration_run_id, operation, collection: "xdr_canonical_evidence",
  doc_id, tenant_id, endpoint_id_set, prior_endpoint_id: null,
  prior_endpoint_identity: <the provenance sub-document as it was, or null>,
  outcome: WRITTEN | SKIPPED_CHANGED_UNDER_RUN | SKIPPED_NOT_ELIGIBLE,
  at }
```

`prior_*` is captured **before** the write, which is what makes the inverse
operation a restore rather than a guess. The ledger carries ids and states only
— no event content, no secret.

**Review question:** the ledger needs its own index
(`{migration_run_id: 1, doc_id: 1}`) and a retention decision. Keep it
indefinitely as a migration artifact, or TTL it after N days?

---

## 6. Rollback / recovery — for review

### 6.1 Resumability (the primary recovery path)
The operation is **idempotent by construction**: a successful write removes the
row from its own eligibility selector. So

* a crash, timeout, pod eviction or network fault mid-run leaves a *consistent
  partial state* — some rows migrated, the rest still eligible;
* the recovery action is simply **run `report` again, then `apply` again**; it
  resumes where it stopped and performs a no-op on everything already done;
* a completed run re-applied returns `observed_candidates = 0` and writes
  nothing.

There is no half-written document possible, because the unit of work is a single
document update of two sibling paths.

### 6.2 Lock recovery
The single-writer lock is released in a `finally`, including on exception. A lock
surviving a hard pod kill is reported as `stale` after 30 minutes and is
**never auto-stolen** — the operator is told, and clearing it is a separate
deliberate act.

### 6.3 The inverse operation
`revert_authoritative_endpoint_identity_backfill`, registered and reviewed like
any other operation. Properties:

* it targets **only** rows whose `provenance.endpoint_identity.authority ==
  "BACKFILL_DETERMINISTIC"` **and** whose `migration_run_id` matches a run
  named by the compiled registry entry — it can never touch a boundary-stamped
  row;
* it `$unset`s `additional_fields.endpoint_id` and **restores**
  `provenance.endpoint_identity` from the ledger's `prior_endpoint_identity`
  (which is `null`/absent for every row in this population, so the restore is an
  `$unset` too);
* it is itself guarded per row, audited, locked, and has `report`/`apply` modes;
* it does NOT run automatically on failure. Failure → resume (§6.1) is the
  default; revert is an owner decision.

**Review question:** should the revert operation be registered in the same
deployment as the backfill (available before it is needed), or only registered
if a revert is actually decided on?

### 6.4 What is NOT a rollback mechanism
* No collection copy / snapshot is proposed here — this is an additive two-path
  `$set` on ≤2,000 documents with a per-row prior-state ledger, which is a
  stronger and cheaper guarantee than a 300k-document copy.
* No `renameCollection`, no drop, no index change. The migration control module
  cannot express any of them.

**Review question:** does the owner nonetheless want a point-in-time backup
taken before `apply` as a matter of policy?

---

## 7. Post-backfill verification — for review

All of it read-only, all of it via the deployer in read-only mode, and the first
four are produced by the operation's own `report` mode so they need no new query
surface.

| # | Check | Pass condition |
|---|---|---|
| V1 | `report` mode re-run after `apply` | `observed_candidates == 0` |
| V2 | Rows written vs census | `written + skipped_changed + skipped_not_eligible == observed_candidates`, and `written` equals the census minus skips |
| V3 | Identity authority census | `count(authority == BACKFILL_DETERMINISTIC)` equals `written`; `count(authority == AUTHENTICATED_INGEST_BOUNDARY)` **unchanged** from its pre-run value |
| V4 | Residual UNRESOLVED census | name-only ≈3,557 and host-less ≈2,049 populations **unchanged** — the backfill must not have reduced them at all |
| V5 | No collateral mutation | for a sampled set of ledger `doc_id`s, `tenant_id`, `host.hostname`, `host.host_id`, `event_time`, `ingest_time` and raw refs are byte-identical to the pre-run capture (captured in the ledger for the sample) |
| V6 | Total document count | `xdr_canonical_evidence` count unchanged — a backfill never inserts or deletes |
| V7 | Index still serves the read | `explain()` on the §d authoritative branch shows `IXSCAN` on `sd_canonical_endpointid_eventtime` with no `SORT` stage (this is the deferred STEP 34C-revisit, now meaningful because the data exists) |
| V8 | Audit completeness | one `e3_migration_runs` record in state `COMPLETED` with the census, the counts and the actor; ledger row count == `written + skipped` |

V7 is the real prize: it is the proof that the §d read can be narrowed to the
single authoritative key, which is the precondition for retiring the legacy
branches and then running Behavior against genuine production evidence.

---

## 8. Tests to be written (when implementation is authorized)

Unit / contract, all against a local preview database or fakes — **none against
production**:

1. `report` mode performs **zero** writes (asserted by write-interception).
2. Eligibility is delegated: the migration contains no predicate of its own and
   every candidate passes `backfill_candidate`.
3. Each non-eligible population (§3.3) yields 0 writes — one test per class,
   including the `host.host_id`-present and non-minted-authoritative cases.
4. Census above `CANDIDATE_HARD_CEILING` → `REFUSED`,
   reason `CANDIDATE_POPULATION_DRIFT`, zero writes.
5. Guarded write: a row mutated between census and write is
   `SKIPPED_CHANGED_UNDER_RUN`, and its stored value is unchanged.
6. Provenance stamp shape exactly as §5.1, `authority ==
   BACKFILL_DETERMINISTIC`, `migration_run_id` present and matching the run.
7. Idempotence: `apply` twice → second run writes 0.
8. Crash simulation: exception after N rows → lock released, run `FAILED`,
   remaining rows still eligible, written rows intact.
9. Collateral-immutability: full document diff before/after is exactly the two
   declared paths.
10. Concurrency: two simultaneous `apply` requests → one runs, one 409
    `MIGRATION_ALREADY_RUNNING`.
11. Inverse operation touches only `BACKFILL_DETERMINISTIC` + matching
    `migration_run_id` rows, and a boundary-stamped row is never modified.
12. Registry closure unchanged: an unknown operation name is still refused and
    audited.

---

## 9. Execution sequence (for the record — not now)

```
DESIGN (this document)  →  OWNER REVIEW
  →  implement operation + tests  →  OWNER REVIEW
  →  deploy control plane only
  →  production `report` mode (zero writes)  →  OWNER REVIEW of census
  →  production `apply` (owner-run)
  →  V1–V8 verification (read-only, via deployer)
  →  retire legacy §d identity branches
  →  FIRST REAL-EVIDENCE SHADOW RUN (canary KUSHU)
```

Nothing in this step touches KUSHU or DESKTOP.

---

## 10. Open review questions, collected

1. `CANDIDATE_HARD_CEILING`: `2000` (headroom) or exactly `1236` (any drift
   refuses)?
2. Ledger retention: permanent migration artifact, or TTL?
3. Register the inverse/revert operation up front, or only on demand?
4. Is a point-in-time backup required before `apply` as policy, given §6.4?
5. V5 sampling: a sample of ledger rows, or capture the full prior document
   projection for **all** ≤2,000 rows (cheap at this size, strictly stronger)?
