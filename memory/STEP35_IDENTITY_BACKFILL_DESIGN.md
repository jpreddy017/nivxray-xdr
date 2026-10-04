# STEP 35 — Bounded Deterministic Identity Backfill
## FINAL DESIGN · owner decisions incorporated · DESIGN ONLY

**Status:** FINAL DESIGN — awaiting authorization to implement.
No operation code written. Nothing executed. The 1,236 rows are UNMODIFIED.
**Scope boundary:** no Behavior run, no shadow run, no KUSHU, no DESKTOP, no
production write of any kind in this step.
**Predecessor:** STEP 34H-D closed **PASS** — `sd_canonical_endpointid_eventtime`
and `sd_canonical_hostname_eventtime` confirmed present, correct field set,
correct directions, correct key ORDER, in production.

---

## 0. Owner decisions — binding constraints

These are not preferences; each one becomes a compiled constant or a refusal
gate, and each one is covered by a named test.

| # | Decision | Where it is enforced |
|---|---|---|
| D1 | Hard ceiling **exactly 1,236**. Any candidate-count drift before apply → **HOLD**. Never truncate, never silently widen. | §4, gate G2, tests T4/T5 |
| D2 | Migration row ledger is a **permanent auditable artifact**. No TTL. | §5.3, test T13 |
| D3 | The bounded **revert operation is defined, registered and tested BEFORE apply**. It may touch only rows *proven* to belong to the corresponding run, and must **restore recorded prior state, never infer it**. | §6.3, gate G5, tests T14–T17 |
| D4 | A **point-in-time production backup / equivalent recoverable pre-change state is required before apply**, and apply refuses without attestation of it. | §6.1, gate G4, test T8 |
| D5 | **Full prior projection for every eligible row**, not a sample, and collateral fields **proven** unchanged after migration. | §5.2 + §7 V5, tests T9/T10 |
| D6 | Add an **index-served `explain()` verification** proving the production query path uses the new index with no blocking sort and no collection scan. | §7 V7 + §8, test T18 |
| D7 | **No Residual Census UI panel.** All UI work deferred. | nothing in this design touches the frontend |

Rationale accepted and recorded: we are modifying **historical security
evidence**. Provenance and recoverability outrank migration convenience.

---

## 1. Why this step exists

The §d canonical read is to be narrowed to ONE authoritative identity key,
`additional_fields.endpoint_id`, plus one bounded legacy NAME branch
(`host.hostname`), retiring three derived branches
(`provenance.collector_id`, `host.host_id`, `host.hostname`).

Retiring `provenance.collector_id` as an *addressing* branch is only safe if the
evidence it currently reaches is reachable through the authoritative field.
STEP 34E measurement (299,771-row corpus) found exactly one class where it is not:

> **1,236 rows** have NO `additional_fields.endpoint_id` but DO carry a
> `provenance.collector_id` that is platform-minted (`ep_…`) — the authenticated
> ingest boundary supplied the identity while a non-sensor DSM normalized the
> event. That value is **authenticated**, not observation-derived.

Those 1,236 rows are the entire population. The backfill copies an
already-authenticated value into the authoritative field, stamps per-row
provenance that keeps it permanently distinguishable from a boundary-stamped
identity, and changes **nothing else in any document**.

Since STEP 34F (boundary stamping) and STEP 34G (`host.host_id` removed as an
identity), **no newly ingested row can join this population**. It is a closed,
shrinking, historical set. That is what makes an exact ceiling (D1) correct
rather than brittle.

**Non-goal:** resolving the name-only population. Those rows stay explicitly
UNRESOLVED and remain addressable only through the legacy NAME branch.

---

## 2. Four registered operations, in mandated order

All four live in the existing closed registry
(`edr_plane/migration_control.py`), alongside the already-shipped
`ensure_canonical_identity_indexes`.

```
1. OP_CAPTURE_PRIOR_STATE = "capture_identity_backfill_prior_state"
       read-only on canonical evidence; writes ONLY the ledger (D5)
2. OP_REVERT              = "revert_authoritative_endpoint_identity_backfill"
       registered and TESTED BEFORE apply (D3)
3. OP_ATTEST_RECOVERABLE  = "attest_pre_change_recoverable_state"
       records the owner's backup/snapshot reference (D4)
4. OP_BACKFILL            = "backfill_authoritative_endpoint_identity"
       refuses to apply unless 1 and 3 are satisfied and 2 is registered
```

Each inherits, unchanged, every property already built and tested for the index
operation — which is precisely why we reuse the registry instead of writing a
script:

| Inherited property | Consequence here |
|---|---|
| Closed registry | names are compiled in; an unknown name is refused + audited |
| Zero caller parameters | caller supplies **only** `mode`; no filter, collection, limit, pipeline or update document can be injected |
| `require_admin` | authenticated admin principal recorded as `actor`; no credential in, none out |
| Single-writer lock (`e3_migration_locks`) | a concurrent second request CONFLICTs (409); lock released even on failure; a stale lock is reported, **never stolen** |
| Durable audit (`e3_migration_runs`) | REQUESTED / RUNNING / COMPLETED / FAILED / REFUSED with `migration_run_id` |
| `report` vs `apply` | report mode performs **zero** writes to canonical evidence |
| Secret-free results | counts, names, states, reasons, ids only |

---

## 3. Eligibility rule

### 3.1 Single source of truth
Eligibility is **not** restated in the migration. It is
`canonical_identity_contract.backfill_candidate(row)` — already written, already
tested, already the only deterministic backfill the contract permits:

```
authoritative field absent
AND provenance.collector_id is platform-minted ("ep_" + suffix)
  → {set:    {additional_fields.endpoint_id: <collector_id>},
     source: "provenance.collector_id",
     basis:  "AUTHENTICATED_INGEST_BOUNDARY_SUPPLIED_PLATFORM_ID"}
→ otherwise None
```

If the migration and the contract ever disagree, the migration is wrong. A guard
test asserts the migration contains no independent predicate of its own.

### 3.2 Database-side selector (a scan bound, not the rule)
A compiled constant, never caller-supplied, deliberately a *superset*:

```
{ "additional_fields.endpoint_id": {"$exists": false},
  "provenance.collector_id":       {"$regex": "^ep_"} }
```

Every document it returns is re-validated **in Python by the contract** before
anything is written. Shape-only `^ep_`: registry membership is an authorization
question answered elsewhere and is explicitly NOT re-litigated — the value was
already accepted at an authenticated boundary.

### 3.3 Explicitly NOT eligible — must be exactly 0 writes
| Population | Measured | Why untouched |
|---|---|---|
| Authoritative field already present | 294,107 | nothing to do; never overwritten |
| Authoritative present but NOT platform-minted | — | a fallback leaked in; that is a DEFECT to investigate, never silently "fixed" |
| Name-only (`host.hostname`, no minted id) | 3,557 / 3,558 | a NAME is never promoted to an identity |
| No `host` object at all (network/collector sensor) | 2,049 | not endpoint-scoped evidence; must never be associated with an endpoint |
| `host.host_id` present, authoritative absent | — | `host.host_id` ∈ `NEVER_IDENTITY`; a copy or a hostname, never a source |

---

## 4. The 1,236 boundary — D1, exact

```
EXPECTED_CANDIDATES      = 1236     # STEP 34E measurement
CANDIDATE_HARD_CEILING   = 1236     # D1: exact, not headroom
```

Behaviour:

1. **Census first, always.** Both modes open with `count_documents` on the
   compiled selector. The number is written to the run record *before* any write
   is contemplated.
2. **Any drift is a HOLD.** `observed != 1236` → state `REFUSED`, reason
   `CANDIDATE_POPULATION_DRIFT`, **zero writes**, and the record carries
   `expected`, `observed` and `drift`. This covers both directions:
   * `observed > 1236` — new rows joined a population that STEP 34F/34G made
     closed. That is a **contract violation to investigate**, not extra work to
     absorb. Truncating to the first 1,236 would hide it.
   * `observed < 1236` — rows were already migrated, deleted, or retained away.
     Also an investigation, because it means our picture of the evidence is
     stale.
3. **Never truncate, never widen.** There is no caller-supplied limit, and no
   code path that processes a partial population. The ceiling is a refusal
   threshold, not a `.limit()` to fill.
4. **Per-row only.** Writes are guarded `update_one` per document (§5.2). No
   `update_many`, no `bulk_write`. The ceiling is therefore a true bound on
   documents touched, and the ledger can be exactly one row per document.
5. **Bounded cursor.** Candidate cursor read with explicit `.limit(1236)` and a
   modest `batch_size`; `no_cursor_timeout` NOT set, so a pause cannot pin a
   server cursor.
6. **Census stability.** The census is taken once per run and re-asserted
   immediately before the write phase; if it moved in between, the run REFUSES
   with `CENSUS_UNSTABLE` rather than proceeding on a stale number.

**A legitimate drift is handled by code review, not by a flag.** If production
genuinely holds a different number for a understood reason, the constant is
changed in a reviewed commit and redeployed. There is no runtime override, and
no environment variable that can relax D1.

---

## 5. Prior-state capture, write, and provenance

### 5.1 Phase 1 — `capture_identity_backfill_prior_state` (D5)
Runs **before** apply. Reads canonical evidence, writes **only** the ledger.

For **every one of the 1,236 eligible rows** it records a *full prior
projection*:

```
prior = {
  doc_id, tenant_id,
  additional_fields:            <entire sub-document as-is>,
  provenance:                   <entire sub-document as-is>,
  host:                         <entire sub-document as-is>,
  event_time, ingest_time,
  raw_refs:                     <every raw/source reference field>,
  collateral_digest:            sha256(canonical_bson(doc EXCLUDING the two
                                       paths this migration may set)),
  full_doc_digest:              sha256(canonical_bson(doc))
}
```

Two digests, two different jobs:
* `collateral_digest` — computed over the document with
  `additional_fields.endpoint_id` and `provenance.endpoint_identity` removed.
  After apply it must be **byte-identical** for all 1,236 rows. That is the
  proof that nothing unrelated moved (D5), and it covers fields we never
  enumerated, including event content, without storing that content.
* `full_doc_digest` — changes by design, and pins exactly which document version
  the prior projection describes, so the revert can refuse a row that has since
  been altered by something else.

Capture is idempotent (keyed on `migration_run_id` + `doc_id`), resumable, and
completion is asserted: `ledger_rows == 1236` or the phase FAILS.

### 5.2 Phase 3 — the guarded write
Exactly two paths are set. Nothing is read-modify-written, so `tenant_id`,
`host.*`, `event_time`, `ingest_time`, raw references and every other provenance
stamp are untouched **by construction**:

```
$set:
  additional_fields.endpoint_id = <platform-minted provenance.collector_id>
  provenance.endpoint_identity  = {
      state:            "RESOLVED",
      authority:        "BACKFILL_DETERMINISTIC",   # NOT the boundary
      source:           "provenance.collector_id",
      basis:            "AUTHENTICATED_INGEST_BOUNDARY_SUPPLIED_PLATFORM_ID",
      migration_run_id: "mig_…",
      backfilled_at:    "<ISO8601 Z>",
      contract_version: "G-26"
  }
```

`authority` is deliberately `BACKFILL_DETERMINISTIC`, distinct from the
`AUTHENTICATED_INGEST_BOUNDARY` written by live stamping. Consequences: a
backfilled identity is forever auditable and separable in any query; the revert
has an exact, self-describing target; and no reader can mistake a migrated row
for one that arrived carrying its identity.

The filter carries the eligibility **and** the captured document version, so a
row that changed between capture and write is **skipped, never overwritten**:

```
filter = { _id: <doc_id>,
           "additional_fields.endpoint_id": {"$exists": false},
           "provenance.collector_id": <exact re-validated value> }
```

`matched_count == 0` → ledger outcome `SKIPPED_CHANGED_UNDER_RUN`. Not an error,
not a retry, not a force. Any skip means the run cannot report a clean pass, and
V2 will surface it.

### 5.3 The ledger — permanent (D2)
Collection `e3_migration_row_ledger`, one document per row:

```
{ migration_run_id, operation, phase,
  collection: "xdr_canonical_evidence",
  doc_id, tenant_id,
  prior: { …full prior projection, §5.1… },
  endpoint_id_set, prior_endpoint_id: null,
  outcome: CAPTURED | WRITTEN | SKIPPED_CHANGED_UNDER_RUN | SKIPPED_NOT_ELIGIBLE,
  at }
```

* **No TTL. No cleanup job. No expiry index.** D2: this is the audit record of a
  modification to historical security evidence, and it is what makes the revert
  a *restore* rather than a guess.
* Required index `{migration_run_id: 1, doc_id: 1}`, created through the same
  reviewed index-contract mechanism as the §d indexes — not ad hoc.
* Contents are ids, states, timestamps, provenance sub-documents and digests.
  No secret, no connection detail. (Note for review: `host` and
  `additional_fields` sub-documents are retained verbatim; they are already
  inside the same production database and the same tenant boundary, so this adds
  no new exposure surface.)

---

## 6. Recoverability — backup, resume, revert

### 6.1 Pre-change recoverable state is a GATE (D4)
Apply **refuses** unless an attestation exists. The migration cannot itself take
a cloud snapshot, so recoverability is made an explicit, recorded precondition
rather than an assumption:

`attest_pre_change_recoverable_state` writes one record to
`e3_migration_preconditions`:

```
{ operation: "backfill_authoritative_endpoint_identity",
  kind: "POINT_IN_TIME_SNAPSHOT" | "EQUIVALENT_RECOVERABLE_STATE",
  reference,                 # opaque snapshot/backup identifier — NOT a secret
  taken_at, attested_by,     # authenticated admin actor
  attested_at }
```

Apply's gate G4 requires:
* a record for this exact operation exists;
* `taken_at` is **not older than 24 hours**;
* `taken_at` is **earlier than** the apply request.

Otherwise: `REFUSED`, reason `NO_ATTESTED_RECOVERABLE_STATE`, zero writes.

The attestation reference is an identifier the owner already holds; it is
recorded for audit and never used to authenticate anything. **No connection
string, credential or key is accepted by this operation** — and the review
should reject any later change that lets one in.

Defense in depth, as asked: the snapshot is layer 1, the full prior projection
ledger (§5.1) is layer 2, and the bounded revert (§6.3) is layer 3. Layers 2 and
3 are precise and instant for these 1,236 rows; layer 1 covers the failure modes
no in-database mechanism can (corruption, operator error elsewhere, infra loss).

### 6.2 Resume is the primary recovery path
The backfill is **idempotent by construction**: a successful write removes the
row from its own eligibility selector. Therefore

* a crash, timeout, pod eviction or network fault mid-run leaves a *consistent
  partial state* — some rows migrated, the rest still eligible;
* with D1 in force, a resumed run's census will be `< 1236` and will **HOLD**.
  That is intentional: a partially completed migration must be reviewed by a
  human, not silently finished. Resumption after a crash is therefore an
  explicit, reviewed act (the constant is adjusted in a reviewed commit, or the
  run is reverted to a clean baseline first). **This is the one place where D1
  costs us convenience, and the trade is accepted deliberately.**
* no half-written document is possible: the unit of work is a single-document
  update of two sibling paths.

Lock recovery: released in `finally`, including on exception. A lock surviving a
hard pod kill is reported `stale` after 30 minutes and is **never auto-stolen** —
clearing it is a separate deliberate act.

### 6.3 `revert_authoritative_endpoint_identity_backfill` — built and tested FIRST (D3)
Registered, reviewed and **fully tested before apply is ever authorized**.
Properties:

* **Proven membership only.** A row is a revert target only if *all* hold:
  1. `provenance.endpoint_identity.authority == "BACKFILL_DETERMINISTIC"`;
  2. `provenance.endpoint_identity.migration_run_id == <the named run>`;
  3. a ledger row exists for `(migration_run_id, doc_id)` with outcome `WRITTEN`;
  4. the current `additional_fields.endpoint_id` equals the ledger's
     `endpoint_id_set`.
  A boundary-stamped row can never satisfy (1). A row from a different run can
  never satisfy (2). A row we did not record can never satisfy (3).
* **Restores recorded prior state, never infers it.** The written value comes
  from the ledger's `prior` projection — for this population
  `prior_endpoint_identity` is absent and `prior_endpoint_id` is null, so the
  restore is an `$unset` of both paths. The revert contains **no logic that
  reconstructs a prior value**, and a test asserts the ledger is the only source.
* **Refuses on divergence.** If a row's `collateral_digest` no longer matches
  the ledger, something else modified that document since the backfill. The
  revert `SKIPS` it with `COLLATERAL_DIVERGED_SINCE_BACKFILL` and reports it,
  rather than reverting into an unknown state.
* Per-row guarded, audited, locked, `report`/`apply` modes, zero caller
  parameters — same inherited properties as everything else.
* **Never automatic.** A failed backfill does not trigger a revert. Revert is an
  owner decision on reviewed evidence.

### 6.4 What is deliberately NOT a rollback mechanism
No collection copy, no `renameCollection`, no drop, no index change. The
migration control module cannot express any of them, and that is a feature.

---

## 7. Verification — V1…V9

All read-only; via the deployer in read-only mode. V1–V4 and V8 come from the
operations' own `report` mode, so they need no new query surface.

| # | Check | Pass condition |
|---|---|---|
| V1 | `report` re-run after apply | `observed_candidates == 0` |
| V2 | Write accounting | `written + skipped_* == 1236` **and** `skipped_* == 0` for a clean pass |
| V3 | Authority census | `count(authority == BACKFILL_DETERMINISTIC) == 1236`; `count(authority == AUTHENTICATED_INGEST_BOUNDARY)` **unchanged** from its pre-run value |
| V4 | Residual UNRESOLVED census | name-only ≈3,557 and host-less ≈2,049 **unchanged** — the backfill must not have reduced them at all |
| V5 | **Collateral immutability, all 1,236 rows (D5)** | recomputed `collateral_digest` is byte-identical to the ledger value for **every** row — zero exceptions, no sampling |
| V6 | Collection cardinality | `xdr_canonical_evidence` total document count unchanged — a backfill never inserts or deletes |
| V7 | **Index-served query path (D6)** | see §8 — `IXSCAN` on `sd_canonical_endpointid_eventtime`, **no `SORT` stage**, **no `COLLSCAN`** |
| V8 | Audit completeness | one `e3_migration_runs` record `COMPLETED` carrying census, counts and actor; ledger rows == 1236; precondition attestation present and linked |
| V9 | Revert rehearsal evidence (D3) | the revert's own test suite passed **before** apply, and revert `report` mode against the real run names exactly 1,236 reversible rows and zero others |

V7 is the real prize: it is the proof that the §d read can be narrowed to the
single authoritative key — the precondition for retiring the legacy branches and
then running Behavior against genuine production evidence.

---

## 8. The `explain()` verification — D6, specified

A read-only verification, expressed as a registered **report-only** operation so
it is repeatable and carries no caller-supplied query:

```
explain_canonical_identity_read_plan     # report mode only, never writes
```

It explains the **exact shape the §d read issues** (built from the compiled
contract, not hand-typed):

```
filter: { tenant_id: <one tenant>,
          "additional_fields.endpoint_id": {"$in": [<one endpoint id>]} }
sort:   { event_time: -1 }
limit:  <the §d bounded page size>
```

Assertions, each a hard pass/fail:

1. winning plan stage is `IXSCAN` (or `LIMIT/FETCH → IXSCAN`);
2. `indexName == "sd_canonical_endpointid_eventtime"`;
3. **no `SORT` stage** anywhere in the winning plan — the index supplies the
   newest-first order;
4. **no `COLLSCAN`** anywhere in the winning plan;
5. `indexBounds` key order is `tenant_id` → `additional_fields.endpoint_id` →
   `event_time`, which is also the **order-preserving attestation** of compound
   key order that G-39 says `list_indexes` can never give us;
6. with `executionStats`: `totalDocsExamined` is bounded by the page size, and
   `nReturned / totalKeysExamined` shows no large over-scan.

The legacy NAME branch is explained the same way against
`sd_canonical_hostname_eventtime`.

Run **after** apply (V7), because before the backfill the authoritative branch
has no rows for this population and the plan proves little. It also permanently
closes the deferred STEP 34C-revisit.

---

## 9. Gates, in order — nothing proceeds past a red gate

| Gate | Requirement | On failure |
|---|---|---|
| **G1** | Capture phase complete: ledger holds a full prior projection for all 1,236 rows | REFUSE apply — `PRIOR_STATE_CAPTURE_INCOMPLETE` |
| **G2** | Census `== 1236` exactly, and stable across the run (D1) | REFUSE — `CANDIDATE_POPULATION_DRIFT` / `CENSUS_UNSTABLE`, **HOLD and investigate** |
| **G3** | Revert operation registered **and its test suite green** (D3) | REFUSE apply — `REVERT_NOT_PROVEN` |
| **G4** | Attested point-in-time recoverable state, < 24h old, earlier than the request (D4) | REFUSE — `NO_ATTESTED_RECOVERABLE_STATE` |
| **G5** | Single-writer lock acquired | 409 `MIGRATION_ALREADY_RUNNING` |
| **G6** | Per-row contract re-validation passes | skip that row, record it; it is not a run failure but it blocks a clean pass |

G1–G4 are evaluated **before the first write** and are reported by `report` mode,
so the owner can see a green board before authorizing apply.

---

## 10. Tests to be written — 18, all local, none against production

**Eligibility and delegation**
1. `report` mode performs **zero** writes to canonical evidence (write-interception).
2. The migration holds no predicate of its own; every candidate passes `backfill_candidate`.
3. Each non-eligible population (§3.3) yields 0 writes — one test per class, including `host.host_id`-present and non-minted-authoritative.

**The exact ceiling (D1)**
4. Census `1237` → `REFUSED` `CANDIDATE_POPULATION_DRIFT`, zero writes, **and not truncated to 1,236**.
5. Census `1235` → `REFUSED` `CANDIDATE_POPULATION_DRIFT`, zero writes.
6. Census moves between the opening count and the write phase → `REFUSED` `CENSUS_UNSTABLE`.
7. No environment variable or request field can relax the ceiling (grep-level guard + request-model `extra: forbid`).

**Gates**
8. Missing / stale (>24h) / post-dated attestation → `REFUSED` `NO_ATTESTED_RECOVERABLE_STATE` (D4).
9. Incomplete capture ledger → `REFUSED` `PRIOR_STATE_CAPTURE_INCOMPLETE` (D5/G1).

**Write correctness**
10. Full-document diff before/after is **exactly** the two declared paths, and `collateral_digest` is unchanged — asserted for every row in the fixture, not a sample (D5).
11. Guarded write: a row mutated between capture and write → `SKIPPED_CHANGED_UNDER_RUN`, and its stored value is unchanged.
12. Provenance stamp shape exactly §5.2, `authority == BACKFILL_DETERMINISTIC`, `migration_run_id` matching the run.
13. Ledger is permanent: no TTL index exists on `e3_migration_row_ledger`, and the required `{migration_run_id, doc_id}` index does (D2).

**Revert, proven before apply (D3)**
14. Revert touches only rows satisfying all four membership conditions; a boundary-stamped row and a row from another run are both untouched.
15. Revert restores from the ledger only — a test removes the ledger row and asserts the revert **refuses** that row rather than inferring a prior value.
16. Revert on a row whose `collateral_digest` diverged → `SKIPPED` `COLLATERAL_DIVERGED_SINCE_BACKFILL`.
17. Round trip: capture → apply → revert returns every document to a byte-identical state (`full_doc_digest` matches the ledger's).

**Plan proof (D6)**
18. `explain` verification asserts `IXSCAN` on the expected index, no `SORT`, no `COLLSCAN`, and `indexBounds` key order `tenant_id → additional_fields.endpoint_id → event_time`.

**Plus, carried forward unchanged**
19. Idempotence: apply twice on a 1,236 fixture → second run REFUSES at G2 (census now 0 ≠ 1236) and writes nothing.
20. Crash simulation: exception after N rows → lock released, run `FAILED`, written rows intact, remainder still eligible.
21. Concurrency: two simultaneous applies → one runs, one 409.
22. Registry closure unchanged: an unknown operation name is still refused and audited.

(18 numbered requirements; 22 test cases.)

---

## 11. Authorized execution sequence — for the record, NOT now

```
FINAL DESIGN (this document)              ← we are here
  → OWNER REVIEW
  → implement 4 operations + 22 tests, all green locally
  → OWNER REVIEW of code + test evidence          [G3 satisfied here]
  → deploy control plane only
  → production CAPTURE phase (ledger only)        [G1]
  → owner takes point-in-time snapshot + attests  [G4]
  → production BACKFILL report mode → green gate board, census == 1236  [G2]
  → OWNER REVIEW of census and gate board
  → owner-run BACKFILL apply
  → V1–V9 verification, read-only via deployer
  → retire legacy §d identity branches (host.host_id, collector_id addressing)
  → FIRST REAL-EVIDENCE SHADOW RUN (canary KUSHU)
```

Nothing in this step touches KUSHU or DESKTOP. No UI work (D7).

---

## 12. Residual judgement calls the reviewer may still want to overturn

Stated plainly rather than buried, because each is a place where I chose and the
owner may disagree:

1. **D1 makes crash-resume a human decision** (§6.2). An exact ceiling and a
   resumable migration are in genuine tension; I resolved it in favour of D1 and
   made the cost explicit instead of adding a resume escape hatch.
2. **Attestation is an honest recorded precondition, not machine-verified.** The
   backend cannot inspect the cloud provider's snapshot inventory, and giving it
   credentials to do so would be a far worse trade than trusting an audited
   admin attestation.
3. **The ledger retains `host` / `additional_fields` / `provenance`
   sub-documents verbatim.** Same database, same tenant boundary, no new
   exposure — but it is a deliberate retention decision, not an accident.
4. **24-hour attestation freshness** is a chosen number. Tighten to 4h if you
   want the snapshot and the apply to be effectively the same operator session.
5. **`explain()` runs after apply.** Before the backfill the authoritative branch
   has no rows for this population, so a pre-apply plan proof would be weaker,
   not stronger.
