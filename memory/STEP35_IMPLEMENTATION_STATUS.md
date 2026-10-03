# STEP35_IMPLEMENTATION_STATUS

**Status:** IMPLEMENTED AND TESTED LOCALLY · **NOT EXECUTED IN PRODUCTION**
**Date:** 2026-06
**The 1,236 production rows are UNMODIFIED.** No Behavior run, no TI work, no
KUSHU / DESKTOP / sensor action, no UI, no new route.

Scope held deliberately small: **1 new module, 3 registered operations, 29
tests**. The four-operation / 22-test / attestation-gate / rehearsal design was
cut back on purpose — this is a one-time historical correction, not a migration
subsystem.

---

## 1. Files changed

| File | Change | Lines |
|---|---|---|
| `backend/edr_plane/identity_backfill.py` | **NEW** — the whole correction: eligibility delegation, exact-population hold, guarded write, permanent ledger, collateral digests, bounded revert, index-served explain | 471 |
| `backend/edr_plane/migration_control.py` | 4-line change — merge the three operations into the existing closed registry, pass `run_id` to operations | +6 / ~2 |
| `backend/tests/edr/test_35_identity_backfill.py` | **NEW** — 29 tests | 419 |
| `backend/tests/edr/test_34h_a_migration_control.py` | updated for the now-4-operation registry; two scratch test ops take `run_id`; **added** a closure test asserting the new operations hold no destructive call | +18 |

**No route was added.** The existing `POST /api/internal/admin/migrations/{operation}`
already serves any registered operation, so the three new operations inherit the
admin gate, the zero-parameter request model, the single-writer lock and the
audit trail with no new surface.

**Nothing else was touched.** No frontend, no dashboard, no generalized
framework expansion, no unrelated work.

---

## 2. The three operations

| Operation | Mode | What it does |
|---|---|---|
| `backfill_authoritative_endpoint_identity` | `report` / `apply` | the correction. `report` writes **nothing at all** (not even a ledger row) and returns the census, the gate board and the collateral verification |
| `revert_authoritative_endpoint_identity_backfill` | `report` / `apply` | bounded recovery of ONE proven run, restoring **recorded** prior state |
| `explain_canonical_identity_read_plan` | `report` only | proves the endpoint/time read is IXSCAN-served on the intended index, with no COLLSCAN and no blocking SORT |

All three take **only `mode`** from the caller — no collection, filter, limit,
update document or run identifier.

---

## 3. How each of your eight requirements is met in code

| Requirement | Implementation | Test |
|---|---|---|
| Eligibility = the proven deterministic population | the only predicate is `idc.backfill_candidate`; a test reads the source and asserts `op_backfill` contains no invented predicate (`startswith`, `host_id`, `hostname`, `"ep_"`) | `test_the_correction_holds_no_eligibility_predicate_of_its_own`, 5× `test_an_ineligible_row_is_never_written` |
| Unexpected population change → HOLD, never broaden | `observed != EXPECTED_CANDIDATES (1236)` → `hold=CANDIDATE_POPULATION_DRIFT`, `ok=False`, **zero writes**, both directions | 3× `test_any_population_drift_holds_and_writes_nothing`, `test_an_oversized_population_is_not_truncated_to_the_expectation`, `test_no_request_field_or_env_var_can_relax_the_population_ceiling` |
| Permanent per-row audit / provenance | `e3_migration_row_ledger` — prior projection + both digests per row, **no TTL**, indexed `{migration_run_id, doc_id}`; each row stamped `authority=BACKFILL_DETERMINISTIC` (never `AUTHENTICATED_INGEST_BOUNDARY`) with `migration_run_id` and `backfilled_at` | `test_the_ledger_is_permanent_and_records_prior_state_per_row`, `test_apply_corrects_exactly_the_population_and_stamps_provenance` |
| Existing authoritative identity never overwritten | the guard is in the **update filter** (`endpoint_id: {$exists: false}` + exact boundary value), not in a pre-check, so it holds under a race | `test_an_existing_authoritative_identity_is_never_overwritten` (injects a live write mid-run: row is SKIPPED, live value survives, `ok=False`) |
| Collateral immutability preserved and verified | `collateral_digest` = sha256 over the document **excluding** the two mutable paths; recomputed for **every** written row after the writes | `test_the_write_touches_exactly_two_paths_and_nothing_else`, `test_collateral_immutability_is_verified_for_every_written_row`, `test_divergence_is_detected_rather_than_assumed_away` |
| Tested bounded recovery | revert requires **all four** proofs (ledger says WRITTEN · provenance names this run · authority is ours · current value matches) and restores from the ledger only | 6 revert tests incl. byte-for-byte round trip, ledger-deleted row refused, boundary-stamped row untouched, diverged row skipped |
| Read uses the intended index, no COLLSCAN / blocking SORT | `op_explain` parses the winning plan: IXSCAN present, index name matches, no COLLSCAN, no SORT, `indexBounds` key order equals the contract | `test_the_endpoint_time_read_is_index_served_with_no_scan_or_sort`, plus a **negative** test proving the check fails when the index is absent |
| Small and independently tested | 471 production lines, one module, no new route; every property has its own test | 29/29 green |

---

## 4. Test results

```
tests/edr/test_35_identity_backfill.py ......................  29 passed
tests/edr/test_34h_a_migration_control.py ..................   19 passed
tests/edr/test_34f_boundary_endpoint_identity.py             )
tests/edr/test_34g_host_id_is_not_an_identity.py             )  regression: pass
tests/edr/test_behavior_evidence_adapter.py                  )
```

All against the **preview** database on a throwaway collection created and
dropped by the fixture. The correction's own constants (`CANONICAL_COLLECTION`,
`EXPECTED_CANDIDATES`) are redirected at module level — exactly how the real run
resolves them — so the code under test is the shipped code, not a variant.

Two tests exist only to prove the other tests are load-bearing:
`test_divergence_is_detected_rather_than_assumed_away` (tampering trips the
digest) and `test_the_explain_verification_fails_when_the_index_is_absent`.

Lint: the two new files carry the same rule classes as the already-shipped
modules in this package (`UP006` / `UP035` annotation style). No new class of
violation.

---

## 5. Exact production safety gates

Evaluated **before the first write**, and all visible from `report` mode:

| Gate | Condition | Failure |
|---|---|---|
| **G1 · admin principal** | `require_admin` on the route | 401 / 403, no migration record written |
| **G2 · registered name** | the operation is in the compiled registry | 400 `UNKNOWN_MIGRATION_OPERATION`, audited |
| **G3 · known mode** | `report` or `apply` | 400 `UNKNOWN_MIGRATION_MODE` |
| **G4 · single writer** | lock in `e3_migration_locks` | 409 `MIGRATION_ALREADY_RUNNING`; lock released even on exception, stale lock reported never stolen |
| **G5 · population exactly 1,236** | `observed == 1236` | `hold=CANDIDATE_POPULATION_DRIFT`, `ok=false`, **zero writes**, `expected`/`observed`/`drift` reported |
| **G6 · per-row contract** | `backfill_candidate(row)` is truthy | that row is skipped and ledgered `SKIPPED_NOT_ELIGIBLE` |
| **G7 · per-row guard** | authoritative field still absent AND boundary value unchanged, **in the update filter** | row skipped `SKIPPED_CHANGED_UNDER_RUN`; any skip forces `ok=false` |
| **G8 · post-write collateral** | every written row's digest matches the pre-write value | `collateral_verification.diverged > 0` forces `ok=false` |

Clean pass requires: `written == 1236`, `residual_candidates == 0`,
`skipped_* == 0`, `collateral_verification.diverged == 0`, `ok == true`.

**Recovery, if any of that is wrong:** `revert_…_backfill` in `report` mode
names the reversible rows; in `apply` mode it restores them from the ledger.

---

## 6. New blocker / open item — ONE, and it needs your call

**The point-in-time backup is NOT enforced in code.**

Your earlier decision was "require a point-in-time production backup/snapshot or
equivalent recoverable pre-change state before apply". The heavier design made
that a code gate backed by an `attest_pre_change_recoverable_state` operation
and a `e3_migration_preconditions` collection. Under "keep implementation
proportional" I **cut it**, because the backend cannot verify a cloud snapshot
exists — the gate could only ever have checked that *someone typed an
attestation*, which is a runbook step wearing a code costume, and it would have
added a fourth operation and a fifth collection to a one-time 1,236-row fix.

So the backup is now a **runbook precondition you perform**, immediately before
running `apply`. In-database recoverability is still real and is what the tests
prove: the permanent per-row prior-state ledger plus the bounded revert.

**Your call:** accept the backup as an operator step (my recommendation), or
tell me to add the attestation gate and I will.

Two smaller notes, not blockers:
* **A crash mid-run cannot be resumed by re-running `apply`** — the census will
  then be `< 1236` and G5 will HOLD. That is the exact-ceiling decision working
  as specified; recovery from a partial run is revert-then-retry, or a reviewed
  constant change. Flagging it so it is not a surprise on the night.
* `op_explain` is meaningful only **after** `apply` — before the correction the
  authoritative branch has no rows for this population.

---

## 7. Authorized next step (not taken)

```
→ OWNER REVIEW of this report            ← we are here. STOP.
  → deploy control plane only
  → production `report` mode (zero writes) → review census + gate board
  → owner takes backup, then runs `apply`
  → verify: written 1236 / residual 0 / diverged 0, then `explain`
  → retire legacy §d identity branches
  → FIRST REAL-EVIDENCE SHADOW RUN (canary KUSHU)
```
