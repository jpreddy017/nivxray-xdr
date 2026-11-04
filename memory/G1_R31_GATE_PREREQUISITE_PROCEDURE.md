# G1-R3.1 · Health-gate prerequisite for R4 — procedure

Read this before running anything. The short version: **the absent gate table
is not an outage, and it is not blocking R4.** The blocker you saw is a
reporting artefact plus a missing durability guarantee, and both are fixed
below by the smallest possible change — a single `CREATE TABLE`, no rows, no
row edits.

---

## 1 · Exact reason the table is absent

The preserved outbox was created and last written by a collector build that
predates R3.1. The `delivery_health_gate` table is declared in
`framework/outbox.py::Outbox._SCHEMA` and is created only when an `Outbox`
object is constructed (`_init_schema()` runs `executescript(_SCHEMA)` with
`CREATE TABLE IF NOT EXISTS`). Since the collector has not been started since
R3.1 was published, that code has never run against this database.

Two separate facts were merged in the dry-run report, and that is what made
it look like a blocker:

| reported field | what it actually meant |
|---|---|
| `delivery_health_gate_table_present: false` | it was computed from **row** presence, not table presence — a bug in the report, now fixed |
| `persisted_health_gate: null` | correct and expected: no gate has ever observed this destination |

Fixed in the tool: the dry run now reports
`delivery_health_gate_table_present` (DDL) and
`delivery_health_gate_row_present` (observation) separately, plus a
`health_gate_prerequisite` block that states the decision.

## 2 · Is R4 actually blocked? No.

R3.1's contract: **a gate with no persisted state has observed nothing, and
CLOSED is the truthful default for a first boot.** The published
`DeliveryHealthGate` starts CLOSED when its store returns `None`, and the R4
tool refuses only when a persisted row says the destination is NOT CLOSED.
Absence has never been a refusal in the code
(`test_c_absent_gate_does_not_block_a_dry_run_or_execution`).

The prerequisite is therefore satisfied by truth. What is genuinely missing is
**durability**: without the table, an outage during the 14,868-row drain
cannot be persisted, so a collector restart mid-drain would forget it — the
exact defect R3.1 exists to prevent.

## 3 · Initialization mechanism (chosen option)

Two candidates were evaluated:

| option | effect | verdict |
|---|---|---|
| **A · start the collector** (`Outbox()` creates the table) | also runs `_reset_stuck_delivering()` (`DELIVERING → QUEUED`, `updated_at` rewritten) and opens the DB for general use | **rejected for this step** — it mutates preserved rows. Proven in `test_opening_the_outbox_would_also_reset_delivering_rows` |
| **B · bounded DDL-only operation** — `g1_r4_recover_dead_letters.py --init-health-gate` | one `CREATE TABLE IF NOT EXISTS` in one transaction, under a verified backup, with before/after proof | **chosen** |

The tool's DDL is byte-identical to the published `Outbox._SCHEMA` block, and
a test fails if the two ever drift
(`test_b_init_ddl_matches_the_published_schema`). After initialization the
real R3.1 gate persists into that table and reads it back across a restart
(`test_b_initialized_database_is_what_the_r31_gate_expects`).

## 4 · Exact DB changes initialization makes

```sql
CREATE TABLE IF NOT EXISTS delivery_health_gate (
    destination_key      TEXT PRIMARY KEY,
    state_version        INTEGER NOT NULL,
    state                TEXT NOT NULL,
    consecutive_failures INTEGER NOT NULL,
    cooldown_seconds     REAL NOT NULL,
    cooldown_until_epoch REAL,
    opened_count         INTEGER NOT NULL,
    probes               INTEGER NOT NULL,
    last_reason          TEXT,
    last_transition_at   TEXT,
    updated_at           TEXT NOT NULL
);
```

That is the entire change. `rows_written: 0`. No `UPDATE`, no `DELETE`, no
`ALTER`, no index on `envelopes`, no `recovery_json` column (that arrives only
with `--execute`), no `failure_detail_json` migration.

## 5 · Proof that envelope statuses and counts are unchanged

The tool fingerprints the database before and after, inside the same
invocation, and prints both:

* `counts_by_status` (dict) — asserted equal;
* `total_envelopes` — asserted equal;
* `envelope_state_sha256` — SHA-256 over `(id, status, attempts, last_error,
  next_attempt_at, updated_at)` for **every row, ordered by id** — asserted
  equal. A single changed status, attempt count or timestamp anywhere in the
  125,452 rows breaks this hash;
* `max_updated_at` — asserted equal;
* `only_new_table_is_the_gate` — the table-name diff must be exactly
  `['delivery_health_gate']`.

`proof` must be all-true or the tool returns exit 4 / `REVIEW`. Tests:
`test_b_init_creates_only_the_gate_table`,
`test_b_init_leaves_statuses_and_counts_untouched` (including the deliberate
`delivering: 4` rows that option A would have reset).

## 6 · Proof that bookmarks and acquisition state are unchanged

`windows_channel_state` — the Windows Event Log bookmark/checkpoint table — is
hashed row by row (all columns, ordered) before and after, and
`bookmarks_unchanged` is asserted. The test additionally re-reads the rows and
compares `channel`, `last_record_id`, `bookmark_xml` and `updated_at` literally
(`test_b_init_leaves_bookmarks_and_acquisition_state_untouched`).

No acquisition is started, no channel is opened, no event is read from Windows,
and no checkpoint is advanced: the operation touches SQLite only.

## 7 · How CLOSED is established truthfully rather than force-set

It is **not written**. The tool writes zero rows
(`test_b_init_writes_no_gate_row_and_fabricates_no_observation`), and the
prerequisite block says exactly why:

```
effective_state : CLOSED
persisted_state : null
satisfied       : true
basis           : "R3.1 first-boot semantics: no persisted state means no
                   observation, and CLOSED is the truthful default. A CLOSED
                   row is NOT written, because a gate that has observed
                   nothing must not claim to have observed health"
```

A truthful `CLOSED` row can only be produced by a real delivery success
against the real destination — which is precisely what the first recovery
batch does, under R1 classification, R2 detail capture and R3.1 persistence.
From that moment the row exists and is honest.

For completeness the tool also accepts `--require-persisted-gate` (strict
posture). It is **not recommended for this prerequisite** and is deliberately
unsatisfiable beforehand: it refuses with "this posture cannot be satisfied
before the first recovery batch without fabricating an observation"
(`test_c_strict_mode_cannot_be_satisfied_without_fabrication`).

## 8 · Endpoint action

Yes, one endpoint action is required (the DDL). Run
`/app/memory/G1_R31_GATE_INIT_EXECUTION_COPY.ps1` — elevated. It:

0. refreshes the checkout and **refuses if the tool lacks
   `--init-health-gate`** (stale-checkout guard);
1. writer guard: process scan + exclusive-open probe;
2. takes a fresh SHA-256-verified `outbox.pre-gate-init.<stamp>.db` (+ `-wal`,
   `-shm`) and preserves the earlier R4 backup;
3. runs `--init-health-gate` and prints every proof flag;
4. re-runs the read-only dry run against a separate copy and prints PASS/FAIL.

Outputs: `C:\nivx\g1-proof\r31-gate-init.json`,
`C:\nivx\g1-proof\r4-dryrun-after-gate-init.json`.

## 9 · PASS / FAIL criteria

PASS requires all twelve:

| # | check |
|---|---|
| 1 | gate init exit 0 (`ACCEPTED` or `ALREADY_PRESENT`) |
| 2 | `rows_written == 0` and `no_gate_row_written == true` |
| 3 | `envelope_state_unchanged == true` |
| 4 | `counts_unchanged == true` (incl. `dead_letter == 14868`) |
| 5 | `total_unchanged == true` |
| 6 | `max_updated_at_unchanged == true` |
| 7 | `bookmarks_unchanged == true` |
| 8 | `only_new_table_is_the_gate == ['delivery_health_gate']` |
| 9 | `schema.delivery_health_gate_table_present == true` |
| 10 | `health_gate_prerequisite.durability == "PRESENT"` and `satisfied == true` |
| 11 | `population.target_count == 14868` and `non_target_dead_letter_count == 0` |
| 12 | `would_write == false` on the dry run |

FAIL → restore `outbox.pre-gate-init.<stamp>.db*` over the live files. Nothing
else is required, because nothing else was changed.

## 10 · Constraint compliance

| constraint | status |
|---|---|
| no requeue of the 14,868 | respected — `rows_written: 0`, statuses hashed equal |
| no Windows Event Log acquisition | respected — SQLite only, collector not started |
| no bookmark/checkpoint advance | respected — `windows_channel_state` hashed equal |
| no replay of historical telemetry | respected |
| nothing delivered/acknowledged | respected — no network call at all |
| no canonical evidence / server dedupe change | respected — endpoint-local DDL only |
| preserved outbox not deleted/reset/recreated | respected — `CREATE TABLE IF NOT EXISTS`, idempotent |
| R3.1 invariant not weakened/bypassed | respected — no fabricated row; only a persisted non-CLOSED state blocks recovery |
| R4 not executed | respected |
| verified backup preserved | respected — earlier backup untouched, new pre-change backup added |

## 11 · Test evidence

`apps/nivxray-xdr-collector/tests/test_g1_r31_gate_prerequisite.py` — **17
tests, all PASS**, driving the real tool against a pre-R3.1 legacy outbox
(dead letters + queued + delivering + delivered + real bookmarks). Collector
suite total: **307 passed**.

Also verified on a full-scale local simulation (14,868 target + 107,700 live
rows + bookmarks): init `ACCEPTED`, `rows_written 0`, all seven proofs true,
then dry run `target_count 14868`, `non_target 0`, `would_write false`,
`durability PRESENT`.

## 12 · Residual risks

1. The DDL is repeated in the tool (guarded by a drift test) so the operation
   can avoid constructing an `Outbox`.
2. Once recovery starts, the collector's normal start WILL reset any
   `DELIVERING` rows to `QUEUED` — that is R3.1-proven restart recovery and
   consumes no retry budget, but it is a row change, so it belongs to the
   recovery step and not to this prerequisite. The dry-run
   `counts_by_status` tells you in advance whether any such rows exist.
3. `failure_detail_json` is still absent on this database. The collector will
   add it additively on its next start (R2 migration); recovery does not
   depend on it, and its absence is why the R4 predicate keys on
   `last_error`.
