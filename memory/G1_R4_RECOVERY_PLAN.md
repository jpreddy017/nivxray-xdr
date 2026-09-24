# G1-R4 · Controlled recovery plan — PREPARATION GATE (nothing mutated)

Published lineage this plan sits on: `origin/feature/rc2-alignment` →
`f97da900` → `38907156` → `86a02907` (B4) → `deb2ec0a` (R3.1).

Status: **preparation only.** No requeue has been performed, the Windows
collector was not started, and `C:\ProgramData\NivXForge\state\outbox.db` has
not been opened by this workspace at all.

---

## 1 · Exact selection predicate

```sql
WHERE status = 'dead_letter'
  AND last_error LIKE 'HTTP 404%'
  AND recovery_json IS NULL          -- once the column exists (idempotency)
```
Optional narrowing switches, off by default and printed when used:
`--created-after`, `--created-before`, `--connector-id`, `--tenant-id`.

Why this and nothing wider:
* `status='dead_letter'` — only terminal rows. `retrying`/`queued` rows are
  already progressing under R1 and must not be disturbed (proved by test
  `test_retrying_rows_are_not_in_the_target_population`).
* `last_error LIKE 'HTTP 404%'` — the population is defined by the ONE fault
  R1 corrected: an unattributed infrastructure 404. Every other terminal
  disposition (`HTTP 422 DECLARATION_REQUIRED`, `HTTP 403
  TENANT_ISOLATION_VIOLATION`, `HTTP 500 retries exhausted`, null) is an
  authoritative or unrelated outcome and is EXCLUDED.
* `recovery_json IS NULL` — a row recovered once can never be recovered
  twice.

The dry run prints the predicate, its bound parameters, the target count, the
non-target dead-letter count and a histogram of the excluded `last_error`
values, so the exclusion is auditable rather than asserted.

## 2 · Expected dry-run count

**14,868** exactly.

`--expect-count 14868` is mandatory for execution. Behaviour:
* dry run, count matches → exit 0, `G1_R4_DRYRUN = READY`;
* dry run, count differs → exit 2, `REFUSED`, nothing written;
* execute, count differs → exit 2, `REFUSED`, **no write attempted**.

A population that does not match the recorded evidence is not the population,
and the tool will not guess which rows the owner meant.

## 3 · Backup / snapshot procedure

`memory/G1_R4_PREPARATION_READONLY.ps1`, step 2:
1. refuse if any collector process (`uvicorn main:app`) holds the database;
2. copy `outbox.db`, `outbox.db-wal`, `outbox.db-shm` to
   `C:\nivx\g1-proof\backup\`;
3. SHA256 both sides and abort on any mismatch;
4. write `backup-manifest.json` (per-file bytes + sha256 + timestamp).

Only reads touch the live files. `--execute` refuses to run without
`--backup <path>`, and refuses a backup smaller than half the live database
(truncation guard). Tests:
`test_execute_without_backup_is_refused`,
`test_execute_with_a_truncated_backup_is_refused`.

## 4 · Batch / recovery algorithm

```
verify: expectation stated · backup present and plausible · health gate CLOSED
migrate: ALTER TABLE envelopes ADD COLUMN recovery_json   (once, execute only)
loop:
  SELECT id,status,attempts,last_error
    FROM envelopes WHERE <predicate> ORDER BY created_at ASC LIMIT <batch>
  BEGIN IMMEDIATE
    per row: UPDATE envelopes
               SET status='queued', attempts=0, next_attempt_at=now,
                   updated_at=now, recovery_json=<provenance>
             WHERE id=? AND status='dead_letter' AND recovery_json IS NULL
  COMMIT
  stop when: no rows left · requeued == expectation · --max-batches reached
report: before/after counts, batches, requeued, accounting assertions
```

Properties:
* **requeue only.** The tool never sends anything, never writes `delivered`,
  never acknowledges, never touches a bookmark or dedupe row. Delivery remains
  the worker's job under R1 classification, R2 detail capture and R3/R3.1
  health-gated pacing (`test_execute_never_delivers_or_acknowledges`).
* **payload and identity untouched** — `raw_json`, `source_event_id`,
  `tenant_id`, `connector_id`, `declared_source`, provenance columns are never
  written (`test_execute_preserves_original_disposition_for_audit`).
* **retry accounting preserved.** `attempts` is reset to 0 because the one
  recorded attempt was spent on the infrastructure fault R1 now classifies as
  retryable — and the original value is written into `recovery_json`, so
  nothing is lost.
* **bounded.** `--batch-size` (default 500) and `--max-batches` cap the
  operation; each batch is one transaction
  (`test_max_batches_bounds_the_operation`).
* **per-row guarded.** The `WHERE id=? AND status='dead_letter' AND
  recovery_json IS NULL` clause means a concurrent change can never be
  overwritten and a row can never be double-recovered
  (`test_execute_is_idempotent`).

Recommended first execution: `--batch-size 500 --max-batches 1` (500 rows),
verify delivery health and reconciliation, then continue.

## 5 · Rollback procedure

```
python scripts/g1_r4_recover_dead_letters.py --db <outbox.db> \
       --rollback --recovery-id r4_<id>
```
Restores `status`, `attempts` and `last_error` from `recovery_json` and clears
it, and only for rows still `queued` — a row that already progressed
(delivered/retrying/delivering) is reported as
`not_restored_because_already_progressed` rather than being dragged backwards
(`test_rollback_restores_the_original_disposition`,
`test_rollback_does_not_reclaim_a_row_that_already_progressed`).

Full rollback of last resort: stop the collector and restore
`C:\nivx\g1-proof\backup\outbox.db*` over the live files.

## 6 · Stop conditions

| condition | behaviour |
|---|---|
| collector process holds the DB | PS block refuses (torn-read guard) |
| `--expect-count` absent | refuse before any write |
| `--backup` absent / truncated | refuse before any write |
| target count ≠ expectation | `REFUSED`, exit 2, no write |
| `delivery_health_gate.state != CLOSED` | `REFUSED`, exit 3 — recovery must not queue into a known-unavailable destination (`test_execute_refuses_a_count_mismatch...`, `test_execute_refuses_while_the_health_gate_is_open`) |
| batch UPDATE raises | `ROLLBACK` that batch, abort |
| `--max-batches` reached | stop, report `REVIEW` (exit 4) |
| accounting assertions fail | exit 4, `REVIEW` |

During DELIVERY (after recovery), R3.1 is the live stop condition: a renewed
destination outage opens the gate, delivery pauses, and no row burns its retry
budget — the defect that created this population cannot recreate it.

## 7 · Reconciliation equations

Immediately after each execute batch (printed by the tool):

```
dead_letter_before - dead_letter_after == requeued
queued_after       - queued_before     == requeued
delivered_after    == delivered_before          (recovery delivers nothing)
SUM(all statuses) unchanged                     (no row created or lost)
```

After delivery drains, the owner-facing equation:

```
TARGET (14,868) = DELIVERED
                + (QUEUED | RETRYING)
                + RETAINED_UNSUPPORTED        (B4: xdr_ingest_raw_retained)
                + TERMINAL_ACCOUNTED          (authoritative refusals, with
                                               R2 failure_detail_json)
```
Any residual is **unexplained loss** and fails the gate. Server-side counters
for the same window:
* `GET /api/xdr/ingest/routing/summary` — accepted vs refused by code;
* `GET /api/xdr/ingest/routing/retained-raw?reason_code=...` — the
  `RETAINED_UNSUPPORTED` term;
* endpoint `recovery_json` count — the recovered denominator.

## 8 · Security EventID extraction method

Server-side evidence cannot name the 24 refused Security EventIDs (the
payload was discarded pre-B4). The **endpoint outbox still holds those
envelopes**, so the sweep is read-only and needs no new Windows events:

1. query `envelopes WHERE source_event_id LIKE '%|Security|%'` on the COPY;
2. regex `System/EventID`, `EventRecordID`, `Provider`, `Channel` out of
   `raw_json`;
3. histogram all Security EventIDs; then isolate the refused window
   `EventRecordID 239169-239192` (24 rows expected) and the ACCEPTED control
   window `239165-239168` (4624/4672);
4. emit metadata only — EventID, record id, provider, channel, outbox status,
   truncated last_error, raw byte length. **No payload is printed.**

Verified locally against a synthetic outbox of the same shape: 24/24 rows
isolated in the refused window, control window resolved to 4624/4672.

## 9 · PowerShell block for owner execution

`/app/memory/G1_R4_PREPARATION_READONLY.ps1` — elevated, read-only, does
backup + dry run + Security sweep and writes:
* `C:\nivx\g1-proof\r4-dryrun.json`
* `C:\nivx\g1-proof\security-eventid-sweep.json`
* `C:\nivx\g1-proof\backup\backup-manifest.json`

It requires the repo checkout at `C:\nivx\nivxray-xdr-collector` (pull
`feature/rc2-alignment` first) so it runs the SAME tool that will later
execute the recovery. Adjust `$Repo` if the checkout path differs.

## 10 · Risks and limitations

1. **The count is unverified from here.** 14,868 is the owner's recorded
   figure; the dry run is the first independent measurement. If it differs,
   execution stays blocked until the predicate and evidence agree.
2. **`last_error` text is the discriminator.** Historical rows predate R2, so
   they have no `failure_detail_json`; the predicate relies on the error
   string the old code wrote. The dry run prints the excluded histogram so a
   variant spelling (e.g. a 404 recorded differently) is visible before
   execution.
3. **Read-only WAL fallback.** If the copy cannot be opened `mode=ro`, the
   tool falls back to `immutable=1` and PRINTS a warning: rows still in an
   uncheckpointed `-wal` would then be invisible and counts are a lower
   bound. Verified working with an uncheckpointed WAL in the normal path.
4. **Delivery volume.** 14,868 requeued events will be delivered by the
   worker at `batch_size × poll_interval`; this is the first real load on the
   R3.1 gate. Start with one bounded batch.
5. **Coverage.** Some recovered events may be `SOURCE_RECORD_NOT_SUPPORTED`
   (Sysmon/Security EventIDs outside the DSM sets). Under B4 they are
   RETAINED, not lost — they land in the `RETAINED_UNSUPPORTED` term rather
   than `DELIVERED`. Expect a non-zero value there.
6. **Schema change on execute.** `--execute` adds the additive
   `recovery_json` column to the endpoint database. Dry run does not
   (`test_dry_run_writes_nothing`).
7. **Repository hygiene** (tracked `outbox.db`, `-shm`, `-wal` artifacts)
   remains OUT of scope here, as instructed.

## 11 · Test evidence for this gate

`apps/nivxray-xdr-collector/tests/test_g1_r4_dead_letter_recovery.py` —
**19 tests, all PASS**, driving the REAL tool against synthetic outboxes:
dry-run byte-for-byte non-mutation, predicate narrowness, non-target
immutability, count-mismatch refusal, backup guards, health-gate refusal,
exact requeue + accounting, provenance capture, no delivery/ack, idempotency,
batch bounding, rollback and rollback-safety.
