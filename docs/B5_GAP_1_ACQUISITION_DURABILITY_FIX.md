# B5-GAP-1 — WINDOWS SENSOR LOSSLESS ACQUISITION + LOCAL EVIDENCE JOURNAL

**Status:** IMPLEMENTED. LOCAL/FOCUSED TESTS PASS. **NOT DEPLOYED.**
**Owner review gate:** open. Nothing was published, no production sensor was
restarted, no Sysmon configuration was touched, no `channels.json` or
`outbox.jsonl` on any endpoint was read or written, no replay, no backfill.
**B5:** remains CLOSED / PASS.

---

## 1. THE ORIGINAL DEFECT

The Windows sensor could lose source telemetry **silently**, across **all**
channels. It was never an EID5 problem.

Pre-fix behaviour, `agents/nivxforge-windows/nivxforge_sensor.py` @ `6afab68a`:

| Property | Pre-fix | Line |
|---|---|---|
| Page size | `/c:100`, hardcoded, non-configurable | `_query_channel` L265 |
| Pagination | **none** — one query per channel per cycle | `collect()` L334-336 |
| Acquisition vs delivery | same serial thread | `run()` L552-587 |
| Delivery bound | `max_per_cycle: int = 200` messages, no time bound | `_drain` L487 |
| Continuity check | **none** | — |
| Cursor advancement | `max(record_id parsed)` — *correct* | L340-342 |
| Durability order | enqueue+fsync → cursor commit — *correct* | L567-568 |

A batch of exactly `limit` was indistinguishable from "caught up", so a
channel producing more than one batch between cycles was abandoned rather
than followed.

## 2. PRODUCTION EVIDENCE (owner-supplied)

```
14:45Z  100 consecutive Sysmon records   RecordID 8470086 - 8470185
14:47Z - 15:06Z   ZERO Sysmon records in the sensor outbox
15:07Z  100 consecutive Sysmon records   RecordID 8496595 - 8496694
                                         jump = 26,410 RecordIDs
```

Genuine Sysmon EID5 present in BOTH visible batches (14:45:09Z RecordID
8470141; 15:07:00Z RecordID 8496661). Therefore not an EID5 filter, not a
DSM issue, not `process_exit` mapping, not ProcessGuid binding, not backend
canonicalization, not a subscription start point. The "EID5 began ~15:17Z"
hypothesis is disproven.

Channel configuration, independently observed:
`Microsoft-Windows-Sysmon/Operational`, `MaximumSize = 67,108,864` (64 MiB),
`retention = false`, `autoBackup = false` → **circular EVTX**.

Persisted cursors at review time: `Security 284760`, `System 22702`,
`Microsoft-Windows-Sysmon/Operational 8969348`.

## 3. ROOT CAUSE

```
  100/cycle ceiling + no pagination          [CODE]
+ acquisition serialized behind 200 POSTs    [CODE]
  at ~2.68 s each                            [PROD MEASURED]
=> cycle period ~10-22 min, capacity ~0.1 rec/s
   (corroborated: the append-only outbox, which is never rotated or
    truncated, contains NO records collected in 14:47-15:06Z)
vs Sysmon production ~20 rec/s               [PROD MEASURED]
=> cursor falls irrecoverably behind the circular channel
=> un-acquired records are evicted by rotation
=> next query legitimately returns the oldest SURVIVING record
+ no continuity check anywhere               [CODE]
=> the loss is SILENT; the cycle reports "collected: 100"
```

Defect class: **INSUFFICIENT PAGING + ACQUISITION STARVATION +
ACQUISITION/DELIVERY COUPLING + NO SOURCE-CONTINUITY AUTHORITY.**

**Correction to the earlier hypothesis, retained deliberately:** the cursor
never jumped to the channel tail. It advanced only to the last record
actually parsed and enqueued. That correct property has been **preserved**,
not replaced.

## 4. ARCHITECTURE — BEFORE

```
Windows Event Log -> read max 100 -> durable enqueue -> cursor commit
   -> LONG SYNCHRONOUS DELIVERY DRAIN  (no acquisition during this period)
   -> Windows keeps producing / circular EVTX keeps rotating
   -> unread source records disappear -> next cycle resumes
   -> RecordID discontinuity -> SILENT TELEMETRY LOSS
```

## 5. ARCHITECTURE — AFTER

```
Security / System / Sysmon
        |
   FAST PAGED ACQUISITION   (page loop, per-channel round robin,
        |                     continuity checks, bounded budgets)
        v
  LOCAL EVIDENCE JOURNAL    <-- ONE TRANSACTION:
   (SQLite, WAL, FULL sync)      { evidence + gaps + cursor }
        |
   DURABLE COMMIT == SOURCE CURSOR COMMIT
        |
        +--> ACQUISITION INTEGRITY MONITOR -> acquisition_integrity.json
        |
   DELIVERY (own wall-clock budget) -> /api/edr/agent/telemetry
        |
   BACKEND ACCEPT -> BACKEND_ACCEPTED -> reclaim
```

**PRIMARY INVARIANT — enforced structurally:** the source cursor can never
advance beyond the last source record durably owned by NivXForge, because
the cursor write *is* the evidence write. There is no code path that
commits one without the other.

## 6. JOURNAL TECHNOLOGY DECISION

**Selected: `sqlite3` from the Python standard library, WAL +
`synchronous=FULL` + `auto_vacuum=INCREMENTAL`.**

Justified against the actual endpoint runtime, not by preference:

- The endpoint artifact is a **PyInstaller** bundle
  (`build/build_windows_installer.ps1`, onedir service host inside a onefile
  installer). `sqlite3` is stdlib, so there is **no new dependency**, no
  wheel, no `requirements` change, no ABI risk. One line was added to the
  build: `--hidden-import sqlite3` and `--hidden-import nivxforge_journal`.
- **No Python is required on the endpoint** (frozen binary) — unchanged.
- Runs as **LocalSystem** in `C:\ProgramData\NivXForge\sensor`, already ACLed
  to SYSTEM + Administrators by the installer. No permission change.
- Single writer, single process, local filesystem — exactly SQLite's
  sweet spot.
- **Rejected:** Kafka, Redis, MongoDB, any external broker or database
  service on the endpoint. Also rejected: a hand-rolled segmented log file,
  because it would require writing crash-recovery and indexing that SQLite
  already provides and proves.

Measured on this container (synthetic): **~29,000 journal writes/sec** in
500-row transactions; **~1,600 acknowledgement updates/sec**. Both are
orders of magnitude above the ~20 records/sec production source rate.

## 7. JOURNAL SCHEMA

`C:\ProgramData\NivXForge\sensor\evidence_journal.db` (schema_version 1)

```sql
evidence(
  journal_sequence INTEGER PK AUTOINCREMENT,  -- OBSERVATION identity, ordered
  channel, source_provider,
  source_record_id INTEGER,                   -- source continuity anchor
  source_event_id, source_event_time,
  collected_at, endpoint_id, tenant_id,
  payload TEXT,                               -- lossless sensor envelope
  payload_bytes INTEGER,
  content_digest TEXT,                        -- CONTENT identity (sha256)
  state, attempts, last_error, accepted_at, updated_at)
UNIQUE INDEX (channel, source_record_id)      -- crash-replay idempotency
INDEX (state, journal_sequence)               -- ordered delivery

cursors(channel PK, committed_record_id, continuity_established, updated_at)

acquisition_gaps(gap_id PK, channel, classification, position,
  expected_next_record_id, first_observed_record_id,
  missing_start_record_id, missing_end_record_id, missing_record_id_count,
  detected_at, cause, reported)

integrity(key PK, value)     -- machine-readable counters and gauges
meta(key PK, value)          -- schema_version, legacy migration record
```

`UNIQUE(channel, source_record_id)` is the crash-safety mechanism: SQLite
treats NULLs as distinct, so a record the source did not number is stored
and never deduplicated away, while a re-read after a crash is idempotent.

**OBSERVED vs DERIVED stays separate.** The journal stores what was
acquired. It invents no RecordID, timestamp, ProcessGuid, ancestry,
termination, ATT&CK mapping, IOC match, compromise state or contributor
relationship.

## 8. EXACT DURABILITY BOUNDARY

`Journal.commit_page()` — one `BEGIN IMMEDIATE ... COMMIT`:

1. `INSERT OR IGNORE` the page's evidence rows
2. `INSERT` any detected acquisition gaps
3. `UPSERT` the channel cursor to `MAX(existing, new)`

`synchronous=FULL` in WAL mode means the COMMIT fsyncs. One fsync per page
(default 500 records), which is the "safe transactional batch": per-event
fsync would cap acquisition below the source rate and re-create the defect
in a new form.

Any exception → `ROLLBACK` → **the cursor does not move** → the same source
range is re-read next cycle → the unique index makes that harmless.

`nvx_excl.Journal.save()` (Gate 7 exclusion adjudication) is fsynced
**before** the transaction, so the cursor only ever advances over records
that are either *owned as evidence* or *owned as a recorded suppression*.
Gate 7 is unchanged: an excluded event never enters the durable evidence
store and never leaves the machine.

## 9. CURSOR-COMMIT ALGORITHM

```
cursor(channel)            := cursors.committed_record_id, default 0
proposed                   := max(cursor, max(RecordID parsed in page))
committed                  := MAX(existing, proposed)   -- can never regress
authority                  := the journal `cursors` table
channels.json              := NON-AUTHORITATIVE MIRROR, written after commit
```

`channels.json` is still written so a downgrade and an operator's eye both
keep working, but it is no longer consulted for authority after migration.

## 10. ACQUISITION PAGING ALGORITHM

`nivxforge_sensor.acquire()`:

```
deadline := now + acquire_budget_seconds
active   := [Security, System, Sysmon]
while active and now < deadline and not halted:
    for channel in active:                     # one page per pass = fairness
        if now >= deadline: break
        if not journal.admits_acquisition():   # reclaims first, then halts
            halted := reason; break
        cursor := journal.cursor(channel)
        page, failure, ms := query(channel, RecordID > cursor,
                                   oldest_first, page_size)
        journal.observe_query(channel, ms, ok = not failure)
        if failure: mark unavailable; DO NOT advance cursor; drop channel
        if page empty: mark caught_up; drop channel
        gaps := detect_gaps(channel, cursor, continuity, page)
        kept, suppressed := exclusions.partition(page)
        exclusion_journal.save()                        # durable first
        journal.commit_page(channel, kept, new_cursor, gaps)   # ONE TX
        if len(page) < page_size: caught_up; drop channel
        elif taken[channel] >= max_per_channel: drop channel   # PAUSE
```

The `wevtutil` invocation is built in one place, `_wevtutil_argv()`, so the
page size and read direction are assertable:

```
wevtutil qe <channel> /q:*[System[EventRecordID><cursor>]]
         /c:<page_size> /e:Events /f:RenderedXml /rd:false
```

`/rd:false` (oldest-first) is load-bearing and is asserted by a test:
`/rd:true` would read the newest N and walk the cursor to the channel tail —
the failure everyone assumed B5-GAP-1 was. It must never become one.

## 11. SCHEDULING / FAIRNESS MODEL

Every stage gets a **wall-clock budget**, because a message count cannot
bound time when a POST costs ~2.7 s — which is precisely how delivery came
to own the whole cycle.

| Knob | Env | Default (interval = 30) | Why |
|---|---|---|---|
| page size | `NIVX_SENSOR_ACQUIRE_PAGE_SIZE` | 500 | ~25 s of source production at 20 rec/s |
| per-channel ceiling / cycle | `NIVX_SENSOR_ACQUIRE_MAX_PER_CHANNEL` | 20000 | ~30x headroom over the ~600 rec/cycle production rate, so a backlog drains while the loop still terminates |
| acquire budget | `NIVX_SENSOR_ACQUIRE_BUDGET_SECONDS` | `max(5, interval*0.5)` = 15 s | acquisition is served first, every cycle |
| deliver budget | `NIVX_SENSOR_DELIVER_BUDGET_SECONDS` | `max(5, interval)` = 30 s | bounded; ~11 messages at 2.68 s |
| legacy outbox budget | `NIVX_SENSOR_LEGACY_DRAIN_BUDGET_SECONDS` | `max(2, interval*0.25)` = 7.5 s | the old file stays deliverable without starving anything |
| source tail probe | `NIVX_SENSOR_SOURCE_TAIL_PROBE` | on | measures lag and rollover risk |
| journal ceiling | `NIVX_SENSOR_JOURNAL_MAX_BYTES` | 512 MiB | bounded evidence capacity |
| warn / critical | `NIVX_SENSOR_JOURNAL_WARN_PCT` / `_CRITICAL_PCT` | 70 / 90 | |
| min free disk | `NIVX_SENSOR_JOURNAL_MIN_FREE_BYTES` | 1 GiB | real disk exhaustion |
| reclaim batch | `NIVX_SENSOR_JOURNAL_RECLAIM_BATCH` | 5000 | |

One scheduling opportunity = one `sensor.run(..., once=True)` call, which is
exactly what the Windows service host already invokes per iteration
(`nivxforge_setup.py` L421). The service loop was **not** changed.

Deliberate consequence: the delivery ceiling is ~11 messages per cycle at
the measured 2.68 s POST latency, so an endpoint producing 20 rec/s will
accumulate a **journal backlog**. That is the correct, visible,
non-destructive failure mode — and it is why backend telemetry-POST latency
(Issue 2, P2) is now on the critical path for *delivery*, no longer for
*acquisition*.

## 12. GAP-DETECTION ALGORITHM

```
LEADING : continuity and cursor and page[0].RecordID > cursor + 1
INTERIOR: consecutive returned RecordIDs are not adjacent
```

`continuity` is per-channel and true only once this sensor has itself
committed a cursor for it — otherwise a first install would report the
entire pre-install history as a gap, which would be a fabricated finding.

Emitted contract (`nvx_journal.build_gap`), verified against the production
numbers by test:

```json
{
  "type": "acquisition_gap",
  "classification": "SOURCE_RECORD_DISCONTINUITY",
  "position": "LEADING",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "expected_next_record_id": 8470186,
  "first_observed_record_id": 8496595,
  "missing_start_record_id": 8470186,
  "missing_end_record_id": 8496594,
  "missing_record_id_count": 26409,
  "detected_at": "...",
  "cause": "NOT_PROVEN"
}
```

`8496595 - 8470186 = 26409` RecordIDs over the range `8470186..8496594`.

**The cause is `NOT_PROVEN` and stays that way.** A RecordID discontinuity
proves a *source continuity discontinuity*. It does not prove that every
missing RecordID carried a security event, and it does not prove
`LOG_ROLLOVER`. `SOURCE_ROLLOVER_RISK` is reported **only** when the oldest
record the source still holds is newer than our committed cursor — measured
by a head/tail probe, never deduced from a delivery backlog.

Negative-evidence semantics are pinned by test:
`NO EVENT OBSERVED != EVENT DID NOT OCCUR`,
`ACQUISITION GAP != BENIGN`, `ACQUISITION GAP != MALICIOUS`.
A test asserts the health payload contains none of the words BENIGN,
MALICIOUS, COMPROMISE or ATTACK.

## 13. ACQUISITION INTEGRITY MONITOR

Machine-readable, rewritten atomically every cycle to
`C:\ProgramData\NivXForge\sensor\acquisition_integrity.json` (mode 600),
and summarised in the cycle report. Contents: per-channel committed cursor
and last journaled RecordID, `records_read`, `records_journaled`,
`backend_accepted`, `delivery_failures`, `query_total`, `query_failures`,
`query_ms_last` / `query_ms_max` (per channel), `acquisition_gap_count`,
`last_acquisition_gap`, `acquisition_lag_records`, `source_tails`
(oldest/newest), `delivery_queue_depth`, `evidence_by_state`,
`journal_bytes`, `journal_live_bytes`, `disk_free_bytes`,
`channels_unavailable`, `caught_up`.

Health states, additive facts rather than one cheerful summary: `HEALTHY`,
`DEGRADED`, `ACQUISITION_LAGGING`, `ACQUISITION_GAP`,
`ACQUISITION_HALTED_JOURNAL_FULL`, `JOURNAL_PRESSURE`, `JOURNAL_CRITICAL`,
`JOURNAL_CORRUPT`, `DELIVERY_BACKLOG`, `BACKEND_UNREACHABLE`,
`CHANNEL_UNAVAILABLE`, `SOURCE_ROLLOVER_RISK`.

**Why this is local and not on the heartbeat:** `HeartbeatBody` and
`TelemetryBody` in `backend/routers/edr_enrollment.py` are both
`model_config = ConfigDict(extra="forbid")`. Adding integrity fields would
return 422 for **every production heartbeat**. No backend contract was
touched. Publishing acquisition integrity to the platform is listed in §19
as the next owner-approved step.

## 14. DISK-PRESSURE BEHAVIOUR

Capacity is judged on **live evidence bytes**, not on the database file
size. SQLite reuses freed pages but cannot always return them to the
filesystem (measured here: the file plateaus at its high-water mark), so
judging capacity on the file would leave a sensor that has delivered
everything permanently "full" and permanently halted — a fabricated outage.
Real disk exhaustion is still caught, by `min_free_bytes` against the actual
filesystem. Both numbers are reported.

- **warning (70%, or low free disk):** `JOURNAL_PRESSURE`.
- **critical (90%, or low free disk):** reclaim accepted rows first, then
  re-measure.
- **still critical after reclaiming:** acquisition **HALTS** before reading
  a page it could not own. `ACQUISITION_HALTED_JOURNAL_FULL` is recorded
  with a reason and a timestamp; the cursor does not move.

Never, at any pressure: overwrite unacknowledged evidence, drop the oldest
unacknowledged evidence, or report healthy. Reclamation only ever considers
`BACKEND_ACCEPTED` rows, oldest first.

## 15. JOURNAL RECLAMATION AND THE ACKNOWLEDGEMENT AUTHORITY

```
ACQUIRED -> QUEUED -> BACKEND_ACCEPTED -> deleted by reclaim()
```

**`SENT != ACCEPTED`.** `BACKEND_ACCEPTED` is set only when
`POST /api/edr/agent/telemetry` returns a 2xx response for that specific
row — that response is the named acknowledgement authority, and it is the
*only* thing that authorises reclamation. A transport attempt that merely
left the host increments `attempts`, records `last_error`, and leaves the
evidence owned locally. There is deliberately **no `RECLAIMABLE` row
state**: a state meaning "safe to delete" invites a future reader to delete
something merely because it was sent.

`ACCEPTED != CANONICALIZED` remains true and is outside the sensor's
knowledge; the sensor claims acceptance only.

## 16. CRASH / RESTART BEHAVIOUR

| Case | Behaviour | Test |
|---|---|---|
| A · journal committed, crash before cursor persistence | **Structurally impossible** — one transaction. Proven instead by reopening the store and finding evidence and cursor together, and by proving a source re-read is idempotent (150 offered, 0 journaled, 150 duplicates ignored) | `test_successful_commit_moves_evidence_and_cursor_together`, `test_crash_before_commit_loses_nothing_because_source_is_rescanned` |
| B · journal write fails | Cursor does **not** advance. Proven with a genuinely read-only connection, not a mock | `test_journal_write_failure_must_not_advance_the_cursor`, `test_acquisition_cursor_holds_when_the_journal_cannot_accept` |
| C · backend unavailable, restart | Journal survives, rows still `ACQUIRED`, acquisition resumes | `test_journal_survives_restart_with_backend_unavailable` |
| D · crash mid-transaction | Full rollback; not one row of the page survives; no gap recorded | `test_partial_transaction_rolls_back_entirely` |
| E · accepted, crash before local ack | Row is redelivered with **byte-identical** payload, so the backend's own identity authority dedupes it. The sensor never mints a new id | `test_accept_then_crash_redelivers_byte_identical_payload` |
| Corruption | Opening raises `JournalUnavailable`; bytes are **renamed and preserved**, never deleted or truncated; `journal_fault.json` records `JOURNAL_CORRUPT` | `test_corrupt_journal_is_visible_and_preserved` |

## 17. MIGRATION BEHAVIOUR

`nvx_journal.migrate_legacy()`, run once on first journal open, guarded by
`meta.legacy_migrated_at`:

- **Adopts** `channels.json` cursors as-is (`Security 284760`,
  `System 22702`, `Sysmon 8969348`), with `continuity_established = 1`
  because those cursors came from real prior acquisition.
- Uses `ON CONFLICT DO NOTHING` and a `MAX()` cursor upsert, so it is
  **idempotent** and a stale bookmark can never drag a cursor backwards.
- **Does NOT**: reset cursors, replay the Windows Event Log, import history
  into the journal, delete or rewrite `outbox.jsonl` / `outbox.offset`,
  touch `identity.json`, or require any manual production database edit.
- `outbox.jsonl` **stays deliverable**: `_drain()` still drains it, now
  under a wall-clock budget, until it is empty. `_enqueue()` is retained but
  is no longer called by the run loop — nothing writes to that file again.

**No production migration was performed.** It runs on the endpoint the
first time an upgraded sensor starts.

## 18. TESTS

All run on Linux CI with a deterministic fake Windows source
(`backend/tests/edr/fixtures_b5_gap1_source.py`) — no `wevtutil`, no HTTP,
no endpoint. Every file is labelled TEST/SYNTHETIC.

| File | Tests | Covers |
|---|---|---|
| `test_b5_gap1_paged_acquisition.py` | **24** | §22 A paging (0/1/99/100/101/200/201/1000/10000), page-size & `/rd:false` assertion, per-channel ceiling, budget exhaustion; §22 B gap detection incl. the production 26409 case; §22 E fairness, channel failure isolation, malformed record |
| `test_b5_gap1_journal_durability.py` | **28** | §22 C durability & crash cases A-E, corruption; §22 D delivery normal/slow/unavailable/retry/recovery/ordering; §22 F pressure, halt, live-bytes capacity, reclamation; §22 G identity, tenant binding, credential absence; §22 H EID1/EID5 + provider-qualified counting; migration |
| `test_b5_gap1_stress_and_silent_loss.py` | **5** | §23 stress 10,000; §24 failure injection; rotation declared not hidden; rollover risk measured not deduced; pre-fix counterfactual |
| **Total new** | **57** | all pass |
| `backend/tests/edr/` (full suite) | **1885 passed, 3 skipped** | existing sensor/installer/Sysmon regression intact |

Notable assertions:

- `test_more_than_one_page_takes_more_than_one_query` — a 250-record backlog
  issues pages at cursors `0, 100, 200`. The pre-fix sensor issued one.
- `test_production_b5_gap_1_discontinuity_is_reported_exactly` — the real
  numbers, `cause = NOT_PROVEN`.
- `test_prefix_single_bounded_page_loses_records_silently` — reproduces the
  production signature (100 records → 26,410 jump → 100 records, 200
  records across a 26,609-RecordID span) from the pre-fix shape, then proves
  the fixed path acquires all 26,609 with zero gaps.
- `test_slow_backend_produces_a_backlog_never_acquisition_loss` and
  `test_b5_gap_1_failure_class_now_yields_backlog_not_loss`.

## 19. STRESS MEASUREMENTS (§23) — SYNTHETIC

```json
{
  "source_events": 10000,
  "events_acquired": 10000,
  "events_journaled": 10000,
  "events_backend_accepted": 10000,
  "unexplained_gaps": 0,
  "duplicates": 0,
  "acquisition_seconds": 0.346,
  "acquisition_events_per_sec": 28919.5,
  "delivery_seconds": 16.257,
  "delivery_events_per_sec": 615.1,
  "max_journal_depth": 10000,
  "ending_journal_depth": 0,
  "journal_bytes_peak": 19158920,
  "journal_bytes_after_reclaim": 14663680,
  "note": "SYNTHETIC harness. Not a production throughput claim."
}
```

**These are not production numbers.** There is no real `wevtutil` scan cost,
no real HTTP latency and no real endpoint in this harness. Production
delivery remains bounded by the ~2.68 s POST latency. The figure that does
transfer is the *ratio*: journal write cost is negligible against both the
source rate and the network.

`journal_bytes_after_reclaim` exceeding zero is the SQLite free-page
high-water mark described in §14; `journal_live_bytes` is 0 and capacity is
judged on that.

## 20. FAILURE-DOMAIN SEPARATION (verified)

| Condition | Produces | Must NOT produce |
|---|---|---|
| slow backend | `DELIVERY_BACKLOG` | acquisition loss |
| backend down | `BACKEND_UNREACHABLE` + `DELIVERY_BACKLOG`, acquisition continues | acquisition loss |
| channel unreadable | `CHANNEL_UNAVAILABLE`, cursor frozen | silence / "nothing happened" |
| journal full | `ACQUISITION_HALTED_JOURNAL_FULL`, halt, evidence kept | overwriting unacknowledged evidence |
| source rotated past us | `ACQUISITION_GAP` (`cause: NOT_PROVEN`) | invented records, or a rollover claim |
| cursor behind source head | `SOURCE_ROLLOVER_RISK` (measured) | inference from backlog |

## 21. SECURITY

- Journal lives in the installer-ACLed state directory (SYSTEM +
  Administrators). `acquisition_integrity.json` is written `0600` via an
  atomic temp-file replace.
- No token, bearer, credential, enrolment secret or `identity.json` content
  is stored or logged. Asserted by
  `test_journal_never_stores_the_agent_credential`, which scans the raw
  database bytes and the integrity snapshot.
- Tenant/endpoint binding is persisted on every row from the durable
  identity — never proposed by the payload.
- All SQL is parameterised; payloads are treated as untrusted opaque text
  and are never evaluated. Corruption is fail-visible, never silently
  repaired.
- Nothing was done to Defender: no exclusions added, no quarantine
  restored, no malware/test/export directory scanned.

## 22. FILES CHANGED

| File | Change |
|---|---|
| `agents/nivxforge-windows/nivxforge_journal.py` | **NEW** (741 lines) Local Evidence Journal: schema, durability boundary, cursors, gap contract, counters, bounded capacity, reclamation, health, integrity snapshot, migration, corruption quarantine |
| `agents/nivxforge-windows/nivxforge_sensor.py` | version `0.2.0` → `0.3.0-windows`; `_wevtutil_argv`, `_query_channel` (page size + timing), `_probe_source_tail`, `detect_gaps`, `_acquire_file_content`, `acquire` (replaces `collect`), `_drain` (wall-clock bound), `_drain_journal`, `_queue_depth`, `_legacy_remaining`, `_mirror_bookmarks`, `_heartbeat`, `_cycle`, `run`, `status`, `use_state_dir`, budget config helpers, CAPABILITIES limits |
| `agents/nivxforge-windows/build/build_windows_installer.ps1` | `--hidden-import nivxforge_journal`, `--hidden-import sqlite3` |
| `backend/tests/edr/fixtures_b5_gap1_source.py` | **NEW** deterministic source harness |
| `backend/tests/edr/test_b5_gap1_paged_acquisition.py` | **NEW** 24 tests |
| `backend/tests/edr/test_b5_gap1_journal_durability.py` | **NEW** 28 tests |
| `backend/tests/edr/test_b5_gap1_stress_and_silent_loss.py` | **NEW** 5 tests |
| `docs/B5_GAP_1_ACQUISITION_DURABILITY_FIX.md` | **NEW** this record |

**No backend route, model, tenancy rule, response authority or Device
Trajectory code was touched. No E3 work was started.**

### Incidental defect corrected in the touched path

`nvx_excl.partition()` returns `(kept, suppressed_count: int)`. The pre-fix
`run()` called `len(excluded or [])` on it, which raises `TypeError` the
moment a COLLECTION-scoped exclusion actually matched (it was masked because
`0 or []` yields `[]`). The new path counts the integer. This was not
optional: the same call site had to be rewritten regardless.

## 23. REMAINING KNOWN RISKS

1. **Acquisition integrity is not visible in the console.** Both agent
   bodies are `extra="forbid"`, so publishing it needs a backend contract
   change and separate approval. Until then, integrity lives on the endpoint
   in `acquisition_integrity.json` and in the service log's cycle report.
   `ACQUISITION_GAP` rows are journaled and flagged `reported=0`, ready for
   that transport.
2. **`wevtutil` scan cost is still unproven in production.** The sensor now
   records `query_ms_last` / `query_ms_max` per channel so the decision can
   rest on evidence. No migration to `EvtSubscribe` / bookmark APIs is
   proposed without it — smallest correct change first.
3. **Delivery is still ~11 messages/cycle at 2.68 s per POST.** Acquisition
   is safe, but a 20 rec/s endpoint will hold a growing journal backlog
   until backlog Issue 2 (telemetry POST latency / batching) is addressed.
   The journal is bounded at 512 MiB; at ~1.9 KB/record that is roughly
   270,000 records of headroom, i.e. ~3.7 hours at 20 rec/s before
   `JOURNAL_PRESSURE`. **This is the single most important production
   number in this document.**
4. **`NIVX_SENSOR_FILE_HASHING` (B3) still runs inside acquisition** and
   sleeps per file. It is capability-gated OFF by default; when enabled it
   will consume the acquire budget and surface as `ACQUISITION_LAGGING`
   rather than hide.
5. **The source tail probe adds 2 `wevtutil` calls per channel per cycle**
   (6 total). Cheap head/tail reads, disableable with
   `NIVX_SENSOR_SOURCE_TAIL_PROBE=0`.
6. **The historical B5-GAP-1 records remain unrecoverable.** Nothing here
   backfills, reconstructs or infers them, by design.
7. **Not yet exercised on real Windows.** All validation is the Linux
   harness plus the existing suite. The installer/service path is unchanged,
   but the frozen bundle must be rebuilt so `sqlite3` is packed in — that is
   a build step, verified only by an actual Windows build.

## 24. ROLLBACK PLAN

1. **Code:** revert the three changed files. `nivxforge_sensor.py` 0.2.0
   reads `channels.json`, which the new build keeps writing as an accurate
   mirror every cycle, so a reverted sensor resumes from the correct cursor
   with no replay and no gap.
2. **Evidence:** `evidence_journal.db` is left in place. Undelivered rows in
   it are NOT deliverable by 0.2.0, so before rolling back, drain the
   journal to zero (`status` reports `journal.delivery_queue_depth`) or keep
   the file for a later re-upgrade. **Do not delete it.**
3. **Endpoint:** no Sysmon, channel, ACL or service-definition change was
   made, so there is nothing to undo there.
4. **Backend:** nothing to roll back — no backend change was made.
5. Rollback is therefore code-only and does not touch production data.

## 25. PROPOSED CONTROLLED PRODUCTION ACCEPTANCE (for approval, not executed)

1. Build the Windows artifact on a Windows runner and prove `sqlite3` is
   bundled (`NivXForgeSensor.exe` starts and `status` prints a journal
   health block).
2. Install on **one** non-production or canary Windows endpoint. Confirm
   migration adopted the existing cursors without replay
   (`meta.legacy_cursors_adopted`, journal depth 0 at first open) and that
   `outbox.jsonl` still drains.
3. Record a 60-minute baseline: `records_read`, `records_journaled`,
   `backend_accepted`, `query_ms_max`, `acquisition_gap_count`,
   `journal_live_bytes`, `delivery_queue_depth`. Acceptance =
   `acquisition_gap_count == 0` and `records_journaled == records_read`.
4. Induce load (a Sysmon-heavy burst) and confirm the backlog grows in the
   journal while `acquisition_gap_count` stays 0 — the exact inverse of
   B5-GAP-1.
5. Only then promote to the validation endpoint `DESKTOP-A9HGFJJ`, and
   re-confirm B5 (EID1/EID5 pairing, ProcessGuid, trajectory) end to end.
6. Decide, on the collected `query_ms_max` evidence, whether the `wevtutil`
   mechanism needs replacing.

**STOP. Awaiting owner approval.**
