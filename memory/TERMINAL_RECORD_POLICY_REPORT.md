# Terminal Record Policy — COMPLETION REPORT
_preview only · no merge · no production deployment_

The gap this closed: a permanently rejected record used to hold its content
batch — and therefore the whole collection window — open forever
(`BLOCKED_BY_DEAD_LETTER_RECORDS`). Truthful, but a production collector
cannot freeze because of one unacceptable source record.

The invariant now enforced:

    TERMINAL  !=  ACCEPTED  !=  CANONICAL EVIDENCE  !=  SUCCESSFUL DELIVERY

A terminal record may well have been **attempted** against the
authoritative boundary and refused; that attempt is preserved rather than
described as though delivery never happened.

## ACCEPTANCE STATES
| Stage | State |
| --- | --- |
| Generic terminal-record mechanism | **IMPLEMENTED** |
| M365 as first consumer | **IMPLEMENTED** |
| Restart / duplicate / concurrent / cross-tenant / recovery scenarios | **SYNTHETIC/REPLAY PROVEN** (real SQLite state, **real** authoritative ingest and a **genuine** 404 permanent rejection) |
| Live Microsoft | **EXTERNAL_ACCESS_BLOCKED** (unchanged) |

## MECHANISM
* New batch state **`completed_with_terminal_records`** — a batch may
  complete automatically once every non-accepted record has an immutable
  terminal record. It is never converted to `committed`; the state, the
  per-batch counter and the history all stay separate.
* New append-only table **`acquisition_terminal_record`** in the EXISTING
  `${XDR_STATE_DIR}/outbox.db`. No new database. Rows are never UPDATEd —
  a recovery appends an event. Each row keeps: tenant, connector, stream,
  batch, record key, acquisition reference (the content blob URI),
  `outbox_row_id` (so the original envelope stays reachable), rejection
  code + verbatim reason, attempt count, first/last attempt timestamps,
  terminal decision, decision basis, who decided, and when.
* **Quarantine evidence is copied from the real delivery attempts**
  (`outbox.row_for_key`), never reconstructed.
* **Recovery** reuses the existing `outbox.replay_dead()` plus one state
  hook: the batch returns to `acquired`, the record must pass the
  authoritative ingest again, and a `replay_requested` event is appended
  while the original `TERMINAL_QUARANTINED` decision is retained. The
  response says in words that a replay request is not proof of recovery.
* **Accounting** stays in three buckets — `accepted_records`,
  `terminal_records`, `waiting/not_yet_accepted` — surfaced per batch by
  `reconcile()` and `status()`.
* **Generic**: `(tenant, connector, stream, batch, record_key)`. A test
  drives the whole terminal lifecycle as a DNS export connector.

## A REAL BEHAVIOUR GAP FOUND BY THE TESTS
The first implementation de-duplicated quarantine events per record, so a
record that was replayed and then **rejected again** produced no new
history — its second rejection was invisible. Fixed: a quarantine is
skipped only when the record's *latest* event is already a quarantine, so
every genuine rejection generation is recorded.

## FILES CHANGED
* `framework/acquisition_state.py` — terminal state, append-only table,
  `_quarantine`, `_complete_with_terminal`, `terminal_records()`,
  `replay_terminal_record()`, three-bucket reporting
* `framework/outbox.py` — `row_for_key()` (failure history lookup)
* `tests/test_terminal_record_policy.py` (new · 15 tests)
* `tests/test_acquisition_durability.py` — the old "blocks the window" test
  replaced by the new, stronger expectation
* `scripts/p0_terminal_record_policy_proof.py` (new · 22 live checks)

No UI. No other transport adopted. Backend, Work Mode and NivXForge EDR
untouched.

## TESTS PROVEN (every case the owner listed)
| Case | Result |
| --- | --- |
| all accepted → `committed` | PASS |
| accepted + terminal → `completed_with_terminal_records` | PASS (never `committed`) |
| terminal record never creates canonical evidence | PASS (checked in Mongo on the live proof) |
| replay preserves original terminal history | PASS |
| replayed record rejected again → history stays truthful | PASS (this is what exposed the dedup gap) |
| replayed record accepted → evidence only from that acceptance | PASS |
| cross-tenant replay impossible | PASS (`NOT_FOUND_IN_THIS_SCOPE`, record stays quarantined) |
| restart cannot convert terminal → accepted | PASS |
| concurrent collectors cannot both release one record | PASS (`REPLAY_NOT_POSSIBLE`) |
| completion waits while other records are in flight | PASS |
| the same rejection is not quarantined twice | PASS |
| generic — DNS-style connector | PASS |

## LIVE PROOF
`scripts/p0_terminal_record_policy_proof.py` — **22/22 PASS**. One batch,
two records: one accepted with a real `200`, one refused with a **genuine
`404 collector not found`** from the authoritative boundary (non-retryable).
Result: `completed_with_terminal_records` with `accepted_records: 1` /
`terminal_records: 1`, window advanced, canonical evidence present for the
accepted record and **absent** for the terminal one, terminal evidence
carrying the real rejection text, survival across a restart, a refused
cross-tenant release, and a replay that only produced evidence once the
corrected delivery was genuinely accepted.

## REGRESSION
* Collector suite **103 passed** (15 new).
* Backend Microsoft/D-series **166 passed**.
* Live proofs re-run: durable acquisition PASS, Phase 1b PASS, preflight
  still honestly `CONFIGURATION_INCOMPLETE`.
* Known pre-existing failures unchanged: **12 failed / 16 passed**.

## REMAINING GAPS
1. **Live Microsoft acquisition** — owner-side app registration + consent
   (`memory/M365_REAL_SOURCE_ONBOARDING.md`, then
   `scripts/m365_preflight.py`).
2. **No operator surface** for terminal records — releasing one is an API
   call on the collector state, not a screen. Deliberate: no UI in this
   gate.
3. **Certificate (private_key_jwt) auth** for Microsoft — still not
   implemented (owner: HOLD).
4. **The other transports** (`rest`, `webhook`, `syslog`) have not adopted
   the acquisition primitive.
5. `prune_committed()` still unscheduled; the terminal history is retained
   indefinitely by design and has no retention policy yet.

**STOPPED for owner review. No further acquisition/infrastructure gate
proposed — the next workstream is the owner's selection of the next
authoritative telemetry domain (stated leading candidate: Network / DNS /
Firewall) with cross-domain detection and correlation as the objective.**
