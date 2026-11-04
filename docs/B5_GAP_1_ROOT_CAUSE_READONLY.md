# B5-GAP-1 — READ-ONLY ROOT-CAUSE REVIEW

**Mode:** READ-ONLY static code inspection. No code edited, no tests executed,
no deployment, no replay/backfill, no sensor restart, no Sysmon change, no
`channels.json` change, no outbox modification.

**Scope:** Windows sensor acquisition path only.

**B5 status:** unchanged — CLOSED / PASS. B5-GAP-1 remains a separate
investigation.

---

## 1. FINAL CLASSIFICATION

```
B5_GAP_1_ROOT_CAUSE = PROVEN
```

**Proven from code:** the Windows sensor has a hard, unrecoverable acquisition
ceiling of **100 records per channel per polling cycle, with no pagination /
no drain-to-catch-up loop**, and the polling cycle period is **unbounded
because event acquisition is executed on the same serial thread as network
delivery**. The sensor additionally performs **no continuity check** between
its persisted cursor and the lowest `EventRecordID` it receives back, so any
gap is unobservable and is reported as a healthy cycle.

**Not EID5-specific.** Nothing in the acquisition path branches on Event ID
for collection. The `event_id` value is only parsed for field extraction
(line 291) and for the optional B3 file-hash capability on EIDs 11/15
(lines 349–358). The prior "EID5 subscription began ~15:17Z" hypothesis is
therefore disproven by code as well as by your endpoint evidence.

**Important honesty boundary (stated explicitly, not glossed over):**
The code **cannot** advance the cursor to the channel tail. Cursor advancement
is strictly `max(record_id of records actually parsed and enqueued)`
(lines 340–342). Therefore the ~26,410 RecordID jump is **not** produced by a
cursor-to-tail bug. It is produced by the 100/cycle ceiling falling
~120× behind Sysmon production, after which the intervening records are
**no longer present in the channel** when the next query runs, and
`*[System[EventRecordID>cursor]]` legitimately returns the oldest *surviving*
records. The code-side defect (ceiling + serialization + no gap detection) is
PROVEN. The terminal eviction step is a consequence on the endpoint side and
is the one link I did not prove from code — see §6 for the single read-only
endpoint check that closes it.

---

## 2. EXACT CODE PATH

All line numbers: `/app/agents/nivxforge-windows/nivxforge_sensor.py`
(commit `6afab68a`, the only writer of `channels.json` in the repo —
verified by grep; `/app/backend/tests/edr/test_windows_installer_scm_entrypoint.py:376`
merely asserts the path).

```
run()                  L549-587   polling loop
 ├─ _sync_policy()     L375-430   1x GET + 1x POST, urllib timeout=20s each
 ├─ collect()          L332-360   ONE _query_channel() call per channel
 │   └─ _query_channel() L264-298 wevtutil, /c:100, subprocess timeout=60s
 ├─ nvx_excl.partition()L560      endpoint exclusion drop
 ├─ _enqueue()         L461-471   append + fsync to outbox.jsonl
 ├─ _save_bookmarks()  L259-261   write channels.json   <-- cursor commit
 ├─ _drain()           L486-528   up to 200 SEQUENTIAL POSTs, timeout=20s each
 ├─ _heartbeat()       L531-546   1x POST
 ├─ _report_enforcement() L433-457 up to 1 session + 1 POST
 └─ time.sleep(max(5, interval))  L587   interval=30 (installer default, L42
                                         of Install-NivXForgeSensor.ps1)
```

### 2.1 The query — verbatim

```python
# L264-272
def _query_channel(channel: str, after_record: int,
                   limit: int = 100) -> tuple[list[dict], str | None]:
    query = f"*[System[EventRecordID>{int(after_record)}]]"
    out = subprocess.run(
        ["wevtutil", "qe", channel, f"/q:{query}", f"/c:{limit}",
         "/e:Events", "/f:RenderedXml", "/rd:false"],
        capture_output=True, text=True, timeout=60)
```

Semantics, item by item as requested:

| Question | Answer from code |
|---|---|
| Batch/page limit | **Yes, hardcoded `limit: int = 100`** (L265). `collect()` never overrides it (L336). It is **not configurable** — no env var, no CLI flag, no policy field. |
| Query direction / order | `/rd:false` = **oldest-first (chronological)**. Confirmed against Microsoft `wevtutil` documentation. So each batch is the *oldest 100 surviving records* with RecordID > cursor. |
| Cursor comparison semantics | **Strict `>`**, exclusive: `EventRecordID>{cursor}`. Correct; no off-by-one, no re-read, no skip-by-one. |
| Ordering by EventRecordID | Not explicitly ordered. Relies on channel chronological order, which for a live channel is RecordID-ascending. Acceptable. |
| Newest-N behaviour | **No.** `/rd:true` is never used anywhere in the repo. |
| Pagination / draining until caught up | **NO. This is the defect.** `collect()` calls `_query_channel()` **exactly once per channel per cycle** (L334-336). There is no `while more_available:` loop, no re-query, no "is the batch full → fetch again" condition. A full batch of exactly `limit` records is indistinguishable, to this code, from a channel that is fully caught up. |
| When does the cursor advance | L340-342, inside `collect()`, then persisted at L568 **after** `_enqueue()` at L567. Ordering is **correct** (durable journal + fsync before cursor commit). |
| Advances to what value | `max(record_id)` over **records actually parsed** — not the highest record queried, **not** the channel tail. |
| >1 batch of events pending | The surplus is simply **left for the next cycle**. Per-cycle throughput stays 100. |
| Mixed channels sharing limits/state | Each of the 3 channels in `CHANNELS` (L75-76) has its own key in `channels.json` and its own independent 100-record budget. No cross-channel contamination. |
| Enqueue before or after cursor commit | **Enqueue + fsync first (L567), cursor commit second (L568).** Correct. If `_enqueue` raises, `_save_bookmarks` is never reached → safe replay. |
| Exception / partial-read behaviour | `_query_channel` non-zero exit, `FileNotFoundError`, `OSError`, or the **60 s `subprocess` timeout** → returns `(<empty list>, reason)`; `collect()` records it in `channels_unavailable` and **`continue`s (L337-339)**, leaving the cursor untouched. Safe for integrity, but it means **a timed-out cycle acquires zero records**, compounding the throughput deficit. Note a `subprocess.TimeoutExpired` at L272 is **not** in the caught tuple at L275 (`OSError`/`SubprocessError`)… it *is* a `SubprocessError` subclass, so it is caught. Confirmed safe. |
| Gap / continuity detection | **NONE.** Nothing anywhere compares `min(record_id returned)` against `cursor + 1`. No counter, no warning, no `channels_unavailable` entry, no field in the cycle report (L574-583). |

### 2.2 Why the cycle period is unbounded — proven from L552-587

`run()` is a strictly serial single-threaded loop. Acquisition cannot begin
again until delivery for the previous cycle has finished. Using the
**already-measured production POST latency of ~2.68 s** (Issue 2 in the
current backlog) and the hardcoded `max_per_cycle: int = 200` (L487):

```
drain worst case      = 200 POSTs x 2.68 s  ~= 536 s   (~8.9 min)
+ policy GET + POST   = up to  2 x 20 s
+ 3 x wevtutil        = up to  3 x 60 s     (scan cost, see 2.3)
+ heartbeat + enforce = up to  2 x 20 s
+ sleep(max(5, 30))   =        30 s
-------------------------------------------------
cycle period          ~= 10 min .. 22+ min
```

Acquisition capacity therefore collapses to
**100 records / ~600–1300 s ≈ 0.08–0.17 records/sec per channel.**

### 2.3 Secondary aggravator (code-proven)

`*[System[EventRecordID>N]]` is an **unindexed XPath scan**. With `/rd:false`
the Event Log service evaluates from the oldest record forward. When the
cursor sits near the tail of a large Sysmon channel, every cycle re-scans the
whole channel to find its 100 matches. That cost grows with channel size and
pushes `_query_channel` toward its 60 s timeout — at which point the cycle
acquires **nothing** (see §2.1, exception row). This is a positive feedback
loop: the further behind the sensor falls, the more expensive each query
becomes, the more cycles acquire zero.

---

## 3. CAN THIS CODE PRODUCE `100 → ~26k gap → 100`?

**Yes. Evaluated against your production evidence, term by term.**

### 3.1 Why "exactly 100" is code-forced

`/c:100` with `limit` hardcoded and non-configurable. A batch of exactly 100
is the **saturation signature**, i.e. "there was more to read and I stopped."
Both of your visible batches are exactly 100. Code-consistent.

### 3.2 Why "consecutive" is code-forced

`/rd:false` + strict `>` + single call → one contiguous ascending run.
`8470086–8470185` is 100 consecutive; `8496595–8496694` is 100 consecutive.
Code-consistent.

### 3.3 Why the outbox timestamps prove cycle sparsity (strong, and it is proof)

`observed_at` is stamped by `_now()` **inside `_query_channel` at parse time**
(L286) — it is the **collection time, not the event time**. So all 100 records
of a batch carry effectively the same `observed_at`. Your data shows exactly
that: one tight cluster at 14:45Z, one at 15:07Z.

Separately: `outbox.jsonl` is **append-only and is never rotated, truncated or
unlinked** — verified by grep across the whole Windows connector; only
`open(QUEUE_FILE, "a")` at L467 writes it, and `_drain` advances only
`outbox.offset` (L515), never the file. **Therefore the absence of Sysmon
records with `observed_at` in 14:47–15:06Z is positive proof that no
collection cycle acquired anything in that window** — it is not deletion, not
rotation, not drain. That establishes the ~22-minute cycle period predicted
in §2.2 from code. This is the load-bearing proof and it is independent of any
assumption about Windows internals.

### 3.4 The RecordID jump — what code proves and what it does not

Sysmon production rate implied by your data:
`26,410 records / 1,320 s ≈ 20 records/sec`.
Sensor capacity from §2.2: `≈ 0.08–0.17 records/sec`.
**Deficit ≈ 120×–250×.** Code-proven ceiling, production-measured rate.

Given oldest-first semantics and `max()` cursor advancement, the code's *next*
query is `EventRecordID>8470185`, and it would have returned `8470186…` **if
those records still existed in the channel.** They did not: the response began
at `8496595`. `wevtutil` cannot skip surviving matches with `/rd:false`, and no
other component writes `channels.json`. Hence the intervening
records were absent from `Microsoft-Windows-Sysmon/Operational` at query time,
i.e. the channel had wrapped past the sensor's cursor while the sensor was
blocked in `_drain`.

So the chain is:

```
hardcoded 100/cycle ceiling (L265)                       [CODE, PROVEN]
  + no pagination loop (L334-336)                        [CODE, PROVEN]
  + acquisition serialized behind 200 sequential POSTs   [CODE, PROVEN]
    (L552-587, L487) at ~2.68 s each                     [PROD, MEASURED]
  => cycle period ~10-22 min, capacity ~0.1 rec/s        [DERIVED]
  => confirmed by append-only outbox timestamp sparsity  [PROD, PROVEN]
  vs Sysmon production ~20 rec/s                         [PROD, MEASURED]
  => cursor falls irrecoverably behind the channel
  => channel retention evicts the un-acquired records    [ENDPOINT, INFERRED]
  => next query legitimately returns oldest survivors    [CODE, PROVEN]
  => ~26,410 RecordIDs permanently lost
  + no continuity check anywhere (L332-360, L574-583)    [CODE, PROVEN]
  => loss is SILENT; cycle reports "collected: 100"
```

Every link is code-proven or production-measured except the eviction step,
which is endpoint configuration. I am **not** claiming code proof for it.

---

## 4. SEVERITY — THIS IS NOT A ProcessTerminate ISSUE

Your read is correct and the code confirms it. Consequences:

1. **General telemetry loss, all channels.** Security, System and Sysmon are
   all subject to the same 100/cycle ceiling. Any channel exceeding ~0.1
   records/sec sustained will lose records.
2. **Silent loss.** The sensor reports `collected: 100`, `channels_unavailable: {}`
   and a healthy heartbeat while discarding 99%+ of the channel. The
   `endpoint_observed` / `endpoint_read` delivery-fidelity counters (L564-565)
   are incremented from `len(events)` — i.e. from **what was read**, not from
   what the channel produced — so the fidelity instrumentation cannot detect
   this either.
3. **Detection-integrity impact.** Any rule requiring event pairing
   (process_start ↔ process_exit, file-write ↔ execute, network ↔ process)
   can silently lose one side. This undermines E3 negative-control semantics:
   an absence currently cannot be distinguished from a non-acquisition.
4. **B5-GAP-1's 10 missing ProcessGuids are explained** as ordinary victims of
   this ceiling, not as an EID5 subscription problem.

---

## 5. SMALLEST SAFE FIX — PROPOSAL ONLY (NO EDITS MADE)

Presented for owner review. Nothing applied.

### FIX-1 (P0, required) — drain the channel within the cycle
**File/function:** `nivxforge_sensor.py` → `collect()` (L332-360)

```
for channel in CHANNELS:
    budget = MAX_RECORDS_PER_CHANNEL_PER_CYCLE   # new, env-overridable
    while budget > 0:
        after  = int(marks.get(channel) or 0)
        found, reason = _query_channel(channel, after, limit=BATCH)
        if reason: record unavailable; break
        if not found: break                      # genuinely caught up
        ... existing per-event handling, cursor max(), events.extend ...
        budget -= len(found)
        if len(found) < BATCH: break             # tail reached
```
Keeps the existing durable ordering (enqueue+fsync → cursor commit) untouched.

### FIX-2 (P0, required) — make the gap observable
**File/function:** `collect()` / `_query_channel()`

On each batch compare `min(record_id)` against `after + 1`. If greater, emit
an explicit, honest declaration — e.g. `acquisition_gaps: [{channel,
cursor_was, lowest_available, records_unobserved}]` — surface it in the cycle
report (L574-583) and report it to the platform so the console can render
`ACQUISITION_GAP_DECLARED` rather than implying absence of activity. This is
required for E3 negative-control correctness and must **not** backfill or
synthesize anything.

### FIX-3 (P1) — decouple acquisition from delivery
Acquisition must not be throttled by POST latency. Minimal form: cap
`_drain`'s wall-clock budget per cycle (instead of a fixed 200-message count)
so a delivery backlog cannot starve acquisition. Structural form: move
`_drain` to a separate thread. Minimal form is the smaller change.

### FIX-4 (P1, endpoint-side, needs owner approval separately)
Raise `Microsoft-Windows-Sysmon/Operational` max log size so retention
comfortably exceeds worst-case sensor lag. Mitigation only — it does **not**
fix FIX-1/FIX-2 and must not be done instead of them.

### Explicitly NOT proposed
Switching to `/rd:true`, using `EvtSubscribe` bookmarks, rewriting the
acquisition architecture, backfilling the 10 ProcessGuids, or touching
`channels.json`/`outbox.jsonl`.

---

## 6. THE ONE REMAINING READ-ONLY CHECK (your call, nothing run)

To convert the eviction link from INFERRED to PROVEN, one non-invasive,
non-mutating endpoint query would suffice — it reads configuration and the
oldest surviving record only, changes nothing, restarts nothing:

```
wevtutil gl Microsoft-Windows-Sysmon/Operational      # maxSize + retention
wevtutil qe Microsoft-Windows-Sysmon/Operational /c:1 /rd:false /f:text
```

If `maxSize` divided by mean record size yields a retention window shorter
than the observed ~22-minute cycle period, the chain in §3.4 is fully closed.
**Not executed. Awaiting your instruction.**

---

## 7. STOP

Report ends here for owner review. No code edited, no tests run, no
deployment, no endpoint interaction. B5 remains CLOSED/PASS.
