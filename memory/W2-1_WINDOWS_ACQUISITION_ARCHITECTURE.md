# W2-1 · WINDOWS ACQUISITION ARCHITECTURE (Program B, Lane 1)

Status 2026-06: **acquisition contract IMPLEMENTED and PROVEN on Linux with a
substituted native boundary. NOT yet proven against a real Windows endpoint —
that requires a Windows host and is the gate for calling any source
`RECEIVING`/`CONNECTED`.**

W1 (PowerShell/Sysmon forwarder) remains **FROZEN**. It was not extended, not
rewritten and not used as the base for this work.

---

## 1 · WHAT WAS ALREADY THERE (reused, not rebuilt)

The durable collector engine is generic and predates this lane — M365 was its
first consumer, not its reason for existing:

| Primitive | File | Reused for |
|---|---|---|
| `AcquisitionState` — ACQUIRED / QUEUED / DELIVERED / COMMITTED with leases and terminal-record events | `framework/acquisition_state.py` | The state vocabulary and the rule that "the vendor returned it" ≠ "NivX accepted it" |
| `Outbox` — SQLite, unique `(tenant, connector, source_event_id)`, retry, dead-letter, replay, metrics | `framework/outbox.py` | Make Durable + duplicate absorption |
| `Envelope` + `declared_source` | `framework/base.py` | The authenticated ingest contract (`DECLARATION_REQUIRED`) |
| `DedupCache` | `framework/dedup.py` | In-process redelivery absorption |

**No second database and no second state machine was introduced.**

---

## 2 · WHAT W2-1 ADDED

### `framework/windows_bookmarks.py` — durable per-channel position
Scope is always `(tenant_id, collector_id, channel)`. Stored in the **same**
SQLite file as the outbox, so a position and the delivery that justifies it
share one fsync domain.

Facts kept deliberately separate — they are different things and are never
conflated:

| Field | Meaning |
|---|---|
| `bookmark_xml` | **Authority.** Where the subscription resumes |
| `last_record_id` | **Evidence only.** Highest `EventRecordID` seen |
| `last_activity_at` | The newest event's own instant (source clock) |
| `last_read_at` | When this collector last read the channel |
| `delivered_through` | The bookmark whose events are all DELIVERED |

`resume_for()` returns a **classified decision with its reason**:
`NO_BOOKMARK_FIRST_COLLECTION` · `RESUME_FROM_BOOKMARK` · `BOOKMARK_STALE`.
A stale bookmark is **reported, never silently replaced with "now"** — jumping
forward would discard evidence without saying so.

**Why `EventRecordID` alone is not the checkpoint:** record ids are
per-channel, restart at 1 when a log is cleared, are non-contiguous under a
filtered subscription, and describe no subscription position. Windows answers
this with the bookmark; the bookmark is the authority here.

### `framework/windows_eventlog.py` — the permanent multi-channel adapter
- **Native boundary isolated** behind an `EvtReader` protocol:
  `NativeEvtReader` binds `win32evtlog` (EvtSubscribe + bookmark, XPath
  filtering applied **by Windows at the subscription**, not by us after
  reading everything); `UnsupportedPlatformReader` is used off-Windows and
  **collects nothing while saying why**. An unread channel and an empty
  channel are different facts and are reported differently.
- **10 channels architected** via a declarative, versioned
  `CollectionProfile`: Sysmon · PowerShell Operational · Windows PowerShell
  (classic) · Security · Microsoft Defender · Task Scheduler · WMI Activity ·
  AppLocker · System · Application. Adding a channel is a **profile change,
  never another collector**.
- **`ForwardedEvents` (WEF/WEC) is declared UNSUPPORTED** with its reason: a
  forwarded record's origin computer and its collector host are different
  facts and that distinction is not yet proven end to end. Later milestone,
  stated rather than silently missing.
- **Channel-qualified identity**: `tenant | origin_computer | channel |
  event_record_id`. A record with no `EventRecordID` is reported
  **unidentifiable** — it never receives a surrogate id, because a surrogate
  would defeat the outbox's dedupe key.
- **Origin vs collector identity**: `origin_computer` (from the event) and
  `collector_host` (this process) are separate canonical fields.
- **Three clocks preserved**: `activity_occurred_at` (+
  `activity_time_source`: `EventData.UtcTime` or `System.TimeCreated`) and
  `sensor_observed_at`. The collector does **not** emit an ingest time — that
  is the core's fact.
- **No endpoint-side SID rendering**: a SID is carried verbatim; principal
  resolution is the core's enrichment decision, where the directory context
  and the audit trail live.
- **Raw XML preserved verbatim** for the core's DSM. The collector extracts
  only what identity, routing and time require, and **never defaults an absent
  field into existence**.

### The invariant, implemented literally
```
Read → Make Durable → Advance Acquisition → Deliver → Account → Verify
```
- `collect()` = **Read**. It holds the new bookmark **pending**.
- The runtime's outbox = **Make Durable**.
- `advance(durable_channels=[...])` = **Advance Acquisition** — and only for
  channels whose records are durable. A channel left out keeps its position
  and is re-read: duplicate delivery is absorbed by the outbox's unique key,
  whereas a skipped window is **unrecoverable**.
- `acquisition_report()` = **Account** — per-channel, every field measured or
  explicitly absent.
- **Verify** remains OPEN (§4).

---

## 3 · PROOF (`tests/test_windows_eventlog_acquisition.py`)

**22/22 pass; full collector suite 129/129 pass.** The native boundary is
substituted with a scripted fake returning real Windows event XML shapes, so
the durability rules are provable without a Windows host. Proven:

1. first collection has no bookmark and classifies itself as such;
2. identity is channel-qualified — the same record id on two channels yields
   two identities;
3. a record with no `EventRecordID` is reported unidentified, not surrogated;
4. the bookmark does **not** advance before the records are durable;
5. after Make Durable it advances and the next read resumes **from it**;
6. a channel not durable keeps its position and is re-read;
7. a lower record id than already seen is reported **LOG CLEARED** with the
   evidence loss stated, and counted;
8. a stale bookmark is classified and **retained**;
9. an unread channel reports `UNSUPPORTED_PLATFORM` / `READER_UNAVAILABLE`
   with the reason, and a read failure records the error and **no** bookmark;
10. activity and sensor clocks stay separate; `TimeCreated` is used only when
    `UtcTime` is absent; no ingest time is claimed;
11. SID verbatim, raw XML verbatim;
12. WEF and unknown channels are refused by profile validation;
13. per-channel `declared_source`; origin computer ≠ collector host.

Registered in the collector app as source type `windows-eventlog`.

---

## 4 · WHAT IS STILL OPEN (must not be reported as done)

| # | Item | Status |
|---|---|---|
| B-1 | Real Windows endpoint run (EvtSubscribe against a live channel) | **BLOCKED — needs a Windows host** |
| B-2 | Backpressure + drop accounting surfaced per channel | OPEN (outbox has retry/dead; per-channel drop accounting not surfaced) |
| B-3 | Authenticated delivery of Windows envelopes through to raw persistence | OPEN |
| B-4 | DSM/parser coverage for the 8 newly architected channels (Sysmon DSM exists) | OPEN |
| B-5 | **Security proof**: real event → canonical evidence → deterministic detection → investigation-consumable evidence on at least one newly supported channel | OPEN — this is the completion gate |
| B-9 | WEF/WEC | LATER MILESTONE (declared unsupported) |

**Nothing here justifies showing a Windows source as `CONNECTED` or
`RECEIVING`.** `INSTALLED ≠ CONFIGURED ≠ CONNECTED ≠ RECEIVING ≠ HEALTHY`, and
only authoritative telemetry evidence may move that state.

---

## 5 · TRUTHFULNESS DEFECTS CLOSED IN THE SAME LANE

### `parser_ok` / `normalized_ok` were assumptions, now measurements
`routers/xdr_ingest.py` defaulted both to `True`, so a collector that said
nothing about its own processing was counted as a **successful parse and a
successful normalization** — and `events_parsed` / `events_normalized` are the
LOCKED evidence behind the CONNECTED gate. Fixed:
- both are now `bool | None`, and **absence means UNMEASURED** — never success,
  never error;
- the core measures the one thing it can observe first-hand (does this
  delivery actually carry a normalized view?) and the **observation wins** over
  a contradicting claim;
- `events_parsed` counts only **measured** successes (it previously counted
  `len(fresh) - parse_errors`, crediting every undeclared delivery);
- new counters `events_parse_unmeasured` / `events_normalize_unmeasured` on
  collectors and `events_unmeasured` on data sources;
- `processing_outcome` provenance is persisted per event
  (`COLLECTOR_DECLARED` · `CORE_OBSERVED_NORMALIZED_VIEW` · `NOT_DECLARED`);
- the ingest receipt returns `parse_unmeasured` / `normalize_unmeasured`.

Verified by direct model exercise: undeclared → `None/None`; claimed-success
with no normalized view → `parsed=True, normalized=False`; core-observed view →
`True` with basis `CORE_OBSERVED_NORMALIZED_VIEW`.

### Timezone safety — offset-naive timestamps could not reach the pipeline
- `nivxforge/.../normalizers/base.py::_try_parse_dt` lacked
  `%Y-%m-%d %H:%M:%S.%f` — exactly Sysmon's `UtcTime` shape
  (`2026-06-01 12:33:44.123`). It fell through to an ISO fallback that
  **returned the naive datetime it parsed**, so naive instants entered the
  pipeline and later comparisons against aware timestamps raised. Both the
  missing format and the fallback are fixed; verified across 7 shapes,
  all now AWARE, offsets preserved where present.
- `services/telemetry_adapters/runner.py` compared a possibly-naive
  `source_event_time` with an aware `now`, so **telemetry lag silently stopped
  being computed for exactly the sources that write naive instants**. Naive is
  now treated as UTC — which those sources declare — instead of crashing the
  rollup.
- `services/ingest_provenance.py` deliberately preserves offset
  presence/absence (`OFFSET_PRESENT` / `OFFSET_ABSENT`) and was **left alone**:
  re-rendering a collector's timestamp would make our arithmetic look like
  their measurement.
