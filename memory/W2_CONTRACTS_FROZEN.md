# W2 CONTRACTS — FROZEN AT W2-0 (owner-ratified 2026-09-18)

Research CLOSED. Architecture RATIFIED (Path 2). These contracts are frozen for
W2 implementation; changes require owner authorisation and their own evidence.
Sources: `W2_RESEARCH_PASS1_INDUSTRY_COMPARISON.md`,
`W2_RESEARCH_PASS2_PRODUCTION_DESIGN.md`. W1 remains CLOSED/FROZEN at 6/6.

## C-1 · Acquisition
Native Windows Event Log API only: `EvtSubscribe` with **`EvtSubscribeStrict`**,
`EvtCreateBookmark` / `EvtUpdateBookmark` /
`EvtRender(EvtRenderBookmark)`, `EvtSubscribeStartAfterBookmark`, structured XML
queries, **raw XML** payloads. No description rendering. No edge SID/AD
enrichment — all resolution is server-side where it is auditable.
One **independent reader per channel**; `stream = channel` in
`AcquisitionState`. Per-channel source query capped at **≤20 clauses**
(documented Windows limit ≈22); overflow is handled by post-acquisition
filtering, never by generating a larger query.

## C-2 · Identity
```
source_event_id = origin_computer | channel | event_record_id
```
`origin_computer` is the host that **generated** the record (for WEF this is the
origin, never the collector). Preserved separately as evidence and never folded
into the identity key: `event_id`, `provider`, `provider_guid`, `activity_id`,
`related_activity_id`, `collector_id`, `collector_hostname`, `subscription_id`.
Server-side delivery identity remains
`sha256(tenant | collector | source | source_event_id | sha256(raw))`.

## C-3 · Two checkpoints (owner refinement — binding)
Two distinct positions, never collapsed into one:

| position | meaning | may advance only when |
|---|---|---|
| **acquisition position** (Windows bookmark XML, per channel) | what has been read out of Windows | the event is **durably recoverable in the local outbox** |
| **accounting position** (per stream) | what has safely entered the NivX evidence path | the **server has authoritatively accounted** for it |

Invariant: *event survivability is owned by the outbox, never by Windows
circular-log retention.* A network or server outage must not risk loss:
```
Windows read → OUTBOX DURABLE → (network fails, host restarts,
record leaves the circular log) → NOT LOST — the outbox still owns it
```
`event_record_id` is retained for human readability only and is explicitly
**not** the resume authority (Winlogbeat documents `record_number` as legacy
behind bookmarks). Crash replay is safe because server-side dedupe is
W1-proven.

## C-4 · Telemetry Integrity Events (platform primitive, not log lines)
```
integrity_event_type : COLLECTION_GAP
source               : windows_eventlog
origin_computer      : <host>
channel              : <channel>
reason               : BOOKMARK_STALE | LOG_CLEARED | SUBSCRIPTION_NOT_FOUND |
                       BACKLOG_WINDOW_EXCEEDED | QUEUE_PAUSED | CHANNEL_UNREADABLE
win32_status         : e.g. 15011 (ERROR_EVT_QUERY_RESULT_STALE)
detected_at · last_known_good · resume_at
loss_confirmed       : true|false
lost_event_count     : UNKNOWN | <n>
collector_id · evidence_ref
```
Recovery rule (from the documented Vector defect): a stale bookmark under
strict mode fails `ERROR_NOT_FOUND`; the implementation **must not** fall back
to `EvtSubscribeToFutureEvents` without first emitting a CONFIRMED gap record.
`ERROR_EVT_QUERY_RESULT_STALE` is **15011** — no other mapping is acceptable.

Consequence, binding on the UI: **a collector may be online and receiving while
its evidence history is incomplete.** `HEALTHY · EVIDENCE INCOMPLETE` is a
required state; plain `HEALTHY` must never hide a confirmed gap. Designed to
generalise beyond Windows (Linux, firewall, cloud, identity, SaaS, NivXForge
EDR) as a **Telemetry Integrity** plane.

## C-5 · Durability & backpressure
Collector states: `NORMAL · BACKLOG · PAUSED · DEGRADED · DROPPING ·
RECOVERING`. Published counters: `queue_depth`, `queue_bytes`,
`oldest_queued_age`, `events_received`, `events_queued`, `events_delivered`,
`events_retried`, `events_dropped`, `bytes_dropped`, `last_successful_delivery`.
Full queue → **pause the source** (never silent loss). **`dropped = 0` must be
measured, not assumed**, and any non-zero drop raises a COLLECTION_GAP.

## C-6 · Time
`ACTIVITY_TIME` only where the format proves it (Sysmon `EventData.UtcTime`);
`OBSERVATION_TIME` with `activity_occurred_at = NOT_OBSERVED` elsewhere
(Security EVTX has no activity field). Offset-naive values are canonicalised to
explicit UTC **with the original value and basis preserved**. Source→NivX
latency is computed and stored, not left for an operator to subtract.

## C-7 · Configuration & upgrade
The authoritative object is a **server-owned, versioned collector profile**
(channels, filtering tier-2, buffer, update ring, assignment). It compiles to
whatever the collector needs. **Raw collector YAML is not a customer-facing
management contract** — the documented Cortex footgun is configuration erased
on upgrade. Requirements: version, validation, assignment, audit, rollback,
staged deployment. An upgrade must never erase collection configuration.

## C-8 · Security
Least privilege per channel (Security requires Administrators or **Event Log
Readers**); ACL-checked key material as in W1; TLS floor enforced; tenant
resolved from the authenticated collector, never from a header; declared-source
routing stays fail-closed.

## C-9 · Gates (executable, one at a time)
`W2-0` foundation · `A` declaration/refusal · `B` DSM correctness ·
`C` per-channel checkpoint isolation + bookmark resume across restart ·
`C2` rollover/stale honesty · `D` cross-channel identity uniqueness ·
`E` temporal honesty · `E2` timezone safety · `F` durability under mid-batch
kill · `F2` filter-limit conformance · `F3` backpressure/data-loss
observability · `G` least privilege · `H` ≥1 real rule fires on a new channel ·
`I` configuration/upgrade integrity.

## C-10 · UI data honesty (binding)
`Verify Ingestion` proves acquisition → durability → transport → parsing →
normalization → canonical evidence → detection readiness. Backend items
declared **BUILD** and not to be wired until real: per-stream counters,
computed collection latency (P50/P95/P99), dedupe observability API,
COLLECTION_GAP records, rule-to-channel bindings, `parser_ok`/`normalized_ok`
as *measured* values. No invented status data. No status word without a
computable contract.

## C-11 · Sequence
`W2-0` (this gate) → `W2-1` acquisition engine + Sysmon regression + PowerShell
→ `W2-2` Security, profiles, custom channels, DSM/rule coverage, cross-channel
correlation → `W2-3` fleet: inventory, assignment, versioning, staged
upgrade/rollback, offboarding, health. **WEF/WEC is a separate milestone.**
W2-1 does not start until W2-0 evidence is accepted by the owner.
