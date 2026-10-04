# FOLLOW-UP · Sysmon source-time canonicalization + normalization contract

Raised by the owner from the real W1 production records, 2026-09-18.
**RECORDED, NOT FIXED.** Explicitly excluded from W1-E1 closure and from the W1
verdict. No code, configuration or deployment change has been made.

## What the owner observed (`xdr_canonical_events`, the five W1 rows)

```
raw.TimeCreated          2026-09-18T08:38:17…
nivx_received_at         2026-09-18T10:01:43…
received_at              2026-09-18T10:01:43…
source_timestamp         null
received_at_substituted  true
canonical_schema         null
normalized               null
event_type               null
parser_ok                true
normalized_ok            true
```
Source→NivX delay in this sample: **1 h 23 m 26 s**.

Owner's requirement for the Attack Observation & Decision Timeline:
```
ACTIVITY TIME  08:38:17  →  SOURCE/SENSOR TIME  08:38:17  →  NIVX RECEIVE TIME  10:01:43
```
NivX must never display 10:01 as when the activity happened.

## Read-only triage (no change made)

### 1 · The evidence plane already does this correctly — verify before building anything
`SysmonDSM.normalize()` resolves activity time through
`services.event_time_basis.resolve()` with
`activity = EventData.UtcTime` ("Sysmon's own record of when the activity
happened") and `TimeCreated` ("when the ETW provider wrote the record") as an
explicitly-labelled fallback, then stamps the basis onto the canonical output
(`detection_content/telemetry/sysmon_dsm.py:78-86, 420-479`). It even carries
honest degradation strings for a record that has no `UtcTime`.

So the separation the owner wants may **already exist** on
`xdr_canonical_evidence` (the evidence plane / SSOT). The nulls above are on
`xdr_canonical_events`, which the ingest code itself labels as a minimal
projection and "not the SSOT" (`routers/xdr_ingest.py:876-880`).

**First action, read-only:** inspect one of the five `xdr_canonical_evidence`
documents for `event_time`, `ingest_time` and the `event_time_basis` fields
before any code is written. If they are correct, this issue collapses to items
2 and 3 and no timeline defect exists.

### 2 · Raw-lane gaps that are real regardless
* `source_timestamp` is null although `raw.TimeCreated` (and `UtcTime`) are
  present on the row. The forwarder does not populate it and ingest does not
  derive it for the raw projection.
* `received_at_substituted = true` with
  `received_at_source = collector:envelope.collection_timestamp` /
  `ingest:http receipt` — D11 correctly *declares* the substitution, but no
  field anywhere records the **latency** (here 1 h 23 m 26 s). Telemetry delay
  should be computed and retained, not left for an operator to subtract.

### 3 · Honesty defect found while triaging this — `parser_ok` / `normalized_ok`
`CanonicalEnvelope.parser_ok` and `.normalized_ok` **default to `True`**
(`routers/xdr_ingest.py:118-119`), and `NivXRay-SysmonForwarder.ps1` never
sends either field. So for every Sysmon delivery these flags assert an outcome
**nobody measured** — the absence of a claim is being recorded as success.
They feed `accepted`, `events_parsed`, `events_normalized` and therefore the
`CONNECTED` state gate.

This does **not** weaken W1-A/W1-B: acceptance was independently established by
fail-closed declared-source routing plus the DSM content-compatibility gate,
and `reasoned=5` came from the core re-parsing `raw` itself (INGEST_CONTRACT
§2.1 — the collector's extraction is provenance, not authority). But a counter
that gates a state machine should not be able to default to "fine".
Similarly `canonical_schema`, `normalized` and `event_type` being null is
*by design* for the raw projection, yet `normalized_ok=true` alongside
`normalized=null` reads as a contradiction and should be made
self-describing.

## Proposed scope when this is authorised (P1, after W1)
1. Read-only confirmation of `event_time` / `event_time_basis` on the five
   existing `xdr_canonical_evidence` docs. No code.
2. Populate `source_timestamp` on the raw projection from the authoritative
   Sysmon time, reusing `event_time_basis` — never re-deriving a second,
   competing time rule.
3. Retain both timestamps and record telemetry latency explicitly.
4. Make `parser_ok` / `normalized_ok` measured rather than defaulted, or
   rename them to state that they are collector-asserted; and resolve the
   `normalized_ok=true` + `normalized=null` contradiction.
5. Forwarder side: send `source_timestamp` from `UtcTime` where present.

Nothing above is to be started until the owner authorises it.
