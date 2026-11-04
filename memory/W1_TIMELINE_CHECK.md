# TIMELINE CHECK — `xdr_canonical_evidence.event_time` for the W1 five

Read-only. Owner-requested step 2, performed **after** the W1 freeze. No code,
configuration or deployment change. No production write. No replay. Nothing was
run on the Windows endpoint.

Probe: `scripts/w1_timeline_check_probe.py` (preview DB only; drives one
Sysmon record shaped exactly like the W1 five through
`process_event_through_pipeline` — the same function the ingest route calls —
then reads back the persisted `xdr_canonical_evidence` document).

---

## VERDICT — **NO TEMPORAL DEFECT ON THE EVIDENCE PLANE**

`event_time` is the **activity** instant, taken from `EventData.UtcTime`, with
the basis declared. The nulls the owner saw live on `xdr_canonical_events` — a
minimal raw projection the ingest code itself labels "not the SSOT"
(`routers/xdr_ingest.py:876-880`) — not on the evidence plane that every
consumer reads.

Probe output, verbatim:

```
event_time             : 2026-09-18 08:38:17.569
ingest_time            : <pipeline clock>
event_time_basis       : ACTIVITY_TIME
event_time_source      : sysmon:EventData.UtcTime
event_time_substituted : False
event_time_format      : ISO_8601

provenance.timestamps.activity_occurred_at
  {"value":"2026-09-18 08:38:17.569","status":"AVAILABLE",
   "source":"sysmon:EventData.UtcTime",
   "reason":"the supplied value carries no UTC offset; it is recorded verbatim
             and its offset is UNKNOWN"}
provenance.timestamps.sensor_observed_at
  {"value":"2026-09-18T08:38:17.5694321Z","status":"AVAILABLE",
   "source":"sysmon:System.TimeCreated"}

VERDICT: event_time IS ACTIVITY TIME (08:38)
```

## The five records, per the owner's reporting template

| # | source_event_id | raw/source activity ts | canonical `event_time` | NivX receive | source→NivX latency | timeline shows |
|---|---|---|---|---|---|---|
| 1 | `DESKTOP-A9HGFJJ\|1696988` | `UtcTime` ≈ 2026-09-18T08:38:17.569Z | = `UtcTime` (ACTIVITY_TIME) | 2026-09-18T10:01:43Z | ≈ 1 h 23 m 25 s | **activity time** |
| 2 | `DESKTOP-A9HGFJJ\|1696989` | its own `UtcTime` | = `UtcTime` | 10:01:43Z | ≈ same batch | **activity time** |
| 3 | `DESKTOP-A9HGFJJ\|1696990` | its own `UtcTime` | = `UtcTime` | 10:01:43Z | ≈ same batch | **activity time** |
| 4 | `DESKTOP-A9HGFJJ\|1696991` | its own `UtcTime` | = `UtcTime` | 10:01:43Z | ≈ same batch | **activity time** |
| 5 | `DESKTOP-A9HGFJJ\|1696992` | its own `UtcTime` | = `UtcTime` | 10:01:43Z | ≈ same batch | **activity time** |

This workspace holds no production credential, so the per-record `UtcTime`
values are **derived from the deployed code path, not read from the five
documents**. That distinction is deliberate and must stay in the record. The
conclusion is nevertheless robust for all five:

* if `UtcTime` is present → `event_time = UtcTime`, basis `ACTIVITY_TIME`,
  `event_time_substituted=False`;
* if it were absent → `event_time = TimeCreated` (08:38:17.569…), basis
  `OBSERVATION_TIME`, substituted `True`;
* `event_time` can only become the 10:01 receive instant if **both** `UtcTime`
  and `TimeCreated` were missing — contradicted by the owner's own read, which
  shows `raw.TimeCreated` populated.

So in no reachable branch does the timeline display 10:01 as the activity
instant. One optional read-only query confirms it on the real documents:

```javascript
db.xdr_canonical_evidence.find(
  { tenant_id: "ten_e759b7288598bd882e3dcac49d",
    source_product: "Sysmon" },
  { _id: 0, event_id: 1, event_type: 1, event_time: 1, timestamp: 1,
    ingest_time: 1,
    "additional_fields.event_time_basis": 1,
    "additional_fields.event_time_source": 1,
    "additional_fields.event_time_substituted": 1,
    "provenance.timestamps.activity_occurred_at": 1,
    "provenance.timestamps.sensor_observed_at": 1,
    "provenance.timestamps.nivx_received_at": 1,
    "provenance.trace_id": 1, "raw_ref": 1 }
).sort({ ingest_time: 1 })
```
Expect 5 docs, each `event_time_basis=ACTIVITY_TIME`,
`event_time_source=sysmon:EventData.UtcTime`, `event_time_substituted=false`,
`activity_occurred_at.status=AVAILABLE`, and `trace_id` matching the W1-C rows.

## Exact code path that selects `event_time`

1. `routers/xdr_ingest.py:506-512` — ingest calls
   `process_event_through_pipeline(...)` with the routing decision.
2. `detection_content/xdr_pipeline.py:298-305` — the DSM is taken **from the
   routing decision** (`microsoft-sysmon`); content never selects a substitute.
3. `detection_content/telemetry/sysmon_dsm.py:78-86` — the parser keeps both
   fields apart: `utc_time ← EventData.UtcTime` ("when the activity
   happened"), `time_created ← System.TimeCreated` ("when the ETW provider
   wrote the record").
4. `sysmon_dsm.py:420-443` — `event_time_basis.resolve(activity=[UtcTime],
   observation=[TimeCreated], supplied=[raw:timestamp], clock=now, …)` with
   mandatory absent-reasons.
5. `services/event_time_basis.py:174-198` — precedence is
   **activity → observation → supplied → unreadable → NivX clock**, and the
   `Resolution.verify()` invariant makes `activity_occurred_at` AVAILABLE only
   when `basis == ACTIVITY_TIME`, with `event_time` required to equal it.
6. `sysmon_dsm.py:452-453` — `event_time=etb.event_time`,
   `ingest_time=<pipeline clock>` (two different fields, never merged).
7. `event_time_basis.apply()` (`:200-208`) — stamps
   `provenance.timestamps.activity_occurred_at` / `sensor_observed_at` and
   publishes the four `event_time_*` declarations.
8. `detection_content/telemetry/models.py:269` — `to_dict()` sets
   `d["timestamp"] = self.event_time`, so the legacy `timestamp` key is the
   **same activity value**, not a receive time.

### Which field the display surfaces actually read
* `detection_content/xdr_ice.py:135` → `canonical.get("timestamp") or
  canonical.get("event_time")` — activity time.
* `services/iue/service.py:132` → same precedence — activity time.
* `services/entity_resolution.py:153`, `detection_content/xdr_spread_watchlist.py:342`
  → `event_time` — activity time.
* `routers/xdr_ingest_routing.py:_accepted_row` → `at = nivx_received_at`
  with `at_basis` naming it. That is a **delivery log**, so receive time is
  correct there and is labelled as such. It is the one surface that shows
  10:01, by design.

## Residual gaps — for the owner's Source Time Fix decision (nothing changed)

1. **Latency is never computed or stored.** Both boundaries exist
   (`activity_occurred_at`, `nivx_received_at`), but nothing derives the delay.
   The 1 h 23 m 25 s in this sample had to be worked out by hand.
2. **`xdr_canonical_events.source_timestamp` is null** although
   `raw.TimeCreated`/`UtcTime` are on the row. Harmless today — no consumer
   reads that projection for time — but it is what made this look like a
   defect, and it will mislead the next reader too.
3. **Offset-naive activity values.** Sysmon's `UtcTime` is
   `"2026-09-18 08:38:17.569"` — space-separated, no offset. It is stored
   verbatim with the honest reason "offset is UNKNOWN", yet
   `event_time_format_state` still reads `ISO_8601`. Other DSMs emit
   offset-aware ISO strings, so a **cross-source** Attack Progress timeline
   would be sorting naive against aware strings. This is the item most likely
   to bite the timeline work, and it is not the same bug the owner suspected.
4. **`parser_ok` / `normalized_ok` default to `True`** and the forwarder never
   sends them (`routers/xdr_ingest.py:118-119`) — those CONNECTED-gate
   counters assert an unmeasured outcome. Tracked in
   `W1_FOLLOWUP_TEMPORAL_NORMALIZATION.md` §3.

Nothing above is to be started until the owner authorises it.
