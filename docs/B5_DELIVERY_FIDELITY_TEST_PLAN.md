# B5-4 · FORWARD DELIVERY-FIDELITY TEST · PROCEDURE (NOT EXECUTED)

**PREPARED ONLY. NOT RUN. No endpoint change, no Sysmon change, no
deployment.** This replaces the 2026-09-22 question that endpoint
retention made unanswerable.

It must expose loss **at each boundary**, not endpoint-count vs
final-canonical-count — a single end-to-end delta cannot distinguish a
sensor that never read a record from an ingest that refused it.

## THE FIVE BOUNDARIES

```
 B0  ENDPOINT GENERATED      Sysmon wrote it to the channel
        │  loss here = configuration / channel rollover
 B1  SENSOR OBSERVED         the sensor read the record
        │  loss here = bookmark, permissions, service gap, backlog
 B2  SENSOR SENT             the sensor transmitted it
        │  loss here = queue drop, spool, network, auth
 B3  BACKEND ACCEPTED        ingest admitted it  (vs REFUSED, with reason)
        │  loss here = envelope/format refusal, tenant refusal, dedupe
 B4  CANONICALIZED           it became canonical evidence
             loss here = unsupported Event ID, normalizer refusal
```

Per Sysmon Event ID, per boundary, for one agreed 60-minute UTC window.
Every count is a SEPARATE measurement — no boundary is inferred by
subtraction.

## WINDOW RULES

* 60 minutes, both bounds in UTC, agreed and written down BEFORE
  starting; the endpoint's UTC offset and clock skew recorded at both
  ends (§0 of the PRE-check already produces this).
* The window must end at least 5 minutes before measuring, so in-flight
  delivery is not counted as loss.
* **Retention guard:** re-read the channel's oldest retained record
  AFTER the window. If it is newer than the window start, the run is
  `INVALID_ROLLOVER` and is repeated — the exact trap that destroyed the
  September evidence.
* Record `Sysmon EventID 16` (ServiceConfigurationChange) and any
  `Security 1102` inside the window: a config change or a log clear
  invalidates the run.
* No normal-use restriction. A quiet hour is a valid measurement; low
  volume is a result, not a failure.

## HOW EACH BOUNDARY IS COUNTED

| boundary | source of truth | method |
|---|---|---|
| B0 | the endpoint channel | READ-ONLY PowerShell: per-Event-ID histogram for the window + first/last `RecordId` (the RecordId span is the authoritative denominator — it cannot be inflated or deflated by query shape) |
| B1 | sensor telemetry | the sensor's own read counter / bookmark position per channel at window start and end |
| B2 | sensor telemetry | records transmitted, plus queue drops and spool depth for the same window |
| B3 | backend | ingest accepted vs REFUSED counts per source, with refusal reasons (the Wave A logger fix means a refusal now carries its payload excerpt and is diagnosable) |
| B4 | backend | canonical observations by `event_type` for the window, from `xdr_canonical_evidence` |

B1 and B2 require the sensor to expose per-channel read/sent counters. If
it does not, that is itself the first finding and the test reports
`SENSOR_COUNTERS_NOT_AVAILABLE` for those boundaries rather than
guessing — a gap that must be closed before anyone claims delivery
fidelity.

## REPORT SHAPE

```
window_utc_start · window_utc_end · endpoint_clock_offset_ms
retention_guard: oldest_retained_after_run · VALID | INVALID_ROLLOVER
config_stability: eventid_16_in_window · security_1102_in_window

per Event ID:
  eid | B0 generated | B1 observed | B2 sent | B3 accepted | B3 refused
      | B4 canonicalized | loss_B0_B1 | loss_B1_B2 | loss_B2_B3
      | loss_B3_B4 | refusal reasons

verdict per Event ID:
  COMPLETE                 B0 == B4
  LOSS_LOCALISED           the boundary is named
  BOUNDARY_NOT_MEASURABLE  a counter does not exist yet
  INVALID_ROLLOVER         retention destroyed the window
```

Deduplication note: a redelivered Windows record is the SAME activity
(channel + RecordId), so B3 dedupe suppression must be counted
separately from refusal. Dedupe is correct behaviour and must never be
reported as loss.

## SEQUENCING

1. **Now** — this procedure, reviewed. Nothing executed.
2. **After B5 acceptance** — run it for EID 1/3/11/12/13/22 with the
   endpoint UNCHANGED. This validates the measurement instrument itself
   on telemetry we already receive, and establishes the current
   fidelity baseline.
3. **Only then** — the one-line `ProcessTerminate` change, and a second
   run that includes EID 5. The server-side readiness (B5-1) is already
   done, so EID 5 will canonicalise as `process_exit` the moment it
   arrives.

The endpoint-side counting block will be issued as a single READ-ONLY
PowerShell script, in the same form as
`WAVE_B_WINDOWS_PRECHECK_READONLY.ps1`, for owner inspection before it
is run. **It is not issued in this wave.**
