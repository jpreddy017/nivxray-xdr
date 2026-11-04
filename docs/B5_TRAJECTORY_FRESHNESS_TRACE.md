# B5 — NEW TELEMETRY / DEVICE TRAJECTORY FRESHNESS TRACE (READ-ONLY)

2026-09-29. Measured against production store `greeting-app-5782-test_database` and
live run `3bd64025`. Nothing deployed, replayed, backfilled, restarted or written. No
endpoint / sensor / Sysmon / outbox change. No E3. No UI change.

## REQUIRED OUTPUT

```
SENSOR_FRESH_TELEMETRY        = PASS
LATEST_ENDPOINT_RAW_EVENT     = ingest_time 2026-09-29T17:45:20.558821Z ·
                                winsec EventID 4798 · channel Security ·
                                payload.observed_at 2026-09-29T10:41:31Z ·
                                TimeCreated 2026-09-29T10:29:35Z
LATEST_ENDPOINT_CANONICAL_EVENT = event_time 2026-09-29T10:36:10.339487Z /
                                ingest_time 2026-09-29T17:41:09.611631Z
                                (xdr_canonical_evidence, host.host_id=ep_1989031c8c1d0085812f)
LATEST_TRAJECTORY_OBSERVATION = captured_at 2026-09-29T10:36:10.339487Z
                                (dev_2adbb41a04a4, v2_shadow_observations)
ENDPOINT_IDENTITY_SPLIT       = NO
EID5_RAW_RECEIVED             = NO
EID5_CANONICALIZED            = NO
EID5_LIFECYCLE_PROJECTED      = NO
EID5_TRAJECTORY_VISIBLE       = NO
FIRST_BROKEN_BOUNDARY         = none in the backend pipeline. For the CONSOLE view:
                                UI window selection. For EID5: the sensor spool
                                REPLAY FRONTIER has not yet reached 14:48Z — the
                                arrival boundary, not a pipeline defect.
ROOT_CAUSE                    = two independent, separately-evidenced facts:
                                (1) H2 CONFIRMED — the console URL pins a Sep-20
                                event, fixing the 30-min window to Sep-20 while
                                fresh Sep-27/28/29 observations already exist;
                                (2) EID5 has not yet been DELIVERED: production is
                                replaying the sensor spool chronologically and the
                                frontier stands at ~10:41Z, still ~4h short of the
                                14:48-14:50Z EID5 batch.
B5_EID5_END_TO_END            = WAITING_FOR_DELIVERY
```

## 1 · H1 REFUTED — THERE IS NO IDENTITY SPLIT

| Identity | Writing path | Docs | Newest |
|---|---|---|---|
| `ep_1989031c8c1d0085812f` (`edr_endpoints.endpoint_id`, `edr_raw_events.source`, canonical `host.host_id`) | EDR sensor path `POST /api/edr/agent/telemetry` | 118,605 raw | raw ingest 17:45:20Z |
| `dev_2adbb41a04a4` (`v2_shadow_observations.event.device_iid`) | **the SAME fresh sensor stream, normalised** — `collector_id = connector_id = ep_1989031c8c1d0085812f`, adapter `nivxforge-linux-sensor/1.0.0` | 45,667 obs | captured 10:36:10Z |

My H1 suspicion was wrong and I am recording that plainly. `dev_2adbb41a04a4` is not a
collector-era orphan: it is the device identity the sensor stream normalises into, and
the two identities are linked by `collector_id`/`connector_id`. The `origin=collector-live`
label that made me suspect an old path is the adapter's own provenance tag, not a
different ingestion route. Fresh sensor data DOES reach the trajectory device.

## 2 · H2 CONFIRMED — THE CONSOLE VIEW IS A WINDOW ARTIFACT

Per-day observation counts for `dev_2adbb41a04a4` by `captured_at` (event time, UTC):

```
Sep 25 =    208
Sep 26 = 24,068
Sep 27 = 16,251
Sep 28 =  3,847
Sep 29 =    503
```

Fresh observations exist. The console URL
`/edr/device-trajectory?device=dev_2adbb41a04a4&event=evt_df9d1ced51b6cc9c%3B349092413`
pins that Sep-20 event, which fixes the detail window to
`2026-09-20T17:23:33Z → 17:53:33Z`. The upper histogram bars visible on Sep 27/28/29 in
the owner's screenshot were real, and the numbers above confirm them.

**No backend change is needed for this.** Clearing the pinned `event=` parameter, or
moving/widening the window to Sep 27–29, or selecting a recent event, surfaces the
fresh rows. The "45,666 / 45,666 observations" counter is the device total, not the
window content, which is why it looked like nothing was missing.

## 3 · SENSOR DELIVERY IS ACTIVE (measured on run `3bd64025`)

- `edr_raw_events` with `ingest_time > 17:14:29Z` = **228** new raw events; newest
  ingest **17:45:20.558821Z**.
- Newest raw doc: `source=ep_1989031c8c1d0085812f`, `source_kind=sensor`,
  `trust_state=AUTHENTICATED`, `received_from_ip=136.110.164.121`,
  `sensor_version=0.2.0-windows`, `computer=DESKTOP-A9HGFJJ`.
- Endpoint: `last_heartbeat_at=17:39:39Z`, `last_telemetry_at=17:40:33Z`,
  `event_count=118,613`, `sensor_state=REPORTING`, `lifecycle_reported=CONNECTED`.
- Agent routes: **200 × 39, 401 × 1**. The single 401 on `/api/edr/agent/telemetry`
  (17:45:10) was immediately followed by `POST /api/edr/agent/session` 200 and
  telemetry resumed 200 — a normal session-expiry → re-auth cycle, not a fault.
- `outbox_queue_depth` **6,468 → 6,870 (GREW)**. Noted honestly: the endpoint is
  currently generating events slightly faster than the spool drains. Not a defect,
  but it means the frontier closes more slowly than a pure drain would.

## 4 · EID5: STILL NOT DELIVERED — AND I DISAGREE WITH ONE DIAGNOSE RECOMMENDATION

Measured: Sysmon `<EventID>5</EventID>` (provider `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}`)
= **0**, with Sysmon EventID 1 control = **212** (matcher valid). All 10 owner-proven
ProcessGuids: **0 occurrences** across raw / retained / canonical / shadow.

The diagnose recommended investigating "Sysmon EventID-5 collection/forwarding on host
DESKTOP-A9HGFJJ". **That recommendation is premature and I am not acting on it**, because
the measured replay frontier already explains the absence:

| Wall-clock | Frontier (`payload.observed_at` of newest ingested raw) | Lag |
|---|---|---|
| 2026-09-29 15:32Z (run d85f3698) | 07:32:08Z | ~8h00m |
| 2026-09-29 17:45Z (run 3bd64025) | **10:41:31Z** | ~7h04m |

The frontier advanced **3h09m of event-time in 2h13m of wall-clock** — it is moving
forward, chronologically, at roughly 1.4× real time. The owner-proven EID5 batch was
generated at **14:48–14:50Z**, which is still **~4h07m of event-time ahead of the
frontier**. Production has not yet replayed that far. Absence here is therefore the
expected consequence of chronological spool replay, and is NOT evidence of a Sysmon
collection gap on the endpoint — the owner already proved EID5 generation and
ProcessGuid pairing locally on the host.

*(Rough forward look, labelled an ESTIMATE and explicitly NOT a measurement: at the
observed ~1.4× rate, ~4h07m of remaining event-time corresponds to roughly ~3h of
wall-clock, assuming the generation rate does not rise further. The growing outbox
depth is the main thing that could stretch it. Nothing should be concluded from this
number; only the frontier measurement is evidence.)*

**Nothing on the endpoint, sensor, Sysmon config or outbox was touched, and nothing
should be**, until the frontier crosses 14:50Z and the arrival question can be asked
honestly.

## 5 · CANONICALISER COVERAGE FOR EID5 — ALREADY SATISFIED ON THIS RUN

The diagnose flagged, as a coverage note, that the parser logs
`WINDOWS_EVENT_ID_NOT_SUPPORTED` for some Windows families (e.g. winsec 5379) and asked
to confirm EID5 is in the canonicaliser's supported set.

Source-level answer for the build now live: run `3bd64025` was built from this
workspace, whose `backend/edr_plane/windows_eventlog.py` carries
`("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` (line 83) and the EID5 branch writing
`"exit_time": activity_time` with provenance `":UtcTime (EventID 5)"` (line 680) — the
code added in `91e561f6` and verified in the pre-deploy gate for `9ba45bce`. So the
gap that would have refused EID5 on the OLD Publish-99/100 builds is closed on the
runtime that is serving now. The winsec-5379 refusals are correct behaviour for a
family that genuinely is not in the supported set, and those records stay retained and
replayable.

This is a statement about the deployed COMMIT, not a runtime probe — the first genuine
EID5 to arrive will be the runtime proof.

## 6 · STATUS

```
B5_EID5_END_TO_END = WAITING_FOR_DELIVERY
```

Not PASS (no genuine EID5 has arrived). Not BLOCKED (no defect demonstrated anywhere:
sensor delivering, identities converged, canonicaliser now supports EID5, trajectory
projection healthy). The console "staleness" is closed as a window-selection artifact
with no code change.

STOP FOR OWNER REVIEW. NO REMEDIATION PERFORMED.
