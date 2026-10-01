# B5 — EID5 DELIVERY RECHECK (READ-ONLY)

Recheck executed: 2026-09-29 (backend read-only queries only)
Environment read: this preview backend, `REACT_APP_BACKEND_URL = https://greeting-app-5782.preview.emergentagent.com`, DB `test_database`
No patch, no deploy, no endpoint change, no sensor restart, no synthetic telemetry, no UI change, no E3.

## RECHECK 1 — BACKEND ARRIVAL (MEASURED)

| Probe | Store | Result |
|---|---|---|
| Sysmon `EventID 5` in raw XML | `xdr_canonical_events.raw.xml` | 0 |
| `normalized.event_id = "5"` | `xdr_canonical_events` | 0 |
| `ProcessTerminate` | `xdr_canonical_events.raw.xml` | 0 |
| `process_exit` / `ACTIVITY_PROCESS_TERMINATION` as event_type | `xdr_canonical_evidence` | 0 (event_type not present in distinct set) |
| Windows sensor envelope (EDR agent path) | `edr_raw_events` | 0 (`source_kind` distinct = `sensor` only, all from `ep_2d57cbe6f80152062109`, Linux sensor) |
| `WINDOWS_EVENT_LOG` envelope literal | `edr_raw_events.payload` | 0 |
| `DESKTOP-A9HGFJJ` in `edr_endpoints` | `edr_endpoints` | 0 (host not enrolled in this environment) |
| `DESKTOP-A9HGFJJ` string in `edr_raw_events` | 7 hits | all 7 are the LOCAL LINUX sensor observing our own `grep`/`curl`/`python3` command lines — NOT Windows telemetry |

Newest Windows telemetry visible in this environment (authoritative):

- connector: `windows-eventlog-g1proof01`, collector `col_d6b0b9e8172246f29be9`, tenant `ten_f1a5479243e901cf159e230fa0`
- store: `xdr_canonical_events` (3,299 docs for `DESKTOP-A9HGFJJ`)
- newest `ingested_at` = **2026-09-25T15:35:33.289519Z**
- newest activity time (`EventData.UtcTime`) = **2026-09-22 16:20:09.742**
- newest event = Sysmon **EID 12** (RegistryEvent)
- EventID distribution for `DESKTOP-A9HGFJJ`: `13`:2335, `12`:766, `11`:107, `3`:70, `1`:16, `4624`:2, `4672`:2, `22`:1, **`5`:0**
- newest canonical evidence by `source_product`: `Sysmon` = ingested 2026-09-29T08:35:24Z but event_time 2026-09-22 16:20:04.800 (no new activity), `WindowsSensor` = ingested 2026-09-26T17:07:39Z with synthetic event_time 2026-06-01, `LinuxSensor` = live (2026-09-29T15:15Z)

Known authoritative ProcessGuid lookup (exact full-value match, no PID/time/name heuristics):

| ProcessGuid | canonical_events | canonical_evidence | raw_events |
|---|---|---|---|
| {9949e5f2-d018-6abb-981c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cffb-6abb-971c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cff0-6abb-961c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfc8-6abb-951c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfbe-6abb-941c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfb6-6abb-901c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfb6-6abb-911c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfb6-6abb-931c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfb6-6abb-8f1c-000000002100} | 0 | 0 | 0 |
| {9949e5f2-cfb6-6abb-921c-000000002100} | 0 | 0 | 0 |

**0 / 10 present.** The GUID sequence suffix `-000000002100` (the current Sysmon session) appears **0** times anywhere.
The 3,295 docs containing the `9949e5f2` prefix are the same machine GUID but the OLD session suffix `-000000002000` (2026-09-22 window), e.g. EID1 `{9949e5f2-aab9-6ab2-ad1e-000000002000}` `taskhostw.exe` at 2026-09-22 16:20:09.739.

So the previous snapshot has **not** changed: 0 WINDOWS_EVENT_LOG envelopes, 0 process_exit, 0/10 ProcessGuids.

## RECHECK 2 — DELIVERY COUNTERS (MEASURED)

`edr_delivery_counters` distinct tenants = `["default"]` only.
Counter documents for tenant `ten_f1a5479243e901cf159e230fa0` (the Windows tenant) = **0**.
Counter documents for any endpoint resolving to `DESKTOP-A9HGFJJ` = **0**.

Measured counters that DO exist (Linux sensor `ep_2d57cbe6f80152062109`, tenant `default`, `evidence_authority: false`):

| channel | received | accepted | deduplicated | parse_failed | canonicalized | last_recorded_at |
|---|---|---|---|---|---|---|
| SENSOR_NETWORK | 991 | 990 | 1 | – | 990 | 2026-09-29T15:14:02Z |
| SENSOR_PROCESS | 101 | 101 | – | – | 101 | 2026-09-29T15:13:47Z |
| UNPARSEABLE_ENVELOPE (ep_2b8835e76cd2a11e667b) | 1 | 1 | – | 1 | – | 2026-09-29T12:38:10Z |
| UNPARSEABLE_ENVELOPE (ep_3f8c266379484f8598e3) | 1 | 1 | – | 1 | – | 2026-09-29T12:44:49Z |

For the Windows endpoint/tenant, stated exactly:

- `received / accepted / refused / deduplicated / parse_failed / canonicalized` = **NO COUNTER DOCUMENT EXISTS for this endpoint or tenant in this environment** (not zero-valued counters — the counter record has never been created here).
- `NOT_MEASURABLE_SENSOR_COUNTERS_NOT_REPORTED` (sensor-side per-event counters remain unavailable).

No loss is inferred.

## MEASURED ENVIRONMENT FACT (not a conclusion about loss)

- Owner-confirmed sensor destination: `https://nivxray.nivxforge.com`
- Backend environment read by this recheck: `https://greeting-app-5782.preview.emergentagent.com`

These are different hostnames. This recheck can only read the store bound to this preview environment. Whether the two hostnames resolve to the same backing store is not measurable from inside this pod; it is therefore reported as a fact, not as loss, and nothing was changed.

## RECHECK 3 — EID5 CHAIN

NOT_YET_OBSERVED. No genuine EID5 record exists in this environment, so no chain (tenant / endpoint / source / event_id / ProcessGuid / exit timestamp / canonical observation / provenance / process_key) can be proven. `EID5 UtcTime -> exit_time` is unproven and was NOT substituted.

## RECHECK 4 — PROCESSGUID LIFECYCLE

NOT_YET_OBSERVED. The 16 genuine EID1 records for `DESKTOP-A9HGFJJ` (session `-000000002000`, 2026-09-22) have no matching EID5 in this environment.

Lifecycle result for every one of them, unchanged and not backfilled: `PROCESS_LIFETIME_UNKNOWN`.

No PID/time/name inference performed.

## RECHECK 5 — IDENTIFIER AUTHORITY

- No new EID5 records → no new identifier minting to evaluate → `NOT_YET_OBSERVED`.
- Regression check on the newest 200 `xdr_canonical_evidence` documents: `_pl`-suffixed identifier authority occurrences = **0** (Closure Wave holds; no new divergence).
- No identifier divergence detected; nothing repaired.

## DECISION TABLE

| Boundary | Previous | Current | Evidence |
|---|---|---|---|
| Endpoint EID5 generation | PROVEN | PROVEN (owner) | owner endpoint proof, unchanged |
| Sensor destination | unknown/suspected fork URL | CONFIRMED (owner) | owner read-only service/config check |
| Sensor backlog | unknown | PROVEN (owner) | outbox.jsonl 238,920,951 / offset 223,890,166 |
| Sensor delivery progress | unknown | ADVANCING (owner) | +103,109 bytes offset over 120 s, outbox growth 0 |
| Backend receive | 0 envelopes | **0 envelopes** | 0 Windows sensor envelopes in `edr_raw_events`; newest Windows record ingested 2026-09-25T15:35:33Z (EID 12) |
| Backend acceptance | no counters | **no counter document for Windows tenant/endpoint** | `edr_delivery_counters` tenants = ["default"] |
| DSM / parser | not exercised for EID5 | not exercised | 0 EID5 reached parser |
| Canonical process_exit | 0 | **0** | `xdr_canonical_evidence` event_type set has no process_exit / PROCESS_TERMINATION |
| ProcessGuid binding | 0/10 | **0/10** | exact full-GUID lookup, suffix `-000000002100` absent entirely |
| Lifecycle termination | PROCESS_LIFETIME_UNKNOWN | PROCESS_LIFETIME_UNKNOWN | 16 EID1, 0 paired EID5 |
| Identifier authority | PASS (no `_pl`) | no new EID5 to evaluate; 0 `_pl` in newest 200 evidence docs | regression probe |

## STATUS

```
EID5_ENDPOINT_GENERATION     = PROVEN
EID5_SENSOR_DESTINATION      = CONFIRMED
EID5_SENSOR_BACKLOG          = PROVEN
EID5_SENSOR_DELIVERY         = ADVANCING
EID5_BACKEND_RECEIVE         = NOT_YET_OBSERVED
EID5_CANONICAL_PROCESS_EXIT  = NOT_YET_OBSERVED
EID5_PROCESSGUID_BINDING     = NOT_YET_OBSERVED
EID5_LIFECYCLE_TERMINATION   = NOT_YET_OBSERVED
EID5_IDENTIFIER_AUTHORITY    = NOT_YET_OBSERVED

B5_EID5_END_TO_END = WAITING_FOR_DELIVERY
```

Normal backlog latency is NOT classified as loss.

## OWNER ANSWERS

1. Newest Windows event currently visible: Sysmon **EID 12**, `EventRecordID 3312734`, activity time `2026-09-22 16:20:09.742`, ingested `2026-09-25T15:35:33.289519Z`, connector `windows-eventlog-g1proof01`, host `DESKTOP-A9HGFJJ`.
2. Windows EDR-agent envelope arrived: **NO** — zero Windows sensor envelopes exist in `edr_raw_events` in this environment (only the Linux sensor is delivering, last at 2026-09-29T15:14:43Z).
3. Known EID5 ProcessGuids present: **NO — 0 / 10**; the entire `-000000002100` session suffix is absent.
4. Exact downstream boundary remaining pending: **BACKEND RECEIVE** (the sensor-ingest arrival boundary for the Windows endpoint in this environment). Everything after it — acceptance counters, DSM/parser, canonicalization to `process_exit`, ProcessGuid binding, lifecycle termination, identifier authority — is untouched and unevaluated because nothing has crossed the receive boundary.

STOP FOR OWNER REVIEW.
