# B5 — PRODUCTION EID5 BLOCKER RESOLUTION (READ-ONLY)

2026-09-29. Production diagnose COMPLETE. No preview evidence used anywhere in this document.
Nothing deployed, patched, restarted, reconfigured, or written. No endpoint or sensor change.

## REQUIRED STATUS LINES

```
PROD_DIAGNOSE                 = COMPLETE
PRODUCTION_RUNTIME            = identified
PRODUCTION_DATABASE_TYPE      = external / Emergent-managed MongoDB (Atlas), NOT in-pod mongod
PRODUCTION_DATABASE_NAME      = greeting-app-5782-test_database
PRODUCTION_TELEMETRY_STORE    = identified (edr_raw_events in greeting-app-5782-test_database)
DESKTOP-A9HGFJJ_PROD_RECEIVE  = PROVEN
EID5_PROD_RECEIVE             = NOT_YET_OBSERVED
EID5_DSM_PARSE                = NOT_YET_OBSERVED
EID5_CANONICAL_PROCESS_EXIT   = NOT_YET_OBSERVED
EID5_PROCESSGUID_BINDING      = NOT_YET_OBSERVED
EID5_LIFECYCLE_TERMINATION    = NOT_YET_OBSERVED
EID5_IDENTIFIER_AUTHORITY     = NOT_YET_OBSERVED

B5_EID5_END_TO_END = WAITING_FOR_DELIVERY
```

CASE B. No post-receive defect is demonstrated, because nothing has reached post-receive yet.

## STEP 1 — EXISTING DIAGNOSE JOB

Deployer job `95e7e8cd-6528-4f50-8702-566d0dc3b0ce` has **COMPLETED**. Full production RCA written by the deployer at `/app/deployer-agent-docs/RCA_d85f3698-86ec-4f79-ac6a-e1309f96cd13.MD`. No additional diagnose jobs were created.

## STEP 2 — AUTHORITATIVE PRODUCTION STORE (measured against: prod deployment + prod run d85f3698)

| Item | Value |
|---|---|
| deployment | `96834a37-643a-4d79-aa15-44810db52b06` · `greeting-app-5782` · active · tier_3 (Scale) |
| **active run** | **`d85f3698-86ec-4f79-ac6a-e1309f96cd13`** · type redeploy · trigger user_deploy · **completed 2026-09-27T09:52:56Z** |
| image | `.../customers-app/greeting-app-5782:d85f3698-...` · amd64 · target_cluster target-6 · namespace customers-app |
| runtime health | 1 of 2 replicas Running/ready, restart_count 0. 2nd pod Pending, `FailedCreatePodSandBox` ×~14,360 ("no IP addresses available in range 10.55.38.1-10.55.39.254") since 2026-09-27T09:53 — Emergent-side cluster IP exhaustion, not telemetry loss |
| live URLs | `https://greeting-app-5782.emergent.host` · custom `https://nivxray.nivxforge.com` (verified) |
| DB type | external / Emergent-managed MongoDB (Atlas), resolved server-side |
| DB name | `greeting-app-5782-test_database` (94 collections) |
| secret bindings | `MONGO_URL` PRESENT non-empty · `DB_NAME` PRESENT non-empty (57 secrets, all non-empty). **No values read or printed.** |
| ingest route → store | `POST /api/edr/agent/telemetry` → collection **`edr_raw_events`** (bearer_session auth, `source_kind: "sensor"`, `sensor_version 0.2.0-windows`). Established from prod RUNTIME, not from source. |
| legacy route caution | the 44,282 `xdr_canonical_evidence` / 5 `xdr_canonical_events` docs trace to the OLDER connector route `POST /api/xdr/ingest/telemetry` (`nivx-sysmon-forwarder/1.0@DESKTOP-A9HGFJJ`), mostly 2026-09-18. Not the current sensor path; not conflated below. |

## STEP 3 — GENUINE WINDOWS TELEMETRY IN PRODUCTION (measured against: prod store `greeting-app-5782-test_database`)

Receive is **PROVEN and live**:
- `edr_endpoints`: host `DESKTOP-A9HGFJJ`, `endpoint_id ep_1989031c8c1d0085812f`, tenant `ten_e759b7288598bd882e3dcac49d`, enrollment ENROLLED, sensor_state REPORTING, event_count 116,025, **outbox_queue_depth 7,181**, `last_telemetry_at 2026-09-29T15:28:33Z`
- `edr_raw_events`: **116,012** docs · newest `ingest_time` 2026-09-29T15:32:31Z
- prod backend log: `POST /api/edr/agent/telemetry` **continuously, one every 1–3 s, status 200 on every call**, latency ~700–3200 ms, newest request 2026-09-29T15:33:23Z. **No 401 / 403 / 413 / 429 / 5xx.**

EID5 is **absent, and the absence is explained**:
- Sysmon provider GUID `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` immediately followed by `<EventID>5</EventID>`: **0**
- **Control**: same pattern with `<EventID>1</EventID>` (ProcessCreate): **210** → the matcher is valid; 0 is real, not a regex miss
- (a naive `<EventID>5</EventID>` matched 227 — those are `Microsoft-Windows-IsolatedUserMode` / winsec, NOT Sysmon ProcessTerminate)
- canonical `event_type` in {`process_exit`, `ACTIVITY_PROCESS_TERMINATION`}: **0**
- exact-value lookup of all 10 authoritative ProcessGuids: **0 of 10** in `edr_raw_events` (payload exact substring) and **0 of 10** in `xdr_canonical_evidence` (`process.process_guid`). No PID/time/name/hostname heuristics used.

**Why: the replay frontier.** The newest-ingested prod raw records carry `payload.observed_at ≈ 2026-09-29T07:32:08Z` (event TimeCreated 07:30:33Z). Production is replaying the sensor spool **chronologically, ~7 h behind wall-clock**. The proven 14:48–14:50Z EID5 batch and its 10 GUIDs are still inside the undelivered backlog (`outbox_queue_depth 7,181`). Corroborating: the GUIDs' `-6abb-` boot-epoch segment is later than the currently-ingested `-6ab8-` / `-6aaa-` segments. **This is not loss.**

## STEP 4/5 — CHAIN AND IDENTIFIER AUTHORITY

NOT_YET_OBSERVED. No genuine EID5 exists in the production store, so no chain and no identifier authority can be proven. Nothing was substituted, reconstructed, or inferred. All existing EID1 processes for the host correctly remain `PROCESS_LIFETIME_UNKNOWN`.

## STEP 6 — CLASSIFICATION: CASE B, WITH A NAMED FORWARD BLOCKER

Classification is **CASE B (WAITING_FOR_DELIVERY)**. No patch is justified by B5 being incomplete.

However, the diagnose surfaced a forward risk (RCA §87), and I resolved it in source. It is now a **demonstrated version gap**, not a hypothesis:

| Evidence | Finding |
|---|---|
| Production active run built from code as of | **2026-09-27T09:52:56Z** (last commit at/before that point: `fdb9c05a`, 2026-09-27T09:37:46Z) |
| `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` admitted to the `SUPPORTED` map in `backend/edr_plane/windows_eventlog.py` | commit **`91e561f6`, 2026-09-29T11:44:25Z** — `git log -S` shows exactly one commit introducing it |
| `git show 91e561f6^:backend/edr_plane/windows_eventlog.py` grep for `"sysmon", 5` / `ACTIVITY_PROCESS_TERMINATION` | **no matches** → the predecessor revision does NOT support Sysmon EID5 |
| `backend/edr_plane/process_identity.py` (`TERMINATION_KINDS`, lifecycle projection) | first commit `e66abc8f`, 2026-09-29T10:39:24Z |
| `backend/edr_plane/canonical_bridge.py`, `delivery_counters.py`, `file_content_acquisition.py` | first commit `6afab68a`, 2026-09-29T12:48:37Z |
| Independent runtime corroboration | the prod store's `edr_delivery_counters` collection is **ABSENT** — the counters module is part of the 09-29 closure wave, so its absence is exactly what a pre-closure-wave production build looks like |
| Independent runtime corroboration | prod `derivations.parser_state` = OK 44,329 / **FAILED 71,744**, with notes `WINDOWS_EVENT_ID_NOT_SUPPORTED`, `WINDOWS_PROVIDER_NOT_SUPPORTED`, `WINDOWS_EVENT_XML_MALFORMED` — `WINDOWS_EVENT_ID_NOT_SUPPORTED` is precisely the refusal the pre-`91e561f6` `SUPPORTED` map emits for an unadmitted event id |

**Consequence, stated plainly:** the production build serving `nivxray.nivxforge.com` is 2 days older than the EID5 support. When the replay frontier reaches 14:48Z, the genuine EID5 records will be **refused as `WINDOWS_EVENT_ID_NOT_SUPPORTED`** by the deployed parser. `B5_EID5_END_TO_END = PASS` is therefore **not achievable on the current production build**, no matter how long the backlog drains.

This is NOT reported as CASE C, because CASE C requires EID5 to have reached production receive and failed there. It has not arrived. The correct status remains WAITING_FOR_DELIVERY, with this gap named.

**No evidence will be lost by the refusal.** Production retains raw bytes and marks them replayable (RCA §79), so once the correct build is live the refused EID5 records can be replayed into canonical evidence through the normal path.

## STEP 7 — FIX POLICY

**No fix is needed and none was written.** The corrected code already exists in the workspace and is the code the owner accepted in the Wave-B / Closure-Wave reviews:
- `backend/edr_plane/windows_eventlog.py` admits `("sysmon", 5) → ACTIVITY_PROCESS_TERMINATION`, and its EID5 branch records `UtcTime` as **`exit_time`** with provenance `"...:UtcTime (EventID 5)"`, **never** as `start_time`. It also declares `not_observed` for `CommandLine`, `Hashes`, `ParentProcessGuid`, `ParentImage`, `process.start_time`, and marks `process.exit_code` / `command_line` / `hashes` / `parent_process_guid` as NOT_SUPPORTED for that class.
- Workspace regression suites re-run read-only now: `tests/edr/test_b5_process_termination.py` + `tests/edr/test_b2_process_identity.py` → **38 passed**.

The gap is purely **deployment currency**, not source correctness. Closing it requires a production deploy, which is **yours to authorise** — I have not deployed and will not without explicit approval.

## BOUNDARY TABLE

| Boundary | Production Evidence (store: `greeting-app-5782-test_database`, run `d85f3698`) | Status | Action Required |
|---|---|---|---|
| Endpoint EID5 generation | owner endpoint proof, 14:48–14:50Z Sep 29 | PROVEN | none |
| Sensor destination | `--backend https://nivxray.nivxforge.com` | CONFIRMED | none |
| Sensor delivery | prod `POST /api/edr/agent/telemetry` 200 OK every 1–3 s to 15:33:23Z | PROVEN / ADVANCING | none |
| Prod receive (host) | `edr_endpoints` REPORTING, 116,012 raw events, `last_telemetry_at 15:28:33Z` | **PROVEN** | none |
| Replay frontier | newest ingested `payload.observed_at ≈ 07:32:08Z`, queue depth 7,181 | ~7 h BEHIND | wait for chronological drain |
| Prod acceptance counters | `edr_delivery_counters` collection **ABSENT** (not zeros) | NOT_MEASURABLE | counters module not in prod build |
| EID5 prod receive | Sysmon+EID5 = 0 (control EID1 = 210) | NOT_YET_OBSERVED | wait for frontier > 14:50Z |
| ProcessGuid presence | 0 of 10, exact-value lookup | NOT_YET_OBSERVED | wait |
| DSM / parser for EID5 | prod build predates `("sysmon", 5)` admission (`91e561f6` 09-29T11:44 vs build 09-27T09:52); prod already emits `WINDOWS_EVENT_ID_NOT_SUPPORTED` at 71,744/116k | **WILL REFUSE ON CURRENT BUILD** | owner-approved deploy of current workspace build, then replay retained raw |
| Canonical `process_exit` | 0 | NOT_YET_OBSERVED | follows the deploy |
| ProcessGuid binding / lifecycle | 0; all EID1 remain `PROCESS_LIFETIME_UNKNOWN` | NOT_YET_OBSERVED | follows the deploy |
| Identifier authority | no new EID5 to evaluate | NOT_YET_OBSERVED | re-verify after delivery |
| Platform: 2nd replica | Pending, `FailedCreatePodSandBox`, no IPs in 10.55.38.1-10.55.39.254 since 09-27 | DEGRADED (1/2) | Emergent-side cluster IP capacity; slows drain, causes no loss |

## WHAT I DID NOT DO

No deploy · no redeploy · no prod restart · no env/secret change (presence only, no values printed) · no Mongo write · no routing/Cloudflare change · no endpoint change · no Sysmon change · no sensor restart/re-enrol/URL change · no `outbox.jsonl` / `outbox.offset` touch · no synthetic telemetry · no historical reconstruction · no preview evidence · no UI work · no E3.

STOP FOR OWNER REVIEW.
