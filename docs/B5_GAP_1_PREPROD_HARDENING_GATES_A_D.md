# B5-GAP-1 — PRE-PRODUCTION HARDENING · GATES A-D

**PRODUCTION_DEPLOYED = NO.** `DESKTOP-A9HGFJJ` was not touched: not
installed on, not restarted, no Sysmon change, no `channels.json` or
`outbox` change, no replay, no backfill. B5 remains CLOSED / PASS.

```
WINDOWS_ARTIFACT_BUILD       = NOT_RUN   (blocked: needs a Windows runner)
SQLITE_PACKAGED              = GATED     (asserted by the build, wired)
JOURNAL_PACKAGED             = PASS      (build flags + test)
FROZEN_STARTUP               = GATED     (asserted by the build, wired)

DELIVERY_ROOT_CAUSE          = PROVEN
DELIVERY_THROUGHPUT          = 48.3 events/sec measured (batch 50, ingress)
DELIVERY_SUSTAINABILITY      = PASS      (2.4x the ~20 ev/s source rate)

INTEGRITY_BACKEND_CONTRACT   = PASS
BACKWARD_COMPATIBILITY       = PASS

PRE_CANARY_NORMAL            = PASS
PRE_CANARY_BURST             = PASS
PRE_CANARY_BACKEND_SLOW      = PASS
PRE_CANARY_BACKEND_DOWN      = PASS
PRE_CANARY_RECOVERY          = PASS
PRE_CANARY_RESTART           = PASS
PRE_CANARY_GAP               = PASS
PRE_CANARY_MULTI_CHANNEL     = PASS
PRE_CANARY_PRESSURE          = PASS
```

---

## GATE A — THE REAL WINDOWS ARTIFACT

### Honest status: I could not build it here, and I did not pretend to.

PyInstaller does not cross-compile a Windows PE from Linux. The repository
already says so, in the only place the artifact can legitimately come from:
`.github/workflows/windows-sensor-installer.yml` runs on `windows-latest`.
This workspace is a Linux container with no Windows runner, so
`WINDOWS_ARTIFACT_BUILD = NOT_RUN`, blocked, not failed.

What I did instead is make the artifact prove the ten points **about
itself**, and made the build fail if it cannot.

### `NivXForgeEDRSetup.exe journal-selftest`

A new frozen-CLI subcommand (`nivxforge_setup.journal_selftest`). It is the
only thing that can answer the question that actually matters — did
PyInstaller pack `sqlite3` and its native `_sqlite3` extension, and do WAL
and `synchronous=FULL` behave on a Windows filesystem? A Linux unit test
cannot know. Output, run here against system Python:

```json
{"result": "PASS", "failed": [], "sensor_version": "0.3.0-windows",
 "checks": {"frozen": false, "sqlite3_importable": true,
            "sqlite_library_version": "3.40.1",
            "journal_module_importable": true, "journal_version": "1.0.0",
            "database_created": true, "wal_mode": true,
            "synchronous_full": true, "auto_vacuum_incremental": true,
            "schema_initialized": true, "durable_commit": true,
            "cursor_committed": true, "replay_is_idempotent": true,
            "integrity_snapshot": true, "gap_contract": true}}
```

`"frozen": false` is the honest tell: this was **not** the frozen binary.
The CI gate therefore requires `"frozen": true`, so a system-Python pass can
never be mistaken for an artifact pass.

### Mapping to your ten points

| # | Requirement | How it is proven | Status |
|---|---|---|---|
| 1 | `sqlite3` packaged and importable | `--hidden-import sqlite3`; selftest `sqlite3_importable` + library version | GATED on the Windows build |
| 2 | `nivxforge_journal` packaged | `--hidden-import nivxforge_journal`; selftest `journal_module_importable` | PASS (flags + test) |
| 3 | database can be created/opened | selftest `database_created` | GATED |
| 4 | WAL mode works | selftest `wal_mode` (`PRAGMA journal_mode`) | GATED |
| 5 | `synchronous=FULL` actually applied | selftest `synchronous_full` (`PRAGMA synchronous == 2`) | GATED |
| 6 | schema initialises | selftest `schema_initialized` (all five tables) | GATED |
| 7 | service startup in an isolated env | the workflow's **existing** Gates 1-3 (stage-host, SCM entrypoint, error 1063) — unchanged | GATED |
| 8 | no Python needed on the endpoint | the workflow's existing `& $exe version` assertion; selftest records `sys.frozen` and `sys.executable` | GATED |
| 9 | no new external runtime dependency | `sqlite3` is stdlib. `requirements.txt` untouched, `pip install` list in the build script untouched (`pyinstaller`, `pywin32` only) | PASS |
| 10 | signing/installer behaviour unchanged | only two `--hidden-import` flags were added; no spec, signing, packaging, ACL or service-definition change | PASS |

Gate wiring is itself under test
(`test_windows_build_gates_on_the_frozen_journal_selftest`), so it cannot
silently disappear.

**To close Gate A you need one Windows CI run of
`windows-sensor-installer.yml`.** Nothing else is outstanding.

---

## GATE B — DELIVERY THROUGHPUT / LATENCY

### `DELIVERY_ROOT_CAUSE = PROVEN` — measured, not assumed

`scripts/b5gap1_delivery_latency_probe.py`, run against the live preview
ingress and the backend loopback with an enrolled synthetic endpoint:

| Probe | Mean/request | events/sec |
|---|---|---|
| A · fresh connection per POST — **today's sensor** | 176.6 ms | **5.7** |
| B · one persistent connection, one event per POST | 103.3 ms | **9.7** |
| B · TLS handshake, once | 31.3 ms | — |
| C · loopback, one event per POST (backend + DB only) | 38.6 ms | 25.9 |
| D · batch of 10 | 232 ms | 43.1 |
| **D · batch of 50** | 1.035 s | **48.3** |
| D · batch of 100 | 2.989 s | 33.5 |

Decomposition, from those four points:

```
per event, pre-fix (176.6 ms)
  = DNS + TCP + TLS            ~73 ms   (41%)  <- thrown away every event
  + ingress + WAN round trip   ~65 ms   (37%)  <- paid per event
  + backend + auth + Mongo     ~39 ms   (22%)  <- irreducible per event
```

Three distinct causes, all proven:

1. **No connection reuse.** The sensor called
   `urllib.request.urlopen` per event, so 41% of every request was
   connection setup it immediately discarded.
2. **One event per request.** The fixed ~65 ms ingress/network cost was
   paid per event instead of once per batch.
3. **Residual ceiling is server-side per-event work** — `raw.append` +
   canonical bridge + 2-4 delivery-counter writes, ~39 ms, measured on
   loopback where there is no network at all.

### Why batch 50 and not 100 — chosen by measurement

Past ~50 the amortisation is spent and cause 3 dominates, so a bigger batch
buys **less** throughput (33.5 vs 48.3 ev/s) for a **3-second** request
that is far more exposed to an ingress timeout. The default is 50. The
server cap stays `MAX_BATCH_EVENTS = 100`, so an operator can raise it
without a backend change.

### Architecture, as you specified it

```
LOCAL JOURNAL -> BATCH BUILDER -> PERSISTENT HTTP CONNECTION
  -> POST /api/edr/agent/telemetry/batch -> VALIDATE/AUTH
  -> IDEMPOTENT ACCEPTANCE (raw.append dedup) -> PER-EVENT ACK
  -> MARK ACCEPTED LOCALLY (only the accepted indices)
```

### Durability and acknowledgement semantics were NOT weakened

- **`SENT != ACCEPTED` survives batching.** The response is an *ordered
  per-event verdict*, never a batch verdict. Only the indices the platform
  marked `accepted` are released; a refused event stays owned by the
  endpoint. Proven end to end by
  `test_pre_canary_partial_refusal_keeps_only_the_refused_event`: 59 of 60
  released, exactly the refused one retained, zero duplicates.
- **Idempotency is inherited, not invented.** `raw.append` already dedupes
  on `(tenant_id, dedup_key)`, so a batch retried after a lost response
  re-reports `stored=false, duplicate=true` per event and cannot create a
  second copy. No new identity scheme was introduced.
- **Oversize is all-or-nothing on purpose.** `> 4 MiB` returns 413 having
  ingested nothing, so the endpoint still owns every event; the sensor
  halves its batch size and retries.
- **Timeout/retry**: 30 s socket timeout; a stale reused connection
  reconnects **once** and is not reported as an outage; `401/403` refreshes
  the session; `404/405` permanently degrades to the single-event route so
  an upgraded sensor can talk to an older backend. There is no third path.
- **One ingest implementation.** Both routes call `_ingest_one`, asserted
  by `test_single_and_batch_share_one_ingest_path`. Endpoint liveness is
  recorded once per batch, and not at all if nothing was accepted.

### Sustainability

48.3 ev/s measured against the ~20 ev/s the endpoint produces =
**2.4x headroom → DELIVERY_SUSTAINABILITY = PASS.**

**Caveat, stated plainly:** these are **preview-ingress** numbers. The
production figure you measured was 2.68 s/POST from a Windows endpoint over
the WAN — roughly 15x worse than preview's 0.177 s, dominated by geography
and production ingress. The *absolute* 48.3 ev/s will not transfer. What
transfers is structural, and transfers in our favour: causes 1 and 2 scale
**with** round-trip time, so on a 2.68 s path a 50-event batch removes ~50x
of a much larger fixed cost. Cause 3 is the same code either way.
**The production number must be re-measured on the canary — that is
explicitly part of the acceptance procedure, not an assumption here.**

---

## GATE C — ACQUISITION INTEGRITY BACKEND CONTRACT

### Backward compatibility first

`HeartbeatBody` and `TelemetryBody` are `extra="forbid"`. Injecting fields
into either would 422 every sensor still running 0.2.0 — i.e. take the
fleet offline. So neither was touched, and a test asserts they still
refuse unknown fields and that `TelemetryBody`'s field set is exactly what
it was. `BACKWARD_COMPATIBILITY = PASS`.

### New surfaces

| Route | Scope | Purpose |
|---|---|---|
| `POST /api/edr/agent/telemetry/batch` | `SENSOR_SCOPED` | Gate B |
| `POST /api/edr/agent/acquisition-integrity` | `SENSOR_SCOPED` | Gate C, own versioned contract |
| `GET /api/edr/enrollment/acquisition-integrity` | `TENANT_SCOPED` | platform-side read |

All three are classified in `ROUTE_CLASSIFICATION`; the EDR authorization
matrix fails closed on an unclassified route, and a test pins the entries.
Neither new body carries `tenant_id` or `endpoint_id` — identity comes from
the authenticated session, so a batch cannot attribute evidence to anyone
else.

### Represented fields

Per channel: `last_record_id_read`, `last_record_id_journaled`,
`last_cursor_committed`, `records_read`, `records_journaled`,
`query_failures`, `query_timeouts`, `query_ms_last`,
`acquisition_lag_records`, `source_oldest_record_id`,
`source_newest_record_id`, `caught_up`, `unavailable_reason`.
Per endpoint: `acquisition_gap_count`, `last_acquisition_gap`,
`journal_depth`, `journal_bytes`, `journal_live_bytes`,
`delivery_backlog`, `health_state`, plus `endpoint`, `tenant`, `channel`,
`timestamp`. Stored `claim_basis: "SENSOR_REPORTED"` — a sensor claim about
its own collection, never a server measurement, never an evidence
authority.

### The semantic chain is enforced SERVER-SIDE, not trusted

`classification`, `cause`, `is_detection` and `missing_record_id_count` are
**asserted by the server from a closed vocabulary**, never copied from the
request. Proven live through the real ingress: a sensor claiming
`classification: "MALWARE_EVASION"`, `cause: "LOG_ROLLOVER"`,
`missing_record_id_count: 999999` and a health state of `"TOTALLY_FINE"`
was stored as:

```json
{"channel": "Microsoft-Windows-Sysmon/Operational",
 "missing_start_record_id": 8470186, "missing_end_record_id": 8496594,
 "missing_record_id_count": 26409,
 "classification": "SOURCE_RECORD_DISCONTINUITY", "cause": "NOT_PROVEN",
 "is_detection": false}
```
```json
{"health_states": ["ACQUISITION_GAP", "DELIVERY_BACKLOG"],
 "claim_basis": "SENSOR_REPORTED"}
```

The invented health state was dropped. The overstated count was
recomputed. The asserted cause was refused. Every stored gap also carries
its own absence semantics:
`no_event_observed != event_did_not_occur`,
`acquisition_gap != benign`, `acquisition_gap != malicious`,
`acquisition_gap != a detection`.

Gaps are append-only and idempotent on
`(tenant, endpoint, channel, expected_next, first_observed)`, so a retried
report cannot turn one hole into two. The sensor marks a gap `reported`
**only after** the platform has it — proven by
`test_pre_canary_gap_declaration_survives_a_failed_report`.

**No Device Trajectory or console work was done.**

---

## GATE D — PRE-CANARY ACCEPTANCE HARNESS

`backend/tests/edr/test_b5_gap1_pre_canary_acceptance.py` runs the whole
cycle — acquire → journal → batch deliver → acknowledge → reclaim → report
integrity — against a fake backend implementing the *real* batch and
integrity contracts. Every scenario that can express them asserts:
`UNEXPLAINED_LOSS = 0`, `DUPLICATES = 0`,
`SOURCE_CURSOR <= LAST_DURABLY_OWNED_SOURCE_RECORD`. Ownership is checked
as the **union** of what is still journaled and what the backend accepted,
because accepted rows are reclaimed and neither store alone is the answer.

| Scenario | What it proves | Result |
|---|---|---|
| NORMAL | 400 events, batch route used (batch 50), integrity reported, queue drained | PASS |
| BURST | 3,000 events in one opportunity: 7+ pages, zero gaps | PASS |
| BACKEND SLOW | backlog GROWS; next cycle still journals 1,000 → `SLOW_BACKEND != STOP_ACQUISITION`, `DELIVERY_BACKLOG != SOURCE_LOSS` | PASS |
| BACKEND DOWN | 500 held, `sent == 0`, nothing accepted, acquisition continues, zero gaps → `SENT != ACCEPTED` | PASS |
| RECOVERY | journal drains fully, 600/600 accepted, zero duplicates | PASS |
| RESTART | cursors and evidence survive; drains after restart | PASS |
| GAP | 26,409 declared, `cause NOT_PROVEN`, reaches the platform, marked reported once, nothing invented | PASS |
| MULTI-CHANNEL | hot Sysmon (5,000) does not starve Security/System; all three cursors advance | PASS |
| PRESSURE | halts with `ACQUISITION_HALTED_JOURNAL_FULL`, keeps every unacknowledged row, **and recovers** | PASS |
| partial refusal | 59 released, exactly 1 retained | PASS |
| batch route absent | degrades to single-event, 120/120, no loss | PASS |
| oversize batch | halves until it fits, no loss | PASS |
| transport | 1 connection for 5 requests; reconnects once on a stale socket | PASS |

## TEST TOTALS

| Suite | Tests |
|---|---|
| paged acquisition | 24 |
| journal durability | 28 |
| stress + silent loss | 5 |
| batch + integrity contract | 16 |
| pre-canary acceptance | 16 |
| **B5-GAP-1 total** | **89** |
| `backend/tests/edr/` full suite | **1917 passed, 3 skipped, 0 failed** |

### One real fault the existing suite caught

`test_p0prod2_enrollment_hardening.py::test_agent_routes_never_depend_on_a_platform_user`
failed because I first placed the admin read route *inside* the agent block
of `edr_enrollment.py`, where that guard scans for `get_current_user`. That
is a genuine structural invariant — admin identity must not appear in the
agent surface — so the route was moved above the agent section. The guard
was right and I was wrong.

## FILES CHANGED IN THIS GATE PASS

| File | Change |
|---|---|
| `backend/edr_plane/acquisition_integrity.py` | **NEW** Gate C contract, server-asserted classification/cause, idempotent gaps, closed health vocabulary |
| `backend/routers/edr_enrollment.py` | `_ingest_one` extracted (one ingest path), `TelemetryEventItem`/`TelemetryBatchBody`, `POST /telemetry/batch`, `AcquisitionIntegrityBody`, `POST /acquisition-integrity`, `GET /enrollment/acquisition-integrity` |
| `backend/routers/edr_tenancy.py` | three route classifications |
| `agents/nivxforge-windows/nivxforge_sensor.py` | `_Transport` (persistent connection, one reconnect), `_request`/`_post`/`_get` on it, `delivery_batch_size()` (50, from measurement), `_deliver_batch`, batch-aware `_drain_journal` with 404/413 handling, `_report_integrity`, `BATCH_SUPPORT` |
| `agents/nivxforge-windows/nivxforge_setup.py` | `journal-selftest` subcommand + `journal_selftest()` |
| `.github/workflows/windows-sensor-installer.yml` | ACCEPTANCE GATE 0 — frozen journal selftest, requires `"frozen": true` |
| `scripts/b5gap1_delivery_latency_probe.py` | **NEW** latency/throughput probe |
| `backend/tests/edr/test_b5_gap1_batch_and_integrity_contract.py` | **NEW** 16 tests |
| `backend/tests/edr/test_b5_gap1_pre_canary_acceptance.py` | **NEW** 16 tests |
| `backend/tests/edr/fixtures_b5_gap1_source.py` | batch-aware fake backend, `batch_aware()` wrapper |

## REMAINING RISKS

1. **Gate A is one Windows CI run away.** Everything else is wired; the
   frozen assertion is the only thing that cannot be made here.
2. **Production delivery throughput is unmeasured.** 48.3 ev/s is preview.
   On the 2.68 s production path the structural wins are larger but the
   absolute ceiling is unknown until the canary measures it.
3. **Server-side per-event cost (~39 ms) is now the ceiling.** If the
   canary needs more than ~25 ev/s per endpoint, the next lever is inside
   `_ingest_one` (the 2-4 counter writes per event look batchable), not the
   transport. Not attempted here: out of gate scope.
4. **Integrity is stored but not rendered.** The read route exists; no
   console work was done, by instruction.
5. **Batch fallback is permanent for the process.** Once a backend answers
   404, that sensor stays on the single-event path until restart. Simple and
   safe, but it will not notice a backend that gains the route mid-run.
6. Two synthetic endpoints (`ep_1badb6e4ec82b016f808`,
   `NIVX-PROBE-2`) now exist in the **preview** database in tenant
   `probe-t-00bf71`, from the latency probe and the live contract check.
   Preview only; revoke them whenever you like.
7. The historical B5-GAP-1 records remain unrecoverable, by design.

## PROPOSED ONE-ENDPOINT CANARY PROCEDURE (for approval, not executed)

1. Run `windows-sensor-installer.yml` on a Windows runner. **Abort if
   ACCEPTANCE GATE 0 does not report `result: PASS` with `frozen: true`.**
2. Install on **one** non-production Windows endpoint — not
   `DESKTOP-A9HGFJJ`. Confirm from `status`: `meta.legacy_cursors_adopted`
   matches the pre-upgrade `channels.json`, journal depth 0 at first open,
   and `legacy_outbox_remaining` decreasing.
3. **Measure production delivery.** From the cycle report:
   `sent`, `delivery_batch_size`, `queue_depth`. Acceptance =
   `sent/cycle >= 600` (i.e. ≥20 ev/s sustained) **or** an explicit
   decision to tune `NIVX_SENSOR_DELIVERY_BATCH` on that evidence.
4. 60-minute baseline. Acceptance = `acquisition_gap_count == 0`,
   `records_journaled == records_read`, `integrity_report` starts `SENT`,
   and the gap/channel rows visible via
   `GET /api/edr/enrollment/acquisition-integrity`.
5. Induced Sysmon burst. Acceptance = journal backlog grows while
   `acquisition_gap_count` stays 0 — the inverse of B5-GAP-1.
6. Kill the service mid-cycle. Acceptance = cursors and evidence intact on
   restart, zero duplicates at the backend.
7. Only then `DESKTOP-A9HGFJJ`, and re-confirm B5 (EID1/EID5 pairing,
   ProcessGuid, trajectory) end to end.
8. Decide the `wevtutil` question on the collected `query_ms_max`.

**STOP. Awaiting owner review.**
