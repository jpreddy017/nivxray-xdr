# B5-GAP-1 · DISPOSABLE WINDOWS CANARY — EXECUTABLE PLAN

**Status: PREPARED AND EXECUTABLE — NOT RUN. `CANARY_STARTED = NO`.**

Windows Gate 0 is `CLOSED_PASS` on the real `windows-latest` artifact
(`docs/B5_GAP_1_WINDOWS_GATE0_CI_CONTRACT.md` §8). The open question is no
longer *"does the journal work on Windows?"* It is:

> does the whole chain sustain real telemetry under load, outage, recovery,
> restart and journal pressure **without silent loss**?

Preconditions, all of them, before step 1 runs:

1. `GATE0_VERDICT = CLOSED_PASS` — met.
2. Explicit owner authorisation naming the disposable host — **NOT MET**.
3. Target host is disposable / validation-only. `DESKTOP-A9HGFJJ` is out of
   scope: no install, no restart, no Sysmon change, no channel/outbox/journal
   change, no test load.

---

## 0. PHASE C0 — CLEAN HOST PREPARATION (authorised host: KUSHU)

Repository findings that decide C0. Nothing here was improvised.

| Question | Repository answer | Evidence |
|---|---|---|
| 1. Does the installer install/configure Sysmon? | **NO.** It installs the sensor + Windows service only. It contains no Sysmon logic at all. | no `Sysmon` reference in `agents/nivxforge-windows/nivxforge_setup.py` or `Install-NivXForgeSensor.ps1` |
| 2. Authoritative Sysmon configuration | the **W1 baseline** XML, written to `C:\NivX\sysmon\nivx-w1-sysmon.xml` | `memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` §1.3 |
| 3. Use the validated baseline/EID5 configuration? | **YES** — W1 baseline with the single validated B5 change `ProcessTerminate onmatch="exclude"` (EID 5 ON). On a clean host it is written that way in ONE step; `docs/B5_EID5_ENABLE_AND_VERIFY.ps1` is pinned to `DESKTOP-A9HGFJJ` and must NOT be run on the canary | `docs/B5_EID5_ENABLE_AND_VERIFY.ps1` §"THE CHANGE"; `docs/B5_EID5_END_TO_END_ACCEPTANCE_REPORT.md` |
| 4. Artifact + SHA256 | `NivXForgeEDRSetup.exe`, sensor `0.3.0-windows` / setup `1.0.0`, from Gate-0 run `36663297037` (commit `2cb841db`). Expected SHA256 = the value in that run's `SHA256SUMS.txt` / `GATE0_WINDOWS_REPORT.json`; C0 halts on mismatch | `docs/B5_GAP_1_WINDOWS_GATE0_CI_CONTRACT.md` §8 |
| 5. Enrolment | `NivXForgeEDRSetup.exe install --tenant <canary_tenant> --token <one-time enrolment token>`; identity is minted per computer. Nothing is copied from any other host | `nivxforge_setup.py::install` |
| 6. Backend origin | `https://nivxray.nivxforge.com` only. The installer's production-origin guard refuses localhost/preview/`.local`, so a relay or hosts entry is the ONLY legal way to impair delivery later | `nivxforge_setup.py::_assert_backend` |
| 7. Canary read credential | `NIVX_CANARY_READ_TOKEN` (operator read token for `/api/edr/wave0/raw-events/stats` and `/api/edr/enrollment/acquisition-integrity`). Never printed, never written to CSV or verdict | `scripts/canary/b5gap1_canary_collector.py` |
| 8. Must KUSHU be renamed? | **NO rename required, and the guard is NOT weakened.** The `-Confirm` bypass was REMOVED. The load generator now requires three conditions every run: not on the forbidden list, named `NVX-CANARY*` **or** listed in `$authorized` (`KUSHU`, owner-authorised), **and** `C:\NivXForgeCanary\CANARY_DESIGNATION.json` present | `scripts/canary/b5gap1_canary_load.ps1` |
| 9. Reboot | **Not required.** `Sysmon64.exe -i` loads `SysmonDrv` immediately; the sensor service starts without a reboot | `memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` §1.4 |
| 10. Rollback | §6 of this document, plus `Sysmon64.exe -u force` and removal of `C:\NivX`, `C:\NivXForgeCanary` on the canary only | §6 |

Sysmon binary integrity: Microsoft re-publishes Sysmon, so no pre-known
SHA256 exists in this repository. The **fail-closed** gate is therefore the
Authenticode signature (`Status = Valid`, signer `O=Microsoft Corporation`),
exactly as W1 required; the observed SHA256 and file version are RECORDED as
provenance and may be pinned by the owner for later runs. For the NivXForge
artifact the expected SHA256 IS known and the mismatch halt is absolute.

C0 block order, one at a time, each fail-closed, each reporting before the
next is issued:

```
C0.1   designation + read-only preflight (no install, no download)
C0.2   Sysmon binary staging + signature gate (no install yet)
C0.3a  stage + VALIDATE the authoritative config (SHA256 gate, XML gate,
       EID 1 / EID 5 proof by rule, rollback evidence) — NO install
C0.3b  apply Sysmon with that config, prove EID 1 + EID 5 live
C0.4   NivXForge artifact SHA256 gate (halt on mismatch)
C0.5   install + enrol + prove service, journal, backend connectivity
C0.6   collector dry sample (read-only, LOAD_GENERATED stays NO)
```

`C0.3` is deliberately SPLIT: the plan originally applied the config in one
step, and validation must precede installation so the owner can review the
exact rules before the driver ever loads them.

### Authoritative canary Sysmon configuration

`agents/nivxforge-windows/sysmon/nivx-b5gap1-canary-sysmon.xml` — the W1
baseline (`memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` §1.3) with the single
B5-validated change `<ProcessTerminate onmatch="include"/>` ->
`<ProcessTerminate onmatch="exclude"/>` (EID 5 ON), and nothing else.
Pinned file hashes of that exact content, UTF-8 **without** BOM:

```
CRLF (written on Windows)  452E331298DF9A3DF3314E2CF707F153891DCE0BCE625B4EE99548D8D5E479AB
LF   (repository form)     60F585860CFBEA3D62888B6CCB90C15F28A49D91832D4FC4526EBEEAA316C67C
```

Two honest notes. (1) The `LOG NOTHING for every unsupported event id`
comment still sits above `ProcessTerminate`: the B5 change swapped only the
`onmatch` token, so the stale comment is part of the configuration that
production actually runs. It is left byte-faithful rather than tidied,
because rule equivalence with production matters more than a comment.
(2) Production's file was written with PowerShell 5.1 `-Encoding UTF8`,
which emits a BOM, so its FILE hash necessarily differs from the values
above. The authoritative "same rules" comparison is the driver's active
rules hash captured in C0.3b, not the file hash.

Defender is never weakened and no Defender exclusion is added at any point.
No load generation and no impairment in C0.

---

## 1. PACKAGE

| File | Role | Touches product code? |
|---|---|---|
| `scripts/canary/b5gap1_canary_collector.py` | read-only measurement collector + invariant verdict | no |
| `scripts/canary/b5gap1_canary_load.ps1` | real source-record generator on the canary; refuses `DESKTOP-A9HGFJJ` | no |
| `scripts/canary/b5gap1_canary_impair.py` | transparent TCP relay for BACKEND_SLOW / DOWN / NETWORK_INTERRUPTION | no |
| `scripts/b5gap1_ingest_cost_profile.py` | **re-used** backend Mongo/ingest profiler | no |
| `backend/tests/edr/test_b5gap1_canary_harness.py` | proves the harness before it is ever pointed at an endpoint | no |

**No ingest middleware is added and none may be added.** Backend per-event
cost comes from the existing profiler only. The sensor hot path is not
instrumented: every sensor-side number is read from artefacts the sensor
already produces (its journal, its `acquisition_integrity.json`, its
integrity counters) or from the platform's existing operator endpoints.

The collector opens the journal `mode=ro`; if a WAL reader cannot attach it
copies `*.db`, `*.db-wal`, `*.db-shm` to scratch and reads the **copy**. The
originals are never opened for writing, never checkpointed, never renamed.
The read token comes from `NIVX_CANARY_READ_TOKEN` and never reaches the CSV,
the verdict or stdout.

---

## 2. CANARY IDENTITY AND ISOLATION

| Item | Value |
|---|---|
| Host | disposable Windows host, named `NVX-CANARY-<n>` |
| Tenant | dedicated canary tenant — never a production tenant, never a fallback tenant |
| Endpoint identity | freshly enrolled on the canary with a one-time token |
| Artifact | the exact `ARTIFACT_SHA256` from the passing Gate-0 run |
| Backend | the production ingress — the point is to measure the REAL path |

**Never copied from `DESKTOP-A9HGFJJ`:** `identity.json`, enrolment or sensor
credentials, endpoint identity, the journal database, `channels.json`,
`outbox.jsonl`/`outbox.offset`. Never printed anywhere: enrolment tokens,
bearer tokens, API keys, service credentials, identity secrets.

Install (operator, elevated, canary only):

```powershell
NivXForgeEDRSetup.exe install --tenant <canary_tenant> --token <enrolment_token>
NivXForgeEDRSetup.exe status
Get-FileHash .\NivXForgeEDRSetup.exe -Algorithm SHA256   # must equal Gate-0 SHA256
```

---

## 3. THE MEASURED CHAIN

```
SOURCE            Windows Event Log / Sysmon, RecordID space
  v  ACQUISITION  paged reads, fair scheduling across channels
  v  JOURNAL      SQLite WAL durable ownership + cursor commit
  v  NORMALIZATION sensor-side payload shaping
  v  BATCH TRANSPORT persistent session, batch 50
  v  BACKEND INGEST production ingress + TLS
  v  AUTHORIZATION endpoint-scoped credential
  v  RAW ACCEPTANCE immutable raw evidence + dedup
  v  CANONICAL EVIDENCE canonical bridge / shadow observation
  v  ACK            per-event acceptance returned to the sensor
  v  JOURNAL RELEASE reclamation of BACKEND_ACCEPTED rows only
```

### Measurement CSV schema

`<out-dir>/canary_<SCENARIO>_<stamp>.csv` — one row per **(sample, channel)**;
endpoint-wide columns are repeated on each channel row so a single query can
answer "was this interval trustworthy for this channel?".

```
sample_at, scenario, elapsed_seconds, channel,

SOURCE       source_oldest_record_id, source_newest_record_id,
             source_records_per_sec
ACQUISITION  cursor_committed, continuity_established,
             last_record_id_journaled, acquisition_lag_records,
             journaled_records_per_sec, query_ms_last
JOURNAL      journal_rows, journal_rows_deliverable,
             journal_rows_backend_accepted, journal_depth, journal_bytes,
             journal_live_bytes, journal_pct, journal_pressure_state,
             oldest_pending_age_seconds, records_read_total,
             records_journaled_total, backend_accepted_total,
             delivery_failures_total, query_total, query_failures_total,
             acquisition_halted_reason, journal_fault
INTEGRITY    acquisition_gap_count, unreported_gap_count, last_gap,
             health_states
TRANSPORT    delivery_backlog, backend_http_status, backend_rtt_ms
BACKEND      backend_received, backend_parsed, backend_accepted,
             backend_canonicalized, backend_deduplicated, backend_refused,
             backend_accepted_per_sec, backend_gap_count,
             backend_tenants_observed
PROVENANCE   journal_read_mode
```

Anything the collector cannot read honestly is empty, and the affected
invariant is reported `NOT_PROVABLE` — never estimated, never assumed PASS.

### Verdict JSON schema

`<out-dir>/canary_<SCENARIO>_<stamp>.json`

```json
{
  "contract": "nivxforge.b5gap1.canary_measurement",
  "contract_version": 1,
  "scenario": "BACKEND_DOWN",
  "scenario_expectations": { "impaired": true, "expect_backlog": true },
  "generated_at": "...",
  "canary": { "tenant_id": "...", "endpoint_id": "...", "state_dir": "...",
              "artifact_sha256": "...", "designation": "DISPOSABLE_CANARY" },
  "samples": 60,
  "csv": "...",
  "verdict": "PASS | FAIL | NOT_PROVABLE",
  "invariants": { "<NAME>": { "result": "...", "observed": {}, "note": "" } },
  "throughput": {
    "sustained_source_rate_eps": 0, "sustained_acquisition_rate_eps": 0,
    "sustained_delivery_rate_eps": 0, "peak_delivery_rate_eps": 0,
    "recovery_drain_rate_eps": 0, "delivery_headroom": 0,
    "peak_delivery_backlog": 0, "final_delivery_backlog": 0,
    "http_rtt_ms_median": 0,
    "note": "no required headroom is asserted here; the production threshold is an owner decision"
  },
  "limitations": [],
  "evidence_labelling": "CANARY/VALIDATION — not production truth",
  "boundary": { "CANARY_HOST_ONLY": true, "DESKTOP_A9HGFJJ_TOUCHED": "NO",
                "PRODUCTION_DEPLOYED": "NO",
                "PRODUCT_CODE_MODIFIED_FOR_MEASUREMENT": "NO" }
}
```

`DELIVERY_HEADROOM = sustained_delivery_rate / sustained_source_rate` is
reported, not judged. The preview figure (batch 50 ≈ 48.3 ev/s) is **not**
accepted as a canary result and is re-measured here.

---

## 4. EXECUTABLE SCENARIOS

Every scenario is: start collector -> inject -> stop -> read verdict. Run
each into its own `--out-dir` so the CSVs stay separable. Nothing below runs
until the owner authorises the canary.

Common environment (canary host, elevated):

```powershell
$env:NIVX_CANARY_READ_TOKEN = '<operator read token>'   # never echoed
$C = 'C:\NivXForgeCanary'
$py = 'python'
$common = @('--backend','https://nivxray.nivxforge.com',
            '--tenant','<canary_tenant>','--endpoint','<canary_endpoint_id>',
            '--artifact-sha256','<gate0 sha256>')
```

### 1 · NORMAL
```powershell
Start-Process $py "scripts\canary\b5gap1_canary_collector.py --scenario NORMAL --duration 900 --interval 15 --out-dir $C\normal $common"
.\scripts\canary\b5gap1_canary_load.ps1 -Scenario NORMAL -Seconds 900
```
Must hold: gaps 0, duplicates 0, journal drains to 0, cursor forward-only.

### 2 · HIGH-VOLUME BURST
```powershell
... --scenario BURST --duration 600 --interval 10 --out-dir $C\burst
.\scripts\canary\b5gap1_canary_load.ps1 -Scenario BURST -Seconds 120 -Rate 200
```
Must hold: acquisition keeps up, backlog grows then drains, no loss.

### 3 · BACKEND SLOW
```powershell
# hosts: 127.0.0.1 nivxray.nivxforge.com   (canary only, reversible)
$py scripts\canary\b5gap1_canary_impair.py --upstream-ip <A record> --mode slow --delay-ms 750
... --scenario BACKEND_SLOW --duration 900 --interval 10 --out-dir $C\slow
```
Must hold: acquisition CONTINUES, cursor keeps advancing, backlog bounded by
journal capacity.

### 4 · BACKEND UNAVAILABLE
```powershell
$py scripts\canary\b5gap1_canary_impair.py --upstream-ip <A record> --mode down
#   alternative: New-NetFirewallRule -DisplayName NVXCANARY-BLOCK -Direction Outbound -RemotePort 443 -Action Block
... --scenario BACKEND_DOWN --duration 900 --interval 10 --out-dir $C\down
```
Must hold: acquisition continues within journal capacity; nothing
unacknowledged is deleted; `BACKEND_UNREACHABLE` surfaces explicitly.

### 5 · BACKEND RECOVERY
```powershell
# stop the relay / remove the firewall rule and the hosts entry
... --scenario RECOVERY --duration 1200 --interval 10 --out-dir $C\recovery
```
Must hold: `peak backlog > 0` **and** `final backlog = 0`, 0 loss, no
double-accepted evidence, no fabricated backfill.

### 6 · SENSOR SERVICE RESTART
```powershell
... --scenario SENSOR_RESTART --duration 600 --interval 10 --out-dir $C\restart
Restart-Service NivXForgeSensor         # mid-drain
```
Must hold: journal recovered, cursor never regresses, no re-send storm, no
loss.

### 7 · NETWORK INTERRUPTION + RECOVERY
```powershell
$py scripts\canary\b5gap1_canary_impair.py --upstream-ip <A record> --mode cut --cut-after-bytes 4096
... --scenario NETWORK_INTERRUPTION --duration 900 --interval 10 --out-dir $C\netcut
```
Must hold: a partially-acked batch is settled per event; no duplicate
acceptance; no silent drop; backlog drains after recovery.

### 8 · MULTI-CHANNEL LOAD (Security + System + Sysmon)
```powershell
... --scenario MULTI_CHANNEL --duration 900 --interval 15 --out-dir $C\multi
.\scripts\canary\b5gap1_canary_load.ps1 -Scenario MULTI_CHANNEL -Seconds 900
```
Must hold: every channel progresses (no starvation), per-channel cursors
correct.

### 9 · JOURNAL PRESSURE
```powershell
# canary only: set a SMALL ceiling, then keep delivery impaired
setx NIVXFORGE_JOURNAL_MAX_BYTES 33554432 /M ; Restart-Service NivXForgeSensor
... --scenario JOURNAL_PRESSURE --duration 1200 --interval 10 --out-dir $C\pressure
```
Must hold: pressure surfaces as an explicit state
(`JOURNAL_PRESSURE` / `JOURNAL_CRITICAL` /
`ACQUISITION_HALTED_JOURNAL_FULL`); the admission decision is explicit,
never a silent drop; nothing unacknowledged is deleted.

### 10 · SOURCE RECORD DISCONTINUITY
```powershell
... --scenario SOURCE_DISCONTINUITY --duration 900 --interval 10 --out-dir $C\discontinuity
.\scripts\canary\b5gap1_canary_load.ps1 -Scenario SOURCE_DISCONTINUITY
```
The generator refuses to run unless the host is not on the forbidden list,
is named `NVX-CANARY*` **or** listed in `$authorized`, **and** carries
`C:\NivXForgeCanary\CANARY_DESIGNATION.json`. There is no switch that waves
the guard through.
Must hold: exactly one declared gap with
`classification = SOURCE_RECORD_DISCONTINUITY` and `cause = NOT_PROVEN`;
never absorbed silently, never labelled benign or malicious.

### Backend cost, per scenario window
```bash
cd /app/backend && PROFILE_N=60 python ../scripts/b5gap1_ingest_cost_profile.py
```
Records ms/event, Mongo commands/event, Mongo ms/event, correlation-rule
read cost. **Measurement only** — see §7.

---

## 5. ACCEPTANCE INVARIANTS

Enforced by the collector's verdict, and each one has a test that proves it
actually fails:

```
SILENT_LOSS                              = 0
UNEXPLAINED_ACQUISITION_GAPS             = 0   (normal/burst/recoverable)
DUPLICATES                               = 0   (retry-window dedup at the
                                                platform boundary is refusal,
                                                not double acceptance)
WRONG_TENANT_EVIDENCE                    = 0
UNACKNOWLEDGED_DELETION                  = 0
CURSOR_MONOTONIC                         = true
SOURCE_CURSOR <= LAST_DURABLY_OWNED_SOURCE_RECORD
SLOW_BACKEND                            != STOP_ACQUISITION
DELIVERY_BACKLOG                        != SOURCE_LOSS
SENT                                    != ACCEPTED
ACCEPTED                                != CANONICALIZED
NO EVENT OBSERVED                       != EVENT DID NOT OCCUR
ACQUISITION GAP                         != BENIGN
ACQUISITION GAP                         != MALICIOUS
JOURNAL_NOT_CORRUPT                      = true
```

Backlog recovery must be proven as a sequence, not asserted:
`backlog_before_recovery > 0` -> `backlog_after_recovery = 0`, with no
silent loss, no duplicate evidence, no cross-tenant evidence and no
fabricated backfill.

Known limits, stated rather than hidden: silent loss is only provable where
the source channel tail is readable (Windows canary); cross-tenant leakage is
excluded only within the reading credential's authority — a platform-wide
scan is a separate owner action.

---

## 6. ROLLBACK CRITERIA

Stop and roll back immediately on: any silent loss; any gap that cannot be
explained from evidence; any duplicate accepted evidence; any wrong-tenant
evidence; any unacknowledged deletion; journal corruption that is not
quarantined and visible; service fails to start/crashes/fails to recover;
host impact beyond the agreed budget; **any** effect observable on a
production tenant.

```powershell
# 1. collect FIRST
Copy-Item C:\ProgramData\NivXForge\sensor\acquisition_integrity.json $C\evidence\
Copy-Item C:\ProgramData\NivXForge\sensor\service.log               $C\evidence\
Copy-Item $C\*\canary_*.csv, $C\*\canary_*.json                     $C\evidence\
# 2. remove the impairment: stop the relay, drop the firewall rule,
#    remove the hosts entry
# 3. then, only then
NivXForgeEDRSetup.exe uninstall            # keeps local evidence
NivXForgeEDRSetup.exe uninstall --purge    # optional, after collection
```
No secret material is collected or printed.

---

## 7. STOP CONDITIONS AND THE OPTIMIZATION RULE

* No owner authorisation / no named disposable host -> **do not start**.
* Any acceptance invariant violated -> **stop, collect, report, do not tune**.
* Canary complete -> **STOP for owner review**. No production step, no
  optimization and no `DESKTOP-A9HGFJJ` action follows automatically.

During the canary: `CORRELATION_CACHE_IMPLEMENTED = NO`,
`COUNTER_BATCHING_IMPLEMENTED = NO`, `RAW_EVENT_PATH_MODIFIED = NO`, no
canonical-bridge shortcuts. If profiling proves correlation-rule reads are
materially expensive, **report the measurement only**.

Only after owner review of the canary measurements, and only if rule reads
remain material, may a cache be *proposed*. It must cache configuration
only (never evidence), have deterministic invalidation/versioning, preserve
tenant-specific rule scope, fail safely, never use stale rules
indefinitely, record the rule provenance/version used for every finding,
never alter historical evidence, and ship with tests for rule update,
disable, delete, tenant isolation, restart and cache invalidation.

---

## 8. LIFECYCLE

```
B5_STATUS                  = CLOSED_PASS
B5_GAP_1_IMPLEMENTATION    = PASS
B5_GAP_1_WINDOWS_ARTIFACT  = PASS        (real windows-latest Gate 0)
B5_GAP_1_DISPOSABLE_CANARY = PENDING     <- this plan, not yet run
```

B5-GAP-1 is **not** fully closed until the disposable canary passes.

```
GATE 0 CLOSED (real Windows)  ->  DISPOSABLE CANARY (this plan)
  ->  real production-path measurements  ->  owner review
  ->  optimize ONLY what the measurements prove dominant
  ->  stress / outage / restart / recovery re-run
  ->  DESKTOP-A9HGFJJ last, and only on explicit authorisation
```
