# B5-GAP-1 · DISPOSABLE WINDOWS CANARY PLAN

**Status: PREPARED — NOT RUN. `CANARY_STARTED = NO`.**

Preconditions, all of them, before a single step of this plan executes:

1. `GATE0_VERDICT = CLOSED_PASS` from a real `windows-latest` run
   (see `B5_GAP_1_WINDOWS_GATE0_CI_CONTRACT.md`).
2. Explicit owner authorisation naming the disposable host.
3. Target host is **disposable / validation-only**. `DESKTOP-A9HGFJJ` is
   **out of scope** and must not be touched.

The canary exists to answer one question with measurements instead of
assumptions: *does the new acquisition/journal/batch path lose nothing on a
real Windows endpoint against the real production ingest path, and where is
the dominant cost actually spent?*

---

## 1. TARGET AND IDENTITY

| Item | Value |
|---|---|
| Host | disposable Windows host (VM or spare workstation), NOT production |
| Hostname convention | `NVX-CANARY-<n>` |
| Tenant | a dedicated canary tenant — never a production tenant, never a fallback tenant |
| Enrolment | one-time enrolment token, supplied at install time by the operator |
| Artifact | the exact `ARTIFACT_SHA256` recorded by the passing Gate-0 run |
| Backend | the production ingress (`https://nivxray.nivxforge.com`) — the point is to measure the REAL path |
| Sysmon | installed configuration is left **unchanged** |

Install form (operator, elevated, on the canary only):

```
NivXForgeEDRSetup.exe install --tenant <canary_tenant> --token <enrolment_token>
NivXForgeEDRSetup.exe status
```

Verify before any load: `ARTIFACT_SHA256` on disk == Gate-0 report value.

---

## 2. THE ELEVEN-STAGE MEASUREMENT PIPELINE

Every stage is measured **separately**, so a loss or a cost can be
attributed to a stage instead of blamed on "the sensor" or "the backend".

```
 1  SOURCE              Windows Event Log / Sysmon channels, RecordID space
 2  ACQUISITION         paged reads, fair scheduling across channels
 3  JOURNAL             SQLite WAL durable ownership + cursor commit
 4  NORMALIZATION       sensor-side shaping of the evidence payload
 5  BATCH TRANSPORT     persistent session, batch size 50
 6  PRODUCTION INGRESS  TLS + edge + routing
 7  AUTH                endpoint-scoped credential validation
 8  RAW ACCEPTANCE      immutable raw evidence + dedup
 9  CANONICAL BRIDGE    canonicalisation / shadow observation
10  MONGO               command count and latency
11  ACK                 per-event acceptance returned to the sensor
```

### Per-stage metrics (recorded, per scenario, per minute)

| Metric | Stage |
|---|---|
| source events/sec | 1 |
| source RecordID first/last observed per channel | 1 |
| acquisition events/sec | 2 |
| acquisition pages/sec, page size | 2 |
| per-channel scheduling fairness (events/sec per channel) | 2 |
| journal writes/sec | 3 |
| journal commit latency ms (p50/p95/max) | 3 |
| committed cursor per channel | 3 |
| journal depth (undelivered rows) | 3 |
| journal bytes used / live bytes / reclaimed | 3 |
| normalization ms/event | 4 |
| batch size (actual, distribution) | 5 |
| batches/sec | 5 |
| transport events/sec | 5 |
| HTTP RTT ms (p50/p95/max) | 5–6 |
| connection reuse count / reconnects | 5 |
| ingress HTTP status distribution | 6 |
| auth failures | 7 |
| backend processing ms/event | 8–10 |
| raw-event persistence ms/event | 8 |
| dedup hits | 8 |
| canonical bridge ms/event | 9 |
| Mongo ms/event | 10 |
| Mongo commands/event | 10 |
| correlation-rule lookup ms/event | 10 |
| ACK latency ms, acked/sec | 11 |
| delivery backlog (sent-not-acked) | 5–11 |
| gap count (and each gap's channel + RecordID range) | 1–3 |
| duplicate count (same source record accepted twice) | 8 |

Baseline for comparison: the preview profile — **~30.3 ms/event, 19 Mongo
commands, ~24.6 ms Mongo, ~5.7 ms CPU**, delivery counters **3 commands,
~1.25 ms/event, ~3.8%**.

---

## 3. FAILURE MATRIX — TEN SCENARIOS

Each scenario names what is injected, what is measured, and what must hold.

| # | Scenario | Injection | Must hold |
|---|---|---|---|
| 1 | `NORMAL` | steady synthetic load at typical endpoint rate | journal drains to 0; gaps 0; duplicates 0 |
| 2 | `BURST` | short high-rate burst above drain rate | acquisition keeps up; backlog grows then drains to 0; no loss |
| 3 | `BACKEND_SLOW` | artificial latency on ingest responses | acquisition CONTINUES; cursor keeps advancing; backlog bounded by journal capacity |
| 4 | `BACKEND_DOWN` | ingress unreachable | acquisition CONTINUES within journal capacity; nothing deleted unacknowledged |
| 5 | `RECOVERY` | backend restored after 3 and 4 | full backlog delivered; 0 loss; 0 duplicates |
| 6 | `SENSOR_RESTART` | stop/start the Windows service mid-drain | journal recovered; cursor unchanged or forward-only; no re-send storm, no loss |
| 7 | `NETWORK_INTERRUPTION` | NIC down / TLS reset mid-batch | partially-acked batch handled per-event; no duplicate acceptance; no silent drop |
| 8 | `MULTI_CHANNEL` | load on Sysmon + Security + System simultaneously | fair scheduling; no channel starved; per-channel cursors correct |
| 9 | `JOURNAL_PRESSURE` | drive journal to its size/pressure limit | pressure surfaced explicitly; acquisition admission decision is EXPLICIT, never a silent drop; nothing unacknowledged is deleted |
| 10 | `SOURCE_RECORD_DISCONTINUITY` | channel cleared / wrapped / provider reset | discontinuity reported as a GAP with `cause = NOT_PROVEN`; never fabricated as benign, never silently absorbed |

For every scenario, record: source vs acquired vs journaled vs sent vs
accepted vs canonicalised counts, and reconcile them.

---

## 4. ACCEPTANCE INVARIANTS

A canary run is acceptable only if **all** of these hold:

```
unexplained acquisition gaps        = 0
silent loss                         = 0
duplicates                          = 0
wrong-tenant evidence               = 0
unacknowledged deletion             = 0
journal eventually drains to 0
acquisition continues while the backend is slow or down,
    within available journal capacity
SOURCE_CURSOR <= LAST_DURABLY_OWNED_SOURCE_RECORD   (always)
SENT != ACCEPTED                                    (never conflated)
ACCEPTED != CANONICALIZED                           (never conflated)
NO EVENT OBSERVED != EVENT DID NOT OCCUR
ACQUISITION GAP != BENIGN
```

Any gap that IS found must be **explained**: channel, RecordID range,
detection time, and the reason — with `cause = NOT_PROVEN` when the cause is
genuinely not proven. A gap explained by guesswork is a failed run.

---

## 5. ROLLBACK CRITERIA

Stop the canary and roll back immediately if any of these appear:

* any silent loss, or any gap that cannot be explained from evidence;
* any duplicate accepted evidence;
* any wrong-tenant evidence;
* any unacknowledged evidence deleted from the journal;
* journal corruption that is not quarantined and made visible;
* the service fails to start, crashes, or fails to recover after restart;
* sustained host impact beyond the agreed budget (CPU / memory / disk);
* any effect observable on production tenants.

Rollback procedure (canary host only):

```
NivXForgeEDRSetup.exe uninstall            # keeps local evidence for review
# collect first, then optionally:
NivXForgeEDRSetup.exe uninstall --purge
```

Collect before purge: journal integrity snapshots, `service.log`, the
per-scenario measurement CSV/JSON, and the enrolled endpoint identity (no
secret material).

---

## 6. STOP CONDITIONS

* Gate 0 not `CLOSED_PASS` -> **do not start**.
* No named disposable host and explicit owner authorisation -> **do not start**.
* Any acceptance invariant violated -> **stop, collect, report, do not tune**.
* Canary complete -> **STOP for owner review**. No production step, no
  optimization, no `DESKTOP-A9HGFJJ` action follows automatically.

---

## 7. OPTIMIZATION DECISION RULE (POST-CANARY ONLY)

Only after canary measurements, and only if correlation-rule reads remain a
**material** share of ms/event, propose a cache design. Any such design must:

* cache **configuration only**, never evidence;
* have deterministic invalidation / versioning;
* preserve tenant-specific rule scope;
* fail safely;
* never use stale rules indefinitely;
* record the rule provenance/version used for every finding;
* never alter historical evidence;
* ship with tests for rule update, disable, delete, tenant isolation,
  process restart, and cache invalidation.

Not implemented. Not approved. Awaiting canary evidence.

---

## 8. WHAT HAPPENS AFTER — IN ORDER

```
GATE 0 CLOSED (real Windows)
        v
DISPOSABLE WINDOWS CANARY (this plan)
        v
real production-path measurements
        v
owner review
        v
optimize ONLY what the measurements prove dominant
        v
stress / outage / restart / recovery re-run
        v
DESKTOP-A9HGFJJ last, and only on explicit authorisation
```
