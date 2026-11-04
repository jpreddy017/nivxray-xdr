# B5-GAP-1 — WINDOWS ACCEPTANCE GATE 0 + §5 INGEST COST PROFILE

**CANARY_STARTED = NO. PRODUCTION_DEPLOYED = NO.** `DESKTOP-A9HGFJJ` was
not touched: not installed on, not restarted, no Sysmon change, no
`channels.json` or outbox change, no journal migration, no generated load.
B5 remains CLOSED / PASS.

```
WINDOWS_ARTIFACT_BUILD    = NOT_RUN   (I cannot trigger CI or build a PE here)
FROZEN_SELFTEST           = PASS      (on a LINUX-frozen PyInstaller binary)
FROZEN                    = TRUE      (on that Linux binary; Windows pending)
SQLITE_PACKAGED           = PASS      (in the frozen bundle; Windows pending)
JOURNAL_PACKAGED          = PASS      (in the frozen bundle; Windows pending)
FROZEN_STARTUP            = PASS      (frozen CLI ran; Windows SERVICE pending)
PACKAGING_REGRESSION      = PASS

ARTIFACT_VERSION          = 0.3.0-windows  (sensor); setup CLI unversioned
ARTIFACT_SHA256           = see §3 — LINUX proof binary, NOT the shipped PE

COUNTER_PROFILE           = COMPLETE
COUNTER_WRITES_PER_EVENT  = 3
COUNTER_COST_PER_EVENT_MS = 1.25   (3.8% of ingest)
OTHER_BACKEND_COST_MS     = 29.0   (16 further Mongo commands, 23.4 ms)
```

---

## 1. WHAT I COULD NOT DO, SAID PLAINLY

**I cannot trigger the Windows workflow, and I cannot produce a Windows PE.**

- Git write actions (push, dispatch) are not mine to perform — they go
  through the chat's **"Save to Github"** control, and the workflow then
  runs on `windows-latest`. No tool here can start it.
- PyInstaller does not cross-compile. A Windows PE embedding a Python
  runtime can only be produced on Windows.

So `WINDOWS_ARTIFACT_BUILD = NOT_RUN`. **Blocked, not failed, and not
faked.** The Windows run is yours to trigger.

What I did instead was remove every *other* source of doubt, so that when
you do run it the only new information is "does this hold on Windows too".

## 2. FROZEN JOURNAL SELF-TEST — PASSED IN A REAL FROZEN BINARY

I built an actual PyInstaller **onefile** executable on Linux using the
**same PyInstaller version the Windows build pins (6.11.1)** and the same
hidden-import set minus the `win32*` modules, then ran the acceptance
command from the binary — not from Python.

```
$ NivXForgeEDRSetup-linuxproof journal-selftest
{
  "result": "PASS", "failed": [], "sensor_version": "0.3.0-windows",
  "checks": {
    "frozen": true,                     <-- the real bundle, not Python
    "python_bundled": true,
    "executable": "/tmp/pybuild/dist/NivXForgeEDRSetup-linuxproof",
    "sqlite3_importable": true,
    "sqlite_library_version": "3.40.1",
    "journal_module_importable": true,
    "journal_version": "1.0.0", "schema_version": 1,
    "database_created": true,
    "wal_mode": true,
    "synchronous_full": true,
    "auto_vacuum_incremental": true,
    "schema_initialized": true,
    "durable_commit": true,
    "cursor_committed": true,
    "replay_is_idempotent": true,
    "integrity_snapshot": true,
    "gap_contract": true
  }
}
exit 0
```

Binary contents confirmed by byte scan: `_sqlite3` (the native extension),
`sqlite3`, and `nivxforge_journal` are all packed.

| Your requirement | Result | Scope |
|---|---|---|
| `frozen = true` | **TRUE** | Linux bundle |
| `SQLITE_IMPORT` | PASS | Linux bundle |
| `SQLITE_LIBRARY_VERSION` | PRESENT — 3.40.1 | Linux bundle |
| `JOURNAL_MODULE` | PASS | Linux bundle |
| `DATABASE_CREATE_OPEN` | PASS | Linux bundle |
| `JOURNAL_MODE_WAL` | PASS | Linux bundle |
| `SYNCHRONOUS_FULL` | PASS | Linux bundle |
| `AUTO_VACUUM_INCREMENTAL` | PASS | Linux bundle |
| `SCHEMA_TABLES` | PASS | Linux bundle |
| `DURABLE_COMMIT` | PASS | Linux bundle |
| `CURSOR_COMMIT` | PASS | Linux bundle |
| `REPLAY_IDEMPOTENCY` | PASS | Linux bundle |
| `INTEGRITY_SNAPSHOT` | PASS | Linux bundle |
| `GAP_CONTRACT` | PASS | Linux bundle |

### What this DOES prove

The freeze *mechanism* is sound. The hidden-import list is right, the
selftest is real and exits non-zero on failure, `sys.frozen` detection
works, PyInstaller 6.11.1 packs the stdlib `sqlite3` package **and its
native extension** without extra hooks, and WAL + `synchronous=FULL` +
`auto_vacuum=INCREMENTAL` all behave inside a bundle.

### What this does NOT prove — and I am not claiming it does

A different bootloader, a different native artifact (`_sqlite3.pyd` +
`sqlite3.dll`), NTFS rather than ext4, and the Windows **service** context
(LocalSystem, `C:\ProgramData` ACLs) are all untested. Those are exactly
what your `windows-latest` run answers. **Windows remains genuinely
unproven, and SQLite support inside the shipped PE remains unproven.**

## 3. ARTIFACT IDENTITY

**This is the Linux proof binary, NOT a shippable artifact. Do not deploy
it anywhere.**

| Field | Value |
|---|---|
| Filename | `NivXForgeEDRSetup-linuxproof` (ELF, onefile) |
| Size | 8,287,536 bytes |
| Sensor version reported | `0.3.0-windows` |
| PyInstaller | **6.11.1** — identical to the version pinned in `build_windows_installer.ps1` |
| Python | 3.11 |
| Build identity | local container build, **not** a CI run; no workflow run id exists |
| Signed | **No** — Windows Authenticode signing is not applicable to an ELF and was not attempted |

`ARTIFACT_SHA256` for the real artifact **does not exist yet**: it is
produced by the Windows run. The Linux proof binary was built into
`/tmp` and is intentionally disposable; the CI workflow is the only place
a hash worth recording can come from. No signing credential or secret was
read, written or printed at any point.

## 4. PACKAGING REGRESSION — PASS, BY DIFF

Measured against `6afab68a`, the commit reviewed in the root-cause report:

```
git diff --numstat 6afab68a -- <file>

Install-NivXForgeSensor.ps1        (no output — byte identical)
build/build_windows_installer.ps1   2  0
nivxforge_setup.py                 75  0
backend/requirements.txt          (no output — byte identical)
```

**Zero deletions and zero modified lines anywhere.** Every change is a pure
addition.

| Protected property | Status | Why |
|---|---|---|
| service identity | UNCHANGED | `nivxforge_setup.py` has 0 deletions; the service class and SCM entrypoint are untouched |
| service permissions | UNCHANGED | installer byte identical |
| installer ACLs | UNCHANGED | installer byte identical |
| sensor state-directory ACLs | UNCHANGED | installer byte identical |
| authentication material handling | UNCHANGED | `identity.json` read path untouched; a test asserts the journal and integrity snapshot contain no credential and no `Bearer` |
| enrollment behaviour | UNCHANGED | enrolment code untouched; existing enrolment suite green |
| tenant binding | UNCHANGED | tenant still comes from the authenticated session; the three new routes are classified in `ROUTE_CLASSIFICATION` |
| startup command | UNCHANGED | installer byte identical; `sensor.run(self.api, self.interval, once=True)` still asserted by `test_windows_installer_scm_entrypoint.py` |
| backend origin | UNCHANGED | installer byte identical |
| signing behaviour | UNCHANGED | build diff is the two `--hidden-import` lines only — no spec, packaging, `--onefile/--onedir` or signing change |
| no new runtime dependency | CONFIRMED | `sqlite3` is stdlib; `requirements.txt` byte identical; the build's `pip install` list is still `pyinstaller==6.11.1 pywin32==308` |

PyInstaller 6.11.1 was installed **in this container only**, to build the
proof binary. It was deliberately **not** added to `requirements.txt`.

The three existing installer suites
(`test_windows_installer_v1.py`, `test_windows_installer_service_stage4.py`,
`test_windows_installer_scm_entrypoint.py`) are green, so these properties
are guarded by tests and not only by a diff.

## 5. INGEST COST PROFILE — MEASURE ONLY

`scripts/b5gap1_ingest_cost_profile.py` plus a pymongo `CommandListener`,
against the real local MongoDB, warmed first so this is steady state and
not a first-call rule load. **No semantics were changed.**

### The counter hypothesis was WRONG. The measurement says so.

```
ingest per accepted event            30.3 ms
  Mongo commands                     19
  time in Mongo                      24.6 ms  (81.4%)
  everything else (CPU)               5.7 ms  (18.6%)

delivery-counter writes               3 of 19 commands
delivery-counter cost              1.25 ms  ->  3.8% of ingest
```

Stage timings (separate run, N=60):

| Stage | Calls/event | ms/event | Share |
|---|---|---|---|
| canonical bridge | 1 | **30.7** | ~90% |
| delivery counters | **3** | **1.25** | **3.8%** |
| `raw.append` | 1 | 1.01 | 3.0% |
| `store.mark_reported` | 1 | 0.49 | 1.4% |
| `store.get_endpoint` | 1 | 0.42 | 1.2% |

Mongo commands per accepted event:

```
update    edr_delivery_counters      3    <- the suspected culprit
findAndModify edr_raw_events         1
insert    edr_raw_events              1
update    edr_raw_events              2
find      edr_raw_events              1
find      edr_endpoints               1
update    edr_endpoints               1
find      v2_shadow_observations      1
insert    v2_shadow_observations      1
insert    xdr_canonical_evidence      1
aggregate xdr_correlation_rules       1    <- per EVENT
find      xdr_correlation_rules       1    <- per EVENT
(+ ~4 further commands outside the top 12)
--------------------------------------------
19 commands, 24.6 ms
```

`cProfile` independently agrees: 0.726 s of 1.189 s across 25 events was
`select.epoll.poll` — **I/O wait, not CPU**. It also showed YAML scanning
and regex compilation, consistent with the per-event
`xdr_correlation_rules` reads.

### Proposed optimisation — and an explicit recommendation NOT to do the obvious one

**Do NOT batch the delivery counters on their own.** At 3.8% it would
recover ~1.25 ms of 30.3 ms. It touches the acceptance path for a
rounding error. Your instinct to measure first was correct and it is what
stopped this.

Ranked by measured value, none implemented:

1. **Cache the correlation rule set (2 commands/event, `aggregate` + `find`
   on `xdr_correlation_rules`).** Rules are configuration, not evidence;
   reading them per event is the clearest waste, and it also explains the
   YAML/regex work. A process-level cache with an explicit invalidation
   would remove ~2 of 19 commands and the parse cost. **Best
   value-to-risk of the three; needs a correctness decision about how
   quickly a rule edit must take effect.**
2. **Reduce the `edr_raw_events` command count (5/event: findAndModify +
   insert + 2 updates + find).** This is the append-then-append-derivation
   pattern. Any change here touches the **immutable raw-bytes and dedup
   guarantee**, so it needs its own design review — not a quick win.
3. **Aggregate the 3 counter writes into 1 per event, or 1 per batch**
   (`counters.record` already accepts a `Dict[str, int]` of deltas, so the
   mechanism exists). Worth ~1.25 ms/event, ~4%. Only worth doing
   **alongside** item 1, never as the headline.

Combined, items 1 and 3 plausibly take 19 commands → ~16 and 30.3 ms →
~27 ms, roughly +12%. That is real but it is **not** the order-of-magnitude
some of the framing implied, and it is much smaller than the transport win
already banked (5.7 → 48.3 ev/s).

**Constraints I did not touch and would not:** counters stay operational
metrics, already stamped `authority: SERVER_OBSERVED` and
`evidence_authority: false`. Batching them must not change *when* an event
is considered accepted — per-event acceptance is the only reason batch
delivery is safe.

**A caveat on all of the above:** 30.3 ms is **local loopback** against a
single-node preview MongoDB, with no HTTP, no TLS and no auth dependency in
the number. Production Mongo latency, index state and collection sizes
differ. If throughput becomes the binding constraint on the canary, re-run
this profile there before changing anything.

## 6. NO CANARY — CONFIRMED

Not done, and not attempted: install on `DESKTOP-A9HGFJJ`, restart its
sensor, change its Sysmon configuration, alter its `channels.json` or
outbox, migrate its journal, generate endpoint load, or start the canary.

The only endpoint-adjacent writes in this whole pass were to the **preview**
database: two synthetic endpoints in tenant `probe-t-00bf71` from the
earlier latency and contract probes, plus profiling rows under
`ep_profile_b5gap1`. Revoke whenever you like.

## 7. FILES CHANGED IN THIS PASS

| File | Change |
|---|---|
| `scripts/b5gap1_ingest_cost_profile.py` | **NEW** stage + Mongo-command profiler (measure only) |
| `docs/B5_GAP_1_WINDOWS_GATE0_AND_COST_PROFILE.md` | **NEW** this record |

No product code was changed in this pass. The `journal-selftest` command
and the ACCEPTANCE GATE 0 workflow step were added in the previous pass and
are unchanged here.

## 8. WHAT REMAINS TO CLOSE GATE 0

One action, yours: **Save to Github, then run
`windows-sensor-installer.yml` on `windows-latest`.** ACCEPTANCE GATE 0 will
run `NivXForgeEDRSetup.exe journal-selftest` and fail the build unless it
reports `result: PASS` **and** `frozen: true` **and** `wal_mode: true`
**and** `synchronous_full: true`. Capture the artifact SHA256 and the run
id from that job.

When it passes, I would still not go to `DESKTOP-A9HGFJJ` first. Your
instinct on a disposable validation endpoint is right, and the acceptance
procedure in
`docs/B5_GAP_1_PREPROD_HARDENING_GATES_A_D.md` §"PROPOSED ONE-ENDPOINT
CANARY PROCEDURE" is written for exactly that: hammer Sysmon, cut and
restore the backend, restart the service, grow and drain the journal, and
confirm the real frozen executable behaves the way the 89 synthetic tests
say it will.

**STOP FOR OWNER REVIEW.**
