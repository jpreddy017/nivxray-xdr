# B5-GAP-1 · WINDOWS GATE 0 — CI ACCEPTANCE CONTRACT

**Status: `BLOCKED_PENDING_REAL_WINDOWS_CI`**

Gate 0 is **not** closed and is **not** claimed to be closed. This document
defines the deterministic contract that closes it, so the decision is made
from machine-readable Windows evidence instead of a human reading CI logs.

No Linux or non-Windows frozen test is accepted as Gate-0 proof.

---

## 1. WHY THIS EXISTS

The B5-GAP-1 fix depends on an embedded SQLite evidence journal inside the
Windows sensor. Four questions cannot be answered anywhere except on a real
`windows-latest` runner, from the real frozen artifact:

| Question | Only answerable on Windows because |
|---|---|
| Did PyInstaller pack `sqlite3` **and** native `_sqlite3.pyd`? | the bundle is a Windows PE |
| Do `WAL` + `synchronous=FULL` behave on **NTFS**? | filesystem semantics differ |
| Does a WAL **reopen/recover** after close? | NTFS + Windows file locking |
| Can the **service** reach and own its state directory? | Windows ACLs / SCM identity |

The artifact therefore proves these **about itself**, and the job fails
closed on the answer.

---

## 2. HOW GATE 0 IS RUN

```
SAVE CURRENT CODE TO GITHUB
        v
Actions -> "NivXForge Windows Installer (V1)"  (windows-sensor-installer.yml)
        v
workflow_dispatch on windows-latest
        v
Gate 0 · frozen journal selftest (primary + restart process)
        v
Gate 0 · compose machine-readable verdict (fail closed)
        v
artifact: NivXForgeEDRSetup-windows-x64 -> gate0/GATE0_WINDOWS_REPORT.json
```

Two phases, two **separate processes of the frozen executable**:

```powershell
NivXForgeEDRSetup.exe journal-selftest --dir <scratch> --json-out gate0-selftest-primary.json
NivXForgeEDRSetup.exe journal-selftest --dir <scratch> --restart-check --json-out gate0-selftest-restart.json
```

The second invocation re-opens the **same** journal directory in a **new
process**. That is the only honest proof of frozen-executable restart
recovery: a same-process reopen cannot distinguish a recovered WAL from a
warm page cache owned by the original connection.

System Python execution is **not acceptable**: both phases must report
`WINDOWS_FROZEN = TRUE`, and the job fails otherwise.

---

## 3. MANDATORY ASSERTIONS (FAIL CLOSED)

Every field below must be **PRESENT** and exactly `PASS`. A missing field is
a **FAILURE**, never a skip or a warning.

| Field | Proves |
|---|---|
| `WINDOWS_SQLITE` | `import sqlite3` works inside the frozen PE |
| `WINDOWS_SQLITE_LIBRARY_VERSION` | must be PRESENT (not `ABSENT`) |
| `WINDOWS_SQLITE_NATIVE_BINARY` | `_sqlite3` native module is a real file in the bundle |
| `WINDOWS_JOURNAL_MODULE` | `nivxforge_journal` loaded from the bundle |
| `WINDOWS_NTFS_DATABASE_CREATE` | DB created on a volume whose FS is `NTFS` |
| `WINDOWS_WAL_CREATE` | `journal_mode=WAL` **and** a real `-wal` file on NTFS |
| `WINDOWS_WAL_REOPEN_RECOVERY` | reopen recovers cursor + rows, still WAL + FULL |
| `WINDOWS_SYNCHRONOUS_FULL` | `PRAGMA synchronous = 2` |
| `WINDOWS_AUTO_VACUUM_INCREMENTAL` | `PRAGMA auto_vacuum = 2` |
| `WINDOWS_SCHEMA` | `evidence, cursors, acquisition_gaps, integrity, meta` |
| `WINDOWS_DURABLE_COMMIT` | a page commits durably |
| `WINDOWS_CURSOR_COMMIT` | the cursor advances only with the durable page |
| `WINDOWS_REPLAY_IDEMPOTENCY` | a replayed page journals 0 rows |
| `WINDOWS_INTEGRITY_SNAPSHOT` | integrity snapshot written to disk |
| `WINDOWS_GAP_CONTRACT` | gap record shape + `cause = NOT_PROVEN` |
| `WINDOWS_STATE_DIR_ACCESS` | the service state dir is writable |
| `WINDOWS_SERVICE_PERMISSION_CHECK` | SYSTEM/Administrators own it; not world-writable |
| `PACKAGING_REGRESSION` | required modules present **and** resolved inside the bundle |
| `WINDOWS_FROZEN_RESTART` | from the RESTART phase only |
| `WINDOWS_FROZEN` | must be `TRUE` in both phases |

**Packaging regression = FAIL CLOSED.** The job fails if any of
`nivxforge_journal`, `nivxforge_sensor`, `sqlite3`, `_sqlite3` is absent,
resolves from **outside** the frozen bundle, or if the native `_sqlite3`
binary is not a real file inside the bundle.

### Non-Windows honesty rule

Off Windows, the four Windows-only checks report the literal string
`N/A_NON_WINDOWS`. The CI contract demands `PASS`, so a Linux run can never
be mistaken for — or promoted to — Windows evidence.

---

## 4. ARTIFACT IDENTITY CAPTURED

`gate0/GATE0_WINDOWS_REPORT.json` carries, alongside the verdicts:

`ARTIFACT_FILENAME`, `ARTIFACT_VERSION`, `ARTIFACT_SHA256`,
`SERVICE_HOST_SHA256`, `COMMIT_SHA`, `BUILD_WORKFLOW`, `WORKFLOW_RUN_ID`,
`BUILD_TIMESTAMP`, `PYINSTALLER_VERSION`, `SIGNING_STATUS`,
`SCRATCH_FILESYSTEM`, `STATE_DIR`, `SQLITE_RUNTIME_BINARIES`.

No signing secret, no credential, no enrolment token is read or printed. The
build already refuses to finish if anything credential-shaped is found
inside the binary.

---

## 5. WHAT THE OWNER PASTES BACK

The report is printed to the job log, written to the job summary, and
uploaded as an artifact. Paste `GATE0_WINDOWS_REPORT.json` as-is; its
`GATE0_VERDICT` is either:

* `CLOSED_PASS` — every mandatory assertion PASSed on real Windows, or
* `BLOCKED_FAIL` — with a `PROBLEMS[]` list naming each failure.

The report also restates the standing boundary, so the audit trail is in the
artifact itself:

```
CANARY_PLAN_READY             = YES
CANARY_STARTED                = NO
CORRELATION_CACHE_IMPLEMENTED = NO
COUNTER_BATCHING_IMPLEMENTED  = NO
RAW_EVENT_PATH_MODIFIED       = NO
DESKTOP_A9HGFJJ_TOUCHED       = NO
PRODUCTION_DEPLOYED           = NO
```

---

## 6. WHAT IS DELIBERATELY NOT DONE

* No correlation-rule cache (the ~24.6 ms Mongo cost stays as measured).
* No delivery-counter batching (measured at ~1.25 ms/event, ~3.8% — not
  worth a change).
* No modification of the `edr_raw_events` command path.
* No integrity UI work.
* No Sysmon change.
* No canary started, no production deployment, `DESKTOP-A9HGFJJ` untouched.

Optimization decisions wait for **canary measurements on the real Windows
production path** (see `B5_GAP_1_CANARY_PLAN.md`).

---

## 7. LOCAL GUARDS FOR THIS CONTRACT

`backend/tests/edr/test_b5_gap1_windows_gate0_ci_contract.py` proves the
contract itself, not the Windows result: every mandatory assertion is
emitted, Windows-only checks never read `PASS` off Windows, the restart
phase refuses to guess a directory, the primary phase never claims restart
recovery, packaging provenance fails closed, and the workflow asserts every
mandatory field, exits non-zero on a missing/non-PASS field, and publishes
the report.
