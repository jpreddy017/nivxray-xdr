# Forensic Snapshots · one real capture, end to end

Tested commit: **`95f81a2a`** · preview
`https://greeting-app-5782.preview.emergentagent.com/edr/forensics`
(customer *Preview Runtime (legacy default)* = tenant `default`).
Production promotion remains on hold.

Screenshots in this directory:
`forensic-snapshot-actions-menu-771cecf2.jpeg` ·
`forensic-snapshot-computer-result-771cecf2.jpeg` ·
`forensic-snapshot-dashboard-history-771cecf2.jpeg`

## The live capture

Requested from **Computer → Actions → Request forensic snapshot** on
`ep_2d57cbe6f80152062109` and followed through to its rows:

| | |
|---|---|
| Job id | `cmd_b3e31417ab4245bc8ff6` |
| Requested by | `admin@nivxray.com` |
| Requested (UTC) | 2026-11-03 15:12:11Z |
| Capture start / finish (UTC) | 2026-11-03 15:12:26Z / 15:12:26Z |
| Rows | **30** process rows (pid · name · path) |
| Sensor | 0.2.0 |
| Status | COMPLETED · ROWS RETURNED |

The **same job id** appears in Dashboard → Forensic Snapshots history with the
same requester, computer and row count. Both entry points address one record:
the job id *is* the response-plane command id, so there is no second store to
drift.

## Sensor change

`agents/nivxforge-linux/nivxforge_sensor.py`

- `CAPABILITIES["collection_actions"] = ["COLLECT_PROCESS_SNAPSHOT"]`, declared
  apart from `response_actions` because it changes nothing.
- `_collect_process_snapshot()` walks `/proc` when the command is claimed and
  returns, per row, `pid`, `name` (`/proc/<pid>/comm`) and `path`
  (`/proc/<pid>/exe`). A path that cannot be read carries
  `path_unavailable: <error>` instead of appearing blank. Rows are capped at
  5,000 and the cap is reported.
- Evidence carries `capture_started_at` / `capture_finished_at` in UTC, the row
  count, the sensor version, and `not_observed`: command line, user, start
  time, image digest, and processes that started or exited during the walk.
- A snapshot is **never sent for verification**: the rows are the evidence, and
  a second `/proc` read cannot prove what the first one saw.
- An older sensor has no such action and returns `FAILED · unknown action`,
  recorded as `CAPABILITY_UNAVAILABLE`. **Stored telemetry is never used to
  answer in its place** — polling records when a process was first observed,
  which cannot establish the set that existed at capture time.

## Plane and scope

- `COLLECT_PROCESS_SNAPSHOT` added to `edr_plane/response.py ACTIONS` as a
  `COLLECTION_ACTION`, and to `authority.PERMISSION_ONLY_VERBS` with basis
  `READ_ONLY_COLLECTION_PERMISSION_ONLY` — permission-gated, audited, never
  approval-gated.
- Routes: `POST /api/edr/forensics/snapshots`, `GET …/snapshots`,
  `GET …/snapshots/{job_id}`, all scoped by the server-resolved customer.

## Status matrix, as required

| Status | Where proved | Behaviour |
|---|---|---|
| QUEUED | fixture + live | recorded; "says nothing about what is running on it" |
| RUNNING | fixture + live | claimed by the endpoint, no result yet |
| COMPLETED_WITH_ROWS | **live** `cmd_b3e31417ab4245bc8ff6` | 30 rows with capture window |
| COMPLETED_ZERO_ROWS | fixture | "an empty result, not a failure, and not a timeout" |
| FAILED | fixture | distinct from zero rows |
| CAPABILITY_UNAVAILABLE | fixture | older sensor; history NOT used instead |
| TIMED_OUT | **live** `cmd_8f07875923d34708ab3f` | unanswered after 180s |
| Retry of delivery | fixture | original job and rows returned unchanged, one document |
| Cross-customer by id | **live** | `404 SNAPSHOT_NOT_FOUND` — "a job id is not a capability" |
| Cross-customer by list | **live** | `nivx-live` sees 0 jobs; its sensor cannot claim the command |

## The defect the live run caught, which no test did

The new redelivery guard matched the `sensor_result: None` placeholder every
command is created with, so the **first real result was swallowed as a replay**
and the job sat at `DISPATCHED` until it timed out. That job
(`cmd_8f07875923d34708ab3f`) is still visible in preview history as TIMED OUT —
left there deliberately as evidence of the state. The guard now requires an
actual reported outcome, and `test_redelivery_preserves_the_original_job_and_result`
covers it.

## Against Cisco's snapshot

Cisco's is Orbital/osquery and returns loaded modules, logged-in users, open
network ports, wireless networks and shell history; its console keeps a
snapshot for two days and offers it from a camera on the event row.

Ours now lists all eight sections with COLLECTED / NOT_COLLECTED and a reason
for each, so the difference is readable rather than inferred:

```
▪ Running processes · 30   pid, name and executable path from one /proc walk
▫ Logged-in users          not collected by this sensor
▫ Open network ports       not collected on demand; connections not collected at all
▫ Loaded modules           not collected by this sensor
▫ Wireless networks        not collected by this sensor
▫ Shell history            not collected by this sensor
▫ Scheduled tasks/services not collected by this sensor
▫ Memory image             never collected; a snapshot is metadata, not a memory dump
```

Retention is stated: no retention job runs in this preview, so jobs are kept
until the database is cleared. The event menu now also offers the capture,
worded "Forensic snapshot of this computer (captures it now)". The duplicate
approval-only "Take Forensic Snapshot" stub was removed — two doors to one
action, one of which collects nothing, is worse than none. The sidebar entry is
no longer badged N/I and reads **Forensic Snapshots**.

## Tests

- backend `tests/edr/test_forensic_snapshots.py` → **11 passed** (disposable
  database, dropped after each run; no preview data written, no endpoint
  enrolled beyond the one already running).
- frontend **29 files / 429 tests** passed, including both entry points, every
  status wording, and the refusal path.

## Next in sequence

Dashboard → Live Query, also reachable from a selected computer. The
raw-to-canonical gap dashboard stays deferred until record eligibility is
checked.
