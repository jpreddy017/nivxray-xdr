# Live Query · one question, answered live

Tested commit: **`9d91bdf8`** · preview
`https://greeting-app-5782.preview.emergentagent.com/edr/live-query`
(customer *Preview Runtime (legacy default)* = tenant `default`).
Production promotion remains on hold.

Screenshots: `live-query-match-result.jpeg` · `live-query-dashboard-history.jpeg`

## What it asks

> Which running processes match this exact name on this computer now?

Answered by the endpoint when it claims the query. Stored telemetry is never
searched: polling records when a process was **first observed**, which cannot
say what is running at this moment. Each request collects afresh — a previous
answer is never handed back, because "now" changes.

## Live acceptance, on the running preview sensor

| Check | Query id | Result |
|---|---|---|
| Known match (`mongod`) | `cmd_d06cb2cb12c84852a716` | ANSWERED · MATCHES — 1 of 29 examined, pid **291**, `/usr/bin/mongod`, collected 2026-11-03 15:29:34Z |
| Earlier match via API | `cmd_185ec0f120f44456826e` | 1 of 24 examined, same pid/path, collected 15:25:57Z |
| Zero matches (`definitelynotaprocess`) | `cmd_7deb0e118bc54ea586f1` | ANSWERED · NO MATCHES — 0 of 24 examined, compared as `definitelynotap` |
| Same completed id on both surfaces | `cmd_d06cb2cb12c84852a716` | shown on the selected computer **and** in Dashboard history with the same name asked, computer and match count |
| Cross-customer by id | — | `404 QUERY_NOT_FOUND` — "a query id is not a capability" |
| Cross-customer by list | — | `nivx-live` sees 0 queries |
| Empty name | — | `400 EMPTY_PROCESS_NAME` — "nothing was asked of the endpoint" |

**Live** = the four rows above involving a query id, plus both cross-customer
checks and the empty-name refusal, all run against the preview API and the
running Linux sensor. Zero-matches was also proved live, not only in fixture.

## The limit that shapes every answer

Linux stores a process name in `/proc/<pid>/comm`, truncated by the kernel to
**15 characters**. A longer name is therefore compared on its first 15, and the
answer says so (`compared as definitelynotap`, with the basis spelled out).
A truncated comparison is never presented as an exact one.

## States, kept apart

| Status | Meaning shown to the analyst |
|---|---|
| QUEUED / RUNNING | recorded, or claimed and not yet answered — says nothing about what is running |
| COMPLETED_WITH_MATCHES | the endpoint ran the query and found matches |
| COMPLETED_NO_MATCHES | "That is an answer — the process is not running under this name right now — not a failure and not a timeout", with the number of processes actually examined |
| FAILED | the endpoint attempted the query and it did not complete |
| CAPABILITY_UNAVAILABLE | an older sensor cannot answer; **stored telemetry was NOT used in its place** |
| TIMED_OUT | no answer within 180s; "nothing is claimed about what is running" |

## Plane

- `LIVE_QUERY_PROCESS_NAME` added to `response.COLLECTION_ACTIONS` and to
  `authority.PERMISSION_ONLY_VERBS` — permission-gated, audited, never
  approval-gated, and never marked VERIFIED.
- Routes `POST/GET /api/edr/live-query/queries`, `GET …/{query_id}`, scoped by
  the server-resolved customer.
- Redelivered answers return the original query and rows unchanged (one
  document, proved in fixture).
- Entry points: **Dashboard → Live Query** (history for the customer) and
  **Computer → Actions → Live Query** (that computer preselected). Forensic
  Snapshots remains reachable from the Dashboard.

## Tests

- backend `tests/edr/test_live_query.py` → **10 passed**, disposable database
  dropped after the run; with snapshots, **21 passed** together.
- frontend **30 files / 437 tests** passed, including the question/target
  display, truncation wording, the no-matches message, the unsupported-sensor
  path, both entry points and the refusal path.

## Next

Dashboard Board, with the five settled decisions: landing page only;
telemetry-backed widgets plus one coverage section; persistent per-detection
Inbox triage; 30-day UTC default with a 14-day preset and custom dates;
optional 60-second refresh showing the last successful refresh time. Snapshot
Diff and the canonicalisation eligibility trace stay deferred.
