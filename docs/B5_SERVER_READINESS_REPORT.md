# B5 · SERVER-SIDE READINESS REPORT

Endpoint UNCHANGED · Sysmon XML UNCHANGED · Sysmon NOT restarted ·
Windows auditing UNCHANGED · 4688/4689 NOT enabled · NOT deployed ·
endpoint hashing NOT implemented · Device Trajectory presentation
UNCHANGED · no historical evidence reconstructed.

## B5_STATUS — COMPLETE, awaiting owner review

## EID5_SERVER_READINESS

Three blocks existed; B5-1 removes the two server-side ones. The
endpoint block (`<ProcessTerminate onmatch="include"/>` = include
nothing) is deliberately left in place.

| plane | before | after |
|---|---|---|
| sensor (`edr_plane/windows_eventlog.py`) | no `("sysmon", 5)` ⇒ `WINDOWS_EVENT_ID_NOT_SUPPORTED` | `("sysmon", 5) → ACTIVITY_PROCESS_TERMINATION` |
| XDR DSM (`detection_content/telemetry/sysmon_dsm.py`) | no `5` in the kind map | `5 → process_exit` |
| CEM kind resolution (`v2/ingestion/canonical.py`) | already `5 → process_exit` | unchanged |

**A new activity class was required, not a reuse of `PROCESS`.** The
PROCESS branch reads `UtcTime` as the process START time; on EventID 5
that same field is the EXIT instant. Reusing the branch would have
recorded an exit as a start — fabricated evidence of when a process
began. `ACTIVITY_PROCESS_TERMINATION` has its own branch and its own
`not_supported` declaration.

**One convergence defect fixed on the way.** The sensor-plane canonical
record stated only the activity CLASS (`"PROCESS"`) and no
`event_type`, so a consumer could not tell a creation from a termination
without re-deriving it from the Event ID — and lifetime resolution needs
exactly that. The sensor plane now states `event_type` from the SAME
vocabulary the XDR plane uses (`SYSMON_KIND` / `WINSEC_KIND`). One fact,
one field name, one source of truth.

## EID5_CANONICAL_CONTRACT

`process_exit`, on both dialects.

**Deliberate, declared deviation from the directive:** you asked for
`process_terminate`. The platform already owns `process_exit` for this
exact fact — it is in the CEM `EVENT_KINDS` enum, it is
`SYSMON_KIND[5]`, it is the reviewed value in the Sysmon event-ID gate
(`tests/edr/test_sysmon_semantics.py`), and `trajectory_window.py` and
`campaign_story.py` already key on it. Adding `process_terminate` would
have created a SECOND name for one fact across five modules — precisely
the dual-vocabulary problem B1 exists to eliminate. The SOURCE's own
class name (`ProcessTerminate`) is preserved in provenance
(`sysmon:UtcTime (EventID 5)`, `winlog.provider`/`event_id`), so nothing
about the source is lost. **If you want the literal rename it should be
its own governed change across the enum, the gate, the trajectory schema
and both consumers — say so and I will do it as a single reviewed
commit.**

Preserved from the record, and nothing else:

| field | value | provenance |
|---|---|---|
| `process.process_guid` | ProcessGuid | `sysmon:ProcessGuid` |
| `process.pid` | ProcessId | `sysmon:ProcessId` |
| `process.executable_path` | Image | `sysmon:Image` |
| `process.exit_time` | UtcTime | `sysmon:UtcTime (EventID 5)` |
| `identity.username` | User | — |
| `event_time` | UtcTime | event-time-basis declarations |

NOT carried over from the creation event, and declared absent:
`CommandLine`, `Hashes`, `ParentProcessGuid`, `ParentImage`,
`process.start_time`. Declared unsupportable by this event class:
`process.exit_code`.

## PROCESS_TERMINATION_IDENTITY_RESULT

Bound through `ProcessGuid`: the exit resolves to the **same
`process_key`** as the creation, with `SOURCE_PROCESS_GUID` authority.
Lifetime moves `PROCESS_LIFETIME_UNKNOWN` → `PROCESS_TERMINATION_OBSERVED`
only on collected evidence, and the termination timestamp is the EID 5
`UtcTime`. An exit with no authoritative identity resolves to
`PID_ONLY_NOT_AUTHORITATIVE`, mints no key, and **does not terminate
anything** — regressed explicitly. Later activity of any other kind still
never becomes a termination.

## PID_REUSE_TEST · TENANT_ISOLATION_TEST

* same PID, two ProcessGuids, exit for the second: the second is
  `PROCESS_TERMINATION_OBSERVED`, the first stays
  `PROCESS_LIFETIME_UNKNOWN`, and `pid_reuse` reports the collision;
* an exit carried under another tenant resolves to a different
  `process_key` and leaves this tenant's process UNKNOWN;
* read path: an unowned tenant scope returns 0 devices (unchanged
  fail-closed), and the opaque cross-tenant refusal is untouched.

## READ_PATH_PRE_POST

Root cause: two unfiltered reads of a 606 MB / 264,241-document store —
`list_devices()` (full documents) and `observations()` (full scan then
filtered **in Python**). Fix: the directory read is projected to the
fields it actually consumes; `observations()` asks the database which
observations address the endpoint, using the indexes that already
existed (`obs_deviceiid_ts`, `obs_computer_ts`, `obs_hostname_ts`,
`obs_connector_ts`, `obs_collector_ts`).

Case-sensitivity was the trap: `_addresses()` compares
case-insensitively and an indexed `$in` does not. So the needles are
taken FROM THE STORE — an indexed `distinct` per reference field (63
device iids, 62 computers; 0.18 s for all eight) filtered
case-insensitively — and `_addresses()` **remains** the admissibility
authority. The query narrows the candidate set; it never decides
membership.

Measured (`scripts/b5_read_path_proof.py`, real store):

| measurement | PRE | POST |
|---|---|---|
| directory-wide `observations()` for all 62 devices | 298,006 ms | **23,196 ms · 12.8×** |
| busiest device · docs examined vs returned | 264,241 examined for 256,418 returned | **256,418 / 256,418 — index-only**, 387 ms |
| unresolved endpoint | 4,450 ms | **167 ms** |
| `GET /api/edr/device-trajectory` (unresolved) | 14.31 s | **3.54 s** |
| `GET /api/edr/device-trajectory` (real device, 24 h) | 14.30 s | **3.59 s** |
| `GET /api/edr/campaign-story` | 11.26 s | 10.99 s |
| tenant isolation · unowned scope | 0 devices | **0 devices** |

## TRAJECTORY_SEMANTIC_EQUIVALENCE

The proof script re-implements the ORIGINAL unfiltered-scan behaviour
verbatim and compares per device across the whole directory.
**61 of 62 devices: identical count and identical evidence digest.**

The single difference was the one continuously-ingesting device
(256,408 vs 256,412) and is **live-write drift, not semantics**: three
alternating rounds gave `POST ≤ PRE ≤ POST` monotonically
(256,420 ≤ 256,432 ≤ 256,432), and in the two quiet rounds
**PRE == POST == POST2 == 256,434 exactly**.

Unchanged: response shape, lane semantics, observation identity, time
semantics (`since_iso` is still applied exactly where it was, in
Python), tenant isolation, endpoint authority, opaque cross-tenant
refusal, evidence counts and content. No schema change, no migration, no
new index, no Device Trajectory presentation change.

## FILE_HASHING_SENSOR_CONTRACT

`docs/B5_FILE_HASHING_SENSOR_CONTRACT.md` — the six approved defaults
converted into an explicit state machine
(`FILE_CREATE → eligibility → settle → identity revalidation → hash
attempt → SHA-256 + provenance OR explicit failure state`), 14 terminal
states, the additive `file.content_acquisition` field block, and named
handling for deletion-before-hash, rename/move, repeated writes,
locked/access-denied, oversized, rate limiting, TOCTOU/changed content,
unsupported type and excluded privacy paths.
`PROCESS_IMAGE_SHA256` and `FILE_CONTENT_SHA256` remain different
observable subjects, in different canonical blocks, with an acceptance
test that the writer's image hash never appears in `file.hashes`.
**Not implemented.**

## DELIVERY_FIDELITY_TEST_PLAN

`docs/B5_DELIVERY_FIDELITY_TEST_PLAN.md` — prepared, **not executed**.
Five separately-counted boundaries (endpoint generated → sensor observed
→ sensor sent → backend accepted/refused → canonicalized), per Sysmon
Event ID, for one agreed 60-minute UTC window. No boundary is inferred
by subtraction. Includes a retention guard (re-read the oldest retained
record AFTER the run; a newer value invalidates the run — the exact trap
that destroyed the September evidence), a config-stability check
(EventID 16 / Security 1102 inside the window), and dedupe counted
separately from refusal. If the sensor cannot expose per-channel
read/sent counters, the plan reports `SENSOR_COUNTERS_NOT_AVAILABLE`
rather than guessing — that gap is itself the first finding.

## FILES_CHANGED

Modified
* `backend/edr_plane/windows_eventlog.py` — `ACTIVITY_PROCESS_TERMINATION`, `("sysmon", 5)`, the termination branch, its `not_supported`, `observed_kind`
* `backend/edr_plane/canonical_bridge.py` — sensor-plane `event_type`
* `backend/detection_content/telemetry/sysmon_dsm.py` — `5 → process_exit`
* `backend/services/edr/device_identity.py` — `_REFERENCE_FIELDS`, `_DIRECTORY_PROJECTION`, `_stored_spellings()`, indexed `observations()`, projected directory read
* `backend/tests/edr/test_p1_10b_process_evidence_honesty.py` — the collection test-double models `distinct` (semantics under test unchanged)

Added
* `backend/tests/edr/test_b5_process_termination.py` (18)
* `backend/scripts/b5_read_path_proof.py`
* `docs/B5_FILE_HASHING_SENSOR_CONTRACT.md`
* `docs/B5_DELIVERY_FIDELITY_TEST_PLAN.md`
* `docs/B5_SERVER_READINESS_REPORT.md`

## TESTS

`pytest backend/tests/edr tests/test_ingestion_phase4.py
tests/test_w1_sysmon_field_preservation.py` → **1,757 passed, 0 failed,
3 skipped.**

The two live-API tests that failed before B5 now PASS — the read-path
fix removed the timeout that caused them, so that regression is closed
honestly rather than by weakening a test.

Two failures remain in `tests/test_v2_framework.py`
(`test_stub_detect_returns_zero`, `test_v2_modules_do_not_import_engine`)
and are **PRE-EXISTING**: reproduced at HEAD with all four B5 source
files stashed. They concern the v2 adapter feature-flag default and the
v2/engine namespace-isolation walk — unrelated to B5, not touched.

## CODE_CHANGED · DATA_CHANGED · ENDPOINT_CHANGED · DEPLOYED

Code: **yes, backend only.** Data: **no** (no migration, backfill,
rewrite or delete; only the pytest suite wrote, into `test_database`).
Endpoint: **NO.** Deployed: **NO.**

## BLOCKERS

1. Owner: accept `process_exit` as the canonical kind, or authorise the
   `process_terminate` rename as its own governed change.
2. Owner authorisation for the one-line Sysmon `ProcessTerminate`
   change. The server is now ready, so it will canonicalise the moment
   it arrives. Until then every process stays honestly
   `PROCESS_LIFETIME_UNKNOWN`.
3. `campaign-story` is still 11 s. It is NOT the directory scan (that
   read is now 1.2 s) — the cost is inside the story engine and was out
   of scope for B5-2. Needs its own measured pass.
4. B3 file hashing stays unimplemented pending your approval of the
   sensor contract.
5. The delivery-fidelity run needs sensor per-channel read/sent counters
   to measure boundaries B1 and B2; otherwise those two are reported as
   not measurable.

## NEXT_OWNER_ACTION

Review this report, then authorise (a) the Sysmon `ProcessTerminate`
one-liner and (b) the first delivery-fidelity run with the endpoint
unchanged — in that order, endpoint after server.
