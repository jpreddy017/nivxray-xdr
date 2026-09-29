# WAVE B · FOUNDATION REPORT (B1 → B4)

Measured, not asserted. Every number below comes from
`backend/scripts/wave_b_foundation_measure.py` (read-only) over the real
corpus `ten_f1a5479243e901cf159e230fa0` / `DESKTOP-A9HGFJJ`, 3,299
canonical observations — full output in
`docs/WAVE_B_FOUNDATION_MEASUREMENT.json`.

Device Trajectory untouched. Nothing deployed. No endpoint changed. No
historical evidence rewritten.

---

## WAVE_B_STATUS

### B1_NORMALIZER_CONVERGENCE

**CANONICAL_AUTHORITY** — `xdr_canonical_evidence` remains the evidence
authority. `v2_shadow_observations` is a DERIVED read model produced by
exactly one projection, `v2/ingestion/telemetry_bridge.observation_doc()`
→ `v2/ingestion/canonical.ces_to_cem_dict()`. Both writers
(`edr_plane/canonical_bridge.py` sensor plane, `routers/xdr_ingest.py`
DSM plane) go through that one function; no second projection was
created and none was found.

**FIELDS_PRESERVED** (measured present-in-canonical → present-in-projection)

| canonical field | in canonical | in projection | lost |
|---|---|---|---|
| `process.process_guid` | 3295 | 3295 | 0 |
| `process.field_provenance` | 3295 | 3295 | 0 |
| `process.command_line` | 16 | 16 | 0 |
| `process.original_file_name` | 16 | 16 | 0 |
| `process.hashes.sha256` | 16 | 16 | 0 |
| `process.hashes.md5` | 16 | 16 | 0 |
| `process.parent_process_guid` | 16 | 16 | 0 |
| `process.parent_command_line` | 16 | 16 | 0 |
| `process.parent_executable_path` | 16 | 16 | 0 |
| `process.ppid` | 16 | 16 | 0 |
| `file.path` | 107 | 107 | 0 |
| `file.field_provenance` | 107 | 107 | 0 |
| `file.hashes.sha256` | 0 | 0 | — (see B3) |

Also preserved and verified by regression: `observation_id`,
`tenant_id`, `endpoint_id`, source identity (provider / channel /
event-id / record-id + the BASIS of each), `observed_at`, `event_type`,
`ProcessId`, `Image`, `User`, raw-evidence reference.

**Six real losses were found and fixed** (all were live before this
wave):

1. `process_guid` / `parent_process_guid` — used only to derive an
   internal `iid` and then DISCARDED. The source's own process identity
   never reached a consumer. B2 would have been impossible.
2. `original_file_name` — absent from CES entirely. Every masquerading
   detection reads it; a renamed binary was indistinguishable from its
   real name downstream.
3. `parent_command_line` — absent from CES entirely.
4. `parent_image` — only the BASENAME survived; the full parent path was
   dropped.
5. `parent_pid` — the projection read only the sensor dialect's
   `parent_pid` and never the DSM dialect's `ppid`, so **every**
   DSM-normalised Sysmon event lost its parent PID.
6. `field_provenance` — dropped wholesale. A preserved value could not
   be traced to the wire field that produced it.

Plus two convergence defects where the SAME fact arrived differently on
the two dialects:

7. **Hash case** — the sensor plane stored `SHA256=9F86…` verbatim while
   the DSM plane stored `9f86…`. An IOC/reputation lookup keyed on the
   lower-case form matched on one path and silently missed on the other.
   Now lower-cased at the source adapter (lossless for hex).
8. **Provenance coverage** — the sensor plane recorded
   `field_provenance` for `process_guid` only; the DSM plane recorded it
   for hashes, command line, parents. Now both record it for every field
   they map.

And one semantic hazard removed: `raw.sha256` is the observation's OWN
content digest, not a file hash. It is now also exposed as
`raw.content_digest_sha256`; the historical name is retained so nothing
breaks, and the regression pins that it is NOT the process-image hash.

**FIELDS_STILL_LOST** — `{}` (measured: `B1_fields_still_lost` is empty
over all 3,299 observations).

Not lost but worth stating: `network.dns_response_ips[]` is projected as
a joined `dns_answer` string; the structured list survives in the `dns`
block. Richer network fields (bytes, duration, community_id) are carried
in canonical evidence and not yet mirrored into `raw` — they are not
security-semantic losses for B1's scope and are listed here so the gap
is on the record rather than implied.

**DUPLICATE_AUTHORITIES_REMOVED** — none existed to remove; the
projection was already single. The DUPLICATE VOCABULARIES were removed
(hash case, provenance coverage, `parent_pid`/`ppid` dialect split).

**B1_TESTS** — `backend/tests/edr/test_b1_normalizer_convergence.py`,
51 tests, all green. It runs the SAME field inventory over BOTH canonical
dialects, asserts the values are the source's values (not placeholders),
and includes a negative control: a sparse Sysmon EID 1 must NOT acquire
fields the source never stated.

**B1_DECISION** — **ACCEPTED.** Canonical evidence reaches the read model
with no security-semantic loss on any field measured.

---

### B2_PROCESS_IDENTITY

**PROCESS_IDENTITY_AUTHORITY** — `backend/edr_plane/process_identity.py`.
Ladder, in order:

```
SOURCE_PROCESS_GUID          tenant + native ProcessGuid      AUTHORITATIVE
ENDPOINT_PID_START_TIME      tenant + endpoint + pid + start  AUTHORITATIVE
PID_ONLY_NOT_AUTHORITATIVE   pid alone → NO KEY IS MINTED     context only
NOT_OBSERVED                 no process named                 —
```

A PID-only observation returns `process_key = None`. It cannot be merged
into a process and cannot be used for attribution — by construction, not
by convention. Tenant and endpoint are identity boundaries (regressed).

Measured on the real corpus: **54 processes, 54/54 by
`SOURCE_PROCESS_GUID`**, 4 unattributed observations, 3,295/3,299
observations carrying a native process identity.

**PID_REUSE_RESULT** — handled and REPORTED. Two observations sharing a
PID but not a lifetime resolve to two process keys, and
`pid_reuse_report()` names every `(endpoint, pid)` that carried more than
one process. Measured on this corpus: **0 reuse cases** — the corpus
window is 63 minutes, so this is a true negative, not a proof of the
mechanism. The mechanism is proven by regression instead.

**PARENT_IDENTITY_RESULT** — parentage is SOURCE-STATED or it does not
exist:

| basis | meaning | resolved? |
|---|---|---|
| `PARENT_STATED_BY_SOURCE_PROCESS_GUID` | source named the parent's native identity | YES — resolves to the parent's own key |
| `PARENT_STATED_BY_SOURCE_PID_ONLY` | source named a parent pid/image only | NO — described, never joined on PID |
| `ROOT_KERNEL_BOUNDARY` | parent pid 0/4 | real root, not a missing parent |
| `PARENT_NOT_OBSERVED` | source stated nothing | no edge emitted |

Measured: **16 relationships, 16/16 by `ParentProcessGuid`.** Every edge
retains `evidence_refs[]` and its derivation basis. Regressions pin that
nothing is inferred from timestamp proximity, filename, or row adjacency.

**TERMINATION_SEMANTICS** — four distinct states:
`PROCESS_START_OBSERVED`, `PROCESS_TERMINATION_OBSERVED`,
`OBSERVED_EVIDENCE_SPAN` (reported as `observed_evidence_span`, labelled
"NOT the process lifetime"), `PROCESS_LIFETIME_UNKNOWN`. Termination
comes only from a collected `process_exit` event; `last_seen` is never
read as an exit.

Measured: **54/54 processes = `PROCESS_LIFETIME_UNKNOWN`.** Cause is a
SENSOR fact, not an engine gap: Sysmon EventID 5 is absent from this
corpus (histogram: 13×2335, 12×766, 11×107, 3×70, **1×16**, 22×1, no 5).
Also fixed: Windows Security **4689** was missing from `WINSEC_KIND`, so
a collected process termination resolved to
`unclassified_telemetry` and could not be recognised as a termination at
all. It now maps to `process_exit` (an observation, not a claim) and the
event-ID review gate was updated with the reasoning.

**B2_TESTS** — `backend/tests/edr/test_b2_process_identity.py`, 20 tests,
green. Includes: the GUID/PID/start ladder, PID-only refusal, PID reuse,
tenant and endpoint boundaries, parent-by-GUID resolving to the parent's
own key, parent-by-PID refusing to resolve, kernel boundary, "no
parentage from proximity", the three lifetime states, and identity
resolving IDENTICALLY from canonical evidence and from the B1
projection.

**B2_DECISION** — **ACCEPTED**, with one honest limitation: PID-reuse and
termination behaviour are proven by regression, NOT by real data,
because this corpus contains neither. Real-data proof needs Sysmon
EventID 5 (and/or 4689) collection — pending the Windows PRE-check.

---

### B3_FILE_IDENTITY

**PROCESS_IMAGE_HASH_STATUS** — **PRESENT AND PRESERVED. Nothing was
rebuilt.** 16/16 `process_create` observations carry MD5 + SHA-256 with
`field_provenance` citing `sysmon:EventData.Hashes`, and B1 now proves
they survive projection. Exposed as its own object
(`process_image_identity()`, `hash_class = PROCESS_IMAGE_HASH`) so it
cannot be misread as a file's content identity.

Measured `process_image_hash_state` across all 3,299: `HASH_OBSERVED`
16, `HASH_NOT_OBSERVED` 3,281, `HASH_NOT_APPLICABLE` 2.

**FILE_CREATE_HASH_STATUS** — **0 of 107.** Measured:

```
file_observations           107
with_any_hash                 0
with_sha256                   0
content_identified            0
path_identity_only          107
with_size                     0
with_source_stated_writer   107
```

Sysmon EventID 11 states the path, the writing process and the time. It
states no hash and no size. So for every written file in this corpus the
CONTENT was never identified: `HASH_NOT_OBSERVED`,
`PATH_IDENTITY_ONLY`. No file hash was invented, and the writing
process's image hash is NOT promoted to the file (regressed twice, once
with the writer's hash deliberately placed on the same event).

**FILE_ENTITY_CONTRACT** — `backend/edr_plane/file_identity.py`:

```
PROCESS IMAGE HASH  !=  FILE-CREATE HASH  !=  FILE CONTENT IDENTITY
```

identity ladder: `CONTENT_IDENTITY_SHA256` → `CONTENT_IDENTITY_NON_SHA256_ONLY`
→ `PATH_IDENTITY_ONLY`. SHA-256 is the primary content identifier where
obtainable; a weak-hash-only file is admitted as a join key and
explicitly NOT claimed as SHA-256 identity; a path-only file can never
present a name match as a content match. The writer is accepted only as
`SOURCE_STATED_ON_FILE_EVENT` — never from proximity.

**HASH_NOT_OBSERVED_SEMANTICS** — one vocabulary, in one place
(`v2/ingestion/canonical`): `HASH_OBSERVED`, `HASH_NOT_OBSERVED`,
`HASH_NOT_APPLICABLE` (no file and no process image on this observation
at all — absence there is not a gap). The read model carries the state
per object: `raw.file.hash_state`, `raw.process_image_hash_state`, and
`artefacts.file[].hash_state`.

**SENSOR_HASHING_REQUIRED** — **YES, if created-file content identity is
wanted.** It cannot be obtained from the current telemetry. Designed, not
implemented: `docs/B3_SENSOR_SIDE_FILE_HASHING_DESIGN.md` — acquisition
pipeline, 10 explicit acquisition-outcome states, eligibility/exclusion
gate, TOCTOU and `content_version_state` classification
(`STABLE_DURING_ACQUISITION` / `CHANGED_DURING_ACQUISITION` /
`CHANGED_SINCE_EVENT` / `CONSISTENT_WITH_EVENT`), rename/move/delete
semantics, repeated-write coalescing, locked/large/timeout/rate-limit
handling, `(volume_guid, file_id, size, mtime)` cache key (path-keyed
caching returns the WRONG hash after delete-recreate), performance and
privacy limits, and the 6 owner decisions required before any code. **No
endpoint-impacting change is proposed in this wave.**

**B3_TESTS** — `backend/tests/edr/test_b3_file_identity.py`, 13 tests,
green. Positive control (source-reported file hash → SHA-256 content
identity with provenance), negative controls (no hash →
`HASH_NOT_OBSERVED`; process image never promoted; file key ≠ image
key), plus coverage measurement and cross-dialect agreement.

**B3_DECISION** — **ACCEPTED as measurement + contract.** File CONTENT
identity remains UNAVAILABLE for created files until the hashing design
is approved. That is a stated capability gap, not a defect.

---

### B4_REPUTATION

**ADAPTER_CONTRACT** — `backend/edr_plane/reputation/`:

```
CANONICAL EVIDENCE → observables.extract() → Observable
   → ReputationService (registry + cache + aggregation)
   → ReputationProvider (Protocol)  ← the ONLY thing a new source implements
   → ReputationResult (per provider, retained)
   → detection / correlation / retrospection
```

A provider answers about observables. It does not read canonical
evidence, does not write evidence, and does not produce detections.
Adding a provider therefore requires an adapter and nothing else.

**OBSERVABLE_TYPES** — `SHA256`, `SHA1`, `MD5`, `DOMAIN`, `IP`, `URL`,
extensible. Every observable carries its SUBJECT —
`PROCESS_IMAGE`, `FILE_CONTENT`, `NETWORK_PEER`, `DNS_QUESTION`,
`URL_RESOURCE` — plus `source_field`, provenance and `evidence_refs[]`.
A process-image SHA-256 and a written-file SHA-256 are both SHA-256 and
are NEVER the same fact.

Measured extraction over the real corpus: `IP:NETWORK_PEER` 140,
`SHA256:PROCESS_IMAGE` 16, `MD5:PROCESS_IMAGE` 16,
`DOMAIN:DNS_QUESTION` 1, `IP:DNS_QUESTION` 1, `SHA256:FILE_CONTENT` 0
(consistent with B3). A malformed digest is refused, never extracted.

**VERDICT_SEMANTICS** — `KNOWN_MALICIOUS`, `KNOWN_GOOD`, `UNKNOWN`,
`LOOKUP_FAILED`, `NOT_SUPPORTED`. Enforced in code, not in prose: a
non-judgement raises if constructed as a MATCH. Aggregation states are
deliberately NOT verdicts: `MALICIOUS_ASSERTED`, `GOOD_ASSERTED`,
`NO_INTELLIGENCE` ("every lookup completed and NO source holds
reputation — this is NOT benign"), `NO_LOOKUP_COMPLETED` ("no lookup
completed — this is NOT 'no known reputation'"), `NOT_SUPPORTED`.
Disagreement is retained (`provider_disagreement`, all results kept); a
malicious assertion is never erased by a good one. Every result keeps
observable, type, subject, provider, verdict, confidence (only when the
source supplied it), `queried_at`, `intelligence_timestamp`,
`intelligence_version`, `expires_at`, `match_basis`, tenant scope and
provenance.

**CACHE_SEMANTICS** — keyed by `(provider_id, tenant_id, type, value)`,
so a tenant-scoped IOC can never answer for another tenant out of a
shared cache. A hit carries `CACHE_HIT_FRESH` / `CACHE_HIT_STALE`, the
ORIGINAL `queried_at`, the read time and the TTL. `LOOKUP_FAILED` is
never cached — a failure can never later be served as intelligence.

**PROVIDERS_IMPLEMENTED** — `LocalIOCProvider` (`nivxforge.local_ioc`),
real and working, `offline = True`. It reads the platform's EXISTING IOC
authority (the `iocs` collection that
`detection_content/ioc_watchlist.py` already binds to) rather than
creating a second home for local intelligence. No API key, no network,
no third-party dependency in the core path. Tenant rule carried over
verbatim: a tenant's IOC never judges another tenant's evidence.
Disposition rule: an IOC entry is `KNOWN_MALICIOUS` unless it explicitly
declares `disposition: KNOWN_GOOD`; an unreadable disposition is
`LOOKUP_FAILED`, never guessed. No other provider was implemented and no
secret was added.

**B4_TESTS** — `backend/tests/edr/test_b4_reputation.py`, 18 tests,
green. Positive control (listed hash → `KNOWN_MALICIOUS` with
severity/confidence/intelligence version/match basis), negative control
(unlisted hash → `UNKNOWN`, "NOT benign"), allow-list → `KNOWN_GOOD`,
store failure → `LOOKUP_FAILED` (and never cached), unsupported type →
not an answer, provider disagreement visible, cross-tenant refusal, and
cache freshness/staleness.

**B4_DECISION** — **ACCEPTED.**

---

### COVERAGE_MATRIX_DELTA

Regenerated mechanically (`scripts/e3_coverage_matrix.py`).
**Zero rule rows changed; zero verdict changes; corpus facts byte
identical.** That is the correct outcome: Wave B changed the FOUNDATION,
not detection content. The matrix remains an internal engineering truth
instrument — `22 SUPPORTED / 14 NOT_APPLICABLE / 1 PARTIAL` is NOT a
Cisco/AMP equivalence claim and is not a maturity percentage.

What Wave B adds to the matrix's future columns (canonical preservation,
graph/entity support, reputation dependency) is now measurable rather
than asserted: `docs/WAVE_B_FOUNDATION_MEASUREMENT.json` is the
instrument, and it is read-only.

### SECURITY_REGRESSIONS

None. No authorisation, tenancy or authentication logic was modified. The
tenant boundary was ADDED to two new surfaces (process identity keys,
reputation cache keys). `tests/edr/test_cross_tenant.py`,
`test_gate7_endpoint_enforcement.py`, `test_p0_a2_*` all green.

### EVIDENCE_REGRESSIONS

None. No historical evidence was rewritten, no collection was migrated,
no field was removed or repurposed. Every change is additive; the one
representational change (lower-case hex digests) applies to NEW
normalisation only and is lossless.

### FILES_CHANGED

Modified
* `backend/v2/ingestion/canonical.py` — CES gains the lost process/file
  fields + `field_provenance`; hash-state vocabulary; CEM `raw`/`process`
  now carry them; `artefacts.file[]` gains hashes/size/`hash_state`;
  `content_digest_sha256`; WINSEC 4689 → `process_exit`.
* `backend/v2/ingestion/telemetry_bridge.py` — maps the new fields;
  SEPARATES process-image hashes from file-content hashes; reads both
  `parent_pid` and `ppid`; `process_guid`/`parent_process_guid` at
  document level.
* `backend/edr_plane/windows_eventlog.py` — hex digests lower-cased;
  full `field_provenance` on process-create and file branches.
* `backend/tests/edr/test_winsec_semantics.py` — 4689 added to the
  reviewed event-ID gate, with the reasoning.
* `backend/tests/edr/test_p0_f13_5_detection_handoff.py`,
  `backend/tests/edr/test_p0_a2_adversarial_live.py` — obsolete-contract
  corrections, documented in-file (see TEST_RESULTS).

Added
* `backend/edr_plane/process_identity.py` (B2)
* `backend/edr_plane/file_identity.py` (B3)
* `backend/edr_plane/reputation/{__init__,contract,observables,service}.py`,
  `.../providers/{__init__,local_ioc}.py` (B4)
* `backend/tests/edr/test_b1_normalizer_convergence.py` (51)
* `backend/tests/edr/test_b2_process_identity.py` (20)
* `backend/tests/edr/test_b3_file_identity.py` (13)
* `backend/tests/edr/test_b4_reputation.py` (18)
* `backend/scripts/wave_b_foundation_measure.py` (read-only measurement)
* `docs/WAVE_B_WINDOWS_PRECHECK_READONLY.ps1`
* `docs/B3_SENSOR_SIDE_FILE_HASHING_DESIGN.md`
* `docs/WAVE_B_FOUNDATION_MEASUREMENT.json`
* `docs/WAVE_B_FOUNDATION_REPORT.md` (this file)

### TEST_RESULTS

`pytest backend/tests/edr` → **1,697 passed, 3 failed, 3 skipped**
(baseline before this wave: 1,587 passed / **7 failed**).

New Wave B tests: **102, all green.**

The 7 pre-existing failures, classified as instructed:

| test | classification | action |
|---|---|---|
| `test_p0_f13_5_*` ×5 | **OBSOLETE-CONTRACT TEST** | test changed. OLD: `trajectory_focus()` could be called with no tenant. WHY WRONG: the route now takes the authoritative tenant as an explicit injected parameter, so a direct in-process call that omits it passes FastAPI's `Depends(...)` SENTINEL into the authorisation check — the test was asserting against a refusal caused by its own call shape. NEW: every caller names the tenant and the principal must hold it. EVIDENCE: `routers/edr_tenancy.py:381` refused with `requested_tenant = Depends(edr_tenant)`. Production authorisation logic UNCHANGED — granting a default tenant to make it pass would be a security regression. |
| `test_p0_a2_adversarial_live::…explicit_tenant_is_refused` | **OBSOLETE-CONTRACT TEST** | assertion only. OLD: reason must contain the literal `"no default tenant"`. WHY WRONG: it asserted product COPY; the wording moved to "…there is no default customer" with no behavioural change. NEW: the invariant is `code == TENANT_REQUIRED` plus an explicit "no default" statement. Refusal behaviour UNCHANGED. |
| `test_p0_f7_live_api::test_projection_matches_mongo_and_writes_nothing` | **PRE-EXISTING · live-edge timeout** | not fixed, not weakened. `/api/edr/campaign-story` answers 200 in **11.1–11.3 s**; the test allows 60 s but the preview edge returns Cloudflare 504 when the whole live suite runs concurrently. Passes in isolation. |

Still failing, both **PRE-EXISTING, proven not caused by Wave B**:

* `test_iteration_82_activation::test_window_semantics_empty_but_identified`
  and `::test_identity_unresolved_honest_state` — reproduced at HEAD with
  all three Wave B source files stashed (`git stash push` → same
  `KeyError: 'FIN-07'` / same timeout). Root causes:
  `services/edr/device_identity.list_devices()` performs a FULL scan of
  `v2_shadow_observations` (262,823 documents) on every call, and
  `/api/edr/device-trajectory` answers in **14.3 s** against a 15 s test
  timeout. Deliberately NOT fixed in this wave: it is an EDR read-path
  performance defect, it touches the frozen trajectory surface, and it
  deserves its own measured change. **Logged as P1.**

Also regressed green: `tests/test_ingestion_phase4.py` (21),
`tests/edr/test_winsec_semantics.py` (94),
`tests/edr/test_phase0_windows_canonical_bridge.py`,
`test_observation_identity.py`, `test_event_id_propagation.py`,
`test_sysmon_semantics.py`, `test_e3_coverage_invariants.py`,
`test_e3_detection_replay.py`.

### CODE_CHANGED
Yes — backend only, as listed. No frontend file was touched. No Device
Trajectory component, route or response shape was changed.

### DATA_CHANGED
**No.** No migration, no backfill, no rewrite, no delete. The only
writes performed during this wave were by the pytest suite into
`test_database`.

### DEPLOYED
**No.** Preview backend only (hot reload). No production deployment.

---

### WINDOWS_PRECHECK_REQUIRED

**YES — and it is READ-ONLY.**
`docs/WAVE_B_WINDOWS_PRECHECK_READONLY.ps1`

It establishes, in one pass: clock/timezone/window alignment (§0),
Sysmon service + driver + binary version (§1), the ACTIVE Sysmon config
(§2 — `sysmon64.exe -c` with NO file argument, which DUMPS rather than
applies), channel state + EventID 1 counts for the window / 24 h / 1 h +
a per-Event-ID histogram + the channel's retained time range (§3 — so a
low count caused by ROLLOVER cannot be mistaken for low activity),
selected EventID 1 fields with the command line truncated to 120 chars
(§4), `auditpol /get` for Process Creation and Termination +
`ProcessCreationIncludeCmdLine_Enabled` (§5), whether Security 4688 /
4689 / 4624 / 4672 / 1102 exist locally in the SAME window (§6), the
NivXForge / Windows collector service state incl. Wecsvc + WinRM (§7),
collector config and `wecutil` subscriptions filtered to channel /
event-id lines with token-like values REDACTED (§8), and channel
readability for the collector identity (§9).

It does not modify Sysmon config, does not touch audit policy, does not
start/stop/restart any service, writes nothing to the registry, clears
no log, reinstalls nothing, and prints no enrolment token, key or
credential. Run elevated (required to READ the Security log and the
Sysmon config).

The block itself is reproduced in the chat message accompanying this
report.

---

### BLOCKERS

1. **Windows PRE-check result** (owner-run). Needed to close the
   unexplained Sysmon EventID 1 = 16 question and to establish whether
   4688/4689 exist locally. No endpoint-changing action will be proposed
   before it.
2. **Process TERMINATION telemetry is not collected** (Sysmon EID 5
   absent, Security 4689 absent). B2 termination semantics are therefore
   proven only by regression, and every process on the real endpoint is
   honestly `PROCESS_LIFETIME_UNKNOWN`.
3. **File CONTENT identity does not exist** for created files (0/107).
   Blocked on owner approval of the B3 hashing design (6 decisions).
4. **P1 · EDR read-path performance**: `list_devices()` full-collection
   scan; `device-trajectory` 14.3 s, `campaign-story` 11.2 s.

### NEXT_RECOMMENDED_ENGINE_WAVE

Only after the PRE-check result and this report are reviewed:

* **B5 (small, unblocks real proof)** — wire B2/B3/B4 as read-only
  measurement surfaces behind the existing authorisation, so the
  foundation is observable in the product and not only in a script. No
  trajectory change.
* Then the deeper **Cisco Secure Endpoint / Defender / CrowdStrike /
  SentinelOne / Sophos / Carbon Black capability study** you scheduled,
  BEFORE finalising E4/E5 behavioural + file-intelligence architecture.
* Not started, as instructed: no ML, no exploit/memory prevention, no
  retrospective engine, no rule-count expansion, no trajectory
  cosmetics, no deployment.
