# PHASE 0 · WINDOWS CANONICAL TELEMETRY BRIDGE

Date: 2026-06 · Pre-production gate · Production mutations: **0**

```
PHASE 0 — WINDOWS CANONICAL BRIDGE: PASS
```

The Stage A blocker is closed. All eight authorised Windows event
families now become canonical evidence, reach the EXISTING server-side
deterministic detection pipeline, and land in the P0-C finding plane.
Proven end to end against the **preview** database with captured-shape
Windows XML, then cleaned up.

---

## WINDOWS_EVENT_LOG ENVELOPE

`canonical_bridge.parse()` now dispatches on the envelope the connector
actually sent. The Linux `activity` dialect is untouched.

| Family | Status | Evidence |
|---|---|---|
| Sysmon 1 · Process Create | **PASS** | canonical PROCESS · ProcessGuid identity · 3-generation ancestry |
| Sysmon 3 · Network Connection | **PASS** | canonical NETWORK · correlated to ProcessGuid |
| Sysmon 11 · File Create | **PASS** | canonical FILE · responsible process preserved |
| Sysmon 12 · Registry Key Create/Delete | **PASS** | canonical REGISTRY · `KEY_CREATE` from the source's own `EventType` |
| Sysmon 13 · Registry Value Set | **PASS** | canonical REGISTRY · `VALUE_SET` + `Details` as value data |
| Sysmon 22 · DNS Query | **PASS** | canonical DNS · own lane, correlated to ProcessGuid |
| Security 4688 · Process Create | **PASS** | canonical PROCESS · identity explicitly downgraded |
| Security 4624 · Successful Logon | **PASS** | canonical AUTHENTICATION · LogonType mapped from source only |

Preview end-to-end run (`tests/edr/phase0_e2e_preview.py`):

```
sysmon_1       canonical=True class=PROCESS        evaluated=True finding_plane=yes
sysmon_11      canonical=True class=FILE           evaluated=True finding_plane=yes
sysmon_12      canonical=True class=REGISTRY       evaluated=True finding_plane=yes
sysmon_13      canonical=True class=REGISTRY       evaluated=True finding_plane=yes
sysmon_22      canonical=True class=DNS            evaluated=True finding_plane=yes
sysmon_3       canonical=True class=NETWORK        evaluated=True finding_plane=yes
winsec_4624    canonical=True class=AUTHENTICATION evaluated=True finding_plane=yes
winsec_4688    canonical=True class=PROCESS        evaluated=True finding_plane=yes
refused        canonical=False evaluation_state=NOT_EVALUATED finding_plane=yes
trajectory lane groups: {"AUTHENTICATION":1,"DNS":1,"FILE":1,"NETWORK":1,
                         "PROCESS":2,"REGISTRY":2}
evaluation-state rows: 9
PHASE0_E2E: PASS
```

---

## IDENTITY

| | |
|---|---|
| PROCESS IDENTITY | **Sysmon `ProcessGuid` is authoritative.** `identity_quality = SOURCE_PROCESS_GUID`; `bind_process_identity()` scopes the GUID to the authenticated endpoint and never downgrades it. `ProcessGuid` is never fabricated |
| PARENT/CHILD ANCESTRY | **PASS by GUID.** `explorer.exe → chrome.exe → powershell.exe` proven: three distinct identities, `parent_iid == parent's iid` at each link. CES already preferred `process_guid` for `process_iid`, so no new identity model was invented |
| PID-ONLY DOWNGRADE | **QUALITY STATE, not a substitute identifier.** With no `ProcessGuid` (Security 4688, or a Sysmon 1 missing the field) the PID, image, command line, parent PID and parent image are **all preserved** as correlation aids, and `identity_quality = PID_ONLY_NOT_AUTHORITATIVE` with the reason *"a PID is reused by the operating system: this is correlation context and must never be read as a lifetime-stable process identity"*. Ancestry is separately graded `PARENT_OBSERVED_PROCESS_GUID` / `PARENT_OBSERVED_PID_ONLY` / `PARENT_NOT_OBSERVED` |
| NO WINDOWS-ON-LINUX MAPPING | Windows evidence never touches `/proc` semantics; the Linux path never sees a GUID |

---

## CANONICAL CLASSES

| Class | Status | Note |
|---|---|---|
| PROCESS | **PASS** | GUID, PID, image, command line, cwd, integrity, hashes, original file name, product/company, user, logon id, session id |
| FILE | **PASS** | path, name, `operation=CREATE` only (Sysmon 11 IS a create — no delete/rename/write is claimed), creation time, responsible process |
| NETWORK | **PASS** | protocol, 5-tuple, direction from `Initiated`, peer hostname labelled as Windows' own peer name and explicitly **not** a DNS observation |
| REGISTRY | **PASS · NEW LANE** | key, value data (13 only), operation from the source's `EventType`, responsible process. Never filed as FILE or PROCESS |
| DNS | **PASS · NEW LANE** | query name, status, raw results, parsed address answers (a `type: 5 …` CNAME is not turned into an address), responsible process. Never filed as NETWORK |
| AUTHENTICATION | **PASS · NEW LANE** | outcome, LogonType + mapped name, target/subject user·domain·SID, logon id, logon process, auth package, workstation, source IP/port, logon GUID |

**No canonical schema migration was needed.** CES
(`v2/ingestion/canonical.py`) already mirrors the Sysmon + Windows
Security union — `process_guid`, `parent_process_guid`,
`registry_key/value/data`, `dns_query`, `dns_answer`, `sid`, `logon_id`,
`logon_type`, `event_id`, `channel` — and `_resolve_kind()` already owned
Sysmon/Win-Sec event-id semantics. Phase 0 fills that existing contract;
previously `canonical_to_ces()` hardcoded `event_id=None` and dropped
every one of those fields.

---

## CHAIN

| | |
|---|---|
| RAW → CANONICAL PROVENANCE | **PASS** — `raw_ref{raw_id, collection}` on every canonical event; the immutable raw Windows record is never discarded; `winlog{channel, provider, event_id, record_id, computer, time_created, family, event_data_fields}` travels with the evidence |
| ACTIVITY IDENTITY | **PASS** — a Windows record is identified by `(channel, event_id, EventRecordID)` on its host, so a redelivery is the same activity observed twice and two different records never collapse |
| CANONICAL → DETECTION | **PASS** — the SAME DSM (`nivxforge-linux-sensor`) claims the envelope and hands off to the SAME `process_event_through_pipeline`. **No new detection engine.** The DSM still refuses a lookalike (`{"activity":"PROCESS"}` and a bare `{"kind":"WINDOWS_EVENT_LOG"}` are both rejected) |
| DETECTION → EVALUATION STATE | **PASS** — 9 evaluation rows for 9 delivered events |
| DETECTION → DURABLE FINDING | **PASS** — finding plane reached on every canonicalised event. No finding is manufactured for a benign event, and none for a parse failure |
| TENANT AUTHORITY | unchanged — resolved from the authenticated delivery; a sensor payload's tenant claim stays an untrusted claim |

---

## TRUTHFULNESS FIXES

**A · PARSE-FAILURE TRUTH — PASS.** `bridge()` previously returned at the
parse failure *before* the finding plane, so a refused event had **no
evaluation row at all** — not `CLEAN`, but not `NOT_EVALUATED` either,
which a console can read as "evaluated and clean". It now records
`DETECTION_NOT_EVALUATED` against the raw event with the reason
*"canonicalisation failed, so no detection ran on this evidence.
NOT_EVALUATED is not CLEAN"*, and returns `evaluation_state:
"NOT_EVALUATED"`. Proven on the real path (`refused` row above). No
finding is manufactured. `NOT_EVALUATED != CLEAN`, `UNKNOWN != ABSENT`,
`ABSENT != VERIFIED` all hold.

**B · FRESHNESS RENDER — PASS.** `TelemetryFreshness.jsx:86` called
`String(error)` on a **structured** `detail` object (`{code, reason,
tenant_id}`) and printed the literal `[object Object]` — telling the
operator nothing at the exact moment it was reporting that it could prove
nothing. `readableError()` now renders `code · reason` recursively, falls
back to JSON, and never suppresses the error or substitutes a healthy
state.

**FRESHNESS TRUTH — PASS, additively.** No existing field changed
meaning. `last_telemetry_at` / `event_count` still describe **transport**
— correctly, the endpoint really did deliver. A new per-endpoint
`investigability` block describes **evidence**:

| State | Meaning |
|---|---|
| `INVESTIGABLE` | canonical observations exist; the activity can be investigated |
| `RAW_ONLY_NOT_INVESTIGABLE` | *"N raw authenticated event(s) arrived and NOT ONE became canonical evidence … because of a canonicalisation gap, not because nothing happened"* — **exactly the Stage A failure mode** |
| `NO_DELIVERY_TO_ASSESS` | nothing delivered yet |
| `UNKNOWN_NOT_ASSESSED` | the projection could not determine it — *"unknown, not clean"* |

Computed from one bounded, tenant-constrained aggregation over
`v2_shadow_observations`. A projection failure returns UNKNOWN, never
"no evidence". The console renders an `EVIDENCE · …` chip
(`data-testid="edr-freshness-investigability-chip"`) plus a statement
line when the state is not `INVESTIGABLE`. No schema migration, nothing
destructive.

---

## REGRESSION

| | |
|---|---|
| LINUX REGRESSION | **NONE** — PROCESS/FILE/NETWORK canonicalisation, `SOURCE_PROCESS_IDENTITY` attribution, `PARENT_OBSERVED` lineage, lane groups and the refusal of an unknown activity are all locked by new tests and unchanged. `process_guid` never appears on a Linux event |
| TENANT ISOLATION | **NONE** — `test_cross_tenant`, `test_edr_route_tenant_authority`, `test_b4b5_tenant_registry_authority` pass |
| ENDPOINT AUTH | **NONE** — `test_p0_a2_enrollment`, `test_p0prod2_enrollment_hardening` pass |
| RESPONSE AUTHORITY | **FAIL-CLOSED, untouched** — `test_p0a_response_authority` passes. No response code was read or modified |
| BACKEND HEALTH | `/api/health` 200 after restart; no import or startup error |

### TESTS

```
TESTS ADDED   41 (39 unit/contract + 2 DSM handoff) + 1 preview e2e probe
TESTS RUN     414 across 27 focused suites
PASSED        411
FAILED        1   (pre-existing · NOT introduced by Phase 0)
SKIPPED       2
```

The one failure:
`tests/test_b4b5_tenant_registry_authority.py::test_edr_and_xdr_resolve_the_same_authority`
→ `TypeError: _agent_tenant() missing 1 required keyword-only argument:
'oracle'`. `routers/edr_enrollment.py` is **not** in this change set
(`git status` confirms). The `oracle` keyword was added by P0-PROD-2 and
the test was never updated — it is part of the known harness debt.
**Reported, not fixed** (out of Phase 0 scope).

One test WAS updated, and deliberately:
`test_p0c_durable_findings.py::test_the_authenticated_ingest_path_records_the_finding_plane`
asserted `record_endpoint_detection(` appears **exactly twice**. Phase 0
adds a third, truthful call site. The assertion is now `>= 3` and
additionally asserts the parse-failure branch reaches the finding plane
before returning — strengthening the test's own intent rather than
relaxing it.

The historical ~48-minute full-suite baseline was **not** run.

---

## FILES MODIFIED

| File | Change |
|---|---|
| `backend/edr_plane/windows_eventlog.py` | **NEW** · 8-family Windows Event Log → canonical, identity quality, truthful refusals |
| `backend/edr_plane/canonical_bridge.py` | dispatch on the Windows envelope; `_parse_windows()`; Windows activity identity; GUID-aware `bind_process_identity()`; parse-failure NOT_EVALUATED; Windows envelope source |
| `backend/v2/ingestion/telemetry_bridge.py` | CES passthrough for `event_id`, `channel`, provider, `process_guid`, `parent_process_guid`, `current_directory`, `integrity_level`, `sid`, `logon_id`, `logon_type`, `registry_*`, `dns_*`; Windows blocks carried on `raw_event`. Empty for every other producer |
| `backend/v2/ingestion/canonical.py` | CEM `raw` now names `registry_key`, `registry_value`, `dns_query`, `dns_answer`, `logon_type`, `sid` explicitly, so a lane keys on the class it is |
| `backend/edr_plane/trajectory_window.py` | `GROUPS` + REGISTRY, DNS, AUTHENTICATION; lane mapping; `dns_query` moved out of `_NET_KINDS` |
| `backend/detection_content/telemetry/nivxforge_sensor_dsm.py` | DSM claims the Windows envelope; `event_type` falls back to the canonical activity class |
| `backend/services/edr/telemetry_freshness.py` | `investigability()` + bounded canonical-count aggregation |
| `apps/nivxray-xdr/src/nivxforge/components/TelemetryFreshness.jsx` | `readableError()`; investigability chip + statement |
| `backend/tests/edr/fixtures_windows_eventlog.py` | **NEW** · captured-shape XML fixtures, positive + negative |
| `backend/tests/edr/test_phase0_windows_canonical_bridge.py` | **NEW** · 39 tests |
| `backend/tests/edr/phase0_e2e_preview.py` | **NEW** · preview-only e2e probe, self-cleaning |
| `backend/tests/edr/test_p0c_durable_findings.py` | structural assertion strengthened (see above) |

No unrelated refactor. No force-push, no history rewrite, no deployment.

---

## NEGATIVE CASES

Every one is named, never silent, and never `CLEAN`:

| Case | Outcome |
|---|---|
| unsupported Sysmon event id (10) | `WINDOWS_EVENT_ID_NOT_SUPPORTED` · *"a coverage gap, not an absence of activity"* |
| unsupported provider (PowerShell 4104) | `WINDOWS_PROVIDER_NOT_SUPPORTED` · retained raw |
| malformed XML | `WINDOWS_EVENT_XML_MALFORMED` |
| no XML in envelope | `WINDOWS_EVENT_XML_ABSENT` · retained and replayable |
| no EventID anywhere | `WINDOWS_EVENT_ID_ABSENT` |
| **no EventData** | canonicalises as a sparse record; process `identity_quality = NOT_OBSERVED`. Not a refusal, not "clean" |
| missing ProcessGuid | identity downgraded, evidence preserved |
| missing ParentProcessGuid | `PARENT_NOT_OBSERVED`; no ancestry invented |
| missing CommandLine | named in `not_observed` |
| invalid timestamp | the time basis is declared; our clock is never passed off as the source's statement |
| duplicate EventRecordID | one activity identity — a redelivery is not new activity |
| out-of-order delivery | class and identity unchanged |
| 4688 without command line | canonicalises; the absence is named |
| any parse/canonicalisation exception | `NOT_EVALUATED` recorded on the real path |

---

## WHAT IS STILL NOT TRUE

Stated so nothing is read as capability:

- **Console changes are `IMPLEMENTED_NOT_RUNTIME_VERIFIED`.** The EDR
  console is built from `apps/nivxray-xdr` and shipped via Vercel; no
  build or deployment was authorised, so the chip and the error render
  are syntax-verified (esbuild) and not yet observed in a browser.
- **No real Windows host has produced any of this.** Everything above is
  captured-shape fixtures plus the preview database. Grade:
  `PROVEN_PREVIEW`, not `PROVEN_PRODUCTION`.
- **Visibility still depends on Sysmon.** Without Sysmon (and a config
  covering 1/3/11/12/13/22) a Windows host yields only what Security
  auditing provides — 4688 requires command-line auditing to be enabled.
- **Out of scope and untouched**: PowerShell 4104 / Module Logging /
  AMSI, ETW, driver, process exit, signer/signature verification,
  endpoint-local detection or prevention, outbox cap/rotation, sensor
  crash recovery, signed installer, DPAPI/TPM, mTLS, Findings UI,
  token-revoke UI, P0-PROD-4, P0-PROD-6.
- **Windows Device Trajectory UI lanes.** The backend now emits REGISTRY,
  DNS and AUTHENTICATION lane groups. Whether `AmpCanvas`/`AmpNavigator`
  render three previously impossible groups attractively is unverified —
  the lane axis is generic and group-ordered, so they will appear, but
  their presentation has never been seen.

---

## MUTATION REPORT

```
PRODUCTION DB WRITES:        0
PRODUCTION ORGANIZATIONS:    0
PRODUCTION TENANTS CREATED:  0
PRODUCTION TOKENS CREATED:   0
PRODUCTION ENDPOINTS ENROLLED: 0
PRODUCTION TELEMETRY:        0
PRODUCTION RESPONSE ACTIONS: 0
PRODUCTION SECRETS ACCESSED: 0
PRODUCTION DEPLOYMENTS:      0
VERCEL CHANGES:              0
WORKERS ENABLED:             0
COMMITS / PUSHES:            0
```

Preview database: written and **cleaned up** by the e2e probe
(`ten_phase0_preview_probe` deleted on both entry and exit).
`EDR_AUTH_PEPPER` was not read, displayed, hashed, compared, logged,
copied or rotated.

---

## EXACT REMAINING BLOCKERS

**For the first production organization/tenant: none technical.** Owner
decisions only:

1. organization `kind = VENDOR` — confirmed by owner directive
2. tenant `kind = INTERNAL_VALIDATION`, `slug = nivx-machines`,
   platform-minted opaque `ten_…` — confirmed by owner directive
3. explicit authorisation for the two production DB writes
4. *(optional, read-only)* confirm `enforcing == true` and that
   `admin@nivxray.com` holds `tenants.manage`, via one authenticated
   `GET /api/xdr/tenants`

**For the first real Windows endpoint (Stage B, not authorised here):**
a Windows host with Python 3.11+ and Sysmon configured; a
production-minted token; and the console rebuild/redeploy so the
investigability chip and error render actually ship. Known non-blockers
carried forward: unbounded outbox, ONSTART-only crash recovery, unsigned
installer.

```
READY FOR FIRST PRODUCTION ORGANIZATION/TENANT: YES
```

### PREPARED · NOT EXECUTED

```http
POST https://nivxray.nivxforge.com/api/xdr/organizations
Authorization: Bearer <production admin JWT>
Content-Type: application/json

{"slug": "nivx-machines",
 "display_name": "NivX Machines",
 "kind": "VENDOR"}
```

```http
POST https://nivxray.nivxforge.com/api/xdr/tenants
Authorization: Bearer <production admin JWT>
Content-Type: application/json

{"organization_id": "<org_… returned by the call above>",
 "slug": "nivx-machines",
 "display_name": "NivX Machines",
 "kind": "INTERNAL_VALIDATION",
 "products": ["xdr", "edr"]}
```

The returned `data.id` (`ten_…`) is the authoritative tenant identity.
Issue each **once, serially**; if either returns a non-2xx, run the
read-only verification in `P1_TENANT_BOOTSTRAP_PRECHECK.md §L` **before**
any retry — the tenant registry has no unique index and the audit write
follows the insert.

---

## STOP POINT

Stopped for owner review. No tenant, no organization, no enrolment
token, no Windows enrolment, no production write, no deployment.
