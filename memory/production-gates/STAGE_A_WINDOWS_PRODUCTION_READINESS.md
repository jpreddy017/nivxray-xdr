# STAGE A · NIVXFORGE WINDOWS PRODUCTION READINESS — READ-ONLY

Date: 2026-06 · Mode: strictly read-only · Production mutations: **0**

Source of truth: working tree at `git HEAD 92ea4f31` (reconciliation
commit on top of `f7a2518`), the live production OpenAPI (862 paths,
`/api/health` 200), and **one local reproduction** of the canonical
parser against the exact payload the Windows sensor emits.

```
============================================================
NIVXFORGE WINDOWS PRODUCTION READINESS
============================================================

OVERALL: PARTIAL — BLOCKED ON ONE DEFECT

NOT READY — the Windows sensor's telemetry payload is REFUSED by the
canonical bridge, so a real Windows endpoint would enrol, authenticate,
heartbeat, fetch policy and deliver telemetry successfully, and its
Device Trajectory, Process Tree, Detections and Findings would all be
EMPTY.
```

The tenant bootstrap side is clean. The Windows endpoint side is not.

---

## THE BLOCKER — reproduced, not inferred

`agents/nivxforge-windows/nivxforge_sensor.py` emits one JSON object per
Windows Event Log record:

```json
{"observed_at": "...", "kind": "WINDOWS_EVENT_LOG",
 "winlog": {"channel": "...", "record_id": 123, "event_id": "1",
            "time_created": "...", "computer": "...",
            "provider": "...", "xml": "<Event>…</Event>"}}
```

`edr_plane/canonical_bridge.parse()` (line 79) begins:

```python
activity = ev.get("activity")
if activity not in ("PROCESS", "FILE", "NETWORK"):
    raise ValueError(f"unknown sensor activity {activity!r}")
```

The Windows payload has **no `activity` key**. Reproduced locally:

```
WINDOWS PAYLOAD: REFUSED -> ValueError unknown sensor activity None
LINUX  PAYLOAD: PARSED   -> LinuxSensor PROCESS
```

Consequence chain, traced through `bridge()`
(`canonical_bridge.py:326-344`) and the ingest route
(`edr_enrollment.py:398-447`):

| Stage | Windows outcome |
|---|---|
| `POST /api/edr/agent/telemetry` | **200 OK** — the sensor sees success |
| `edr_raw_events` row | **written**, immutable, `trust_state: AUTHENTICATED` |
| `mark_reported` → `last_telemetry_at`, `event_count` | **updated** — the console shows the endpoint as *delivering* |
| `parse()` | **ValueError** |
| Derivation appended | `parser_state: FAILED`, `outcome: NO_CANONICAL_EVIDENCE` |
| `v2_shadow_observations` canonical observation | **none** |
| `process_event_through_pipeline` (detection) | **never reached** — `bridge()` returns at line 343 |
| `DETECTION_MATCHED` / `..._NO_MATCH` derivation | **none** |
| `record_endpoint_detection` (P0-C findings + evaluation state) | **never called** |
| Device Trajectory (`v2_shadow_observations`) | **empty** |
| Process Tree (canonical evidence) | **empty** |
| Detections / Findings | **empty** |
| Events Explorer (`edr_raw_events`) | **populated** — raw Windows XML visible |

Two things make this worse than a blank screen, and both must be stated:

1. **The endpoint looks healthy while producing no evidence.**
   `last_telemetry_at` and `event_count` advance on the raw write, so
   telemetry freshness will report a *fresh, delivering* endpoint whose
   investigative surfaces are all empty. That is precisely the
   "NO TELEMETRY ≠ BENIGN" confusion the programme is built to avoid,
   arriving through a different door.
2. **P0-C's honest-gap guarantee does not fire.** The
   `NOT_EVALUATED` evaluation-state row exists only for events that
   canonicalise and then fail detection (`canonical_bridge.py:557-572`).
   A parse failure returns before that, so there is **no evaluation-state
   record at all** — not `CLEAN`, but not `NOT_EVALUATED` either. The
   evidence is simply absent from the finding plane.

The raw bytes are retained and replayable by design, so **no evidence is
lost** — everything delivered before a fix can be re-canonicalised
afterwards. That is the one genuinely good property here.

### The asset that already exists

`services/behavioral/sysmon_adapter.py` (`normalize_sysmon_xml`) already
normalises Sysmon Event XML → canonical behavioural evidence, and is
registered in `services/registry/__init__.py:100`. It is reachable only
through `POST /api/behavioral/sysmon` — **not** from the authenticated
sensor path. A fix is a bridge to existing code, not a new engine.

---

## TENANT BOOTSTRAP

Full detail in `P1_TENANT_BOOTSTRAP_PRECHECK.md`. Summary:

| | |
|---|---|
| TENANT_ID `nivx-machines` | **NOT POSSIBLE** — deployed `CreateTenantBody` has no `tenant_id`; the id is minted server-side as `ten_` + `secrets.token_hex(13)`. `nivx-machines` is expressible as the **`slug`** |
| DISPLAY_NAME `NivX Machines` | ✔ exact |
| CREATE METHOD | two administrative writes, in order |
| CREATE API | `POST /api/xdr/organizations` **then** `POST /api/xdr/tenants` (tenant requires an existing ACTIVE organization) |
| REQUEST BODY | org `{slug, display_name, kind∈VENDOR/CUSTOMER/MSSP}` · tenant `{organization_id, slug, display_name, kind∈INTERNAL_VALIDATION/CUSTOMER/LAB/LEGACY_ADOPTED, products[]}` |
| AUTHENTICATION | verified JWT bearer only (`sub` = email); or `X-XDR-API-Key`+`X-Tenant-Id` machine pair; both together = refused. Client headers cannot establish identity |
| AUTHORIZATION | `tenants.manage` at `xdr_tenancy.py:55/94`; `role == "admin"` short-circuits to allow (`xdr_rbac.py:959`). Denial → `403 ACCESS_DENIED` + audited |
| ATOMICITY | **NOT GUARANTEED** — read-then-write with **no unique index** on `tenants`/`organizations` (live index metadata: `_id_` only) and no transaction. Two concurrent creates can both succeed |
| IDEMPOTENCY | **NOT IMPLEMENTED** — duplicate returns `409 TENANT_SLUG_EXISTS`; rejection ≠ idempotency |
| TENANT ISOLATION | PASS — single authority (`services/tenant_registry`) shared by XDR and EDR; no first/global/domain/host/browser/preview fallback |
| DEFAULT FALLBACK | `"default"` exists **only** on the non-enforcing branch (`tenant_registry.py:143-147`). Preview `.env` = `true`; production **INFERRED ON** from the observed `TENANT_REQUIRED` refusal, not read |
| AUDIT | `TENANT_CREATED` / `ORGANIZATION_CREATED`, actor = verified JWT principal, per-tenant HMAC chain, `prev_sig="genesis"`, `sig_key_id` inside the signed payload |
| EXPECTED WRITES | **4 documents**: 1 `organizations`, 1 `tenants`, 2 `xdr_audit_log`. No policy, role, workspace, token, endpoint or async write. Both handlers are synchronous with no hooks |
| ROLLBACK | `PUT /api/xdr/{tenants,organizations}/{id}/state` → `SUSPENDED`/`ARCHIVED`, audited. **No DELETE route exists** in the 862-path OpenAPI. Risk LOW and in the safe direction |
| KNOWN ORDERING GAP | tenant is inserted **before** the audit emit, and `emit_audit` is fail-closed — a failed audit leaves the tenant existing with no audit row. Never retry a create whose outcome is unknown; read first |

```
PRECHECK: BLOCKED — owner decision only (tenant id form + org kind +
          authorization for the first two production writes)
```

---

## WINDOWS SENSOR

| | |
|---|---|
| IMPLEMENTATION | `agents/nivxforge-windows/nivxforge_sensor.py` (537 lines) + `nivxforge_exclusions.py` (canonical evaluator, shared with Linux) + `Install-NivXForgeSensor.ps1` (165 lines). Version `0.2.0-windows` |
| INSTALLATION | elevated PowerShell. Stages to `C:\Program Files\NivXForge\sensor`; state in `C:\ProgramData\NivXForge\sensor` |
| **PREREQUISITE** | **Python 3.11+ must already be on the host** — `Resolve-Python` throws otherwise. There is no bundled runtime and no signed MSI. `PACKAGES["windows-x64"].signing_status` is `UNSIGNED` |
| SERVICE/AUTOSTART | **not a Windows service.** `schtasks /SC ONSTART /RU SYSTEM /RL HIGHEST`. Survives reboot; **does NOT restart after a process crash** until the next boot — no failure action, no watchdog |
| PRIVILEGE | installs as Administrator, runs as SYSTEM |
| CREDENTIAL STORAGE | `identity.json` in a state directory ACL'd to `SYSTEM` + `BUILTIN\Administrators`, inheritance broken (`SetAccessRuleProtection($true,$false)`). **Filesystem permissions only — no DPAPI, no TPM.** SYSTEM/Administrator on the host can read it |
| TOKEN DELIVERY | the enrolment token is passed as a **PowerShell command-line argument**, so it is visible in the process list during install and in PowerShell history. The platform never logs it; the delivery channel is the exposure |
| ARM64 | `windows-arm64` package declared with `files: []` — **NOT_IMPLEMENTED** |
| HEARTBEAT | IMPLEMENTED — `POST /api/edr/agent/heartbeat` with `queue_depth`; deliberately not telemetry |
| POLICY FETCH | IMPLEMENTED — `GET /api/edr/agent/policy`, persisted to `policy.json`, last-applied kept enforcing on failure with `policy_stale` |
| POLICY ACK | IMPLEMENTED — `POST /api/edr/agent/policy-ack` with `running_config_digest`; only the ACK can make the platform report APPLIED |
| EXCLUSIONS | IMPLEMENTED — evaluated locally **before** the durable journal, so an exclusion cannot be defeated by replay and excluded evidence never leaves the host |
| REBOOT SURVIVAL | task IMPLEMENTED_NOT_RUNTIME_VERIFIED; journal survives (on disk) |
| UPDATE | re-run the installer (keeps identity unless `-ReEnroll`); no self-update, no channel |
| UNINSTALL | `-Uninstall` (keeps evidence) / `-Purge` (removes identity + journal) |
| STATUS | **IMPLEMENTED_NOT_RUNTIME_VERIFIED** — no real Windows host has ever enrolled (Gate 1, owner hardware) |

---

## WINDOWS ENROLLMENT CHAIN

| Property | Status | Evidence |
|---|---|---|
| token cryptographic generation | **IMPLEMENTED** | `secrets.token_urlsafe(32)` = 256-bit, prefix `enr_` |
| stored form | **IMPLEMENTED** | HMAC-SHA-256 with `EDR_AUTH_PEPPER`; plaintext returned once and written nowhere |
| single use | **IMPLEMENTED** | `used_at: None` in the match filter |
| atomic consumption | **IMPLEMENTED** | `find_one_and_update` — single-document atomicity, "one winner, always" |
| expiration | **IMPLEMENTED** | `expires_at_dt > now` checked on every read **plus** a TTL index (TTL is cleanup, not authorisation) |
| unique constraints | **IMPLEMENTED** | unique indexes on tokens, credentials, sessions and endpoints — unlike the tenant registry |
| unused-token revocation | **IMPLEMENTED** | `POST /api/edr/enrollment/tokens/{id}/revoke`; a CONSUMED token stays consumed and the endpoint it minted stays valid. **NOT_WIRED in the console** |
| tenant scope | **IMPLEMENTED** | every query is `{tenant_id, token_hash}`; the presented tenant must be a registered ACTIVE tenant or the caller is told only "token not valid" |
| endpoint scope | **IMPLEMENTED** | `endpoint_id` is **minted by the platform** from durable machine attributes (processor id > machine guid > device_iid > hostname); the agent cannot name itself |
| replay rejection | **IMPLEMENTED** | token burned FIRST, before credential issue — "a token that could be retried after a partial enrolment is a token that can enrol twice" |
| cross-tenant rejection | **IMPLEMENTED** | wrong tenant → `TENANT_NOT_AUTHORITATIVE`, recorded in the rejections feed, generic oracle to the caller |
| credential privilege boundary | **IMPLEMENTED** | telemetry envelope forbids `tenant_id`/`endpoint_id` (`extra="forbid"`); identity comes from the session. Admin routes require a platform JWT — an endpoint credential cannot reach them |
| secret redaction | **IMPLEMENTED** | `redact()` deliberately shows no trailing fragment; only a keyed fingerprint appears in audit |
| TLS verification | **IMPLEMENTED (default)** | `urllib` verifies against the system trust store. **No pinning.** `--api` is operator-supplied: an `http://` URL would downgrade silently. Must be `https://nivxray.nivxforge.com` |
| embedded admin credentials | **NONE** | one reusable build, no tenant credential, no API key, no device identity in the artifact |
| rejected-attempt feed | **IMPLEMENTED**, `GET /api/edr/enrollment/rejections` — **NOT_WIRED in the console** |

Enrollment is the strongest part of the stack. **No blocker here.**

---

## WINDOWS TELEMETRY — CAPABILITY TRUTH

Acquisition architecture (actual, from source): **`wevtutil qe` against
three channels** — `Security`, `System`,
`Microsoft-Windows-Sysmon/Operational` — bookmarked by
`EventRecordID`, rendered as XML, 100 records/channel/cycle.

**No ETW session. No kernel driver. No WMI. No direct process/file/
registry/network/DNS API calls. No hashing. No signature verification.**
A missing or unreadable channel is reported as unavailable, never as an
absence of activity. That honesty is implemented.

So Windows visibility is **exactly what the OS is configured to audit**,
and then only as raw XML — because of the blocker, none of it is
projected.

| Capability | Acquisition (host-dependent) | After the blocker |
|---|---|---|
| DEVICE IDENTITY | hostname, MachineGuid (registry), ProcessorId (wmic, hashed), OS version, platform, agent version — **IMPLEMENTED** at enrolment. Local IP, MAC, logged-in user, boot time, domain — **NOT_IMPLEMENTED** | device record populated (enrolment path, not canonical) |
| PROCESS START | Sysmon Event 1, or Security 4688 if audited — **PARTIAL, host-dependent** | **NOT_WIRED** |
| PROCESS EXIT | Sysmon 5 / 4689 if audited — **PARTIAL**; canonical declares `process.exit_time` **NOT_SUPPORTED** | NOT_WIRED |
| PID / PPID | present in the XML — **PARTIAL** | NOT_WIRED |
| PROCESS TREE | **PID/PPID ONLY.** The canonical `process_iid` identity and `parent_lookup_state` are minted from `/proc/<pid>/stat` semantics (Linux). Sysmon's ProcessGuid — the one field that *would* give stable Windows process identity — is **not extracted**. Process Tree reads canonical evidence only | **NOT IMPLEMENTED for Windows** |
| COMMAND LINE | in Sysmon 1 / 4688 XML when audited — **PARTIAL** | NOT_WIRED |
| POWERSHELL | `powershell.exe`/`pwsh.exe` visible only as process events, host-dependent. **Script Block Logging (4104), Module Logging and AMSI content are NOT collected** — the `Microsoft-Windows-PowerShell/Operational` channel is not in `CHANNELS`. Process command line ≠ script content | NOT_WIRED |
| FILE | Sysmon 11/23/26 if configured — **PARTIAL acquisition**. Canonical has a FILE lane, but `file.actor_process` is declared **NOT_SUPPORTED** | NOT_WIRED |
| REGISTRY | Sysmon 12/13/14 if configured — raw XML only. Canonical declares `registry` **NOT_SUPPORTED**; trajectory has **no REGISTRY lane** | **NOT_IMPLEMENTED** end-to-end |
| NETWORK | Sysmon 3 if configured — raw XML only. Canonical NETWORK lane exists but is fed by `/proc/net` socket-inode→PID semantics | NOT_WIRED |
| DNS | Sysmon 22 if configured — raw XML only. **No DNS lane in the canonical model and no DNS lane in the trajectory** | **NOT_IMPLEMENTED** |
| USER / AUTH | Security 4624/4625/4634 if audited — raw XML only. **No authentication lane in the canonical model**; `identity.username` exists only inside a PROCESS event | **NOT_IMPLEMENTED** as a lane |
| HASHING | sensor computes **none**; `process.sha256` declared **NOT_SUPPORTED**. Sysmon can emit hashes in XML, but nothing extracts them | NOT_WIRED |
| SIGNER / SIGNATURE | `process.signer`, `process.integrity` declared **NOT_SUPPORTED** | NOT_IMPLEMENTED |
| TIMESTAMPS | `observed_at` (sensor), `winlog.time_created` (OS), `ingest_time` (platform); `event_time_basis` distinguishes activity/observation/clock and refuses to fill a gap from its own clock — **IMPLEMENTED** | the basis resolver is never reached |

---

## DURABILITY (Windows-specific)

| | |
|---|---|
| LOCAL BUFFER | `outbox.jsonl` + `outbox.offset` in `C:\ProgramData\NivXForge\sensor` |
| DISK PERSISTENCE | **YES** — append, `flush()`, `os.fsync()` **before any network call**; acquisition is never coupled to delivery |
| RESTART SURVIVAL | **YES** (files) — but the scheduled task is `ONSTART` only, so after a **crash** the sensor does not restart until reboot: the journal survives while **collection stops** |
| REBOOT SURVIVAL | **YES** — task is ONSTART/SYSTEM; journal and bookmarks on disk |
| ORDERING | **FIFO** — single append-only file read sequentially |
| ACK | **YES** — the offset advances only after the platform accepts each line |
| RETRY | **YES** — on failure the drain breaks and holds the offset; next cycle replays from the same point. A `401/403` re-opens the session and re-seeks |
| DEDUP | **two layers** — `EventRecordID` bookmarks per channel, plus server-side payload-digest dedupe (`result.stored` false ⇒ no re-canonicalisation) |
| OVERFLOW | **NO BOUND — this is a real gap.** No max size, no rotation, no cap, no drop policy. `outbox.jsonl` grows until the disk fills. `max_per_cycle=200` bounds sending, not growth |
| RETENTION | none — the file is never truncated; the offset advances but the bytes stay forever. Disk grows monotonically |
| QUERYABILITY | **NONE** locally — this is a delivery outbox, **not** an endpoint event journal (Gate 2 PARTIAL, confirmed for Windows) |
| INTEGRITY (at rest) | **NONE** — plain JSONL, no checksum, no signature; ACL is the only protection |

Behaviour under stress:

| Condition | Classification |
|---|---|
| NETWORK OFFLINE | **LOSSLESS** until the disk fills — journal-then-send, offset held |
| API OFFLINE | **LOSSLESS**, same mechanism |
| TLS FAILURE | **LOSSLESS** (URLError → hold) |
| AUTH FAILURE | **LOSSLESS** — session cleared, re-opened, re-seeked from the held offset |
| QUEUE FULL / DISK FULL | **POSSIBLE LOSS** — no overflow policy; `open()`/`fsync()` raises inside `_enqueue`, which is uncaught, so the cycle dies and events are dropped at acquisition |
| SENSOR CRASH | **BOUNDED LOSS** — journalled events survive; **collection stops until reboot** (no restart action) |
| WINDOWS REBOOT | **LOSSLESS** for journalled events; bookmarks resume; the gap while powered off is a genuine non-observation |
| HIGH EVENT RATE | **BOUNDED LOSS · UNKNOWN magnitude** — 100 records/channel/cycle at a 30 s interval ≈ 3.3 records/s/channel. `EventRecordID` bookmarks mean a faster-than-drain channel falls behind but does not skip; if Windows **rotates** the channel before the sensor catches up, those records are gone. No rate measurement exists |

---

## BACKEND

| | |
|---|---|
| AUTHENTICATED INGEST | **IMPLEMENTED · PROVEN_PREVIEW** — `POST /api/edr/agent/telemetry`, session bearer, envelope forbids caller-supplied tenant/endpoint |
| TENANT VALIDATION | **IMPLEMENTED** — session-derived, then `tenant_registry.authoritative()`; sensors never name their own tenancy |
| ENDPOINT VALIDATION | **IMPLEMENTED** — `AuthenticatedEndpoint.provenance()` stamped onto every immutable raw event |
| RAW PERSISTENCE | **IMPLEMENTED** — `edr_raw_events`, immutable, digest-deduped, derivations appended, replayable |
| CANONICALIZATION | **BROKEN FOR WINDOWS** — see the blocker |
| CANONICAL PERSISTENCE | `v2_shadow_observations` — never written for Windows |
| TRAJECTORY API | **IMPLEMENTED** (`edr_plane/trajectory_window.py`, 1135 lines, windowed, cursor-paged, endpoint-wide invariant lane axis, `UNKNOWN_NOT_ASSESSED` never `CLEAN`). Lanes are **PROCESS / FILE / NETWORK only** — no REGISTRY, DNS, USER, POLICY, EXCLUSION or RESPONSE lane |
| SERVER DETECTION | **IMPLEMENTED** — one shared `process_event_through_pipeline`; unreachable for Windows |
| DURABLE FINDINGS | **IMPLEMENTED** (P0-C) — `edr_findings` + `edr_finding_evaluations`, `NOT_EVALUATED ≠ CLEAN` preserved; not reached for Windows, and a parse failure writes **no evaluation row at all** |

---

## CONSOLE

| Surface | Backend | Data (Windows) | API | UI | Wired | Real-endpoint | Production |
|---|---|---|---|---|---|---|---|
| COMPUTERS | ✔ | ✔ (enrolment) | ✔ | `EdrComputersPage` | ✔ | preview | ✖ |
| DEVICE DETAILS | ✔ | ✔ | ✔ | `EdrDevicePage`/`DeviceOverview` | ✔ | preview | ✖ |
| DEVICE TRAJECTORY | ✔ | **✖ blocker** | ✔ | `EdrDeviceTrajectoryPage` + `AmpCanvas`/`AmpNavigator`/`AmpEventDetails` (3300 lines) | ✔ | preview (Linux) | ✖ |
| PROCESS TREE | ✔ | **✖ blocker** | ✔ | `EdrProcessTreePage` | ✔ | preview | ✖ |
| EVENTS EXPLORER | ✔ | **✔ raw XML** | ✔ | `EdrEventsPage` | ✔ | preview | ✖ |
| FILES | XDR-hosted only | ✖ | ✔ | reserved | ✖ | ✖ | ✖ |
| REGISTRY | ✖ | ✖ | ✖ | ✖ | ✖ | ✖ | ✖ |
| NETWORK | ✖ (`network_ui` NOT_IMPLEMENTED) | ✖ | ✖ | reserved | ✖ | ✖ | ✖ |
| DNS | ✖ (`dns_ui` NOT_IMPLEMENTED) | ✖ | ✖ | reserved | ✖ | ✖ | ✖ |
| USER CONTEXT | ✖ as a lane | ✖ | ✖ | ✖ | ✖ | ✖ | ✖ |
| DETECTIONS | ✔ | **✖ blocker** | ✔ | `EdrDetectionsPage` | ✔ | preview | ✖ |
| FINDINGS (P0-C) | ✔ | ✖ | ✔ | **✖ no page, no nav** | **✖** | ✖ | ✖ |
| POLICY | ✔ | ✔ | ✔ | `EdrPoliciesPage` | ✔ | preview | ✖ |
| EXCLUSIONS | ✔ | ✔ | ✔ | `EdrExclusionsPage` (list only; approve/revoke/proof NOT_WIRED) | partial | preview | ✖ |
| RESPONSE STATE | ✔ read | n/a | ✔ | `EdrResponsePage` | ✔ | fail-closed | fail-closed |
| TELEMETRY FRESHNESS | ✔ | ✔ | ✔ | `TelemetryFreshness.jsx` | ✔ | preview | ✖ |

Known UI defect located: `TelemetryFreshness.jsx:86` renders
`String(error)` on a non-string error object → the `[object Object]`
label. One-line fix, **not applied** (Stage A is read-only).

---

## ENDPOINT-LOCAL SECURITY

Verified by scanning `agents/nivxforge-windows/nivxforge_sensor.py` end
to end. The only local decision logic is exclusion evaluation.

| | |
|---|---|
| LOCAL DETECTION | **NOT_IMPLEMENTED** |
| LOCAL BEHAVIOURAL ENGINE | **NOT_IMPLEMENTED** |
| LOCAL ML / NEURAL INFERENCE | **NOT_IMPLEMENTED** |
| LOCAL PREVENTION | **NOT_IMPLEMENTED** |
| LOCAL RETROSPECTION | **NOT_IMPLEMENTED** |
| ISOLATION | **NOT_IMPLEMENTED** — declared in the sensor's own `response_actions_conditional`: `ISOLATE_ENDPOINT: "not implemented by the Windows sensor in V1"`; `response_actions: []` |
| PROCESS KILL | **NOT_IMPLEMENTED** |
| QUARANTINE / FILE DELETE | **NOT_IMPLEMENTED** |
| REMOTE SHELL / SCRIPT | **NOT_IMPLEMENTED** |

Detection is **server-side, deterministic, on delivered telemetry.**
`findings_intake.py` states it in its own header: *"NivXForge has no
local behavioural, prevention, reputation or ML engine in this build."*

---

## MISSING FOR ENTERPRISE EDR DEVICE VISIBILITY — ordered

1. **Windows canonical bridge** — teach the ingest path the
   `WINDOWS_EVENT_LOG` shape (Sysmon 1/3/11/12/13/22, Security
   4688/4624/4625). Reuse `services/behavioral/sysmon_adapter.py`. **The
   single blocker; everything below is worthless without it.**
2. **Stable Windows process identity** — extract Sysmon `ProcessGuid`
   into `process_iid`, replacing `/proc`-derived start-identity
   semantics. Without it Process Tree is PID/PPID guessing.
3. **Hash + signer extraction** from Sysmon XML (`Hashes`, `Signed`,
   `Signature`, `SignatureStatus`) — fields Sysmon already provides and
   nothing reads.
4. **PowerShell Operational channel** (4104 script blocks, module
   logging) — add to `CHANNELS` and canonicalise script content.
5. **REGISTRY lane** — canonical model + trajectory lane + UI.
6. **DNS lane** — canonical model + trajectory lane + UI.
7. **USER / AUTHENTICATION lane** — logon/logoff/failed-logon as
   first-class trajectory rows, not a `username` inside a process event.
8. **Findings UI** (P0-C) — the only durable-evidence surface with a
   backend and no consumer.
9. **Outbox bound + rotation + overflow policy** — today it grows until
   the disk fills.
10. **Sensor crash recovery** — a Windows service, or a task failure
    action; ONSTART alone means a crash silences the endpoint until
    reboot.
11. **Signed installer + bundled Python runtime** — `UNSIGNED` and a
    hard Python 3.11 prerequisite are not enterprise-deployable.
12. **Secure token delivery** — out of the command line.
13. **DPAPI/TPM credential binding**, then mTLS.
14. **Endpoint-local event journal** (Gate 2) — queryable, retained,
    integrity-protected; distinct from the delivery outbox.
15. **Windows ARM64 package** — declared, empty.
16. **Local prevention/detection layer** — the long-term gap the
    reconciliation named; explicitly *after* this foundation.

---

## FIRST REAL WINDOWS ACCEPTANCE PROCEDURE (prepared · NOT executed)

**Phase 0 · unblock (code change, Stage B, owner-authorised)**
0.1 Extend the canonical bridge for `WINDOWS_EVENT_LOG` (items 1–3
    above), preview-tested against captured Sysmon XML.
0.2 Prove on a **preview** Windows host or fixture that a Sysmon Event 1
    becomes a canonical observation, a trajectory row and an
    evaluation-state record.
0.3 Only then touch production.

**Phase 1 · tenant (2 production writes)**
1. `POST /api/xdr/organizations` → `org_…` · verify count == 1
2. `POST /api/xdr/tenants` → `ten_…` · verify count == 1, slug
   `nivx-machines`, display `NivX Machines`, state ACTIVE
3. `GET /api/xdr/tenants/default` → **404** (no default tenant)
4. `GET /api/xdr/audit-log?tenant=$TEN&action=TENANT_CREATED` → 1 row,
   actor = admin, `prev_sig=genesis`; `verify/chain` → valid

**Phase 2 · token (1 write)**
5. `POST /api/edr/enrollment/tokens` with `X-Tenant-Id: $TEN` — capture
   the plaintext from the response body only; never echo, log or paste
   it into a shared channel
6. `GET /api/edr/enrollment/tokens` → state `UNUSED`, single_use true

**Phase 3 · Windows host**
7. Confirm prerequisites: Windows 10 21H2+/11/Server 2019+, x64,
   **Python 3.11+ installed**, elevated PowerShell, Sysmon installed
   with a process/network/file/registry/DNS config (without Sysmon,
   visibility collapses to whatever Security auditing provides)
8. Download the package via `GET /api/edr/onboarding/packages` →
   `windows-x64`
9. Run `Install-NivXForgeSensor.ps1 -BackendUrl https://nivxray.nivxforge.com
   -TenantId $TEN -EnrollmentToken <token>` — the token is consumed once
10. Verify `token state == USED`, `used_by_endpoint_id == <endpoint_id>`
11. **Replay proof**: re-run enrolment with the same token → `401
    ENROLLMENT_TOKEN_INVALID`, and a row in
    `GET /api/edr/enrollment/rejections`
12. **Cross-tenant proof**: enrol with a wrong tenant →
    `TENANT_NOT_AUTHORITATIVE`
13. **Privilege proof**: the endpoint session bearer against
    `GET /api/edr/enrollment/endpoints` → refused

**Phase 4 · liveness and policy**
14. Endpoint appears in `GET /api/edr/enrollment/endpoints` and under
    Computers, `sensor_state=ENROLLED_NEVER_REPORTED`
15. Device identity: hostname, platform, os_version, sensor_version
16. `GET /api/edr/agent/whoami` → identity matches
17. Authenticated heartbeat advances `last_heartbeat_at`, **not**
    `last_telemetry_at`
18. Policy fetch → DELIVERED; policy ACK → APPLIED with matching
    `running_config_digest`

**Phase 5 · real telemetry (the actual acceptance)**
19. Generate **safe, ordinary** Windows activity — open Notepad, run
    `whoami`, `ipconfig`, browse one HTTPS site. Nothing destructive,
    nothing malicious.
20. `GET /api/edr/events` → raw Windows records present
21. `GET /api/edr/telemetry/freshness` → fresh, and consistent with what
    the trajectory actually holds
22. `GET /api/edr/endpoints/{id}/trajectory` → **real PROCESS rows**
23. Command line present on process rows
24. Parent/child ancestry correct (`explorer.exe → notepad.exe`)
25. `powershell.exe` visible with its command line
26. File / registry / network / DNS rows — **only whatever Phase 0
    actually delivered**; anything absent is reported as
    `NOT_IMPLEMENTED`, never as "no activity"
27. User context: logon attribution
28. **Durability**: disconnect the network 5 min, generate activity,
    reconnect → `queue_depth` rises then drains, events arrive, no
    duplicates, ordering intact
29. Restart the scheduled task → resumes from the bookmark
30. Reboot Windows → task starts, journal intact, no duplicate events

**Phase 6 · detection and finding**
31. Run **one approved, non-destructive** validation event — owner
    chooses; candidate: an EICAR **write** (no execution) or a benign
    `whoami` chain matching an existing deterministic rule. **No
    real malware, no live technique.**
32. `DETECTION_MATCHED` derivation on the raw event
33. `GET /api/edr/findings` → durable finding
34. Finding evidence resolves back to the original canonical event and
    then to the immutable raw bytes
35. `GET /api/edr/findings/evaluation-state` → unmatched evidence is
    `NOT_EVALUATED` / `EVALUATED_NO_MATCH`, **never CLEAN**
36. Investigation opens on the endpoint from real evidence

**Phase 7 · boundaries**
37. Cross-tenant read with a second tenant → refused
38. No-header read → `403 TENANT_REQUIRED`
39. Response plane: still fail-closed; no action dispatched; `ACCEPTED ≠
    DISPATCHED ≠ EXECUTED ≠ REPORTED ≠ VERIFIED` preserved
40. Console claims no local prevention anywhere

**Acceptance standard.** Anything short of Phase 5 step 22 producing
**real process rows with real command lines and real ancestry** is
**PARTIAL**, not PASS. "Agent installed", "heartbeat received",
"endpoint in Computers" and "some events received" are each explicitly
NOT PASS.

---

## EXACT BLOCKERS

1. **`canonical_bridge.parse()` refuses the Windows sensor payload**
   (`ValueError: unknown sensor activity None`) — reproduced. Windows
   telemetry cannot become canonical evidence, so Device Trajectory,
   Process Tree, Detections and Findings are all empty, while the
   endpoint reports as fresh and delivering. **Requires a code change:
   owner authorisation needed.**
2. **Owner tenant-identity decision** — `nivx-machines` as `tenant_id`
   is not creatable; accept the opaque `ten_…` id with
   `slug=nivx-machines`, or authorise a code change.
3. **Owner decisions** — organization `kind`, tenant `kind`, and
   authorisation for the first two production DB writes.
4. **Windows host prerequisites** — Python 3.11+ and Sysmon (with a
   collection config) must be present, or Windows visibility collapses
   to raw Security-log XML.
5. **Unbounded outbox** — no size cap or rotation; a long outage grows
   `outbox.jsonl` until the disk fills. Not a blocker for a short
   acceptance run; a blocker for fleet deployment.
6. **No sensor crash recovery** — ONSTART-only task; a crash silences
   the endpoint until reboot.
7. **Production `NIVX_TENANT_REGISTRY_ENFORCE=true`** — inferred, not
   read. One authenticated `GET /api/xdr/tenants` returns
   `data.enforcing` and settles it read-only.

---

## STAGE A MUTATION REPORT

```
PRODUCTION DB WRITES:        0
TENANTS CREATED:             0
TENANTS MODIFIED:            0
ORGANIZATIONS CREATED:       0
ENDPOINTS CREATED:           0
TOKENS CREATED:              0
ENDPOINTS ENROLLED:          0
PRODUCTION TELEMETRY:        0
RESPONSE ACTIONS:            0
SECRET VALUES ACCESSED:      0
CODE CHANGES:                0
COMMITS:                     0
PUSHES:                      0
DEPLOYMENTS:                 0
VERCEL CHANGES:              0
WORKERS ENABLED:             0
```

Reads only: repository source; production `/api/openapi.json` and
`/api/health`; two unauthenticated `GET`s (both `403`, expected); preview
DB index metadata and document counts; one **local, offline** call to
`canonical_bridge.parse()` on a synthetic payload (no database, no
network, no production). `EDR_AUTH_PEPPER` was not read, displayed,
hashed, compared, logged, copied or rotated.

---

## FINAL DECISION

```
NOT READY — the Windows sensor's telemetry payload is refused by the
canonical bridge (edr_plane/canonical_bridge.py:79). Enrolling a real
Windows endpoint today yields a healthy-looking computer with an empty
Device Trajectory, an empty Process Tree, no detections and no findings.
```

The tenant create request is prepared and **not sent**:

```http
POST https://nivxray.nivxforge.com/api/xdr/organizations
Authorization: Bearer <production admin JWT>
Content-Type: application/json

{"slug": "nivx-machines", "display_name": "NivX Machines",
 "kind": "<VENDOR | CUSTOMER | MSSP — owner>"}
```

```http
POST https://nivxray.nivxforge.com/api/xdr/tenants
Authorization: Bearer <production admin JWT>
Content-Type: application/json

{"organization_id": "<org_… from the previous call>",
 "slug": "nivx-machines", "display_name": "NivX Machines",
 "kind": "<CUSTOMER | INTERNAL_VALIDATION | LAB — owner>",
 "products": ["xdr", "edr"]}
```

Stopped for owner review. Nothing was created, modified, deployed,
enrolled, rotated, enabled or dispatched.
