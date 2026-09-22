# NivXRay XDR + NivXForge EDR · Windows Telemetry, Endpoint Journal & Forensic Evidence
# AUTHORITATIVE GAP ANALYSIS (read-only · 2026-06)

Owner directive: read-only analysis only. **No implementation code was written
for this report.** Every status below is backed by code, test or runtime/DB
evidence, cited inline. Architecture documents were NOT accepted as proof.

Benchmark statements about commercial products come from their public
documentation as known to this agent (knowledge cutoff Jan 2026) and were
**not re-verified live in this task**; they are used for architectural
patterns only, never as a parity claim.

---

## 1 · EXECUTIVE SUMMARY

1. **Windows Event Log acquisition is real and architecturally sound, but has
   never run on a Windows endpoint.**
   `apps/nivxray-xdr-collector/framework/windows_eventlog.py` (658 lines)
   implements a native `win32evtlog` **EvtSubscribe + EvtCreateBookmark**
   reader (`NativeEvtReader`, l.316-335), 22 declared channels, per-channel
   durable bookmarks (`framework/windows_bookmarks.py`, 266 lines, stored in
   the same SQLite fsync domain as the outbox), and refuses to simulate on
   non-Windows (`UnsupportedPlatformReader`, l.300). 413 lines of unit tests
   pass **on Linux**. Runtime evidence: `xdr_canonical_events` contains
   **0 rows** with `collection_method: "windows-eventlog"`. → class **B**
   across the board.
2. **There is no NivXForge EDR Windows sensor.** The only sensor in the repo
   is Linux (`agents/nivxforge-linux/nivxforge_sensor.py`, supervised). All
   Windows telemetry today arrives through the **collector** (agentless /
   forwarder model), not through an endpoint sensor. → **E** for native
   endpoint sensor telemetry.
3. **No ETW. No WMI-API telemetry.** Grep finds ETW only as detection-content
   vocabulary and WMI only as (a) an Event Log channel and (b) behaviour
   keywords in reasoning services. → **E**.
4. **There is no Endpoint Event Journal.** `framework/outbox.py` is a durable
   **delivery outbox** (SQLite, attempts, dead-letter) — it is not retained
   history, has no retention/rollover policy, no index, and no query surface.
   → **C** (durability yes, journal no).
5. **Raw + canonical dual-evidence and the truth model are the strongest part
   of the platform.** Raw XML is preserved verbatim (test
   `test_raw_xml_is_preserved_verbatim`), SIDs are never resolved at the
   endpoint, `xdr_canonical_evidence` carries `raw_ref` + provenance, and
   `services/windows_channel_truth.py` keeps COLLECTION / PARSE / NORMALIZE /
   DETECTION as **separate** dimensions with states including
   `NOT_CONFIGURED`, `CONFIGURED`, `NOT_OBSERVED`, `RECEIVING`.
6. **Analysis coverage is far narrower than acquisition coverage, and the code
   says so honestly.** Only 5 channels have a DSM
   (`ANALYSIS_SUPPORTED`: Sysmon, Security, both PowerShell channels,
   Defender); detection coverage is `PARTIAL`/`NOT AVAILABLE` even there.
   17 declared channels are acquired-and-preserved but unparsed.
7. **Channel set is a code-declared profile, not administrator-arbitrary.**
   An unknown channel is refused (`UNKNOWN_CHANNEL`, l.220-222;
   `test_unknown_channel_is_refused`) and `ForwardedEvents` is explicitly
   declared unsupported. This is deliberate honesty today and a **gap**
   against the directive's "arbitrary administrator-configured channels".
8. **No forensic artifact acquisition** (EVTX, hives, prefetch, Amcache,
   memory) anywhere in the repo. → **E**, and per directive out of scope.

Bottom line: the platform has an excellent *evidence contract* and a genuine
Windows Event Log *acquisition design*, with **no endpoint-proven Windows
collection, no native endpoint telemetry, and no journal**. The first
implementation gate must therefore be *proof on a real Windows host*, not more
breadth.

---

## 2 · CURRENT NIVXFORGE EDR ARCHITECTURE (evidence)

| Component | Code | Status |
|---|---|---|
| Linux endpoint sensor | `agents/nivxforge-linux/nivxforge_sensor.py`, supervised (`supervisor` program `nivxforge_sensor`, durable state `/app/agents/nivxforge-linux/.state`) | **A** (running; 188,346 `edr_raw_events`) |
| Windows endpoint sensor | — | **E** |
| Endpoint enrolment / identity | `edr_endpoints` (222 docs, `os_family` unset on all), `edr_plane/canonical_bridge.py` binds authenticated endpoint → canonical evidence | **C** (no OS family recorded, no Windows endpoint) |
| Raw endpoint rows | `edr_raw_events` (raw payload + `payload_sha256` + `dedup_key` + `trust_state: AUTHENTICATED` + `derivations[]`) | **A** (Linux) |
| Endpoint→canonical bridge | `edr_plane/canonical_bridge.py:346` mints `cev_<raw>_<gen>`, sets `raw_ref`, binds process identity, records `CANONICAL_EVIDENCE_CREATED` / `DUPLICATE_OBSERVATION_OF_KNOWN_ACTIVITY` derivations | **A** |
| Endpoint response + evidence | `routers/xdr_response_evidence.py` (P0/P0.1 closed) | **A** |

## 3 · CURRENT NIVXRAY XDR ARCHITECTURE (evidence)

| Component | Code | Status |
|---|---|---|
| Authenticated ingest | `POST /api/xdr/ingest/telemetry` — API-key principal, server-side tenant authority (`services/tenant_registry.authoritative`), declared-source routing fail-closed (`services/source_routing.py`), delivery idempotency, routing-block evidence rows | **A** (proven live this session) |
| Raw evidence | `xdr_canonical_events` (776 rows; methods `rest`/`rest-poll`/`syslog`/`webhook`/`wef`/`windows_eventlog_pull`) | **A** |
| Canonical evidence | `xdr_canonical_evidence` (181,968 rows; `event_id`, `tenant_id`, `raw_ref`, `provenance.timestamps` 8 boundaries) | **A** |
| DSM / parsers | `detection_content/telemetry/*`: `sysmon_dsm`, `windows_security_dsm`, `windows_powershell_dsm`, `windows_defender_dsm`, `linux_auditd_dsm`, `cef_leef`, `zeek_json`, `snort`, `m365`, `aws_cloudtrail`, `nivxforge_sensor_dsm` | **A** for those sources |
| Evidence Namespace Bridge | `services/evidence_bridge.py` + `GET /api/incidents/{id}/canonical-evidence` (P1, closed) | **A** |
| Windows truth surface | `services/windows_channel_truth.py`, `routers/xdr_windows.py` (8 **read-only** routes), UI `src/xdr/datasources/windows/*` | **B** (no write/config API) |
| Trajectory | `v2/trajectory/*` + `GET /api/v2/cases/{id}/trajectory/device` | **C** (87 case-linked observations platform-wide; most incidents `NOT_ASSOCIATED`) |
| Evidence Lake / historical search | `services/event_search.py` over `xdr_canonical_events` | **C** (no lifecycle/retention tiering found) |

## 4 · WINDOWS EVENT LOG COVERAGE MATRIX

Acquisition mechanism for every row below: `EvtSubscribe` + bookmark
(`NativeEvtReader`), XPath filter per channel, raw XML preserved.

| Channel | Declared source | Collection | Normalization (DSM) | Detection | Status |
|---|---|---|---|---|---|
| Microsoft-Windows-Sysmon/Operational | sysmon | declared | SUPPORTED (`sysmon_dsm`) | SUPPORTED | **B** |
| Security | windows_security | declared | SUPPORTED (`windows-security-evd`) | PARTIAL | **B** |
| Microsoft-Windows-PowerShell/Operational | windows_powershell | declared | SUPPORTED | NOT AVAILABLE | **B** |
| Windows PowerShell (classic) | windows_powershell | declared | SUPPORTED | NOT AVAILABLE | **B** |
| Defender/Operational | microsoft_defender | declared | SUPPORTED | NOT AVAILABLE | **B** |
| TaskScheduler/Operational | windows_task_scheduler | declared | NOT YET (roadmap 1) | NOT AVAILABLE | **C** |
| WMI-Activity/Operational | windows_wmi | declared | NOT YET (roadmap 2) | NOT AVAILABLE | **C** |
| AppLocker/EXE and DLL | windows_applocker | declared | NOT YET (roadmap 3) | NOT AVAILABLE | **C** |
| System / Application | windows_system / windows_application | declared | NOT YET (roadmap 4-5) | NOT AVAILABLE | **C** |
| CodeIntegrity, RDP (LSM + RCM), WinRM, DNS-Client, Firewall, SmbClient/Security, Directory Service, DNSServer/Audit, BitLocker, WindowsUpdateClient | per-channel | declared | NOT YET | NOT AVAILABLE | **C** |
| **ForwardedEvents (WEF/WEC)** | — | **declared UNSUPPORTED** (origin-vs-collector host distinction unproven) | — | — | **D** |
| Setup, Kerberos/NTLM operational, Terminal-Services others, SMB server, service-control detail | — | **not in `CHANNELS`** → refused as `UNKNOWN_CHANNEL` | — | — | **E** |
| Arbitrary admin-configured channel | — | **refused by design** | — | — | **E** vs directive §4 |

Field preservation (verified by tests): raw XML verbatim, per-channel identity
(`channel` + `EventRecordID`, two channels with the same record id are two
identities), SID verbatim, origin computer kept separate from collector host,
activity vs sensor clock separate, `TimeCreated` used only when `UtcTime` is
absent. **Not verified anywhere**: Keywords / Task / Opcode / Level /
ActivityID / ProcessID+ThreadID (`Execution`) / UserData round-trip into
canonical evidence.

## 5 · NATIVE ENDPOINT TELEMETRY COVERAGE MATRIX (Windows)

| Telemetry family | Current Windows source | Mechanism | Status |
|---|---|---|---|
| process start, command line, parent, ancestry | Sysmon EID 1 / Security 4688 **via Event Log only** | Event Log | **B** |
| process termination | Sysmon EID 5 (channel acquired; no DSM mapping found) | Event Log | **C** |
| image / module load | Sysmon EID 7 (no DSM mapping) | Event Log | **C** |
| driver load | Sysmon EID 6 (no DSM mapping) | Event Log | **C** |
| file create/write/delete/rename | Sysmon EID 11 mapped to `file_create`; delete/rename unmapped | Event Log | **C** |
| registry | Sysmon EID 12/13/14 → single `registry_event` type | Event Log | **C** |
| network connection | Sysmon EID 3 → `network_connect` | Event Log | **B** |
| DNS | Sysmon EID 22 → `dns_query`; DNS-Client channel unparsed | Event Log | **C** |
| logon / authentication / RDP / SMB / WinRM | Security + RDP/WinRM/SMB channels (only Security has a DSM) | Event Log | **C** |
| PowerShell / script block | PowerShell channels, DSM present, no detection content | Event Log | **B/C** |
| WMI activity | channel declared, no DSM | Event Log | **C** |
| services / scheduled tasks / persistence | System + TaskScheduler channels, no DSM | Event Log | **C** |
| signer / signature, integrity level, hashes | only if Sysmon emits them; no canonical fields verified | Event Log | **C** |
| thread/process injection indicators | Sysmon EID 8/10 (unmapped) | Event Log | **C** |
| removable device, security-control changes | not declared | — | **E** |
| **process/thread/image/file/registry from the OS directly (no Sysmon dependency)** | — | ETW / kernel / WMI **absent** | **E** |

**Structural finding:** today NivXRay XDR's Windows process/file/registry
visibility is *Sysmon-dependent*. Microsoft Defender for Endpoint's
`DeviceProcessEvents` / `DeviceFileEvents` / `DeviceRegistryEvents` /
`DeviceNetworkEvents` / `DeviceLogonEvents` / `DeviceImageLoadEvents` are
sensor-native, not Event-Log-derived. That is the single largest capability
gap in this report.

## 6 · WMI COVERAGE
`Microsoft-Windows-WMI-Activity/Operational` is a **declared, unparsed**
channel (roadmap position 2). No WMI **API** consumer, no `__InstanceCreation`
/ permanent-subscription telemetry, no `Win32_*` querying by any collector.
WMI appears elsewhere only as detection vocabulary
(`services/reasoning/behavior_extractor.py`). → **C** (channel) / **E** (API).

## 7 · ETW / WINDOWS-NATIVE TELEMETRY COVERAGE
**E — none.** No ETW session, no provider subscription, no
`Microsoft-Windows-Threat-Intelligence`, no kernel callbacks, no minifilter.
All Windows visibility is Event-Log-mediated.

## 8 · NIVXFORGE EDR ENDPOINT EVENT JOURNAL STATUS

| Journal property | Evidence | Status |
|---|---|---|
| durable local store | `framework/outbox.py` (SQLite, `${XDR_STATE_DIR}/outbox.db`) | **A** |
| crash/restart recovery | outbox + bookmark share one fsync domain; `test_bookmark_does_not_advance_before_durability` | **A** |
| acquisition checkpoint continuity | `WindowsBookmarkStore` (bookmark authority, record id evidence only, `RESUME_FRESH/STALE/LOG_CLEARED`) | **A** (unit) |
| retry / dead-letter accounting | `max_attempts`, `DEAD_LETTER` | **A** |
| **retention policy / size+time limits / rollover** | none found | **E** |
| **short-term forensic history after delivery** | rows exist only until delivered | **E** |
| **index / queryability / Live Endpoint Search** | none | **E** |
| tamper resistance / integrity / encryption at rest | none found (`payload_sha256` exists on the server side only) | **E** |
| loss accounting vs Windows log rollover | `RESUME_STALE` / `RESUME_LOG_CLEARED` classified but no quantified loss record | **C** |
| resource/CPU/disk budget | none declared | **E** |

Conclusion: NivXForge EDR has a **transport outbox**, not an Event Journal.
Sophos's Event Journal + Live Discover pattern (durable local telemetry
history queryable after the fact) is **not** implemented. The outbox is the
right foundation to evolve — a second endpoint store would be wrong.

## 9 · NIVXRAY XDR RAW + CANONICAL EVIDENCE STATUS
**A.** Dual evidence is real: raw row (`xdr_canonical_events` /
`edr_raw_events`) + canonical row (`xdr_canonical_evidence` with `raw_ref`,
`provenance.normalizer_id`, `provenance.trace_id`, 8 timestamp boundaries),
now joined to every downstream representation by the frozen
`canonical_evidence_id` bridge. Unparsed channels are preserved verbatim and
reported as `NORMALIZATION: NOT YET SUPPORTED`, never discarded — directive
§7 "do not discard unknown evidence" is already honoured.

## 10 · FORENSIC READINESS
- Reconstructable **today** (where Sysmon/Security telemetry exists): who
  logged on, what process started, parent, command line, network destination,
  DNS, one file-create, coarse registry event, detection, response, response
  verification.
- **Not** reconstructable: module/driver loads, process exits, file
  delete/rename, service/task persistence detail, WMI, injection indicators,
  signer/integrity context — acquired-but-unparsed or not acquired.
- Artifact acquisition (EVTX, hives, prefetch, Amcache, Shimcache, tasks,
  browser artifacts, memory, file capture, triage package): **E / none**.
- **Boundary recommendation**: continuous telemetry = event streams (Event
  Log + future ETW + sensor); on-demand forensic acquisition = artifacts and
  memory, requested per endpoint, rate-limited, chain-of-custody hashed,
  stored as raw evidence with its own canonical reference. Out of scope now.

## 11 · THREE-CLOCK READINESS
**A/B.** `ACTIVITY_TIME` vs `SENSOR_OBSERVED_AT` separated in the Windows
adapter (`test_activity_and_sensor_clocks_are_separate`); `INGEST_TIME` is the
HTTP boundary and is proven live for the auditd path
(`scripts/p0_d11_ingest_provenance_live_proof.py`: 8 distinct boundaries, none
substituted). **Gap**: the Windows separation is unit-proven only, and
`sensor_observed_at` propagation to the incident surfaces is the queued
`Sensor Clock Mapping` task.

## 12 · LOSS / RECOVERY / BACKPRESSURE READINESS
Covered by code+tests: durability-before-advance, per-channel isolation
(`test_channel_not_durable_keeps_its_position`), log-cleared detection, stale
bookmark, read failure recorded as error not bookmark, unsupported platform
reports "not read", delivery idempotency at ingest, duplicate-activity
suppression at the endpoint bridge.
Not covered: quantified loss accounting on rollover, local queue-pressure
policy, journal rollover, sustained-burst behaviour, clock-skew handling,
credential-rotation-mid-delivery, Windows-side upgrade compatibility.

## 13 · SECURITY + TENANT ISOLATION
**A.** Tenancy exists only via `POST /api/xdr/tenants` (registry enforcing —
verified live: `allow_new_tenant` now refused with
`ALLOW_NEW_TENANT_DEPRECATED`); ingest tenant comes from the authenticated
key and every envelope/collector/header tenant must agree; declared-source
routing is fail-closed; bookmarks are scoped `(tenant, collector, channel)`;
response-evidence read **and** write authority closed (P0/P0.1); evidence
bridge access authority is the incident (P1). Residual: endpoint enrolment
records no `os_family`, and no Windows-side sensor upgrade/signing story
exists because there is no Windows sensor.

## 14 · PERFORMANCE / RETENTION IMPLICATIONS
No collection-cost model, no per-channel volume budget, no retention tiering
for `xdr_canonical_evidence` (181,968 rows) or `edr_raw_events` (188,346
rows), no index/storage-growth policy, no endpoint resource budget. Tiering
proposal (always-on / enhanced / investigation-only / on-demand artifact) is
**not** represented anywhere in code today.

## 15-20 · BENCHMARK COMPARISON (public patterns; not parity claims)

| Product | Pattern worth adopting | NivX position |
|---|---|---|
| **Microsoft Defender for Endpoint / Defender XDR** | sensor-native typed event families (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`), device timeline, Advanced Hunting over 30-day retention | NivXRay XDR has the canonical model but only Event-Log-derived process/network depth; **no sensor-native families** |
| **Cisco Secure Endpoint / Cisco XDR** | connector + **Device Trajectory / File Trajectory**, Orbital-style live endpoint query | Trajectory *presentation* exists (`v2/trajectory`); the telemetry feeding it is thin (87 case-linked observations) and there is no live endpoint query |
| **Sophos Intercept X / XDR** | **Endpoint Event Journals** (durable local telemetry history) + **Live Discover** queries against them | NivXForge EDR has a delivery outbox only — the journal is the single biggest endpoint-side gap |
| **Palo Alto Cortex XDR / XSIAM** | causality chains (CGO) built at the agent, normalized cross-source data plane | NivXRay XDR builds causality server-side from sparse observations; no agent-side causality |
| **CrowdStrike Falcon** | one lightweight kernel-level sensor streaming all event families; event search over streamed telemetry | NivXForge EDR: Linux-only user-space sensor; no Windows sensor |
| **SentinelOne Singularity** | agent-side Storyline binding activity to one lineage id; Deep Visibility hunting | NivX has an equivalent *identity* substrate (`process_iid`, IRG, canonical bridge) but no agent-side storyline and no hunting surface over it |
| **Elastic / Splunk ES** | tiered hot/warm retention + schema-on-read historical search | NivXRay XDR `event_search` has no tiering or retention policy |

## 21 · CAPABILITY GAP MATRIX (ranked)

| # | Gap | Owner | Status | Recommended action |
|---|---|---|---|---|
| 1 | Windows Event Log acquisition never proven on a real Windows host | NivXForge EDR | **B** | one-host acceptance proof (bookmark resume, reboot, log-clear, raw XML → canonical) |
| 2 | No Windows endpoint sensor | NivXForge EDR | **E** | after gap 1: Windows sensor skeleton reusing the authenticated endpoint enrolment + `edr_raw_events` path |
| 3 | No Endpoint Event Journal (retention, query, rollover, integrity) | NivXForge EDR | **C/E** | evolve `outbox.py` into a journal with explicit retention + loss accounting |
| 4 | No ETW / no sensor-native process·file·registry·image telemetry | NivXForge EDR | **E** | ETW/kernel design gate after gap 2 |
| 5 | 17 acquired channels have no DSM → no canonical evidence | NivXRay XDR | **C** | DSM per roadmap order (TaskScheduler, WMI, AppLocker, System, Application) |
| 6 | Channel set not administrator-arbitrary; WEF/ForwardedEvents unsupported | both | **D/E** | channel-profile write API + WEF origin-host proof |
| 7 | Sysmon EIDs 5/6/7/8/10 and file delete/rename unmapped | NivXRay XDR | **C** | extend `sysmon_dsm` canonical types |
| 8 | Event Log metadata (Keywords/Task/Opcode/Level/ActivityID/Execution) not proven into canonical evidence | NivXRay XDR | **C** | canonical field + test |
| 9 | Sibling canonical evidence of one delivery not associated to the incident (found in P1) | NivXRay XDR | **C** | association fix |
| 10 | No forensic artifact acquisition | NivXForge EDR | **E** | design-only boundary (deferred by directive) |
| 11 | No retention/cost/telemetry-tier model | both | **E** | policy design gate |
| 12 | `edr_endpoints.os_family` unset on all 222 endpoints | NivXForge EDR | **C** | record OS family at enrolment (prerequisite for any Windows fleet view) |

## 22 · RECOMMENDED FINAL ARCHITECTURE

```
Windows endpoint
  ├─ NivXForge EDR Windows Sensor (future)
  │    ├─ Event Log acquisition   EvtSubscribe + bookmark   [exists, unproven]
  │    ├─ ETW / kernel telemetry  process·file·registry·image·net [absent]
  │    └─ WMI / auditing APIs     persistence + subscriptions      [absent]
  └─ NivXForge EDR Endpoint Event Journal   (evolve outbox.db)
       durable · retained · checkpointed · queryable · loss-accounted
            │  authenticated, tenant-bound, replay-protected transport
            ▼
NivXRay XDR ingest  (declared-source routing, fail-closed, idempotent)
  → RAW forensic evidence (verbatim XML / payload + hash + raw_ref)
  → DSM / normalizer → CANONICAL evidence (canonical_evidence_id)
  → Evidence Lake (tiered retention · historical search)
  → detection · correlation · incident · investigation · hunting
  → timeline · trajectory · attack story · forensic reconstruction
  → response orchestration + independent verification
```
Principles preserved: dual raw+canonical evidence, three clocks, one evidence
namespace (P1 bridge), separate truth dimensions, source-agnostic canonical
model with vendor specifics confined to adapters.

## 23 · IMPLEMENTATION GATES (priority order)

- **G1 · Windows Event Log endpoint proof** (gap 1) — prove the existing
  adapter on one real Windows host end to end.
- **G2 · Event Log metadata + Sysmon EID completeness** (gaps 7, 8).
- **G3 · DSM expansion in the declared roadmap order** (gap 5).
- **G4 · Endpoint Event Journal** — retention, rollover, loss accounting,
  integrity, then query (gap 3).
- **G5 · NivXForge EDR Windows sensor skeleton** + `os_family` at enrolment
  (gaps 2, 12).
- **G6 · ETW / sensor-native telemetry families** (gap 4).
- **G7 · Channel-profile configuration API + WEF origin-host proof** (gap 6).
- **G8 · Retention / telemetry-tier policy** (gap 11).
- **G9 · Forensic artifact acquisition** (gap 10) — design gate only.

## 24 · FIRST SMALL IMPLEMENTATION TASK
See `RECOMMENDED NEXT TASK` below.

---

RECOMMENDED NEXT TASK: **G1 · prove the existing NivXForge EDR Windows Event
Log acquisition on ONE real Windows endpoint, end to end, and report the truth
it produces — no new channels, no ETW, no journal work.**

**OBJECTIVE** — Move Windows Event Log acquisition from class B
(implemented, not endpoint-proven) to class A for a minimal channel set
(`Security`, `Microsoft-Windows-Sysmon/Operational`,
`Microsoft-Windows-PowerShell/Operational`): a real Windows host runs the
collector, real records are acquired through `EvtSubscribe` + bookmark, are
made durable before the bookmark advances, are delivered to authenticated
NivXRay XDR ingest, become raw evidence and then canonical evidence with a
`canonical_evidence_id`, and appear in the Windows truth surface with the
correct per-dimension states.

**FILES / COMPONENTS EXPECTED** (change only if the proof shows a defect)
- `apps/nivxray-xdr-collector/framework/windows_eventlog.py`,
  `framework/windows_bookmarks.py`, `framework/outbox.py`,
  `main.py` (`windows-eventlog` connector already registered)
- `apps/nivxray-xdr-collector/scripts/w2r0_windows_preflight.ps1`
- `backend/routers/xdr_ingest.py` (no change expected),
  `backend/detection_content/telemetry/{sysmon,windows_security,windows_powershell}_dsm.py`
- `backend/services/windows_channel_truth.py`, `routers/xdr_windows.py`
- new: `/app/memory/G1_WINDOWS_EVENTLOG_ENDPOINT_PROOF.md` + one proof script

**PASS CONDITIONS**
1. A real Windows host acquires records on the three channels; raw rows land
   with `collection_method: "windows-eventlog"` (today: 0).
2. Raw XML is preserved verbatim and the record is addressable by
   `(channel, EventRecordID)`; SID verbatim; origin computer ≠ collector host.
3. Bookmark resume proven across **collector restart**, **host reboot** and
   **log clear** — no duplicate delivery, no silent gap, `RESUME_*` state
   correct in each case.
4. Bookmark never advances before the record is durable in the outbox
   (kill the process mid-delivery and show the record is redelivered).
5. `ACTIVITY_TIME` (event's own `UtcTime`/`TimeCreated`),
   `SENSOR_OBSERVED_AT` (collector read) and `INGEST_TIME` (HTTP receipt) are
   three distinct, source-attributed values.
6. Canonical evidence exists for the DSM-supported channels and carries
   `raw_ref` + `canonical_evidence_id`; the P1 bridge resolves it from the
   incident surface when an incident is promoted.
7. `GET /api/xdr/windows/channels` reports per channel: COLLECTION =
   `RECEIVING`, and NORMALIZATION / DETECTION exactly as
   `ANALYSIS_SUPPORTED` states — no composite "healthy".
8. An acquired channel with no DSM is reported acquired-and-unparsed, its raw
   XML retained.

**FAIL-CLOSED CONDITIONS**
- Non-Windows platform → `UNSUPPORTED_PLATFORM`, zero events, never simulated.
- Channel unreadable / access denied → reported unread with the error, not
  empty and not healthy; bookmark unchanged.
- Unknown or `ForwardedEvents` channel → refused with its declared reason.
- Ingest authentication failure or tenant mismatch → no raw row, no
  idempotency claim, no canonical evidence; records stay in the outbox.
- Any known or unprovable loss → stated as loss; never reported as complete
  telemetry.

**REAL WINDOWS PROOF REQUIRED** — Unit tests on Linux are NOT acceptable for
this gate. The proof must run on a genuine Windows host (owner-provided VM or
host) and must record: Windows build, Sysmon version/config presence, channel
list, record counts per channel, bookmark values across the three restart
scenarios, the resulting raw + canonical ids, and the exact truth states
returned by the Windows surface. If no Windows host can be provided, the task
stops and says so — no substitute proof will be manufactured.

**STOP CONDITION** — Report the outcome and STOP. Do not add channels, do not
start ETW/WMI, do not build the Event Journal, do not expand DSMs, and do not
touch Dense Timeline, Sensor Clock Mapping, Evidence Read Grant, Control
Center, Hunting or Event Explorer work in this task.

STOPPING FOR OWNER REVIEW.
