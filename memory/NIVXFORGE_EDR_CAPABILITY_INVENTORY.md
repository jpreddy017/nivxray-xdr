# NIVXFORGE EDR — CAPABILITY INVENTORY & M2 ENGINEERING INTAKE

**Mode: READ-ONLY.** No commit, push, merge, branch mutation, tracked-file
edit, database write, deployment, installer execution or response action was
performed. No credential value was read, printed or copied. M1 and every
frozen baseline are untouched.

Date: 2026-06 · Assessor: engineering agent · Evidence basis: live repository
inspection, live route reflection, executed test suites, and read-only
queries against the preview Mongo.

---

# A · SOURCE BASELINE

## A.1 Repository and access

| Field | Value |
|---|---|
| Repository | `jpreddy017/nivxray-xdr` |
| Access used | the authoritative working repository on this pod (`/app`, full object store, 2,200+ commit history) |
| Isolated clone | **not created** — the pod has ~260 MB free against a ~119 MiB pack plus checkout; a second full clone could not be established safely. Inspection was performed **read-only** against the existing object store and a sparse, non-destructive `git worktree` on a scratch path. No working directory was altered. Coverage limitation recorded in §G. |
| GitHub API / Actions history | **not consulted** — no token available. Whether `windows-sensor-installer.yml` has ever executed, and with what result, is therefore UNKNOWN (§G). |

## A.2 Branch topology — `main` is NOT the newest EDR source

| Branch | Head | Date | Position |
|---|---|---|---|
| `main` | `7f280b66` | **2026-07-19** | stale; every active branch is 2,100–2,230 commits ahead |
| `fix/p0-sensor-delivery` | `f971c765` | 2026-10-22 | **checked-out trunk of record**; 2,226 ahead of main |
| `release/edr-process-graph` | `614f20f9` | 2026-10-20 | 2,212 ahead; 8 commits the trunk does not have |
| `integration/e3-dt` | `35ca22b8` | 2026-10-20 | ancestor of the trunk |
| `feature/process-graph-falcon` | `dee7bf3c` | 2026-10-20 | not an ancestor of the trunk |
| `engineering/m1-g3-integrated` | `388bb3d6` | 2026-10-22 | **M1, G3-PASSED**, not an ancestor of the trunk |
| `engineering/m1-g4-preparation` | `b8020771` | 2026-10-22 | M1 + G4 runbook, not an ancestor of the trunk |
| `safety/dt2-1-19of19` | `38afd524` | 2026-09-28 | trajectory UI line |

## A.3 The divergence that matters most

The M1 engineering lineage and the trunk **split at `ae340563` (2026-10-04)**
and have not been reconciled.

| Path | Trunk (`f971c765`) | M1 (`388bb3d6`) |
|---|---|---|
| `nivxforge_m1.py` (clean installer, 2,547 lines) | **absent** | present |
| `nivxforge_transaction.py` (996 lines) | **absent** | present |
| `nivxforge_scm_worker.py` (352 lines) | **absent** | present |
| `nivxforge_sensor.py` | +106 lines of its own | +299 different lines |
| `nivxforge_setup.py` | +135 lines of its own | +1,372 different lines |
| `backend/routers/edr_maintenance.py` (415 lines) | present | **absent** |
| `test_m1_clean_install.py`, `test_installer_transaction.py`, `test_p0_installer_upgrade_repair.py` | absent | present (≈4,800 lines) |

**Consequence:** the installer, transaction/recovery engine and SCM worker
exist on exactly one lineage, the backend `edr_maintenance` router on the
other, and `nivxforge_sensor.py` / `nivxforge_setup.py` have **two divergent
heads**. This is the single largest structural risk in the programme — not
because either side is wrong, but because a future merge of two independently
hardened installer/sensor lines is a security-relevant operation that nobody
has yet scoped. It is P0 in §E.

## A.4 Source trees inspected

```
agents/nivxforge-windows/        sensor, journal, setup, build/, sysmon/  (+ m1, transaction, scm_worker on M1 branch)
agents/nivxforge-linux/          sensor 1,314 · exclusions 315 · content acquisition 274 · delivery counters 101
agents/_shared/                  exclusions 315
backend/edr_plane/               29 modules · 12,358 lines
backend/services/edr/            6 modules · 2,019 lines
backend/routers/edr*.py          17 routers · 7,263 lines
backend/detection_content/library/   rules_edr_linux.py 310 · rules_enterprise.py 1,727
backend/tests/edr/               113 files · 31,996 lines
apps/nivxray-xdr/src/nivxforge/  console, 15 pages, 3 trajectory implementations · ≈10,000 lines
apps/nivxray-xdr/src/xdr/pages/  39 pages (hunting, search, event explorer, trajectory entry)
.github/workflows/               windows-sensor-installer.yml (762 lines), rc4x/rc5 gates
docs/                            prior audit `docs/audit/NIVXFORGE_EDR_TRUTH_AUDIT.md` (2026-06, 40 rows) and 10 handoff contracts
```

`backend/routers/edr.py` exists (1,994 lines); **`backend/services/edr/` and
`backend/edr_plane/` both exist** — the brief's starting paths are real, with
one correction: there is no `backend/routers/edr.py`-only surface; EDR is
spread across 17 routers.

## A.5 Live route reflection

`server.app` mounts **971 routes, of which 97 are `/api/edr/*`**: agent 13,
wave0 10, endpoints 8, enrollment 8, exclusions 8, policies 7, response 5,
connector 5, saved-views 5, onboarding 4, findings 4, events 3, groups 2,
audit 2, plus `detections`, `endpoint-detections`, `endpoint-commands`,
`process-tree`, `device-trajectory`, `file-trajectory`, `campaign-story`,
`fleet-spread-index`, `telemetry/freshness`, `computers`, `observation-narrative`.

## A.6 Test evidence actually executed

| Suite | Command | Result |
|---|---|---|
| Trunk EDR suite | `pytest backend/tests/edr -q` | **2,392 passed · 16 failed · 3 skipped** (230 s) |
| `test_34h_a_migration_control.py` in isolation | same file alone | **passes** → the 12 failures are order/state pollution in the shared Mongo, not proven product defects |
| `test_p0_f13_5_detection_handoff.py` in isolation | same file alone | **4 failed, 3 passed** — a real harness defect: `deps._db` is unbound in that context (`deps.py:149 _require()`), so `trajectory_focus` cannot reach `edr_endpoints` |
| M1 suite (branch `388bb3d6`) | `pytest backend/tests/edr/test_m1_clean_install.py -q` | **373 passed** |

Read-only note: the 16 failures were **not** fixed, per the no-implementation
boundary.

## A.7 Operational evidence (read-only Mongo, preview environment)

| Collection | Documents | What it proves |
|---|---|---|
| `edr_raw_events` | **357,832** | the authenticated ingest path has carried real sensor traffic at volume |
| `v2_shadow_observations` | **362,854** | canonical observations exist — **356,803 from adapter `nivxforge-linux-sensor/1.0.0`**, 6,691 `sysmon-normalizer`, 223 `golden@1.0` |
| — by kind | `network_connect` 333,250 · `process_create` 24,817 · `detection` 3,159 · `registry_*` 3,120 · `file_*` 348 · `dns_query` 61 | |
| — with `event.process.parent_iid` | **23,031** (22,832 Linux) | parent-child linkage is populated, not theoretical |
| `edr_endpoints` | **592** (578 `linux`, 10 `windows`/`WINDOWS`) | enrolment works; the fleet is effectively Linux |
| `edr_agent_credentials` | 608 | per-endpoint credential issuance is real |
| `edr_findings` / `edr_finding_evaluations` | **1,183 / 142,253** | detections are durable AND "not evaluated" is distinguishable from "no finding" |
| — by rule | `EDR-LNX-002` 1,103 · `EDR-LNX-004` 101 · `DET-EX-001` 5 · `DET-PS-001` 2 · others 2 | |
| `edr_response_commands` | **266** — `AUTHORIZED` 183 · `CAPABILITY_UNAVAILABLE` 75 · **`VERIFIED` 5** · `VERIFICATION_FAILED` 1 · `DISPATCHED` 1 · `FAILED` 1; actions `ISOLATE_ENDPOINT` 259, `KILL_PROCESS` 7 | response has genuinely executed and been independently verified — five times, on Linux |
| `edr_processing_queue` | 83,707 | the ingest pipeline is a real queue |
| `edr_rejected_telemetry` | 6,108 | rejects are recorded, not dropped |
| `edr_policies` / `edr_exclusions` / `edr_policy_audit` | 11 / 6 / 41,356 | policy and exclusion planes are used and audited |
| `e3_behavior_detections`, `edr_behavior_shadow_detections`, `edr_process_entities`, `edr_detections`, `edr_audit` | **0** | the behaviour-shadow engine and the process-entity store have produced nothing |

The 357k-event corpus is **one Linux container endpoint** (360,442 of 361,767
events from `ep_2d57cbe6…`), tenant `default`. Payload shape confirms a
genuine process observation with `pid`, `ppid`, `start_time`, `image`,
`image_path`, `command_line`, `user`, `sha256` and an explicit
`not_observed: [exit_time, signer, integrity]`.

---

# B · CAPABILITY INVENTORY

Status vocabulary as specified. "Integration-verified" requires evidence that
the capability has actually run end to end — a test alone is not enough.

## B.1 · A — Endpoint sensor and data collection

| Capability | Status | Source | Tests | UI/API | Operational evidence | Gaps |
|---|---|---|---|---|---|---|
| Linux sensor: process, network, file collection | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `agents/nivxforge-linux/nivxforge_sensor.py` `collect_processes` (225), `collect_network` (402), `collect_files` (457) | `test_p0_b_linux_sensor.py` (520 L) | `/api/edr/agent/telemetry` | 356,803 canonical observations from this adapter | file watch is a single `--watch` path, not a policy-driven ruleset |
| Linux process identity: `start_time` + inode→pid network attribution | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `_proc_start_identity` (351), `_inode_pid_map` (333), `_proc_parent` (299) | yes | — | 22,832 observations carry `parent_iid` | no cgroup/container identity, no namespace awareness |
| Windows sensor: Security / System / Sysmon via `wevtutil`, bookmarked, gap-detected | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `agents/nivxforge-windows/nivxforge_sensor.py` `acquire` (717), `_query_channel` (556), `detect_gaps` (666), `_probe_source_tail` (602) | `test_b5_gap1_*` (3 files, 1,646 L), `test_g41_resumability.py` | same agent API | 10 Windows endpoints enrolled; 6,691 `sysmon-normalizer` observations exist but their sensor provenance is not isolable from fixtures in this environment | **no DNS, no registry, no file, no network collection of its own** — it collects whatever those three channels contain and nothing else |
| Durable evidence journal (SQLite), quarantine, batch delivery, integrity reporting | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `nivxforge_journal.py`, `_drain_journal` (1089), `_report_integrity` (1208) | `test_b5_gap1_journal_durability.py` (543 L) | `/api/edr/agent/telemetry/batch` | CI gate 0 exercises the frozen journal on `windows-latest` (run history UNKNOWN) | — |
| Sysmon integration | **PARTIALLY IMPLEMENTED** | `sysmon/nivx-b5gap1-canary-sysmon.xml`; `edr_plane/windows_eventlog.py` | `test_b5gap1_canary_harness.py` | — | 6,691 observations | Sysmon is **not deployed by the installer**; the channel is reported unavailable when absent (honest, but it means the richest Windows source is optional) |
| Windows canonicalisation coverage | **PARTIALLY IMPLEMENTED** | `windows_eventlog.py:84 SUPPORTED` — exactly **9 pairs**: Sysmon 1, 3, 5, 11, 12, 13, 22; Security 4688, 4624 | `test_*windows*` | — | refusals are explicit (`WINDOWS_EVENT_ID_NOT_SUPPORTED`) with a reason string | **missing**: Sysmon 7 (image load), 8 (CreateRemoteThread), 10 (ProcessAccess → credential access), 15, 17/18 (pipes), 19–21 (**WMI persistence**), 23/26 (file delete), 25 (process tampering); Security 4625, 4672, 4697 (**service install**), 4698 (**scheduled task**), 4720; System 7045 |
| Reliable delivery, retries, offline queue, delivery counters | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `nivxforge_delivery_counters.py` (both platforms), `edr_plane/delivery_counters.py`, `_drain` | `test_p0_sensor_delivery_repair.py` (M1 branch) | `/telemetry/freshness` | 6,108 recorded rejections; 83,707 queue rows | — |
| User authentication events | **PARTIALLY IMPLEMENTED** | Security 4624 only | — | Events Explorer `AUTH` tile | — | 4625 (failed logon) absent, so brute force is invisible |
| Service creation / scheduled task / WMI persistence collection | **NOT FOUND** | — | — | — | — | no 4697/4698/7045/Sysmon 19–21 canonicalisation; no agent-side persistence enumeration |
| macOS sensor | **NOT FOUND** | — | — | — | — | — |

## B.2 · B — Detection and prevention

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Endpoint detection rules | **PARTIALLY IMPLEMENTED** | `rules_edr_linux.py` — **5 Linux rules**, authored against the existing `DetectionRuleContent` model and evaluated by the shared `library/registry.py::evaluate_event`; 1,183 durable findings | 5 rules is a starting set, not coverage |
| Enterprise rule pack | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED for endpoints** | `rules_enterprise.py` — 32 rules (23 Windows, 4 cloud, 3 identity, 1 Linux, 1 hypervisor) across 11 ATT&CK tactics | these are XDR-source rules; only 8 non-Linux findings exist, so endpoint-sourced firing is essentially unproven |
| Evaluation-state integrity ("no finding" ≠ "not evaluated") | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `edr_plane/findings_intake.py`; 142,253 evaluation rows | — |
| Behavioural sequence detection (shadow mode) | **PARTIALLY IMPLEMENTED** | `behavior_shadow_runner.py` (675), `behavior_shadow_detection_store.py` (429), `behavior_shadow_frontier.py`, `behavior_sd_provider.py`, `behavior_evidence_adapter.py` — a deliberately shadow-only sink so a shadow match can never read as an analyst detection | **0 documents** in the shadow store: the engine has never produced output here |
| Local behavioural / ML / reputation / prevention engine | **NOT FOUND — and explicitly disclaimed in source** | `findings_intake.py` docstring: *"NivXForge has no local behavioural, prevention, reputation or ML engine in this build"* | the entire prevention axis (NGAV, ransomware rollback, memory protection, exploit mitigation) is absent by design |
| ATT&CK mapping | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `xdr_framework_mappings` 16,532 docs; `/trajectory/attack`; `XdrMitreHeatmap` | endpoint-sourced coverage is bounded by the 9 canonicalised Windows pairs and 5 Linux rules |
| Ransomware / injection / credential-access / exploit detection | **NOT FOUND (endpoint plane)** | — | the telemetry that would feed them (Sysmon 8/10/25, 4625/4672) is not canonicalised |

## B.3 · C — Endpoint investigation

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Device Trajectory | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `edr_plane/trajectory_window.py` (**1,616 L**), `routers/edr_trajectory_v3.py`, `/device-trajectory`, `/endpoints/{id}/trajectory[/attack|/focus|/hours|/file-facts]`; UI `EdrDeviceTrajectoryPage.jsx` (1,527 L) + `AmpCanvas` + `AmpNavigator` | **three parallel UI implementations** (`trajectory/`, `trajectory_amp/`, `trajectory_v3/`) — duplication risk |
| Process tree, endpoint pivot | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `routers/edr.py:719 get_process_tree` + `_project_endpoint_process_tree`; empty-window explainability computed backend-side (`in_window` / `outside_window` counts) | it resolves lineage from `event.process.iid/parent_iid` — it does **not** use the dedicated identity authority (next row) |
| Process identity authority (GUID-preferred, composite fallback, PID-reuse) | **IMPLEMENTED BUT NOT WIRED** | `edr_plane/process_identity.py` (450 L): `resolve_identity` (basis `tenant_id, endpoint_id, pid, start_time`), `resolve_parent`, `lifecycle`, `build`, `pid_reuse_report`, `_dedupe_edges`; tested by `test_b2_process_identity.py` and `test_b5_process_termination.py` | **its only importers are those two tests and `scripts/wave_b_foundation_measure.py`** — no router, service or bridge imports it; `edr_process_entities` holds 0 documents. Proven in source, unreachable from the product |
| Event timeline / causality | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `trajectory_window.py` two-axis projection; `services/edr/observation_narrative.py` | causality is lineage + time, not a true causal graph |
| Command-line intelligence | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `device/CommandIntelligence.jsx`, `XdrCommandIntelPage`, `xdr_lolbas_primitives` 11,196 docs, adapter `command_line` 694 observations | — |
| File / hash pivots | **PARTIALLY IMPLEMENTED** | `services/edr/file_trajectory.py` (329 L) returns Cisco's full field set **and declares `content_digests_available: false`**, downgrading a SHA-256 query to `key_type: "name"` | the substrate has no file-content digest: `event.raw.sha256` is the digest of the ingested observation, not of a file. Hash-keyed fleet correlation is impossible until the sensor emits real file hashes |
| Network pivots | **PARTIALLY IMPLEMENTED** | 333,250 `network_connect` observations with process attribution (Linux) | Windows contributes no network events of its own |
| Evidence provenance & negative explainability | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `not_observed` arrays in the sensor payload; `canonical_identity_contract.py`, `acquisition_integrity.py`, `detection_replay.py`; `EndpointNotResolved.jsx` | this is the platform's strongest differentiator |
| Investigation graph | **PARTIALLY IMPLEMENTED** | `RelationshipCanvas.jsx` (578 L), `campaign_story.py` (367 L, read model) | no entity-level graph query API |

## B.4 · D — Threat hunting

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Estate-wide event search | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `routers/edr_events.py` (424 L) — server-side filter/sort/cursor pagination over `edr_raw_events`, tenant predicate applied **in the database**; `/events/facets`, `/events/taxonomy`; UI `EdrEventsPage.jsx` (509 L), `XdrEventExplorerPage` | the router itself states the connector observes no file/network/registry events, so those filters are deliberately absent |
| Canonical search | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `GET /api/xdr/search` + `/search/capabilities`; `XdrHuntingPage.jsx` (391 L) | XDR-layer, not endpoint-scoped |
| Cross-endpoint sweeping / spread | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `routers/xdr_spread.py`, `/fleet-spread-index`, `xdr_spread_sightings` 9,074, `xdr_spread_watchlist` 3,014 | "observed across N endpoints" only — with a 1-endpoint corpus this is untested at fleet scale |
| IOC intelligence | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `iocs` 188,261 docs; `XdrIocIntelPage` | no endpoint-side IOC sweep: nothing pushes an indicator to agents |
| Saved hunting queries | **PARTIALLY IMPLEMENTED** | `routers/edr_saved_views.py` (196 L), 5 routes | `edr_saved_views` holds **1** document |
| EDR-console hunting page | **PLACEHOLDER OR MOCK ONLY** | `EdrReservedPages.jsx:39` — "Arrives in a later slice", routed at `/edr/hunting` | honest placeholder; the capability lives at the XDR layer instead |
| ATT&CK-guided hunting | **PARTIALLY IMPLEMENTED** | `XdrMitreHeatmap`, `/trajectory/attack` | no hunt-from-technique flow |

## B.5 · E — Endpoint response

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Response state machine with independent verification | **IMPLEMENTED AND INTEGRATION-VERIFIED (Linux)** | `edr_plane/response.py` (622 L): `REQUESTED → DISPATCHED → EXECUTED → VERIFIED`, and *"REQUESTED ≠ SUCCEEDED"*; `routers/edr_response.py` (270 L) | — |
| Network isolation | **IMPLEMENTED AND INTEGRATION-VERIFIED (Linux only)** | Linux sensor `_apply_isolation` (825) via **nftables** table `nivxforge_isolation`, `_control_channel`, `_nameservers`, `_control_plane_proof` (877), `_behavioural_proof` (920) with a real TCP probe | **259 isolation commands, 5 VERIFIED, 75 CAPABILITY_UNAVAILABLE**; the preflight names the exact missing privilege instead of claiming containment |
| Process termination | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `_execute_command` (1029), `_proc_identity` (999), `_verify_command` (1082) | 7 KILL_PROCESS commands; none observed VERIFIED in this data |
| Release from isolation | **IMPLEMENTED** | `_remove_isolation` (860), `RELEASE_ISOLATION` | not separately evidenced |
| **Windows response of any kind** | **NOT FOUND** | the Windows sensor has **no** `_serve_commands`, no command execution, no isolation; `quarantine` in that file is *journal* quarantine, not file quarantine | the entire Windows response axis is absent |
| File quarantine / remote artifact retrieval / live response / RTR-equivalent | **NOT FOUND** (`/edr/forensics`, `/edr/live-query` are routed placeholders) | — | — |
| Approval workflow & governance | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | `routers/edr_exclusions.py` `/{id}/approval`, `XdrApprovalsPage`, `edr_plane/authority.py` (423 L) | approvals exist for exclusions, not for response actions |
| Audit log | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `routers/edr_audit.py` (355 L); `edr_policy_audit` 41,356, `edr_enrollment_audit` 4,234, `xdr_audit_log` 26,143 | `edr_audit` collection itself is empty — the audit lives in the per-plane collections |
| Rollback / recovery | **BLOCKED BY DEPENDENCY** | `nivxforge_transaction.py` (996 L) + `test_installer_transaction.py` (806 L) exist **only on the M1 lineage** | unreachable from the trunk until §A.3 is resolved |

## B.6 · F — Endpoint management

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Enrolment + per-endpoint credentials | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `routers/edr_enrollment.py` (720 L), `nvxenr_` tokens, TTL ≤ 86,400 s, shown once, digest-stored; `/tokens/{id}/revoke`, `/endpoints/{id}/rotate|revoke` | 592 endpoints, 608 credentials, 4,234 audit rows |
| Identity resolution | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `services/edr/device_identity.py` (594 L) — excludes `UNATTRIBUTED_LEGACY_OBSERVATION` and `*_FAILED_CLOSED` rows from an explicit-tenant answer | — |
| Heartbeat / health / freshness | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `services/edr/endpoint_health.py` (413 L), `telemetry_freshness.py` (261 L), `/heartbeat`, `/telemetry/freshness`, `TelemetryFreshness.jsx` | `edr_endpoints.status` is unset on all 592 rows — health is derived, never stored |
| Policy deployment + ack | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `routers/edr_policies.py` (389 L), `/policy`, `/policy-ack`, `_sync_policy` in **both** sensors | 11 policies, 41,356 audit rows |
| Exclusion management + enforcement proof | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `routers/edr_exclusions.py` (367 L), `/exclusion-enforcement`, `/enforcement-proof`, `agents/_shared/nivxforge_exclusions.py` shared by both sensors | 6 exclusions |
| RBAC + tenant isolation | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `edr_scope()` intersection in `routers/edr.py:40–74` — authority **narrows, never widens**; raises rather than returning an empty projection to an unauthorised caller; `routers/xdr_rbac.py` | the strongest security property in the platform |
| Agent version management | **PARTIALLY IMPLEMENTED** | `sensor_version` reported in telemetry and `build-info.json`; onboarding packages describe artifacts as they exist on disk, absent means absent | no update channel, no version policy, no staged rollout |
| Endpoint groups | **PARTIALLY IMPLEMENTED** | 2 `/api/edr/groups` routes; `routers/edr.py:1222` is explicit that "no groups" must never be shown when the truth is "groups are not a feature yet" | — |
| Tamper protection | **NOT FOUND** | the M1 installer applies protected ACLs and verifies the running image, which is install-time integrity, not runtime tamper protection | no service-stop protection, no self-defence |
| Software / hardware inventory | **NOT FOUND** | `_machine_facts()` collects host facts only | — |
| Uninstall safety | **BLOCKED BY DEPENDENCY** | M1 `m1_uninstall` preserves `state_dir`, removes only ownership-confirmed resources, proves process exit (PID-reuse aware) | M1 lineage only; **G4 NOT RUN** |

## B.7 · G — Enterprise readiness

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Windows installation | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | M1 `nivxforge_m1.py` 2,547 L, 373 portable tests, independent G3 **PASSED** | **G4 NOT RUN**; HOLD stands |
| Windows build pipeline | **IMPLEMENTED — RUN HISTORY UNKNOWN** | `.github/workflows/windows-sensor-installer.yml` (762 L) builds the real PE on `windows-latest`, verifies the PE header, the frozen CLI, the production-origin guard, the removal of plaintext `--token`, secret-shaped argv refusal, build provenance, unknown-flag refusal — **and runs a real Windows SCM lifecycle gate plus a re-enrolment stop-race/rollback gate** | triggers on `agents/nivxforge-windows/**`; since M1 is not on the trunk, **M1 has never been through it**. Whether any run has ever succeeded is UNKNOWN (no Actions access) |
| Linux installation | **PARTIALLY IMPLEMENTED** | loose Python files served by `/api/edr/onboarding/packages` | **no package, no systemd unit, no service account, no update path** |
| Linux enrolment security | **PARTIALLY IMPLEMENTED — a real inconsistency** | `nivxforge-linux/nivxforge_sensor.py:1296` takes `--token` **on the command line**, the exact interface the Windows build refuses and the CI gate asserts is "REMOVED" | the token is exposed to `/proc`, shell history and the platform's own process telemetry |
| Offline operation / event loss | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED** | Windows journal + quarantine + gap detection; Linux `outbox.jsonl` | Linux has no durable journal equivalent |
| Observability | **IMPLEMENTED AND INTEGRATION-VERIFIED** | delivery counters both sides, `/acquisition-integrity`, `/raw-events/stats`, freshness, 6,108 recorded rejections | — |
| Performance / resource consumption | **INSUFFICIENT EVIDENCE** | budget controls exist (`acquire_budget_seconds`, `deliver_budget_seconds`, `page_size`, `max_records_per_channel_per_cycle`) | no benchmark, no CPU/memory measurement on either platform |
| Upgrade / recovery | **BLOCKED BY DEPENDENCY** | transaction engine on M1 lineage only | §A.3 |
| Scale | **INSUFFICIENT EVIDENCE** | one endpoint produced 98% of all telemetry | multi-endpoint, multi-tenant load is unmeasured |

## B.8 · H — NivXRay integration

| Capability | Status | Evidence | Gaps |
|---|---|---|---|
| Endpoint → incident linkage | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `/endpoints/{id}/linked-incidents`, `LinkedXdrIncidents.jsx`, `workspace_cases` 1,812 | — |
| Shared canonical evidence (no second pipeline) | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `canonical_bridge.py` (802 L) feeds the existing detection/IUE/ICE/IKG/VEEE pipeline; `campaign_story.py` writes nothing and decides nothing | this is the correct anti-duplication architecture and it is already in place |
| Device Trajectory in NivXRay | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `XdrDeviceTrajectoryPage` → `DeviceTrajectoryEntry` → shared trajectory components | three implementations (§B.3) |
| Threat Hunting / IOC / ATT&CK / Analytics / Reports | **IMPLEMENTED BUT NOT OPERATIONALLY VERIFIED from the endpoint plane** | `XdrHuntingPage`, `XdrIocIntelPage`, `XdrMitreHeatmap`, `XdrReportsPage` | endpoint evidence reaches them only through the canonical bridge, which carries 9 Windows event types |
| Detection replay / negative explainability | **IMPLEMENTED AND INTEGRATION-VERIFIED** | `detection_replay.py` (247 L) over 3,299 canonical rows from the real Windows acceptance corpus | — |

---

# C · MATURITY SCORING

Rubric as specified: completeness 30 · correctness & tests 20 · integration
20 · security & failure handling 15 · operational evidence 15. These are
**implementation-maturity** scores. They are **not** detection accuracy, not
prevention effectiveness, not performance, and **not competitive equivalence**
to any commercial product.

| Group | Compl. | Tests | Integ. | Sec. | Oper. | **Score** | Confidence |
|---|---|---|---|---|---|---|---|
| A · Sensor & collection — Linux | 70 | 80 | 90 | 70 | 90 | **79%** | HIGH |
| A · Sensor & collection — Windows | 45 | 85 | 70 | 85 | 20 | **58%** | MEDIUM |
| B · Detection | 20 | 70 | 60 | 80 | 25 | **42%** | MEDIUM |
| B · Prevention | 0 | — | — | — | 0 | **0%** | HIGH (absent by design) |
| C · Investigation | 80 | 85 | 85 | 85 | 70 | **81%** | HIGH |
| D · Threat hunting | 55 | 70 | 70 | 90 | 35 | **62%** | MEDIUM |
| E · Response — Linux | 70 | 80 | 80 | 90 | 60 | **75%** | MEDIUM-HIGH |
| E · Response — Windows | 0 | — | — | — | 0 | **0%** | HIGH |
| F · Endpoint management | 65 | 80 | 85 | 95 | 75 | **78%** | HIGH |
| G · Enterprise readiness — Windows | 60 | 90 | 60 | 90 | 10 | **58%** | MEDIUM |
| G · Enterprise readiness — Linux | 30 | 60 | 70 | 40 | 55 | **48%** | MEDIUM |
| H · NivXRay integration | 75 | 80 | 90 | 85 | 65 | **79%** | HIGH |

**Weighted platform maturity ≈ 55–60%**, and that single number is the least
useful figure in this report: the platform is roughly **75–80% mature on
investigation, identity, tenancy and evidence integrity**, and **0–40% on
detection content, prevention and Windows response**. Performance and scale
are **UNKNOWN** and are excluded from every score above rather than guessed.

---

# D · COMPARISON WITH ESTABLISHED PLATFORMS

Compared on function, not branding. Sources: vendor documentation current as
of 2026 (CrowdStrike Falcon Insight / RTR / Network Containment; Microsoft
Defender for Endpoint; SentinelOne Singularity; Elastic Defend integration
reference; Wazuh; osquery; Sysmon).

| Capability | Falcon | Defender | SentinelOne | Elastic Defend | Wazuh | **NivXForge** |
|---|---|---|---|---|---|---|
| Kernel-level telemetry | yes | yes | yes | yes | partial | **no** — user-mode polling (Linux) and event-log reads (Windows) |
| Process tree / genealogy | yes | yes | yes | yes | partial | **yes** (a genuine strength) |
| Device/host trajectory timeline | yes | yes | yes | yes | no | **yes** |
| Real-time response shell (RTR) | yes | yes (Live Response) | yes | partial | no | **no** |
| Network containment | yes, survives reboot & cloud loss | yes | yes | yes | no | **Linux only, unproven across reboot** |
| File quarantine | yes | yes | yes | yes | partial | **no** |
| Forensic artifact / memory collection | yes | yes | yes | yes | partial | **no** |
| NGAV / ML malware prevention | yes | yes | yes | yes | no | **no** |
| Ransomware behaviour + rollback | yes | yes | yes (rollback) | yes (MBR) | no | **no** |
| Memory / exploit protection | yes | yes | yes | yes | no | **no** |
| Live query across fleet | yes | yes (AH) | yes | yes (**osquery manager**) | yes | **no** (placeholder route) |
| IOC sweep pushed to endpoints | yes | yes | yes | yes | yes | **no** (IOCs exist backend-side only) |
| Tamper protection | yes | yes | yes | yes | partial | **no** |
| Software/hardware inventory | yes | yes | yes | partial | yes | **no** |
| Tenant isolation rigour | enterprise | enterprise | enterprise | enterprise | basic | **strong** — fail-closed, authority-narrowing |
| Negative explainability ("why empty") | weak | weak | weak | weak | weak | **strongest in class** — genuinely differentiating |
| Evidence provenance per field | partial | partial | partial | partial | weak | **strong** |

## D.1 Build / adopt / integrate, per gap

| Gap | Recommendation | Reasoning |
|---|---|---|
| Windows telemetry depth | **ADOPT Sysmon** (already in-tree as a config) and deploy it from the installer; expand `SUPPORTED` from 9 → ~25 pairs | zero new agent code, MIT-equivalent EULA redistribution caveat must be checked; Sysmon is a Microsoft binary — redistribution requires review, deployment-by-operator avoids it |
| Linux telemetry depth | **ADOPT eBPF** (`libbpf`/CO-RE) rather than `/proc` polling | polling cannot see short-lived processes; eBPF is the industry norm. High effort, high value, Linux ≥ 5.8 |
| Live query / fleet question-answering | **ADOPT osquery** (Apache-2.0) behind the existing approval/authority plane | exactly what Elastic did; replaces the `/edr/live-query` placeholder with a proven engine; adds a 10–20 MB binary and an update burden |
| Rule content | **BUILD on the existing `DetectionRuleContent` model**, optionally importing **Sigma** (DRL) as a content source | there is already one evaluator; a second rule engine would violate the platform's own anti-duplication rule |
| NGAV / ML prevention | **DEFER, then INTEGRATE** (e.g. a scanning service) — do not build | building AV is a multi-year programme with a false-positive liability the product cannot currently absorb |
| Memory / exploit / ransomware prevention | **DEFER** | requires kernel-mode drivers, WHQL signing and a support organisation |
| Windows response execution | **BUILD** — port the Linux `_serve_commands` / verify pattern to Windows (WFP or Firewall API for isolation, `TerminateProcess` for kill) | the state machine, authority, audit and verification planes already exist; only the agent-side executor is missing |
| Tamper protection | **BUILD** (service ACL hardening already exists in M1; add a protected-process/watchdog design) | partially pre-built |
| Inventory | **BUILD small** (WMI / dpkg / rpm enumeration) | low effort, high customer-visible value |

No proprietary code or asset from any vendor is to be copied.

---

# E · DEVELOPMENT PRIORITIES

## E.0 The verdict on M2

**M2 Process Intelligence and Device Trajectory should NOT be the next
development priority — because the evidence shows it is substantially already
built, while two cheaper items block everything downstream.**

Device Trajectory is live, projected by a 1,616-line windowed engine, served
by 10+ routes, rendered by 5,000+ lines of UI, and already carries 23,031
parent-linked observations. Process identity — GUID-preferred, composite
fallback, parent resolution, lifecycle, PID-reuse reporting — is written and
tested in `edr_plane/process_identity.py` and is **unwired**. A new M2 design
phase would substantially re-specify work that exists.

The three things that genuinely limit process intelligence today are **not
process-intelligence problems**:

1. the Windows canonicaliser admits **9 event types**, so Windows process
   lineage is thin no matter how good the graph is;
2. the identity authority is **not connected** to the tree that serves
   analysts;
3. **G4 has not run**, so no Windows endpoint is producing real lineage at
   all.

Recommended sequence: **P0 first, then a narrow M2 that wires and extends what
exists rather than designing it again.**

## E.1 P0 — essential foundations

| # | Item | Why it is P0 | Effort | Risk |
|---|---|---|---|---|
| P0-1 | **Run G4 on GitHub-hosted `windows-latest`** before requiring a VM | `windows-sensor-installer.yml` already builds the real PE and runs a real SCM lifecycle gate on Windows with no secrets. M1 is not on the trunk, so it has never been through it. This converts most of the G4 "NOT RUN" rows into real native evidence **without** waiting for a lab VM. What genuinely needs a VM afterwards: interactive-admin install, LocalSystem Authz under a real ACL, reboot continuity, end-to-end Device Trajectory | LOW | LOW — CI only, M1 source unmodified |
| P0-2 | **Reconcile the M1 ↔ trunk divergence** (§A.3) under a written merge plan | two divergent heads of `nivxforge_sensor.py` / `nivxforge_setup.py`, and the transaction engine and `edr_maintenance` on opposite sides. The longer this waits, the more expensive and more security-relevant it becomes | MEDIUM | **HIGH if unmanaged** — must not disturb the G3-approved subtree |
| P0-3 | **Fix the Linux enrolment-token interface** to stdin-only, matching Windows | the platform's own CI asserts the plaintext `--token` interface is "REMOVED" on Windows while Linux still requires it; the token lands in `/proc`, shell history and the product's own telemetry | LOW | LOW |
| P0-4 | **Package the Linux agent** (systemd unit, service account, update path) | 578 of 592 endpoints are Linux and there is no supported way to install the agent | MEDIUM | LOW |
| P0-5 | **Resolve the 16 trunk test failures** (12 order-dependent, 4 real harness/DB-binding) | an unreliable suite erodes every claim built on it | LOW | LOW |

## E.2 P1 — detection and investigation

| # | Item | Why |
|---|---|---|
| P1-1 | **Expand Windows canonicalisation from 9 → ~25 (family, EventID) pairs** and deploy Sysmon from the installer | the single highest-leverage change in the programme: it feeds process trees, trajectory, hunting, ATT&CK and every future rule at once. Priority order: Sysmon 7, 8, 10, 23/26, 19–21; Security 4625, 4672, 4697, 4698; System 7045 |
| P1-2 | **Wire `process_identity.py` into the process tree and trajectory** and populate a process-entity store | the capability is already written; connecting it is far cheaper than redesigning it |
| P1-3 | **Consolidate three Device Trajectory UIs into one** | `trajectory/`, `trajectory_amp/`, `trajectory_v3/` + the XDR entry page are four doors to one capability |
| P1-4 | **Emit real file content hashes from both sensors** | unblocks `file_trajectory`'s hash-keyed correlation, which is otherwise complete and honest about being empty |
| P1-5 | **Grow endpoint rule content** on the existing evaluator (5 → 25–40), Sigma import optional | — |
| P1-6 | **Make the behaviour-shadow engine produce output** (0 documents today) or formally park it | — |

## E.3 P2 — response and fleet management

| # | Item |
|---|---|
| P2-1 | **Windows response executor** — port the Linux command/verify pattern; isolation via the Windows Firewall/WFP API, kill via `TerminateProcess`, each with the same independent post-hoc proof |
| P2-2 | **Isolation survival across reboot** (Falcon's stated property) and a release path that is proven, not assumed |
| P2-3 | **Approval workflow extended to response actions**, not only exclusions |
| P2-4 | **Endpoint groups, agent version policy, staged rollout** |
| P2-5 | **Tamper protection** |
| P2-6 | **osquery-backed live query** behind the approval plane |

## E.4 P3 — advanced prevention

File quarantine with restore · memory/forensic collection · NGAV integration ·
ransomware behavioural blocking with rollback · exploit mitigation · kernel
(eBPF / ETW-TI) telemetry. Each needs a kernel or signing capability the
programme does not yet have; none should start before P0 and P1 close.

---

# F · M2 — PROCESS INTELLIGENCE & DEVICE TRAJECTORY ASSESSMENT

## F.1 Against the brief's eleven questions

| Required capability | Status | Where it already is |
|---|---|---|
| Stable process identity beyond PID | **IMPLEMENTED, NOT WIRED** | `process_identity.py:206 resolve_identity` — ProcessGuid preferred; else `(tenant_id, endpoint_id, pid, start_time)`; `identity_basis` recorded; UNKNOWN when incomplete |
| Parent-child linking | **IMPLEMENTED AND VERIFIED** | `resolve_parent` (256); Linux `_proc_parent` (299); 23,031 observations with `parent_iid` |
| Reparenting & PID reuse | **IMPLEMENTED, NOT WIRED** | `pid_reuse_report` (432), `_dedupe_edges` (419); Linux `_proc_start_identity` disambiguates by start ticks |
| Process start / exit | **PARTIAL** | start yes everywhere; exit only via Sysmon 5 (`ACTIVITY_PROCESS_TERMINATION`), and the Linux sensor reports `exit_time` as `not_observed` |
| Image path, hash, signer, command line | **PARTIAL** | path, command line, user, SHA-256 (Linux, of the executable) yes; **signer and integrity are explicitly `not_observed`** |
| User / session association | **PARTIAL** | `user` on Linux, `actor_iid` in CEM; `session_iid` is null in sampled observations |
| Process→network / process→file pivots | **PARTIAL** | Linux network is process-attributed via inode→pid (333,250 observations); Windows contributes none; file pivots lack content digests |
| Timeline reconstruction | **IMPLEMENTED AND VERIFIED** | `trajectory_window.py` (1,616 L), two-axis windowed projection |
| Detection→process linking | **PARTIAL** | 3,159 `detection`-kind observations share the process iid space; `campaign_story.py` already reports `process_identity_resolved_via` and raises a `canonical_process_identity` gap when it cannot |
| Cross-event correlation | **IMPLEMENTED** | `canonical_bridge.py`, IUE/ICE/VEEE pipeline, `xdr_correlation_matches` 410 |
| Tenant-isolated graph queries | **IMPLEMENTED AND VERIFIED** | `edr_scope()` intersection applied in-database on every projection |
| Source-backed evidence & negative explainability | **IMPLEMENTED AND VERIFIED — best-in-class** | `not_observed` arrays; `/process-tree` computes `in_window` vs `outside_window` so an empty window is never presented as an empty endpoint |
| Dense analyst-friendly tree / trajectory UI | **IMPLEMENTED (triplicated)** | `EdrDeviceTrajectoryPage` 1,527 L, `AmpCanvas` 623 L, `AmpNavigator` 401 L, `RelationshipCanvas` 578 L, `EdrProcessTreePage` 320 L |

## F.2 Reusable components (do **not** rebuild)

`edr_plane/process_identity.py` · `edr_plane/trajectory_window.py` ·
`edr_plane/canonical_bridge.py` · `edr_plane/windows_eventlog.py` ·
`services/edr/device_identity.py` · `services/edr/endpoint_query.py` ·
`routers/edr.py::_project_endpoint_process_tree` · `routers/edr_trajectory_v3.py` ·
the Amp/trajectory UI component set · `edr_scope()` · the CEM `*_iid` identity
space.

## F.3 The exact gaps

1. `process_identity.py` is imported by **no** router, service or bridge; the
   process-entity store is empty. **Wiring, not design.**
2. Windows lineage is capped at 9 canonicalised event types; no image load,
   no remote-thread, no process-access, no WMI, no service/task creation.
3. No process **exit** on Linux; lifecycle is therefore open-ended.
4. No signer / certificate / integrity level anywhere.
5. No file-content hashes, so process→file pivots cannot cross endpoints.
6. Session identity is null in practice.
7. Four UI entry points to one capability.
8. No fleet-scale evidence: 98% of all telemetry came from one container.

## F.4 Bounded G1 design — recommended scope, **not** authorized to implement

If work proceeds after P0, it should be an **integration slice (M2-lite)**,
not a new subsystem:

- **Scope:** wire `process_identity.resolve_identity/resolve_parent/lifecycle/
  pid_reuse_report` into `_project_endpoint_process_tree` and
  `trajectory_window`; publish `identity_basis` and the PID-reuse report on
  the existing `/process-tree` and `/endpoints/{id}/trajectory` responses;
  add Windows exit and image-load/remote-thread/process-access
  canonicalisation; collapse the UI to one implementation.
- **Canonical contract:** the CEM `*_iid` space already in
  `v2_shadow_observations` — no new identity space, no new store, no second
  pipeline. Backwards compatible: every current field keeps its meaning.
- **Event identity, ordering, dedup:** ProcessGuid when present, else
  `(tenant_id, endpoint_id, pid, start_time)`; order by `captured_at` with
  `sequence` as the tie-break; dedup by the existing `dedup_key` and
  `_dedupe_edges`.
- **Security boundary:** `edr_scope()` unchanged; no new route may read
  evidence without it; UNKNOWN identity must surface as UNKNOWN, never as a
  guessed edge.
- **Tests:** PID reuse within one window; reparenting; an orphan whose parent
  is outside the window; a process with no exit; a same-PID different-start
  pair; cross-tenant refusal; empty-window explainability.
- **Performance limits:** a declared node/edge ceiling per window with an
  explicit truncation statement in the response — never silent truncation.
- **NivXRay integration:** consume the existing trajectory routes; add no
  parallel investigation surface in either product.

---

# G · LIMITATIONS AND COVERAGE

1. **No isolated clone** (disk ~260 MB free). Inspection was read-only
   against the existing object store plus a sparse scratch worktree. No
   working directory was altered, but a fully independent clone was not
   established.
2. **No GitHub API access.** Branch protection, PR history and — importantly —
   whether `windows-sensor-installer.yml` has ever run, and with what result,
   are UNKNOWN. Its *content* is verified; its *execution* is not.
3. **No authenticated live-API probing.** No operator credential is recorded
   for this environment, so route behaviour was established from reflection,
   source and tests, not from authenticated responses. Statuses therefore rest
   on code + tests + persisted data, never on a 200.
4. **Single-endpoint corpus.** 98% of telemetry came from one Linux
   container; nothing here evidences fleet scale, multi-tenant load or
   performance.
5. **Windows runtime evidence is absent** by definition: G4 is NOT RUN.
6. **The preview database is not production.** Counts evidence that code
   paths have executed; they do not evidence customer deployment.
7. Percentages are **provisional implementation maturity** under the stated
   rubric. They are not detection accuracy, not prevention efficacy, not
   performance, and not competitive equivalence.
8. The prior `docs/audit/NIVXFORGE_EDR_TRUTH_AUDIT.md` (2026-06, 40 rows) was
   read and its central findings re-verified against current code; this report
   supersedes it in scope but does not contradict it.

---

# H · BOUNDARIES HELD

No commit, push, merge, PR or branch mutation. No tracked source file edited.
No database write, migration or deployment. No installer, agent or response
action executed. No credential read, printed or copied. M1
(`388bb3d6` / subtree `db21f422…` / `b8020771`) untouched and unmodified. No
security HOLD removed. G4 remains NOT RUN and on HOLD. No implementation was
performed and none is authorized by this document.
