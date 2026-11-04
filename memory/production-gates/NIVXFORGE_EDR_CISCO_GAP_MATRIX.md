# NIVXFORGE EDR · CISCO SECURE ENDPOINT CAPABILITY GAP MATRIX

**Audit type:** READ-ONLY engineering audit.
**Run:** 2026-09-26 (owner directive *PROCEED WITH READ-ONLY EDR GAP AUDIT*).
**Implementation changes made during this audit: ZERO.** No application
code, sensor code, backend code, CSS/UI, test, or deployment
configuration was modified. The only writes were this document and
`NIVXFORGE_EDR_IMPLEMENTATION_PLAN.md`.

Cisco Secure Endpoint / AMP is used **only as a capability benchmark**.
No Cisco code, signature, algorithm, API or UI was copied or inspected.

---

## 0 · Evidence standard applied (owner-set)

`IMPLEMENTED + PROVEN` requires **both**:

1. an identifiable implementation path, cited with file + line, **and**
2. an execution proof: a passing deterministic test, or a live-proof
   script/result recorded in this repository.

A code path alone is never sufficient. Classes used:

| Class | Meaning |
|---|---|
| `IMPLEMENTED + PROVEN` | code path + execution proof, both cited |
| `IMPLEMENTED + UNPROVEN` | code path exists; no test and no live proof asserts it |
| `PARTIAL` | only some platforms, or only some sub-capabilities |
| `NOT IMPLEMENTED` | no code path performs it |
| `NOT APPLICABLE` | not a NivXForge responsibility at this layer |

Evidence provenance tags on every proven row:

* **[T]** deterministic test in `backend/tests/edr` — **re-run in this
  session: 425 passed, 1 skipped, exit 0** (`/tmp/edr_pytest.log`; the
  single skip is `test_iteration_82_activation.py:213`, a corpus
  precondition, unrelated to any capability below).
* **[L]** historical live proof script/result committed in the repo
  (`/app/scripts/*_proof.py`, `/app/memory/**`).
* **[S]** current-session read-only verification performed by this audit
  (source read, live collection counts read from MongoDB).

Nothing below was classified from a UI label, a route name, a comment, a
TODO, a schema, a stub, or a document. Every row was read from source.

### Current-session read-only observations [S]

`edr_raw_events 218,757` · `edr_endpoints 279` · `edr_policies 10` ·
`edr_policy_versions 11` · `edr_policy_audit 145` ·
`edr_policy_endpoint_state 5` · `edr_exclusions 6` ·
`edr_exclusion_sets 6` · `edr_endpoint_exclusion_enforcement 2` ·
`edr_response_commands 82` · `edr_rejected_telemetry 2,769` ·
`edr_saved_views 1` · `edr_groups 8` · `edr_connector_deployments 4` ·
**`edr_findings 0`**.

---

## 1 · Three material corrections to previously recorded status

These are the substantive findings of this audit. Each contradicts a
claim previously carried in project documentation.

**C1 · `KILL_PROCESS` was recorded as NOT IMPLEMENTED. That is wrong.**
It is implemented end to end and it is the *best-evidenced* response
verb in the product: `edr_plane/response.py:144` resolves the target to
an observed process identity, `agents/nivxforge-linux/nivxforge_sensor.py:1007-1051`
refuses a bare pid (`TARGET_IDENTITY_UNVERIFIED`) and refuses a reused
pid (`TARGET_IDENTITY_MISMATCH_PID_REUSE`) before signalling, and
`:1057-1095` verifies by an independent post-action `/proc` read.
Proof: `tests/edr/test_p0_f5_response_identity.py` (kill, refusal,
pid-reuse, verification) **[T]**, `scripts/p0_f5_response_proof.py`
**[L]**. **However** the release catalog
(`edr_plane/connector/catalog.py:44-55`) declares **no response actions
at all**, so a real capability is undeclared to the policy authority —
the mirror image of the usual defect, and still a defect.

**C2 · There is no NivXForge EDR detection engine.** The row
"deterministic rule engine (server-side) — IMPLEMENTED + PROVEN" was
over-stated. `edr_plane/fabric/analyzers/deterministic_rule.py:69-128`
does not evaluate anything; its own docstring states it *projects* the
derivation the XDR ingest pipeline already wrote. Detection actually
happens in `edr_plane/canonical_bridge.py:463-523`, which hands the
sensor event to the **XDR** `detection_content.xdr_pipeline.process_event_through_pipeline`.
Consequences: (a) EDR owns no endpoint-oriented rule content; (b) the
fabric's findings store `edr_plane/fabric/store.py:23` has **no caller
anywhere in `routers/` or `services/`** and `edr_findings` holds **0
documents** **[S]** — findings are computed by a read-only proof script
and never persisted, never surfaced, never retrospected; (c) a detection
fabric outage is recorded honestly as `DETECTION_NOT_EVALUATED`
(`canonical_bridge.py:524-537`) but leaves the evidence permanently
unevaluated, because no re-evaluation path consumes it (Gate 6).

**C3 · Response has tenant authority but no action-level authority.**
**CLOSED 2026-09-26 by P0-A** (`P0A_RESPONSE_AUTHORITY.md`). The finding
as audited was:
`routers/edr_response.py:54-58` required only an authenticated user plus
`edr_tenant`/`edr_scope` (`routers/edr_tenancy.py:198-223`). There is no
role check, no approver distinct from the requester, and no two-person
rule: for `ISOLATE_ENDPOINT` the record is self-authorised by
`requested_by` (`edr_plane/response.py:158-205`) and the state jumps
straight to `AUTHORIZED`. `grep -n "role\|RBAC\|require_role\|permission"`
over `routers/edr_response.py|edr_exclusions.py|edr_policies.py` returns
exactly one hit, and it is a comment. Exclusions, by contrast, *do*
enforce a second operator (`edr_plane/exclusions/store.py:225`
`SELF_APPROVAL_REFUSED`). So the strongest control in the product sits
on the *least* destructive surface.

---

## A · TELEMETRY

| Capability | Windows | Linux | Class | Evidence |
|---|---|---|---|---|
| Authenticated, per-device credentialled telemetry | yes | yes | **IMPLEMENTED + PROVEN** | `edr_plane/enrollment/transport.py`, `enrollment/identity.py`; `tests/edr/test_p0_a2_enrollment.py` **[T]**; 218,757 raw events **[S]** |
| Heartbeat + declared cadence + queue depth | yes | yes | **IMPLEMENTED + PROVEN** | linux `:1147-1179`, win `:449-464`; `test_p0_a1_endpoint_health.py` **[T]** |
| Durable outbox, offline buffering, offset replay | yes | yes | **IMPLEMENTED + PROVEN** | linux `:496-562`, win `:382-448`; `test_p0_b_linux_sensor.py` **[T]**, `scripts/p0_3_sensor_recovery_proof.py` **[L]** |
| Rejected telemetry quarantined, never silently dropped | yes | yes | **IMPLEMENTED + PROVEN** | `enrollment/rejection.py:32`; `edr_rejected_telemetry 2,769` **[S]**; `test_p0_a2_enrollment.py:456` **[T]** |
| Process start | **no** | yes | **PARTIAL** | linux `collect_processes:217-288` **[T]**. Windows collects **only Windows Event Log records** (`CAPABILITIES.collects = ["WINDOWS_EVENT_LOG"]`, win `:58-81`, `_query_channel:211`) — no process object model |
| Process exit | no | no | **NOT IMPLEMENTED** | declared in `fields_not_supported`; `not_observed:["exit_time",…]` linux `:282` |
| PID / PPID / real parent attribution (not bare ppid) | no | yes | **PARTIAL** | `_proc_parent:291-324` attributes a parent only if `/proc` still holds it and its start precedes the child; else `parent_lookup_state` names the gap. `test_p0_f4_endpoint_process_tree.py` **[T]** |
| Process start identity (`start_ticks`) as response anchor | no | yes | **IMPLEMENTED + PROVEN** | linux `:264-270`, `_proc_identity:974`; `test_p0_f5_response_identity.py` **[T]** |
| Executable path / command line / user | no | yes (best effort) | **PARTIAL** | linux `:245-277` reads `/proc/<pid>/{cmdline,exe}`; both legitimately `null` for kernel threads and unreadable processes, and previously observed `null` on live polls. Field-completeness measurement does not exist |
| Executable SHA-256 | no | partial | **PARTIAL** | `_sha256_file:203` with a 64 MiB cap; `null` whenever `exe` is unresolvable |
| Signer / signature / integrity level | no | no | **NOT IMPLEMENTED** | both sensors' `fields_not_supported` |
| File events | **no** | watched-path only | **PARTIAL** | `collect_files:449` is a **polled directory baseline diff**, not a filesystem monitor; the writing process is explicitly not observed (linux `:93-94`). Catalog declares `file_event_collection` true for Linux, false for Windows |
| Network events (dest IP/port/proto, process binding) | **no** | yes | **PARTIAL** | `collect_network:394` + `_inode_pid_map:325`; catalog `network_event_collection` Linux true / Windows false |
| DNS | no | no | **NOT IMPLEMENTED** | no collector |
| Registry | no | n/a | **NOT IMPLEMENTED** | `registry_event_collection: false` (catalog `:52`); `registry.*` in `fields_not_supported` |
| Script / LOLBin / module / memory visibility | no | no | **NOT IMPLEMENTED** | no collector; `memory.*` declared unsupported |
| USB / removable media | no | no | **NOT IMPLEMENTED** | `usb_device.*` declared unsupported |
| Syscall-level fidelity (eBPF / ETW / kernel driver) | no | no | **NOT IMPLEMENTED** | `collection_method` is `PROC_POLL` / `WINDOWS_EVENTLOG_QUERY`; both sensors declare the limit in `limits[]` |
| Short-lived process coverage | no | no | **NOT IMPLEMENTED** | linux `limits[]`: a process that starts and exits inside one poll is missed entirely |

**Honest statement of the Windows position.** Windows telemetry is not a
thin version of Linux telemetry; it is a *different* thing. It is an
event-log forwarder with bookmarks (`_bookmarks:199`, `CHANNELS` =
Security, System, Sysmon/Operational). Every Windows process/file/
network/registry row above is therefore `no`, and the connector declares
it. Cisco parity on Windows starts at zero object telemetry, not at 70%.

**The real telemetry risk is field completeness, not event classes.**
Adding Windows classes on top of an unmeasured `null` rate for
`image_path`/`command_line`/`sha256` multiplies unusable evidence. No
metric for field completeness exists anywhere in the codebase **[S]**.

---

## B · CANONICAL EVIDENCE MODEL

| Capability | Class | Evidence |
|---|---|---|
| Immutable raw store; derivations appended, never overwritten | **IMPLEMENTED + PROVEN** | `edr_plane/raw_events.py:102,171` (`$push` only); `test_wave0_raw_events.py` **[T]** |
| tenant / endpoint / sensor / event ids, ingest + event time, provenance | **IMPLEMENTED + PROVEN** | `raw_events.py:48-140`, `canonical_bridge.py:310-452`; `test_p0_d11_ingest_provenance_live_proof.py` **[L]**, `D11_INGEST_PROVENANCE_REPORT.md` |
| Canonical activity identity + process identity binding | **IMPLEMENTED + PROVEN** | `canonical_bridge.activity_identity:51`, `bind_process_identity:273`; `test_p0_2c_alias_invariant.py` **[T]** |
| Authenticated-ingest trust labelling (`REAL_SENSOR_DERIVED` cannot be forged) | **IMPLEMENTED + PROVEN** | `canonical_bridge.py:473-486`; `test_p0_a2_adversarial_live.py` **[T]** |
| `policy_version` / `config_digest` stamped on each event | **NOT IMPLEMENTED** | the digest lives on the policy ACK and in the exclusion journal (`_shared/nivxforge_exclusions.py:208-210`), never on the evidence row. An evidence row cannot answer "which policy was in force when this was collected" |
| Typed `process` / `file` / `network` / `registry` sub-objects | **PARTIAL** | payload is a sensor envelope; canonicalisation is per-activity and partial |
| Every investigation node/edge resolves to an `evidence_ref` | **IMPLEMENTED + UNPROVEN** | refs are carried (`fabric/contracts.py` `evidence_refs`), but no test asserts "every rendered node resolves" |
| Single EDR→XDR evidence boundary | **IMPLEMENTED + UNPROVEN** | `GATE_17_DETECTION_SOURCE_ARCHITECTURE.md` is DESIGN FROZEN; the code path exists (`canonical_bridge`) and is not asserted as the *only* boundary by any test |

---

## C · DETECTION

| Capability | Class | Evidence |
|---|---|---|
| Server-side detection over endpoint telemetry (via the XDR content pipeline) | **IMPLEMENTED + PROVEN** | `canonical_bridge.py:463-523`; `test_p0_detection_attribution.py`, `test_p0_f_endpoint_detection.py`, `test_p0_f13_5_detection_handoff.py` **[T]**; `scripts/p0_detection_attribution_proof.py` **[L]** |
| EDR-owned endpoint detection content (rules written for endpoint activity) | **NOT IMPLEMENTED** | see **C2**. No EDR rule store; `test_p0_f3_rule_store_binding.py` binds to XDR content |
| Honest non-evaluation (`DETECTION_NOT_EVALUATED` with reason) | **IMPLEMENTED + PROVEN** | `canonical_bridge.py:524-537`; `test_gate3_fabric_contracts.py` **[T]** |
| Finding contract: rule id/version, severity, evidence refs, explanation | **IMPLEMENTED + PROVEN** (contract only) | `fabric/contracts.py`, `analyzers/deterministic_rule.py:98-121`; 15 passing contract tests **[T]**; `scripts/gate3_fabric_real_evidence_proof.py` produced 400 findings **read-only** **[L]** |
| Findings persisted / queryable / surfaced | **NOT IMPLEMENTED** | `fabric/store.py:23` has no caller; `edr_findings 0` **[S]** |
| MITRE technique attribution on endpoint findings | **PARTIAL** | contract field exists; no coverage measurement for endpoint activity |
| Endpoint-local (on-sensor) detection engine | **NOT IMPLEMENTED** | neither sensor evaluates anything; they collect, exclude, and execute commands |
| Offline / air-gapped decision plane | **NOT IMPLEMENTED** | the sensor caches policy + exclusions only (`POLICY_FILE`, linux `:108`) |
| File reputation / hash verdict / cloud lookup cache | **NOT IMPLEMENTED** | no reputation store, no verdict cache, no lookup path |
| Behavioural / sequence / injection / persistence / ransomware detection classes | **NOT IMPLEMENTED** | `capability/inventory.py:454-489` declares each `NOT_IMPLEMENTED` with `TELEMETRY_MISSING` |
| ML scoring | **NOT IMPLEMENTED** | no model, no inference interface, no training or evaluation harness anywhere in the repo **[S]** |
| Retrospection / re-evaluation of stored evidence | **NOT IMPLEMENTED** | `GATE_06_RETROSPECTION.md` is design-only; blocked on a findings store with a caller |

---

## D · PREVENTION

Every row is **NOT IMPLEMENTED**, and the product declares it rather
than implying otherwise: `catalog.py:49` `endpoint_prevention: false`,
and `policy/contracts.py:137-141` refuses `PREVENT` with
`NOT_SUPPORTED_BY_CONNECTOR` because the catalog is the single source the
policy authority reads.

Terminate-on-detection · quarantine file · block by hash · block network
indicator · exploit prevention · memory/injection protection · script
control · ransomware behavioural protection · device control.

The unified action model `ALLOW / DETECT / BLOCK / TERMINATE /
QUARANTINE / ISOLATE` exists **as an enum only**
(`edr_plane/contracts/response.py:63-68`) with no evaluator and no
enforcement point: **IMPLEMENTED + UNPROVEN as a contract, NOT
IMPLEMENTED as behaviour**. Enum members such as `QUARANTINE_FILE`,
`NETWORK_BLOCK`, `FORENSIC_SNAPSHOT`, `LIVE_QUERY`, `REMOTE_UNINSTALL`
(`:36-51`) are **declared vocabulary, not capability** — the executable
verb set is `ACTIONS = ("KILL_PROCESS", "ISOLATE_ENDPOINT",
"RELEASE_ISOLATION")` (`edr_plane/response.py:32`) and an unknown action
is refused (`:130`).

---

## E · RESPONSE

| Capability | Class | Evidence |
|---|---|---|
| Command lifecycle with distinct `REQUESTED → (AUTHORIZED) → DISPATCHED → EXECUTED → VERIFIED` | **IMPLEMENTED + PROVEN** | `response.py:126-360`, `routers/edr_audit.py:171`; `test_p0_f6_response_ui_backend.py` **[T]**; 82 real commands **[S]** |
| Nothing is claimed executed from the fact it was sent | **IMPLEMENTED + PROVEN** | `request_action` returns an explicit `honesty_note`; `verify()` `:290` requires post-action evidence; `test_p0_f5_response_identity.py` **[T]** |
| `KILL_PROCESS` with process-identity binding + independent verification (Linux) | **IMPLEMENTED + PROVEN** | see **C1**; `test_p0_f5_response_identity.py`, `test_p0_f7_live_api.py:234-241` **[T]**; `scripts/p0_f5_response_proof.py` **[L]** |
| `KILL_PROCESS` on Windows | **NOT IMPLEMENTED** | win `CAPABILITIES.response_actions = []` (`:69`) |
| Endpoint isolation with kernel read-back proof + protected control channel (Linux) | **IMPLEMENTED + PROVEN** at test level, **UNDECLARED** at release level | `_apply_isolation:800`, `_nft_ruleset:767`, `_control_plane_proof:852`, `_verify_isolation:958`; `response.py:364-457` refuses to call it isolated without proof (`ISOLATION_UNPROVEN`); `test_p0_f10_isolation.py`, `test_p0_f10_live_api.py` **[T]**, `scripts/p0_f10_isolation_proof.py` **[L]**, `P0_RESPONSE_EXECUTION_TENANT_ISOLATION.md` 21 PASS **[L]**. Not present in `catalog.py` declared capabilities |
| Isolation on Windows | **NOT IMPLEMENTED** | win `:70-72` declares it unimplemented |
| Auto-release of isolation raises a new authorised command, never flips a state on a timer | **IMPLEMENTED + PROVEN** | `response.py:211-241`; `test_p0_f10_isolation.py` **[T]** |
| Tenant isolation of the response plane | **IMPLEMENTED + PROVEN** | `routers/edr_tenancy.py:198`; `test_cross_tenant.py`, `test_security_state_isolation.py` **[T]**; 21 PASS live **[L]** |
| **Action-level RBAC / approval separate from the requester** | **CLOSED 2026-09-26 · IMPLEMENTED + PROVEN** (P0-A) | `edr_plane/authority.py`; `response.execute` required, destructive verbs require an authority-issued approval bound to {tenant, endpoint, action, requester}, self-approval and replay refused. `tests/edr/test_p0a_response_authority.py` 27 **[T]** + `test_p0a_response_authority_live.py` 8 **[T/L]**; `P0A_RESPONSE_AUTHORITY.md` |
| Quarantine / file retrieval / forensic snapshot / live query / scan / remove-persistence | **NOT IMPLEMENTED** | not in `ACTIONS`; `_execute_command:1054` returns `unknown action` |
| Automated response from a detection (no human in the loop) | **NOT IMPLEMENTED** | no path from a finding to `request_action` **[S]** |

---

## F · EXCLUSIONS

| Capability | Class | Evidence |
|---|---|---|
| Typed exclusions: path, extension, hash, process, command line, network address; match EXACT/PREFIX/SUFFIX/CONTAINS/GLOB | **IMPLEMENTED + PROVEN** | `exclusions/contracts.py`, `_shared/nivxforge_exclusions.py:40-42`; `test_gate7_endpoint_enforcement.py` **[T]** |
| Two-operator approval; inert until APPROVED; revocation | **IMPLEMENTED + PROVEN** | `exclusions/store.py:217-262` (`SELF_APPROVAL_REFUSED`), `contracts.py:168` `INACTIVE_PENDING_APPROVAL`; **[T]** + `GATE_07_EXCLUSIONS.md` **[L]** |
| Scope (tenant / group / endpoint) + effective-window enforcement | **IMPLEMENTED + PROVEN** | `contracts.py:236-250`, `lifecycle_state`; parametrised unapproved/revoked/expired tests **[T]** |
| Server-fabric enforcement that preserves the suppressed truth | **IMPLEMENTED + PROVEN** | `exclusions/enforcement.py`; `/api/edr/exclusions/enforcement-proof` delta on real evidence (0 → 3 bypassed / 2 suppressed → 0) **[L]** |
| Endpoint-side enforcement (event never leaves the machine) | **IMPLEMENTED + PROVEN** | `_shared/nivxforge_exclusions.py:219-248` before the outbox; linux `:1217-1227`; `test_gate7_endpoint_enforcement.py` **[T]**, `scripts/gate7_endpoint_enforcement_live_proof.py` **[L]**, `edr_endpoint_exclusion_enforcement 2` **[S]** |
| One canonical evaluator shipped to every platform, byte-identical | **IMPLEMENTED + PROVEN** | `test_gate7_endpoint_enforcement.py:58` asserts byte equality of the shipped copies **[T]** |
| Refusal is reported, never a silent skip | **IMPLEMENTED + PROVEN** | `validate():59-82`; `REFUSED_UNSUPPORTED_TYPE` / `_ENGINE` / `_MALFORMED` tests **[T]** |
| Report carries digests, never the excluded content | **IMPLEMENTED + PROVEN** | `_sha`, `observed_value_digests` capped at 5; `test_…:97-105` asserts the cleartext path is absent **[T]** |
| Engine-scoped exclusions | **PARTIAL** | `affected_engines` is real, but only two engines exist: `endpoint.collection` and the server rule plane. `endpoint.prevention` is refused by design (`:38`) |
| **Exclusion scoped to DETECTION rather than COLLECTION** | **NOT IMPLEMENTED** | the endpoint engine *is* `endpoint.collection` (`:35`) and drops the event before the outbox (`:221-226`). Operationally correct for a collection exclusion; wrong as the only available behaviour, because a tuning exclusion then destroys forensic evidence irreversibly |
| Signed-publisher / certificate exclusions | **NOT IMPLEMENTED** | signer metadata is not collected (family A) |
| Threat-name and wildcard-by-engine exclusions (Cisco parity) | **NOT IMPLEMENTED** | no threat-name axis exists |

---

## G · INVESTIGATION

| Capability | Class | Evidence |
|---|---|---|
| Device Trajectory over real observations | **IMPLEMENTED + PROVEN** (performance + render) | `edr_plane/trajectory_window.py`, `trajectory/*`; `test_gate10_trajectory_window_fast_paths.py` 5 passed **[T]**; 8/8 reads 1.06–1.82 s on 208,754 observations, `GATE_10_SCALE_AND_PERFORMANCE.md` **[L]** |
| Trajectory node/edge → evidence provenance assertion | **IMPLEMENTED + UNPROVEN** | no test asserts full resolvability (family B) |
| Process tree from canonical identity, not pid alone | **IMPLEMENTED + PROVEN** | `test_p0_f4_endpoint_process_tree.py` **[T]**; `_proc_parent` identity rule |
| Campaign story | **IMPLEMENTED + PROVEN** | `edr_plane/campaign_story.py`; `test_p0_f7_campaign_story.py`, `test_p0_f7_live_api.py` **[T]** |
| Events Explorer: server-side filters, keyset pagination, facets, raw-event pivot | **IMPLEMENTED + PROVEN** | `routers/edr_events.py:243-391`; `GATE_11_EVENTS_EXPLORER.md`, 0-overlap keyset proof, tenantless query refused 403 **[L]** |
| Saved views (query state only, tenant-enforced) | **IMPLEMENTED + PROVEN** | `routers/edr_saved_views.py`; cross-tenant resolve refused `VIEW_NOT_FOUND` **[L]**; `edr_saved_views 1` **[S]** |
| Audit trail across policy/exclusion/delivery/connector/response/enrolment | **IMPLEMENTED + PROVEN** | `routers/edr_audit.py:62-320` aggregates from the real records; `edr_policy_audit 145` **[S]** |
| **File Trajectory (SHA-256-centric, estate-wide)** | **NOT IMPLEMENTED** | no hash-centric model; `capability/inventory.py:818` `sha256_pivot_menu NOT_IMPLEMENTED` |
| **Live Query / on-demand endpoint interrogation** | **NOT IMPLEMENTED** | enum member only (`contracts/response.py:46`) |
| **Forensic snapshot** | **NOT IMPLEMENTED** | enum member only (`:45`) |
| Threat hunting surface | **NOT IMPLEMENTED** | `inventory.py:829` |
| DNS / network investigation surfaces | **NOT IMPLEMENTED** | `inventory.py:822-828` (telemetry missing first) |
| CSV / evidence export from the explorer | **NOT IMPLEMENTED** | labelled in `GATE_11` |

---

## H · POLICY

| Capability | Class | Evidence |
|---|---|---|
| Versioned immutable policy + `config_digest` | **IMPLEMENTED + PROVEN** | `policy/store.py:90-124`; `edr_policy_versions 11` **[S]**; `scripts/gate5_7_11_live_proof.py` **[L]** |
| Endpoint ACK of the exact digest is the ONLY route to APPLIED | **IMPLEMENTED + PROVEN** | `policy/store.py:302-375` (`RECORDED_APPLIED` vs `RECORDED_OUT_OF_SYNC`); full lifecycle CREATED→…→VERIFIED proven on a real enrolled endpoint **[L]**; `GATE_05_POLICY_AUTHORITY.md` |
| Precedence: endpoint override > group > enrolment placement > `POLICY_UNASSIGNED` | **IMPLEMENTED + PROVEN** | `resolve_assignment:245`; **[L]** Gate 5/8 |
| Drift detection (`OUT_OF_SYNC`, `STALE`) | **IMPLEMENTED + PROVEN** | `endpoint_policy_state:377`, sensor `_sync_policy:599` `stale` flag; **[L]** |
| Capability-truthful settings (a setting the connector cannot honour is refused, not silently accepted) | **IMPLEMENTED + PROVEN** | `policy/contracts.py:137-141` reading `catalog.capabilities`; `test_gate16_edr_independence.py` **[T]** |
| Policy audit trail | **IMPLEMENTED + PROVEN** | `_audit:59`; `edr_policy_audit 145` **[S]** |
| `AUDIT / DETECT / PROTECT` mode triad | **PARTIAL** | only `DETECT_ONLY` and `PREVENT` exist (`contracts.py:65-66`), and `PREVENT` is unimplementable today. No `AUDIT` mode |
| Signed / authenticity-validated policy | **NOT IMPLEMENTED** | a digest proves integrity of transport, not authorship |
| Safe rollback to a prior version | **NOT IMPLEMENTED** | a rollback is a new version; no rollback verb, no ACK-verified revert |
| Policy scheduling / maintenance windows / duplicate-and-edit | **NOT IMPLEMENTED** | no code path |

---

## I · SENSOR IDENTITY & SELF-PROTECTION

| Capability | Class | Evidence |
|---|---|---|
| Per-device credential, never shared, never embedded in the artifact | **IMPLEMENTED + PROVEN** | `enrollment/security.py`, `catalog.py:29-34` refuses an artifact matching a credential shape (`ARTIFACT_REFUSED_EMBEDDED_CREDENTIAL`); `test_p0_a2_enrollment.py` **[T]**; `edr_agent_credentials 310` **[S]** |
| Restricted state directory (`0600` identity file) | **IMPLEMENTED + UNPROVEN** | linux `:51` comment + write mode; no test asserts the mode on disk |
| Stable identity across reinstall / upgrade | **IMPLEMENTED + UNPROVEN** | `Install-NivXForgeSensor.ps1:27`, `_reg_machine_guid:121`; asserted by no test and by no Windows run |
| Unauthenticated / forged telemetry refused and quarantined | **IMPLEMENTED + PROVEN** | `rejection.py`, `canonical_bridge.py:473-486`; `test_p0_a2_adversarial_live.py` **[T]** |
| Crash recovery / supervised restart / transient-error survival | **IMPLEMENTED + PROVEN** | linux `:1192-1249` (documented real outage + fix), `scripts/nivxforge_sensor_supervise.py`; `scripts/p0_3_sensor_recovery_proof.py` **[L]** |
| Signed / integrity-verified connector updates | **NOT IMPLEMENTED** | `signing_status: "UNSIGNED"` on every release (`catalog.py:68,104,135,160`) |
| Tamper detection · anti-uninstall · service protection · anti-replay of commands · update rollback | **NOT IMPLEMENTED** | no code path; `-Uninstall` is unauthenticated and local (`Install-NivXForgeSensor.ps1:44-103`) |
| Sensor diagnostics bundle / support snapshot | **NOT IMPLEMENTED** | `DIAGNOSE` is an enum member only |

---

## J · PERFORMANCE / RELIABILITY

| Capability | Class | Evidence |
|---|---|---|
| Bounded drain; backlog surfaced as `queue_depth` so BACKLOG ≠ SILENCE | **IMPLEMENTED + PROVEN** | linux `_drain:505`, `_queue_depth:1132`; `test_p0_3_telemetry_freshness.py`, `test_p0_a1_endpoint_health.py` **[T]** |
| Fleet blindness detection (`BLIND_NO_DELIVERY`, `DELIVERY_CEASED`) | **IMPLEMENTED + PROVEN** | `services/edr` freshness + `test_iter107_p0_3_freshness_review.py` **[T]**; real outage caught in minutes (linux `:1199-1205`) **[L]** |
| Trajectory read performance on a real corpus | **IMPLEMENTED + PROVEN** | `GATE_10` 8/8 reads ≤1.82 s on 208,754 observations **[L]**, 5 tests **[T]** |
| `DROPPED_EVENT_COUNT` / `DROP_REASON` / `QUEUE_PRESSURE` / first+last dropped | **NOT IMPLEMENTED** | `grep DROPPED\|drop_reason\|QUEUE_PRESSURE` over both sensors: **no hits** **[S]**. Nothing is knowingly dropped today, but `ZERO` and `UNKNOWN` are indistinguishable, which is the one thing a customer will ask |
| Sensor CPU / memory / disk / event-rate self-measurement and caps | **NOT IMPLEMENTED** | no measurement, no configurable ceiling |
| Burst load, p95 under concurrency, failure injection | **NOT IMPLEMENTED** | `GATE_10` records the gap; legacy `/edr/device-trajectory` still 6.1 s |
| Backup / restore equivalence | **NOT IMPLEMENTED** | Gate 15 `NOT_STARTED` |

---

## K · RELEASE INTEGRITY

| Capability | Class | Evidence |
|---|---|---|
| Release catalog with disclosed identity; artifact truth read from disk | **IMPLEMENTED + PROVEN** | `catalog.py:173-246`; `CONNECTOR_PRODUCTIZATION.md` **[L]**; `edr_connector_deployments 4` **[S]** |
| `ARTIFACT_NOT_PUBLISHED` / `_INCOMPLETE` / `_REFUSED` instead of a fabricated download | **IMPLEMENTED + PROVEN** | `:211-225`; 2 of 4 catalog entries publish nothing and offer no button **[S]** |
| Build once, install everywhere; same SHA-256 across deployments; no per-endpoint rebuild | **IMPLEMENTED + PROVEN** | `DISTRIBUTION_CONTRACT:297`, `rebuild_required_per_endpoint: False`; `gate5_7_11_live_proof.py` deployment section **[L]** |
| Declared capability per release drives the policy authority | **IMPLEMENTED + PROVEN** | `capabilities_for_connector_version:271` (OS-aware, so Linux cannot inherit the Windows declaration); `test_gate16_edr_independence.py` **[T]** |
| Release declaration completeness | **PARTIAL** | the declaration has **no response-action axis at all**, so a proven `KILL_PROCESS` and a proven Linux isolation engine are undeclared (**C1**) |
| Code signing / notarisation | **NOT IMPLEMENTED** | `UNSIGNED` everywhere |
| Build ID / reproducible build / SBOM / provenance attestation | **NOT IMPLEMENTED** | no build identifier is recorded |
| Support lifecycle honesty (`PREVIEW_NOT_FOR_PRODUCTION`, `SUPERSEDED`, `NOT_RELEASED`, `end_of_support`) | **IMPLEMENTED + PROVEN** | `catalog.py:57-167`; never labelled production-ready **[S]** |

---

## L · MULTI-TENANCY, AUTHORITY & AUDIT

> **Letter-mapping note.** The verbatim A–O family list from the owner
> directive is not preserved in this repository (searched `/app/memory`,
> `/app/docs`, `PRD.md`). Families **A–K** match the previously recorded
> structure exactly. **L–O** below are the remaining Secure Endpoint
> domains this codebase touches, audited to the same standard. If the
> original L–O labels differ, only the headings need renaming — no
> classification changes.

| Capability | Class | Evidence |
|---|---|---|
| Server-resolved tenant; a client-supplied tenant can never widen authority | **IMPLEMENTED + PROVEN** | `routers/edr_tenancy.py:168-230`; `test_edr_route_tenant_authority.py` 169 passed **[T]**, S1 live authz matrix 66 PASS **[L]** |
| Cross-tenant read refusal on every EDR surface | **IMPLEMENTED + PROVEN** | `test_cross_tenant.py`, `test_security_state_isolation.py` **[T]**; saved-view `VIEW_NOT_FOUND` **[L]** |
| Tenant partitioning of response commands | **IMPLEMENTED + PROVEN** | `P0_RESPONSE_EXECUTION_TENANT_ISOLATION.md` 21 PASS **[L]** |
| Unattributed / failed-closed evidence excluded from tenant answers | **IMPLEMENTED + PROVEN** | `edr_scope` + `device_identity.list_devices`; `test_p0_d14_tenant_authority_live_proof.py` **[L]** |
| Aggregated operator audit across all EDR planes | **IMPLEMENTED + PROVEN** | `routers/edr_audit.py` **[S]** + Gate 11/Audit UI **[L]** |
| **Role-based authority on destructive actions** | **NOT IMPLEMENTED** | **C3** — critical |
| Two-person control on response (exists for exclusions, absent for response) | **NOT IMPLEMENTED** | **C3** |
| Audit immutability / export / retention policy | **IMPLEMENTED + UNPROVEN** | audit is aggregated from source records (good), but there is no tamper-evident ledger and no export |
| Operator authentication hardening (MFA, session policy, API tokens with scopes) | **NOT APPLICABLE** at EDR layer / **NOT IMPLEMENTED** platform-wide | inherited from the host platform's auth; no EDR-scoped API token model exists |

---

## M · PLATFORM COVERAGE & CONNECTOR LIFECYCLE

| Capability | Windows | Linux | macOS | Class | Evidence |
|---|---|---|---|---|---|
| Released connector artifact | yes (unsigned, preview) | yes (unsigned, preview) | **none** | **PARTIAL** | `catalog.py`; `grep -i macos\|darwin` over `agents/` + catalog: **no hits** **[S]** |
| Real-host onboarding proof | **no** | yes | n/a | **PARTIAL** | Gate 1 `BLOCKED` — no Windows host available; owner-only dependency, postponed and explicitly **not waived** |
| Guided install with generated deployment context (no rebuild) | yes | yes | n/a | **IMPLEMENTED + PROVEN** | `Install-NivXForgeSensor.ps1`, `routers/edr_onboarding.py`; deployment live proof **[L]** |
| Uninstall | local switch only | manual | n/a | **PARTIAL** | `Install-NivXForgeSensor.ps1:44-103`; unauthenticated, not remote, not audited |
| Remote uninstall / remote upgrade / connector version fleet management | no | no | n/a | **NOT IMPLEMENTED** | `REMOTE_UNINSTALL` is an enum member only |
| Groups and placement at enrolment | yes | yes | n/a | **IMPLEMENTED + PROVEN** | `policy/store.py:157-244`; `edr_groups 8` **[S]**; Gate 8 **[L]** |
| Bulk fleet operations (move group, reboot, rescan) | no | no | n/a | **NOT IMPLEMENTED** | `CISCO_AMP_360_PARITY_MATRIX.md` §2 records the same gap |
| Kernel-mode component / driver | no | no | n/a | **NOT IMPLEMENTED** | user-space Python sensors; a hard Cisco parity ceiling |
| Containers / mobile / network-device coverage | no | no | n/a | **NOT IMPLEMENTED** | — |

---

## N · INTEGRATION & PROGRAMMATIC SURFACE

| Capability | Class | Evidence |
|---|---|---|
| EDR → XDR evidence handoff through one authenticated bridge | **IMPLEMENTED + PROVEN** | `canonical_bridge.py:454-523`; `test_p0_f13_5_detection_handoff.py` **[T]** |
| Incident linkage from endpoint evidence | **IMPLEMENTED + PROVEN** | `canonical_bridge.py:504`; `test_p0_f7_campaign_story.py`, `test_p0_f7_live_api.py` **[T]** |
| Vendor-neutral detection-source model (NivXForge as one source among CrowdStrike/Defender/SentinelOne/Cortex) | **IMPLEMENTED + UNPROVEN** | `GATE_17_DETECTION_SOURCE_ARCHITECTURE.md` DESIGN FROZEN; no second source implemented |
| SIEM / CEF-LEEF export path | **PARTIAL** | `test_p1_10_cef_leef_dsm.py` covers DSM shapes on the XDR side; no EDR-scoped export endpoint **[S]** |
| Documented external EDR API for customers (versioned, scoped tokens, rate-limited) | **NOT IMPLEMENTED** | EDR routes are console-session routes; no public API contract, no API token scope model |
| Outbreak control lists (simple custom detections, blocked/allowed application lists, IP block lists) | **NOT IMPLEMENTED** | `inventory.py:843` `outbreak_control_ui NOT_IMPLEMENTED`; no backend list model |
| Threat-intel / reputation feed ingestion | **NOT IMPLEMENTED** | family C |
| Webhook / alerting egress (email, Slack, ticketing) | **NOT IMPLEMENTED** | no EDR notifier **[S]** |

---

## O · OPERATOR EXPERIENCE, REPORTING & PRODUCT READINESS

| Capability | Class | Evidence |
|---|---|---|
| Independent EDR console origin (no XDR UI dependency) | **IMPLEMENTED + PROVEN** | `test_gate16_edr_independence.py` 5 passed **[T]**; `GATE_16_EDR_INDEPENDENCE.md` |
| Surfaces that exist: Overview, Computers, Device + Trajectory, Process Tree, Events, Detections, Campaign Story, Policies, Exclusions, Response, Downloads, Add Device, Audit | **IMPLEMENTED + PROVEN** | `apps/nivxray-xdr/src/nivxforge/pages/*`, `trajectory/*` **[S]**; per-gate live captures **[L]** |
| Honest "not implemented" surfaces instead of empty shells | **IMPLEMENTED + PROVEN** | `EdrNotImplementedPage.jsx`, `EdrReservedPages.jsx` **[S]** |
| Two-theme (light/dark) correctness on desktop | **IMPLEMENTED + PROVEN** | `scripts/nvf_contrast_audit.py` 0 failures both themes, production build PASS, 10 real-SPA captures **[L]** |
| **Responsive / mobile correctness** | **FAILED** (recorded) | `GATE_12_UI_UX_TWO_THEME.md` = `PASS_DESKTOP / RESPONSIVE_VALIDATION_PENDING`; last validation failed 30/30 mobile assertions (touch targets, step-card overflow on Downloads, sidebar pushing content off-screen). Recurrence count 2 |
| Filter taxonomy baseline (43 mandated items) | **NOT IMPLEMENTED · OWNER INPUT PENDING** | `capability/taxonomy.py:29-103` — categories frozen, item list deliberately not reconstructed, and any filter UI must disclose the incomplete baseline |
| Scheduled/exportable reporting, executive summary, compromise roll-up | **NOT IMPLEMENTED** | `CISCO_AMP_360_PARITY_MATRIX.md` §1 (no compromised-computer roll-up, no connector-health histogram, no ingest-health tile) |
| Implemented-truth documentation set | **IMPLEMENTED + PROVEN** | `/app/docs/nivxforge-edr/` (README, Quick Start, User Guide, Windows Connector Deployment, Policy, Exclusions, Events) **[S]**; planned guides listed as NOT YET WRITTEN |
| Test baseline integrity | **IMPLEMENTED + PROVEN** | `tests/edr` **425 passed / 1 skipped / 0 failed, re-run in this session** **[T,S]** |
| Weekly exclusion digest | **NOT IMPLEMENTED** | owner-deferred operational enhancement, recorded, not built |

---

## 2 · Roll-up

**IMPLEMENTED + PROVEN (34 rows).** Authenticated telemetry ·
heartbeat + queue depth · durable outbox and replay · rejected-telemetry
quarantine · Linux process telemetry with real parent attribution ·
process start identity · immutable raw store with appended derivations ·
ingest provenance · canonical/process identity binding ·
forged-telemetry refusal · server-side detection via the XDR pipeline ·
honest non-evaluation · finding contract · response lifecycle with
five distinct states · `KILL_PROCESS` with identity binding and
independent verification (Linux) · Linux isolation with kernel read-back
and protected control channel · auto-release as a new authorised command
· response-plane tenant isolation · all nine exclusion rows listed in F ·
policy versioning, digest, ACK-only-APPLIED, precedence, drift,
capability-truthful settings, audit · sensor credential hygiene and
artifact credential refusal · crash/transient-error survival · fleet
blindness detection · trajectory performance · process tree · campaign
story · Events Explorer · saved views · audit aggregation · release
catalog with artifact truth, honest non-publication, build-once
distribution, OS-aware capability declaration, support-lifecycle honesty
· tenant authority across every EDR route · EDR console independence ·
two-theme desktop correctness · documentation set · test baseline.

**IMPLEMENTED + UNPROVEN (8).** Evidence-ref resolvability of every
investigation node · single-EDR→XDR-boundary exclusivity · unified
action-model contract (enum only) · state-directory permissions ·
identity stability across reinstall/upgrade · audit immutability and
export · vendor-neutral detection-source model · Windows real-host
onboarding (blocked on an owner-provided host).

**PARTIAL (12).** Windows telemetry (event-log only) · process start
coverage · parent attribution coverage · path/command-line/user field
completeness · executable hashing · file events (polled baseline, Linux
only) · network events (Linux only) · engine-scoped exclusions ·
policy mode triad (no `AUDIT`) · release declaration (no response axis) ·
MITRE attribution · SIEM export · platform coverage · uninstall.

**NOT IMPLEMENTED (headline).** Prevention in every form · endpoint-local
detection · offline decision plane · ML · file reputation · behavioural
/ injection / persistence / ransomware classes · findings persistence and
retrospection · quarantine · file retrieval · live query · forensic
snapshot · File Trajectory · DNS and registry telemetry · script/LOLBin
visibility · process exit · signer metadata · drop accounting · sensor
resource metering · policy signing and rollback · connector signing and
build ID · tamper/self-protection · remote upgrade/uninstall · outbreak
control lists · public API · alert egress · reporting · macOS · action
RBAC · automated response.

---

## 3 · Critical security / correctness gaps (ranked)

1. **No action-level authority on destructive response.** **CLOSED
   2026-09-26 by P0-A** — see `P0A_RESPONSE_AUTHORITY.md`. `response.execute`
   is now required, destructive verbs require an approval issued by the
   single response authority and bound to {tenant, endpoint, action,
   requester}, self-approval and replay fail closed, and release is
   permission-gated and idempotent.
2. **Endpoint exclusions destroy evidence.** The only endpoint engine is
   `endpoint.collection`; a tuning exclusion silently and irreversibly
   removes forensic telemetry. Needs `scope: COLLECTION | DETECTION |
   PREVENTION`, defaulting to `DETECTION`.
3. **Detections are computed and then discarded.** `edr_findings 0`;
   `fabric/store.persist` has no caller. There is no durable EDR verdict,
   therefore no retrospection, no detection UI over findings, and no
   measurable detection quality.
4. **Evidence cannot answer which policy governed it.** No
   `policy_version` / `config_digest` on the evidence row, so an
   exclusion or mode change cannot be reconstructed against past
   evidence.
5. **`ZERO` and `UNKNOWN` are indistinguishable for data loss.** No drop
   counters, no sensor resource metering.
6. **Unsigned connector, unsigned policy, unprotected uninstall.** No
   authenticity anywhere in the delivery chain; local `-Uninstall`
   disables the sensor with no authority and no audit.
7. **Windows is an event-log forwarder.** Correctly declared, but Cisco
   parity on Windows begins at zero object telemetry — and Gate 1 cannot
   close without an owner-provided Windows host.
8. **Field completeness is unmeasured.** No metric exists for
   `image_path` / `command_line` / `sha256` null rates, so telemetry
   quality regressions are invisible.

## 4 · Cisco Secure Endpoint parity gaps (capability-level, not UI)

Prevention engines (TETRA/exploit/script/ransomware/behavioural) ·
cloud + local file reputation and hash verdicts · offline protection ·
Outbreak Control (simple custom detections, blocked/allowed application
lists, IP block lists) · File Trajectory and estate-wide SHA-256 pivots ·
Orbital-class Live Query · forensic snapshot and file retrieval ·
quarantine with restore · automated retrospective detection · Device
Control · connector self-protection and password-protected uninstall ·
signed connector and signed policy · macOS coverage · kernel/ETW-grade
telemetry fidelity · public documented API and SIEM connectors ·
scheduled reporting.

## 5 · Proposed sequence (detail in `NIVXFORGE_EDR_IMPLEMENTATION_PLAN.md`)

* **P0** — response authority/RBAC · exclusion scope · findings
  persistence · policy stamping on evidence · telemetry field
  completeness (before new event classes) · drop accounting · Windows
  object telemetry.
* **P1** — endpoint-local deterministic detection and offline decision
  plane · prevention v1 (terminate + quarantine with restore) ·
  File Trajectory · outbreak control lists · connector and policy
  signing · Gate 12 responsive closure.
* **P2** — live query · forensic snapshot · behavioural/ransomware
  engines · validated ML · exploit/memory protection · macOS · public
  API · reporting.

## 6 · Audit hygiene

Nothing in this document was inferred from UI text, route names,
comments, TODOs, schemas, stubs or prior documentation. Where prior
documentation conflicted with the source, the source won and the
conflict is recorded in §1. **No implementation, code, sensor, CSS or
test change was made.**
