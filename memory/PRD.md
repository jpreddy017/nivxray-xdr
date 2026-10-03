# NivXForge EDR / NivXRay XDR — PRD

## Problem statement
Evolve NivXForge EDR into a production-ready Enterprise SPA: promote the
Phase 0 Windows Canonical Bridge to production (backend + XDR/EDR consoles),
bootstrap the NivX Machines validation tenant, ship a true Windows Installer
(EXE) built by GitHub Actions, and enrol the first real Windows endpoint to
prove live Sysmon telemetry canonicalization and Device Trajectory.

## Architecture
- Frontend: React SPAs — NivXRay (XDR), NivXForge (EDR).
- Backend: FastAPI + MongoDB. All routes under `/api`.
- Sensors: Python — `agents/nivxforge-linux/`, `agents/nivxforge-windows/`.
- Windows artifact: GitHub Actions `windows-latest`,
  `.github/workflows/windows-sensor-installer.yml` → `NivXForgeEDRSetup.exe`.
- Invariants: strict tenant/role authority, fail-closed secrets, immutable
  canonical evidence, no fallback tenant, no preview/localhost endpoints.

## Implemented
- Phase 0 Windows Canonical Bridge promoted to production (backend, XDR, EDR).
- NivX Machines internal-validation tenant reused: `ten_e759b7288598bd882e3dcac49d`.
- Windows Installer V1 CI workflow + build script (unsigned internal build).
- Enrolment token `tok_9cca5b436ad2400d` minted; endpoint enrolled:
  `ep_1989031c8c1d0085812f` (identity intact, no re-enrolment needed).
- Stage-4 `sc.exe` syntax fix + idempotent resume path (commit `ad4a58ef`).
- **2026-06 · Stage-4 SCM runtime fix (commit `56a4d130`, LOCAL — needs
  "Save to Github")**: `--service-run` dispatched from raw argv before any
  argparse; real `ServiceFramework` + `StartServiceCtrlDispatcher` with
  START_PENDING→RUNNING, STOP/SHUTDOWN, clean STOPPED; service host switched
  from one-file to a **onedir payload** inside the one-file installer;
  `service.log` diagnostics; CI acceptance gates (stage-host, SCM argv
  recognition, real create→start→RUNNING→stop→STOPPED→delete lifecycle).
  See `memory/production-gates/WINDOWS_INSTALLER_STAGE4_SCM_RUNTIME_FIX.md`.

- **2026-06 · Post-push verification (read-only)**: pushed as `3700d3f3`
  (platform bookkeeping commit on top of `56a4d130`; installer files byte
  identical remote-vs-local). Run **36296416653** SUCCESS on windows-latest:
  all four gates green including the real SCM lifecycle
  CREATE→START→RUNNING→STOP→STOPPED→DELETE. Artifact
  `NivXForgeEDRSetup-windows-x64` id 10924240416 (17,932,393 B zip).
  Job logs (403) and artifact bytes (401) need repo-admin auth, so the EXE
  SHA-256 and `sc qc` text are NOT independently obtained. See
  `memory/production-gates/WINDOWS_INSTALLER_STAGE4_POST_PUSH_VERIFICATION.md`.

## Backlog
- P0: **Windows activity projection fix implemented (commit `86e02057`,
  LOCAL, not pushed, not deployed)** — one resolver
  `windows_eventlog.envelope_activity` + `flat_view` + facet/filter
  predicates generated from `SUPPORTED`; consumers updated:
  `edr_events._row`, activity facet, activity filter, `edr.py`
  detections + process/trajectory surface, `response.py` targeting.
  Second mismatch found and fixed: canonical `AUTHENTICATION` vs the
  console vocabulary `AUTH` (projection alias, both names in the row
  basis). 41 new tests; `tests/edr` 673 passed. Report:
  `memory/production-gates/WINDOWS_ACTIVITY_PROJECTION_FIX.md`.
  Awaiting owner review → Save to Github → backend republish only (no
  migration, no backfill).
- P1 (recorded, deliberately out of that patch): Windows derivations
  report `parser_name=nivxforge-linux-sensor`; sensor `<Events>`
  batch-wrapper defect (~1 record per 100 refused as malformed XML);
  sensor `_attr()` cannot read single-quoted attributes; broader Windows
  event-family coverage (5379, 4798, 4648, 4672); store the canonical
  activity class on the derivation at ingest.
- P0: **Windows canonicalization gap — diagnosis DONE, patch NOT applied.**
  Canonical bridge works (Sysmon 1 → PROCESS, observation
  `kind=process_create`, detection evaluated). First broken boundary is the
  PROJECTION layer: `edr_events._row` (line 126), the activity facet
  (322-326), the activity filter (233), `edr.py` 494/568 and
  `response.py` 94 all read the Linux dialect `payload["activity"]`, which
  a `WINDOWS_EVENT_LOG` envelope does not have. Secondary sensor defects:
  `<Events>` wrapper corrupts ~1 record per 100-record batch; `_attr()`
  cannot read single-quoted attributes. Full A–F report:
  `memory/production-gates/WINDOWS_PHASE0_CANONICALIZATION_GAP_DIAGNOSTIC.md`.
  Awaiting owner approve/reject of the minimal patch.
- P0: owner PASS/HOLD on the artifact, then endpoint repair instructions.
- P1: close evidence-access gaps — read-only GitHub PAT (logs + artifact
  hash), and make `service.log` presence a hard CI assertion.
- P0: live Windows canonicalization proof (endpoint online, Sysmon ingested,
  canonical evidence + Device Trajectory).
- P1: full investigation surface (Hunt, Files, Network, Forensics, Live Query).
- P1: EDR UI parity matrix (Cisco AMP-style UX).
- P2: `test_edr_and_xdr_resolve_the_same_authority` harness debt (`oracle=`).
- P2: Gate 12 mobile responsive refactor (`nivxforge.css`).
- P2 deferred: DPAPI/TPM credential hardening, tenant-creation unique index,
  Windows sensor outbox cap/rotation.

## Known issues
- `test_sensor_runtime_state_is_never_committed` flakes under the parallel
  full suite (git invocation); passes in isolation.

## 2026-06 · Push gate status (owner-approved, Option A)
- Owner approved CI-only commit `d03d8523` AS PRESENTED. Decision: INCLUDE
  both intermittent tests (`test_sensor_runtime_state_is_never_committed`,
  `test_production_launcher_refuses_admin_credential_bootstrap`). NO
  exclusions added for them — verified: workflow has no `-k`/`--deselect`
  naming either test.
- `86e02057` (projection patch) left byte-identical. patch-id
  `0479b1adb6b28e76b44b7c6927e923fbd5a002a5`; full `git show` sha256
  `8c8e72bdcee0535b0a7028ad6d3a1782e3abe9bad25e59a7de646bd0aea4880f`.
- Local branch `feature/rc2-alignment`; order preserved:
  `86e02057` → (report commit) → `d03d8523` = HEAD.
- Zero edits made this turn. Awaiting owner "Save to GitHub", then
  authoritative CI observation. On first failure of either intermittent
  test: capture evidence, NO rerun, NO exclusion, STOP for owner review.
- Republish remains BLOCKED pending owner review of CI evidence.

## 2026-06 · FIRST CI FAILURE — STOP (read-only triage, nothing changed)
- RC4.x Quality Gate RED on push + pull_request. HOLD on republish.
- Classified: (A) CI env — `JWT_SECRET`/`EMERGENT_LLM_KEY` absent on runner,
  `deps.validate_config()` fail-closed → durable-findings/f4/f3/gate3;
  (B) CI data-seed — `resolve_tenant_scope` reads `users` collection, empty
  mongo:7 → f13_5 403; (C) harness leakage — `mod.subprocess.run = fake_run`
  mutates the stdlib `subprocess` singleton for the whole xdist worker,
  poisoning the two owner-protected tests; (D) NO projection defect, 41/41 pass.
- Full evidence: memory/production-gates/RC4X_CI_FIRST_FAILURE_TRIAGE.md
- Remediation PROPOSED only, awaiting owner approval. No reruns, no exclusions.

## 2026-06 · CI hermeticity hardening — local commit 3aadd519, NOT PUSHED
- One commit: scoped installer `subprocess.run` fake via monkeypatch (+ new
  `tests/edr/test_edr_suite_hermeticity.py` guard), explicit CI-only config in
  the workflow step (`JWT_SECRET`, `EMERGENT_LLM_KEY`, `ADMIN_*`,
  `NIVX_AI_ENABLED=false`), self-seeding `principal` fixture for
  `test_p0_f13_5` + two 403 negative controls.
- Proofs A–J with `backend/.env` absent (git worktree) and empty Mongo:
  602 passed / 0 failed / 0 errors twice; 41/41 projection; both previously
  contaminated tests pass in both orders and under `-n 2 --dist loadscope`.
- `86e02057` still byte-identical. No app code, no deploy, no CI re-run.
- Evidence: memory/production-gates/RC4X_CI_HERMETICITY_PREPUSH_PROOF.md
- Marker-based test classification proposed only:
  memory/production-gates/RC4X_TEST_MARKER_PROPOSAL.md
- AWAITING OWNER REVIEW before push. Republish still on HOLD.

## 2026-06 · RC4.x CI GREEN on the authoritative runner (read-only verified)
- Remote `jpreddy017/nivxray-xdr` @ `feature/rc2-alignment`, HEAD `8c53c002`.
- RC4.x Quality Gate SUCCESS on push (run 36308919817) and pull_request
  (36308923628); step "Unit tests — EDR plane (deterministic scope)" green in
  both, with no `continue-on-error`/`|| true` ⇒ 0 failures, 0 errors.
- Commit order intact: `86e02057` → `d03d8523` → `3aadd519`; `86e02057`
  resolves on the remote unchanged (5 files, +679 −11).
- Remote workflow + all 7 relevant test files hash-match local.
- Literal pytest count lines NOT retrievable read-only (log download needs
  admin; no PAT used) — documented as a limitation.
- `Vercel – nivxray-xdr` red = legacy root project, OUT OF SCOPE;
  `nivxray-xdr-production` and `nivxray-edr-production` are green.
- Evidence: memory/production-gates/RC4X_CI_ACCEPTANCE_RECORD.md
- PRODUCTION REPUBLISH STILL ON HOLD pending owner approval. After republish:
  verify 4624→AUTH, Sysmon 1→PROCESS, facets populated, PROCESS filter
  returns processes, Device Trajectory shows real process evidence.

## 2026-06 · Backend republish APPROVED by owner — blocked on the owner's click
- Pre-publish safety gate re-verified read-only: no frontend file, no .env /
  requirements, no new env reads in production code, no schema/index/migration/
  backfill, collection policy and the 8 SUPPORTED families unchanged, response
  authority fail-closed unchanged, sensor untouched.
- Production BEFORE baseline: /api/health ok, openapi 862 paths
  sha256 8c04168feebf43f0 (still the pre-projection build).
- Platform constraint (unchanged): republish is an OWNER-ONLY click in the
  Emergent UI; the agent cannot trigger it and it cannot be scoped
  backend-only (frontend diff is empty, so the rebuild is a frontend no-op).
- Acceptance script ready: memory/production-gates/prod_projection_verify.sh
  (read-only GETs; needs a console bearer token the owner pastes into their own
  shell). Gate doc: WINDOWS_PROJECTION_BACKEND_REPUBLISH.md
- Defect closes only when facets AUTH/PROCESS > 0, per-record 4624→AUTH and
  Sysmon 1→PROCESS, PROCESS filter returns real records, unsupported families
  stay explicit gaps, tenant isolation holds, and Device Trajectory resolves
  real canonical process evidence.

## 2026-06 · CORRECTION + production acceptance harness
- Publish 100 (`d85f369`) IS already live. The earlier "production is still
  pre-projection" claim was WRONG: preview (patched) serves the same OpenAPI
  hash `8c04168feebf43f0` / 862 paths, because the patch adds no route.
- Valid build fingerprint instead: `GET /api/edr/events?activity=AUTHENTICATION`
  → pre-patch 422 ACTIVITY_INVALID (edr_events.py:227-231 @ 86e02057^) vs
  patched 200 with `filters_applied.activity == "AUTH"`. Confirmed on preview,
  and `activity=BOGUS` still 422 (validation intact).
- Owner-run acceptance script: memory/production-gates/prod_projection_verify.py
  (getpass, one login POST, GETs only, PASS/FAIL per criterion). Agent cannot
  run it: admin password is owner-held and no token may enter chat.
- Supervisor health-check finding = false positive, untouched. SQLite/WAL repo
  hygiene deferred.

## 2026-06 · Production gate recorded: S1-S5 PASSED · S6 HELD
- Owner will not accept Device Trajectory as final. New workstream:
  DEVICE TRAJECTORY V2 — operational (not visual) parity with Cisco Secure
  Endpoint-class investigation. No Cisco assets/CSS/code/branding.
- PHASE A COMPLETE (read-only, no code change):
  memory/production-gates/DEVICE_TRAJECTORY_V2_GAP_ANALYSIS.md
- Findings in brief: V1 already has windowed cursor paging, endpoint-wide
  lineage-ordered axis, lifelines, parent→child connectors, 30-day + 24-hour
  navigator with drag handles, filters, pivots, and a focus handoff endpoint.
  Real gaps: no Events→Trajectory entry point (EdrEventsPage has zero
  trajectory links); no first-class relationships[]/detections[]/density[]/
  coverage[] in the contract; no search match navigation; no RAW evidence tab
  (though GET /api/edr/events/{raw_id} exists); no keyboard ops; inspector
  fixed at 348px; URL uses replace so Back does not step; no request abort.
- Telemetry-limited (NOT UI bugs): no Sysmon 5 process end, no signer/
  integrity, 4688 lacks ProcessGuid+hashes, no file-read/module/WMI coverage.
- Per-dimension parity: UI PARTIAL · NAV PARTIAL · TIMELINE GOOD ·
  RELATIONSHIP PARTIAL · SEARCH/FILTER PARTIAL · EVIDENCE PARTIAL ·
  TELEMETRY COVERAGE HONEST/NARROW. No aggregate score, by owner rule.
- NEXT: await owner approval, then Phase B architecture doc. No code yet.

## 2026-06 · PHASE B COMPLETE (design only) — Device Trajectory V2
- memory/production-gates/DEVICE_TRAJECTORY_V2_ARCHITECTURE.md (61 sections,
  flowcharts A-R, component diagram, contract, parity matrix, DT2-0..DT2-9,
  rollback, risks, open decisions, 35-answer exit gate).
- Decision: extend V1, replace nothing (REPLACE: none). Add 4 first-class
  contract objects: relationships[], detections[], density[], coverage[] —
  additive keys, V1 clients unaffected.
- Coverage truth is 7-state with an UNKNOWN-first rule; fabricated
  NOT_COLLECTED intervals forbidden.
- PUSH/REPLACE history rules defined (fixes V1 indiscriminate replace:true).
- Perf harness saved: memory/production-gates/dt2_perf_baseline.py.
  BASELINE NOT YET CAPTURED — prod needs owner token; preview pod services were
  restarting (~25s uptime) so local numbers would be noise. Substrate found:
  test_database has 236,444 observations, device dev_42e8c6dc74b9 = 232,379.
- NO code/deploy/DB write/sensor/response change. Awaiting approval for DT2-0.

## 2026-06 · DT2-0 IMPLEMENTED (local commit 114e06d6, NOT pushed/deployed)
- New package backend/edr_plane/trajectory/{models,contract}.py: 13 typed
  contract objects with constructor-time validation. Evidence-backed
  relationships only (FORBIDDEN_BASES rejects temporal proximity etc.),
  7-state coverage with UNKNOWN-first + proof requirement, density with no
  severity field, process identity authority AUTHORITATIVE/DERIVED/UNSTABLE,
  no invented process end, focus with 4 explicit states (no silent fallback).
- Owner decisions implemented: retention truth (4 separate range fields),
  UNATTRIBUTED artifacts kept, 4624 without binding gets no process edge,
  inspector width per-session (nothing persisted), DETECTION→PROCESS only when
  authoritative.
- Wiring: GET /api/edr/endpoints/{id}/trajectory gains ADDITIVE `dt2` key +
  optional `raw_event_id` focus param; V2 failure degrades to
  dt2.state=DT2_CONTRACT_UNAVAILABLE and never breaks V1.
- Tests: 45 new (A–AI list) + 148 focused regression green; ruff clean.
- Live read-only preview check on a 232,379-observation device: V1 keys intact,
  42 edges all with evidence+basis, focus FOCUS_RESOLVED, cross-tenant 403.
- Reports: DEVICE_TRAJECTORY_V2_DT2_0_IMPLEMENTATION.md and
  DEVICE_TRAJECTORY_V2_PUBLIC_REFERENCE_ADDENDUM.md.
- No deploy, no DB write/migration, no sensor, no canonicalization/detection
  semantics, no response authority. DT2-1 NOT started. Awaiting owner approval.

## 2026-06 · DT2-0 ACCEPTED by owner · DT2-1 AUTHORIZED but CI-BLOCKED
- Owner accepted DT2-0 (commit `114e06d6`) subject to the authoritative
  GitHub CI gate. DT2-1 (timeline/navigation/interaction engine) authorized
  for that slice ONLY. DT2-2+ forbidden.
- Owner decisions for DT2-1: (1) push only via owner "Save to Github" after
  agent diff inspection — agent must not push; (2) **DT2-1 implementation is
  BLOCKED until authoritative CI is GREEN for `114e06d6`; local pytest is NOT
  a substitute**; (3) mouse/trackpad acceptance = synthetic WheelEvent
  simulation only, report "PHYSICAL HARDWARE UX VALIDATION: NOT PERFORMED",
  owner does physical acceptance; (4) frontend scope = minimum safe substrate
  (navigation/interaction engine + bounded windowed rendering, KEEP the
  existing lane/node renderer, no virtualization rewrite — STOP and report if
  a measured blocker forces expansion); (5) layered test harness — frontend
  unit/interaction (existing JS runner) + backend pytest (contract/tenant/
  cursor/focus/V1) + focused Playwright (deltaMode, gestures, anchored zoom,
  scroll-domain isolation, URL PUSH/REPLACE, Back/Forward, A→B→C stale
  rejection, inspector-vs-trajectory scroll). All 50 required cases must be
  mapped UNIT / PLAYWRIGHT / PYTEST / MANUAL-HARDWARE; no case passes on
  design description alone.
- **Commit inspection DONE (this turn, read-only):**
  `memory/production-gates/DT2_0_COMMIT_INSPECTION_RECORD.md` — `114e06d6` =
  5 files, +1387/−0, approved scope only, zero secrets, zero runtime
  artifacts (no sqlite/wal/shm/log/env), no frontend/CI/deps/sensor/env/
  supervisor change, no migration, `edr.py` change is 3 additive edits with
  V2 inside try/except after all V1 keys are written. patch-id
  `7a23172106bba1cdc543bfebb5d1192ec2df87c5`, `git show` sha256
  `6e7a29c34ad4e5522f111122361ea16bdb5ec9231973c65b88487ec577978b2a`.
  Verified the DT2-0 suite is NOT in the workflow's 10 `--ignore` entries and
  is hermetic ⇒ CI will really execute it.
- No `origin`/upstream exists in this pod, so the agent structurally cannot
  push. Owner "Save to Github" is the only path.
- Open hygiene item for the owner before the click: untracked
  `memory/availability_probe.log` (44 KB, secret-clean, regenerable) would be
  swept into the auto-commit — recommend deleting it first. Tracked
  SQLite/WAL/SHM files are unmodified, so they cannot be swept in.
- STOPPED. Awaiting: Save to Github → GREEN authoritative CI for `114e06d6`
  → then DT2-1 implementation begins.

## 2026-06 · Pre-GitHub housekeeping DONE — tree clean, ready for the click
- Owner-approved deletion of the single untracked runtime artifact
  `memory/availability_probe.log` executed. No commit made for the deletion
  (the file was untracked). Generator `memory/availability_probe.sh` remains
  tracked and intact.
- `git status --short` is **empty**: nothing staged, zero tracked
  modifications, zero untracked files, no SQLite/WAL/SHM/log/env pending.
- Publish chain: `f1dcb454` → `114e06d6` (DT2-0 code) → `736c91b0` (DT2-0
  report) → `521f9e1d` (platform auto-commit of the inspection record, PRD +
  `DT2_0_COMMIT_INSPECTION_RECORD.md`, **memory/ docs only, zero code**).
- HEAD is now `521f9e1d`, NOT `736c91b0` as the owner expected — the platform
  auto-committed the previous turn's report. Both `114e06d6` and `736c91b0`
  are verified ancestors of HEAD, so the CI checkout contains DT2-0, which
  satisfies the owner's stated requirement.
- `114e06d6` re-verified byte-identical: sha256
  `6e7a29c34ad4e5522f111122361ea16bdb5ec9231973c65b88487ec577978b2a`,
  patch-id `7a23172106bba1cdc543bfebb5d1192ec2df87c5`.
- Tracked SQLite/WAL/SHM hygiene debt deliberately NOT touched — separate
  debt, kept out of the DT2 chain per owner agreement.
- DT2-1 still BLOCKED on GREEN authoritative CI. Nothing deployed.

## 2026-06 · DT2-2C TEMPORAL / CAUSAL SEQUENCE PRIMITIVE DONE (server-side only)
- New `backend/edr_plane/trajectory/sequence.py`. Separation kept explicit:
  `relationships.py` = WHAT is related (evidence); `sequence.py` = HOW proven
  relationships are ordered and WHAT causality level may be claimed.
- `StepTimes` keeps source/ingest/canonicalization/detection as four distinct
  fields; ordering uses source/observed time ONLY, never backfilled.
- `SequenceStep` can only reference an existing `ProcessEdge`/`ActivityEdge`.
  Levels: CAUSAL_EVIDENCE (spawn child IS next actor, carries the edge's own
  derivation basis + evidence_ref + predecessor id), ORDERED_OBSERVATION
  (same proven actor), CAUSALITY_UNKNOWN (no link, or not orderable).
- Grouping is by proven process identity only, so unrelated observations 1 ms
  apart land in separate sequences. Forbidden bases rejected at construction.
- No behavioral/malicious classification, no ATT&CK, no scoring, no UI, no
  DT2-1/canonicalization/detection change, no DB/migration/deploy.
- Tests: `backend/tests/edr/test_dt2_2c_sequence.py` (29) + DT2-2A/2B
  regression → 83 passed.
- NEXT: DT2-2D behavioral relationship engine (must keep evidence vs
  inference levels separate). P0 tenant authority hardening still pending.

## 2026-06 · DT2-2D BEHAVIORAL RELATIONSHIP PRIMITIVE DONE (server-side only)
- New `backend/edr_plane/trajectory/behavior.py`. Layering strictly one-way:
  evidence → 2A ProcessEdge → 2B ActivityEdge → 2C TemporalSequence →
  2D BehavioralRelationship. Behaviors reference step_ids and re-use the
  steps' own evidence_refs; no edge/evidence/time is ever manufactured.
- Truth levels: OBSERVED (one direct, GUID-proven evidence step),
  DERIVED (>=2 steps joined by proven CAUSAL_EVIDENCE lineage),
  CORRELATED (non-causal join or PID-surrogate identity — epistemic
  strength only, NOT suspicion), INFERRED (defined, deliberately unused:
  construction requires a named inference producer that does not exist).
- Behavior types: PROCESS_CHAIN, EXECUTION_TO_DNS/NETWORK/FILE/REGISTRY.
  Anything else rejected at construction; judgement-bearing provenance keys
  (severity/score/verdict/mitre/beaconing/persistence/...) rejected too.
- Tests: `backend/tests/edr/test_dt2_2d_behavior.py` (31) + 2A/2B/2C
  regression → 114 passed.
- NEXT: multi-step behavior patterns (exec → DNS → network → file → child
  exec) feeding both Device Trajectory and the Incident Behavior Tree.
  P0 tenant authority hardening still pending.

## 2026-06 · DT2-2E TRAJECTORY GRAPH PROJECTION CONTRACT DONE (not wired)
- New `backend/edr_plane/trajectory/projection.py` — pure COMPOSITION layer:
  DT2-0 `contract.build` (identity, coverage, availability, ranges,
  detections, focus) + 2A process_edges + 2B activity_edges + 2C
  temporal_sequences + 2D behaviors → `TrajectoryGraph`. Owns no
  relationship/coverage/behavior logic of its own.
- Renders: ProcessNode (depth, lifeline as EVIDENCE SPAN with end_time
  permanently None, presence OBSERVED vs REFERENCED_BY_CHILD_EVIDENCE_ONLY),
  ActivityNode (DNS/NETWORK/FILE/REGISTRY attached to the proven actor),
  GraphEdge (evidence_ref + WHY + basis + split times + causality level),
  order/sequences, behaviors, detection_pivots, navigation (cursors,
  before/after pivots that stay UNKNOWN), coverage re-exported verbatim.
- Stable ids: `pnode:{iid}`, `anode:{iid}:{activity_id}`, DT2-2A/2B edge ids,
  DT2-2C step ids; all focus targets validated through DT2-0 `FocusTarget`.
- Tests: `backend/tests/edr/test_dt2_2e_projection.py` (32) + 2A/2B/2C/2D
  regression → 146 passed. API route NOT wired (owner decision).
- NEXT (owner-stated order): **P0 customer/tenant authority hardening —
  remove the browser-authoritative `SELECT CUSTOMER` control and make tenant
  resolution server-derived** BEFORE the visible AMP-class trajectory
  implementation.

## 2026-06 · P0 TENANT AUTHORITY — READ-ONLY AUDIT COMPLETE (verdict FAIL)
- Artifact: `memory/production-gates/TENANT_AUTHORITY_AUDIT.md` (13 sections).
  No code/UI/DB/deploy change; no probes run (owner deferred the live
  cross-tenant matrix to a separate authorization, preview only).
- Verdict FAIL. Two structural defects:
  1. `edr_tenancy.edr_tenant()` validates the registry ONLY; principal
     authorization (`edr_scope`) is an optional per-route call, and EIGHT
     TENANT_SCOPED ops never call it — `/api/edr/detections`,
     `/campaign-story`, `/file-trajectory`, `/fleet-spread-index`,
     `/response/actions/{command_id}`, `/response/isolation-policy`,
     `/wave0/raw-events/stats`, `/wave0/raw-events/replay-candidates`.
     On those, a client-supplied `X-Tenant-Id` EXPANDS authorization.
  2. No server auto-bind on `/api/edr/*`: a single-authorized-tenant
     principal gets 403 TENANT_REQUIRED, so the browser must name the
     customer → `CustomerPicker` ("◇ SELECT CUSTOMER") is rendered with NO
     role condition and is non-functional for normal customers
     (`/api/xdr/tenants` needs `tenants.read` = platform admin only).
- Also found: tenant-existence enumeration oracle (TENANT_NOT_FOUND vs
  TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL), fail-open default
  (`NIVX_TENANT_REGISTRY_ENFORCE` off ⇒ `"default"` compat tenant + arbitrary
  tenant strings accepted), vendor/MSSP inferred from role names, R4 gate
  tests cross-principal refusal on `/api/edr/endpoints` only.
- Minimum fix plan recorded (fix 1 → test 3 → fix 2 → fix 4 → fix 5), then the
  deferred probe matrix, then back to AMP-class trajectory (DT2-2F).

## 2026-06 · P0 TENANT AUTHORITY — FIX 1 DONE (edr_tenant is now authorizing)
- `routers/edr_tenancy.edr_tenant()` reworked: takes the verified principal
  (`Depends(deps.get_current_user)`) and resolves
  `session_context.authorize_requested_tenant(principal, X-Tenant-Id)` FIRST,
  then `tenant_registry.authoritative(...)`. Stamps
  `request.state.effective_tenant_id/tenant_resolution_basis`. No second
  authorization model; `edr_scope()` calls all left in place (defense in depth).
- Single-authorized-tenant principal is now AUTO-BOUND server-side (no header
  needed); naming another tenant ⇒ TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL;
  cross/multi-tenant with no header ⇒ TENANT_REQUIRED; zero-tenant ⇒
  TENANT_NOT_RESOLVED. Authorization runs before the registry lookup, so an
  unheld tenant's existence is never confirmed.
- All 8 G1 routes are structurally proven (live route-table introspection) to
  depend on the fixed dependency, so the bypass is closed at the gate.
- NEW FINDING (G1-B, NOT fixed — out of Fix 1 scope): a SECOND resolver
  `routers/edr_enrollment._tenant()` is still registry-only and serves 7
  TENANT_SCOPED ops (`/api/edr/enrollment/*`, `/api/edr/onboarding/computers*`).
  Pinned in the test as `SECOND_RESOLVER_OPERATIONS` so the list can only shrink.
- Tests: `backend/tests/edr/test_p0_tenant_authority_fix1.py` (23) → 23 passed.
  No preview probes (owner deferred). SELECT CUSTOMER / UI untouched.
- NEXT: owner review, then next tiny step (fix-plan items 2-6 still open:
  non-disclosing refusal, R4 gate extension, UI switchability, enforcement
  default, vendor/MSSP model) + G1-B.

## 2026-06 · P0 TENANT AUTHORITY — FIX 1B DONE (duplicate resolver ELIMINATED)
- `routers/edr_enrollment._tenant()` DELETED (not hardened — removed). Its 5
  enrollment routes + the 2 onboarding routes in `routers/edr_onboarding.py`
  now take `tenant_id/tenant: str = Depends(edr_tenant)`, so there is ONE
  principal→tenant authority on the EDR plane.
- The `users["customer"]` compat fallback is gone from this authorization path
  (asserted absent from edr_enrollment, edr_onboarding and edr_tenancy).
- SENSOR plane untouched: `_agent_tenant()` / `sensor_tenant()` still derive
  tenant from the authenticated enrolment/agent credential and read no header
  (asserted; live sensors keep polling /agent/session + /agent/policy 200).
- `SECOND_RESOLVER_OPERATIONS` in the Fix 1 test is now `()` and the
  route-table test requires EVERY TENANT_SCOPED /api/edr/* op to depend on
  `edr_tenant` — 15 of 15.
- Repaired two pre-existing B5 tests that called the deleted helper
  (`tests/test_b4b5_tenant_registry_authority.py`), plus one latent TypeError
  (`_agent_tenant` keyword-only `oracle`) that had been failing before.
- Tests: fix1 suite 26 + B5 suite 30 + R4 (1 skipped, credential-gated) →
  56 passed, 1 skipped. No preview probes. SELECT CUSTOMER / UI untouched.
- STILL OPEN: fix-plan items 2-6 and the deferred preview cross-tenant probe
  matrix. Tenant Authority is NOT declared closed.

## 2026-06 · P0 TENANT AUTHORITY — FIX 2 DONE (non-disclosing tenant refusal)
- `routers/edr_tenancy.py`: for a principal WITHOUT `tenants.read`, a REQUESTED
  tenant that is unheld / unregistered / inactive now yields ONE byte-identical
  403 (`TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` + `disclosure:
  TENANT_EXISTENCE_AND_STATE_NOT_DISCLOSED`). Closes the enumeration oracle a
  `soc_manager`/`mssp_operator` (all_tenants, no tenants.read) had.
- Privilege is read from the EXISTING RBAC vocabulary
  (`xdr_rbac._resolve_user_permissions` → granular, else built-in role
  expansion); unresolvable privilege fails closed towards NON-disclosure.
  Precise code survives in the server log + `_audit_scope_denial`.
- NOT normalised (discloses nothing about another customer): `TENANT_REQUIRED`,
  `TENANT_NOT_RESOLVED`, `ACCESS_DENIED`, and refusals about the principal's
  OWN auto-bound tenant (e.g. own ARCHIVED tenant still says TENANT_NOT_ACTIVE).
- Authorisation unchanged and still authorise-first; no grant path added.
- Tests: new `tests/edr/test_p0_tenant_authority_fix2.py` (16) + fix1 suite
  updated (28, incl. new f14b) + B5 (30) + R4 (skip) → 73 passed, 1 skipped.
- STILL OPEN: fix-plan items 3-6 and the deferred preview cross-tenant probe
  matrix. Tenant Authority is NOT closed.
- RECORDED FOR LATER (owner): tenant authorization and PRODUCT ENTITLEMENT are
  separate decisions — the Cisco-style "no EDR entitlement/licence" experience
  comes later, after the cross-tenant boundary is proven.

## 2026-06 · P0 TENANT AUTHORITY — FIX 3 LIVE R4 PROOF (1 pre-existing FAIL)
- Extended `backend/tests/test_edr_route_tenant_authority.py` with CLAUSE 6:
  the cross-tenant matrix now runs per-operation over ALL 60 TENANT_SCOPED
  EDR ops (43 read + 17 mutating) in BOTH directions, using the two existing
  preview customers (`nivx-live` via analyst@nivx-live.com, `default` via
  analyst@default.com — both passwords env-supplied, never literals).
- Live result: **660 passed, 43 skipped, 1 failed** in 8m25s. Preview only,
  read-only; mutating ops driven for REFUSAL cases only (nothing created,
  isolated, rotated or revoked).
- PROVEN LIVE: own-tenant reached; auto-bind with NO header (Fix 1); A→B and
  B→A refused with TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL + fail_closed +
  disclosure note on all 60 ops incl. the 8 G1 and 7 G1-B routes; unheld /
  nonexistent / ARCHIVED indistinguishable (Fix 2 live); refusal bodies carry
  no foreign data.
- 43 SKIPPED = the zero-tenant cell. UNPROVEN LIVE: the only zero-tenant
  preview user (`a05-notenant-…`) has no password hash. No account or
  credential was created (owner decision). Hermetic proof stands (fix1 f10,
  fix2 g09). Set TEST_ZERO_TENANT_EMAIL/PASSWORD to prove it live.
- 1 FAILED — PRE-EXISTING, NOT PATCHED (owner instruction to stop and report):
  `POST /api/edr/enrollment/tokens/{token_id}/revoke` is live but absent from
  `ROUTE_CLASSIFICATION` (git -S confirms it was never classified), so the
  fail-closed completeness clause rejects it. Verified it is NOT a bypass:
  introspection shows it does depend on `edr_tenant` + `get_current_user`.
  It is UNCLASSIFIED + UNTESTED authority, awaiting owner authorisation to
  classify TENANT_SCOPED and add its refusal-only probe.
- STILL OPEN: fix-plan items 4-6 (SELECT CUSTOMER / browser authority,
  fail-open enforcement default + "default" residue, vendor-MSSP model).

## 2026-06 · P0 TENANT AUTHORITY — FIX 3A DONE (classification + R4 probe)
- `POST /api/edr/enrollment/tokens/{token_id}/revoke` added to
  `ROUTE_CLASSIFICATION` as TENANT_SCOPED (coverage entry only; the route
  already depended on `edr_tenant` + `get_current_user`, no authorization or
  business change) and given a REFUSAL-ONLY probe in the R4 SAMPLES table
  (nonexistent token id, never called with an authorized tenant).
- TENANT_SCOPED count 60 → **61** (11 SENSOR_SCOPED, 16 PRODUCT_METADATA,
  88 classified total) — matches the owner's expected 61, no further
  discrepancy found.
- Live proof for the route: TENANT_REQUIRED (no header), precise NOT_FOUND /
  NOT_ACTIVE for the privileged admin, A→B refused, B→A refused, and
  unheld/nonexistent/ARCHIVED indistinguishable for the scoped analyst.
  13/13 focused tests pass; completeness clause is GREEN again.
- Zero-tenant live cell remains UNPROVEN LIVE / PREREQUISITE MISSING
  (owner-approved). No account, no credential created.
- STILL OPEN: fix-plan items 4 (SELECT CUSTOMER / `?tenant=` / localStorage),
  5 (fail-open enforcement default + "default" residue), 6 (vendor/MSSP model).
- PERMANENT REQUIREMENT (unchanged): after Tenant Authority closes, NivXForge
  Device Trajectory returns to the Cisco Secure Endpoint / AMP operational-clone
  target — publicly observable UI/UX, interactions, navigation and analyst
  functionality, implemented independently on real NivXForge evidence.

## 2026-06 · P0 TENANT AUTHORITY — FIX 4A DONE (single-customer UI authority)
- The EDR console no longer renders "SELECT CUSTOMER" for a principal the
  SERVER resolved to one customer. Decision comes from ONE authoritative
  field, `active_customer.basis` out of `/api/xdr/rbac/session-context`
  (`SINGLE_AUTHORIZED_TENANT`/`INHERITED_FROM_INCIDENT`/
  `EXPLICIT_REQUEST_TENANT` ⇒ context only; `MULTIPLE_AUTHORIZED_TENANTS`/
  `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` ⇒ picker kept as-is). NO role name
  is inspected anywhere (that stays Fix 6).
- New: `src/nivxforge/tenantContext.js` (decision), `components/
  CustomerContext.jsx` (non-selectable pill, `data-testid=
  nvf-customer-context`, `data-selectable="false"`).
- `src/lib/tenant.js`: added a SERVER BINDING (`bindServerTenant`,
  `serverBoundTenant`, `tenantIsSwitchable`, `TENANT_BOUND_EVENT`) that
  outranks the browser; **`?tenant=` was REMOVED from the resolution order**
  so it can never reach the `X-Tenant-Id` interceptor. A bound principal
  ignores/overwrites a stale `nvx_tenant` and `setActiveTenant()` is a no-op
  for it. A deep link is now ADOPTED as an explicit selection only when the
  server says the principal may switch (minimum multi-tenant change made).
- Console also gates page children on session-context resolution
  (`nvf-tenant-resolving`) so no tenant-bound fetch fires with a stale
  browser value, and `useIncidentContext()` subscribes to the binding.
- Live preview proof (single-customer analyst + hostile `?tenant=default`
  AND planted `localStorage.nvx_tenant=default`): no SELECT CUSTOMER,
  context pill `nivx-live` / `SINGLE_AUTHORIZED_TENANT` / non-selectable,
  the word "default" appears nowhere, no TENANT_NOT_AUTHORIZED banner,
  storage corrected to `nivx-live`, nav works, `?tenant=` not re-attached.
  Cross-tenant admin still gets the picker and deep-link adoption works.
- Tests: vitest 65 passed (13 new, `src/lib/__tests__/tenantAuthority.test.js`);
  backend untouched (`git diff backend/` empty) and fix1+fix2 hermetic suites
  re-run 43 passed.
- STILL OPEN: fix-plan items 5 (fail-open enforcement default + "default"
  residue) and 6 (vendor/MSSP authority model, audited switching); live
  zero-tenant cell; XDR-plane surfaces outside the EDR console.
- PERMANENT REQUIREMENT (unchanged, do not weaken): after Tenant Authority
  closes, NivXForge Device Trajectory returns to the Cisco Secure Endpoint /
  AMP operational-clone target — publicly observable UI/UX, interactions,
  navigation and analyst functionality, on real NivXForge evidence.

## 2026-06 · P0 TENANT AUTHORITY — FIX 4B DONE (fail-closed authority)
- `src/lib/tenant.js`: added `sealTenantAuthority()` / `tenantAuthoritySealed()`.
  A SEALED authority makes `activeTenant()` return null and `setActiveTenant()`
  a no-op, so on a resolution failure NOTHING may act as a customer — not
  `?tenant=`, not `nvx_tenant`, not `"default"`, not the first tenant, not the
  customer the browser was acting as a moment before. `bindServerTenant()`
  unseals only on a successful server answer.
- `src/nivxforge/tenantContext.js`: `contentGateFor(sessState, control)` →
  RESOLVING (neutral) / AUTHORITY_UNAVAILABLE (fail closed, also when the
  server resolves NOT_AUTHORIZED) / RENDER. The console seals during render
  before children can mount.
- New `components/CustomerAuthorityUnavailable.jsx` — "CUSTOMER AUTHORITY
  UNAVAILABLE" + Retry, reusing the existing session-context fetch (no new
  auth flow; 401 still goes through the api interceptor to /login). The topbar
  shows `◇ NOT RESOLVED`, never another customer's name.
- Live preview proof (session-context forced 503 + `?tenant=default` +
  planted `localStorage=default`): fail-closed panel shown, zero tenant-bound
  content, the word "default" absent everywhere, pill basis
  AUTHORITY_UNAVAILABLE; Retry with the endpoint restored recovers to
  `nivx-live` with no SELECT CUSTOMER.
- Tests: vitest **76 passed** (24 in `tenantAuthority.test.js`, 11 new for 4B).
  BACKEND UNCHANGED (`git diff backend/` empty).
- STILL OPEN: Fix 5 (fail-open registry-enforcement default + backend
  "default" residue) and Fix 6 (vendor/MSSP authority model + audited
  switching); live zero-tenant cell; XDR-plane tenant UX.
- PERMANENT REQUIREMENT (unchanged): after Tenant Authority closes, NivXForge
  Device Trajectory returns to the Cisco Secure Endpoint / AMP
  operational-clone target — publicly observable UI/UX, interactions,
  navigation and analyst functionality, on real NivXForge evidence.
## 2026-06 · P0 TENANT AUTHORITY — FIX 5A DONE (registry enforcement is an invariant)
- `services/tenant_registry.py`: new `authoritative_required(tenant_id, purpose=)`
  — reads NO environment flag, has no `compat_default`, never returns `"default"`,
  never returns an unvalidated tenant. Requires: registered tenant + tenant
  ACTIVE + organization registered + organization ACTIVE. A registry/DB lookup
  failure is now a refusal (`REGISTRY_UNAVAILABLE`, 503), not a swallowed
  exception. The legacy flag-gated `authoritative()` is kept for the
  XDR/collector/ingest planes and simply DELEGATES when enforcing, so those
  planes are byte-identical.
- `routers/edr_tenancy.py`: `edr_tenant()` and `sensor_tenant()` now call
  `authoritative_required()`. `routers/edr_enrollment.py::_agent_tenant()` (the
  sensor enrolment/agent credential resolver, the only other EDR registry call
  site) likewise; its generic-401 error-oracle rule is unchanged.
- Result: `NIVX_TENANT_REGISTRY_ENFORCE` unset / `false` / `0` / `off` / `true`
  all behave IDENTICALLY for EDR — there is no runtime state in which principal
  authorization succeeds and registry validation is silently disabled.
  Fix 2 non-disclosure is intact (unheld / unregistered / archived / registry
  failure remain ONE opaque 403 for an unprivileged principal).
- Tests: `tests/edr/test_p0_tenant_authority_fix5a.py` (new, A–M incl. every flag
  value parametrised) + fix1 + fix2 + `test_b4b5_tenant_registry_authority.py`
  → **131 passed, 0 failed**. No legacy test depended on EDR fail-open.
  `backend/.env` NOT changed. No frontend change. No "default" residue touched.
- STILL OPEN: Fix 5B (backend `"default"` residues — `authorised_incident()`,
  `list_customers()`, `compat_default="default"`), Fix 6 (vendor/MSSP authority
  model + audited switching); live zero-tenant cell; XDR-plane tenant UX.
- PERMANENT REQUIREMENT (unchanged): after Tenant Authority closes, NivXForge
  Device Trajectory returns to the Cisco Secure Endpoint / AMP
  operational-clone target — publicly observable UI/UX, interactions,
  navigation and analyst functionality, on real NivXForge evidence.
## 2026-06 · P0 TENANT AUTHORITY — FIX 5B DONE (no implicit "default" fallback)
- `services/session_context.py::authorised_incident()`: the terminal
  `or "default"` is GONE. An incident naming neither `tenant_id` nor
  `user_email` now returns the new state `INCIDENT_TENANT_UNRESOLVED` with
  `doc=None` for EVERY principal (including cross-tenant), instead of being
  attributed to the real registered tenant `default`. Legacy `user_email`
  attribution and the existing `INCIDENT_TENANT_OUT_OF_SCOPE` /
  `INCIDENT_NOT_FOUND` / `NOT_AUTHORIZED` states are unchanged.
- `services/session_context.py::list_customers()`: group key is now
  `tenant_id ?? user_email` with a `$match` dropping null/empty keys, so an
  unattributed case can no longer manufacture a customer called `default`.
- The REAL tenant `default` is untouched: not deleted, renamed, deactivated or
  migrated. Live `/api/xdr/rbac/session-context` still lists
  `customer=default` with identical counts (944 open / 944 total; 0 cases in
  the corpus lack BOTH fields, so the removed branch was dead-but-dangerous).
- `compat_default="default"` remains ONLY on the legacy flag-gated
  `tenant_registry.authoritative()`, which no EDR path calls after Fix 5A —
  XDR/collector/ingest semantics deliberately unchanged. XDR display-label
  residues (`xdr_mss.py`, `incidents.py`, `xdr_respond_boundary.py`, the
  vendor/cortex wizards) stay owner-fenced (T-RISK-3/4/5).
- Tests: `tests/edr/test_p0_tenant_authority_fix5b.py` (new) + 5A + fix1 +
  fix2 + `test_a05_tenant_scope_contract.py` → **185 passed, 0 failed**.
- PRE-EXISTING failures (NOT caused by 5B, reported not rewritten):
  `tests/test_edr_context_p0_f13_3.py` — 4 cases expect `/api/edr/context` 200
  for a cross-tenant admin with no `X-Tenant-Id` (Fix 1 now returns 403
  TENANT_REQUIRED) and 1 case asserts a stale snapshot count (241 vs the
  current 944). Owner decision required before touching that file.
- STILL OPEN: Fix 6 (vendor/MSSP authority model + audited switching); live
  zero-tenant cell; XDR-plane tenant UX.
- PERMANENT REQUIREMENT (unchanged): after Tenant Authority closes, NivXForge
  Device Trajectory returns to the Cisco Secure Endpoint / AMP
  operational-clone target — publicly observable UI/UX, process/relationship/
  time rendering, process lifelines, parent/child navigation, event attachment,
  before/after investigation, search/filter/MATCH navigation, zoom/pan,
  evidence/raw/provenance inspection — on real NivXForge evidence.
## 2026-06 · LEGACY TEST REPAIR — tests/test_edr_context_p0_f13_3.py (owner-approved)
- TEST-ONLY change. PRODUCT CODE UNCHANGED (`git status` shows only the test
  file). No data, no credentials, no frontend, no deploy.
- The four `/api/edr/context` cases now present the REAL registered tenant
  explicitly (`X-Tenant-Id: default`), matching the post-Fix-1 contract, and a
  new case `test_context_without_tenant_context_is_refused` PINS
  `403 TENANT_REQUIRED` + `fail_closed:true` + `authority:server` for a
  cross-tenant principal with no tenant context, so the pre-Fix-1 implicit
  behaviour cannot be reintroduced.
- `test_context_xdr_pivot`: with the tenant now presented explicitly the
  server reports `basis=EXPLICIT_REQUEST_TENANT` (previously
  `INHERITED_FROM_INCIDENT`). The inheritance contract is still asserted:
  `active_customer.value == investigation.tenant_id == "default"` and
  `entry_context == XDR_PIVOT`.
- `test_session_context`: the frozen `open_incidents == 241` snapshot is gone.
  New invariants — `incidents >= 1`, `0 <= open_incidents <= incidents`,
  every row has a real customer (Fix 5B), the queue_href matches the customer,
  and session-context's count for `default` EQUALS `/api/xdr/mss/
  customer-operations` for the same customer (both derive from the one
  authoritative queue predicate `dashboard_lenses._scope`, which is the actual
  product contract and stays true as live evidence changes).
- Result: `test_edr_context_p0_f13_3.py` 7 passed (was 5 failed / 1 passed) and
  fix1 + fix2 + 5A + 5B re-run green → **120 passed, 0 failed**.
## 2026-06 · P0 TENANT AUTHORITY — FIX 6A DONE (inspection + contract only)
- DESIGN ONLY. No authority code, role semantics, membership, grant, database,
  frontend, switch API or audit persistence changed; no credential created;
  live zero-tenant cell still UNPROVEN LIVE / PREREQUISITE MISSING.
- Full report: `memory/production-gates/FIX6A_VENDOR_MSSP_AUTHORITY_DESIGN.md`.
- Headline findings: cross-tenant authority is inferred from the free-text
  `users.role` (`_CROSS_TENANT_ROLES` in `dashboard_lenses.py`), the EDR
  CustomerPicker's selectable list is the WHOLE registry (`/api/xdr/tenants`,
  `tenants.read`) rather than a grant set, there is NO successful-switch audit
  event (refusals ARE audited as `ACCESS_DENIED`/`tenant_scope`, 442 live
  rows), and `organization.kind = VENDOR/MSSP` is inert metadata.
- Grant source already exists: `users.tenant_ids[]` → PROPOSED_DATA_MODEL_
  CHANGE = NONE + one optional additive `platform_authority` marker. No second
  authority store; `X-Tenant-Id` stays the requested-context input.
- BLOCKING OWNER DECISION for Fix 6B: the 3 live `admin` + 1 `soc_manager`
  principals hold no `tenant_ids[]`, so grants-first would remove their
  customer authority — option (A) documented narrow platform-wide authority
  for `platform_admin` (audited per resolution) vs (B) write explicit grants
  (a data change needing approval).
- PERMANENT REQUIREMENT (unchanged): immediately after Tenant Authority
  closes, NivXForge Device Trajectory returns to the Cisco Secure Endpoint /
  AMP operational-clone target — the real publicly observable UI/UX,
  process/relationship/time rendering, process lifelines, parent/child
  navigation, event attachment, before/after investigation, search/filter/
  MATCH navigation, zoom/pan/scroll, evidence/raw/provenance inspection and
  analyst workflow, implemented independently on real NivXForge evidence.
  Not AMP-inspired, not a generic timeline.
## 2026-06 · P0 TENANT AUTHORITY — FIX 6B-0 DONE (read-only live grant plan)
- OWNER DECISION: Fix 6 uses OPTION B — explicit per-principal tenant grants
  (`users.tenant_ids[]`). NO `platform_authority` bypass. Role = what you may
  do; explicit grants = where. `soc_manager` and `mssp_operator` lose
  automatic all-tenant breadth. `authorized_count` becomes grant-derived; the
  picker reads `authorized_tenants[]` while the queue stays evidence-derived;
  `organization.kind` stays NON-AUTHORITATIVE; G6-7 deferred.
- READ-ONLY step. DATA_CHANGED = NO, CODE_CHANGED = NO (git clean).
  Full plan: `memory/production-gates/FIX6B0_LIVE_GRANT_PLAN.md`.
- 4 live role-based multi-tenant principals found. Proposed (NOT applied):
  `admin@nivxray.com` → ["default","nivx-live"] (VENDOR INTERNAL, org
  "NivXMachines (Preview)" kind VENDOR; 100+8 audit rows, 318 endpoints, all
  sampled raw events, 20 own/assigned cases); `p0a-approver@nivxray.com` →
  ["default"] (HIGH, already carries tenant_id=default);
  `approver@nivxray.com` → ["default"] (MEDIUM, documentation-only evidence);
  `a05-admin-37051a53@nivxray.test` → UNRESOLVED (zero evidence, a05 fixture
  residue). The other 40 tenants in the admin audit trail are gate/test
  fixtures and are deliberately NOT proposed.
- Fix 6B dependency flagged: `tests/test_a05_tenant_scope_contract.py` seeds a
  role-only `admin` and asserts cross-tenant outcomes; under grants-first that
  FIXTURE must seed explicit tenant_ids (test change, not product weakening).
- NEXT: Fix 6B-1 = write ONLY the approved grants (idempotent, no other field,
  no credential) and re-report resolved scope, with NO authority-code change;
  grants-first enforcement + audited switch become Fix 6B-2.
- PERMANENT REQUIREMENT (unchanged): the moment Tenant Authority closes,
  NivXForge Device Trajectory returns to the Cisco Secure Endpoint / AMP
  operational-clone target — real publicly observable Cisco-class UI/UX,
  process/relationship/time interaction, lifelines, parent/child navigation,
  event attachment, before/after investigation, MATCH navigation, zoom/pan,
  evidence/provenance inspection — on real NivXForge evidence.
## 2026-06 · P0 TENANT AUTHORITY — FIX 6B-1 DONE (approved grant write only)
- DATA PREPARATION ONLY via `/app/scripts/fix6b1_grant_write.py` (idempotent;
  second run = NO_OP on all three). ONE field written (`users.tenant_ids`) on
  three principals; registry validated first (both tenants ACTIVE under the
  ACTIVE VENDOR org `nivxmachines-preview`).
  - `admin@nivxray.com`        → ["default","nivx-live"]  (owner-approved)
  - `p0a-approver@nivxray.com` → ["default"]
  - `approver@nivxray.com`     → ["default"]
  - `a05-admin-37051a53@nivxray.test` → UNTOUCHED (no tenant_ids)
- Proof: users total 76 before/after; no other principal's `tenant_ids`
  changed; role/tenant_id/password untouched (all three still log in 200);
  the ~40 fixture tenants were NOT granted.
- AUTHORITY_CODE_CHANGED = NO, FRONTEND_CHANGED = NO, TESTS_CHANGED = NO.
  Legacy role→all_tenants breadth therefore still exists (a cross-tenant probe
  to the fixture tenant `probe-t-00bf71` still returns 200) — expected until
  Fix 6B-2 removes the inference.
- NEXT (Fix 6B-2, bounded): grants-first `resolve_tenant_scope()` /
  `authorize_requested_tenant()`, retire `_CROSS_TENANT_ROLES` inference,
  grant-derived `authorized_count`, `TENANT_CONTEXT_SWITCHED` audit via the
  existing `xdr_audit_log`; role-only-admin FIXTURES (starting with
  `tests/test_a05_tenant_scope_contract.py`) seed their own explicit
  tenant_ids then. Picker-from-grants UI comes after 6B-2.
- PERMANENT REQUIREMENT (unchanged): immediately after Tenant Authority
  closes, return to the Cisco Secure Endpoint / AMP Device Trajectory
  operational-clone target — process lifelines, parent/child relationships,
  time-based trajectory, attached DNS/network/file/registry activity,
  detection markers, before/after navigation, event/detection focus,
  search/filter/MATCH navigation, smooth zoom/pan/scroll, evidence/raw/
  provenance inspection and the real analyst investigation workflow, on real
  NivXForge evidence.
## 2026-06 · FIX 6B-2 DESIGN AMENDMENT (authority classes) — design only
- OWNER DECISION: `admin@nivxray.com` is the initial NIVX PLATFORM SUPER ADMIN
  by EXPLICIT designation — never inferred from `role == admin`. Three classes:
  CUSTOMER USER/ANALYST, CUSTOMER ADMIN (admin rights only inside granted
  customers), NIVX PLATFORM SUPER ADMIN (platform scope).
- CODE_CHANGED = NO, DATA_CHANGED = NO. Full design:
  `memory/production-gates/FIX6B2_AUTHORITY_SCOPE_DESIGN.md`.
- Proposed representation: ONE additive field `users.authority_scope ∈
  {CUSTOMER, PLATFORM}`, absent ⇒ CUSTOMER. No is_super_admin/superuser/
  global_access/persisted all_tenants. Never inferred from role, tenants.read,
  organization.kind, tenant_ids length, picker or X-Tenant-Id. Unsettable from
  the browser (the ONLY `users` write in the backend is the password change at
  `routers/auth.py:81`; the principal doc is re-read per request).
- `tenant_ids[]` stays the CUSTOMER breadth and is NEVER filled with the
  registry; admin keeps ["default","nivx-live"] as stated operational context.
- Fix 6B-2 plan: delete `_CROSS_TENANT_ROLES`; `all_tenants` kept as a value
  DERIVED only from PLATFORM scope so the 4 existing consumers (incl. the
  deferred G6-7 `xdr_rbac.authorize_tenant`) need no change; grant-derived
  `authorized_count`; `TENANT_CONTEXT_SWITCHED` audit emitted from the small
  `POST /api/edr/session/active-tenant`; refusal auditing untouched.
- ORDERING RULE: Fix 6B-1b (write `authority_scope: "PLATFORM"` on
  admin@nivxray.com only) MUST land BEFORE the 6B-2 enforcement flip, or the
  owner account degrades to CUSTOMER scope.
- A05 + other role-only-admin FIXTURES seed their own `authority_scope`/
  `tenant_ids` during 6B-2; the CUSTOMER-admin refusal case
  (grants [default,nivx-live] → probe-t-00bf71 REFUSED) is proven with a
  hermetic stubbed principal, no new live credential.
- RECORDED, NOT BUILT: a PLATFORM Super Admin must eventually land on the
  NIVX SUPER ADMIN CONTROL CENTER (cross-customer tenants/health/EDR/XDR/
  endpoints/sensor/telemetry/detections/integrations/pipeline/policy/service/
  deployment/authority-failure/audit/drill-down/controls, evidence-backed
  only, explicit UNKNOWN where telemetry is absent) — NOT an expanded customer
  picker, and NOT before Device Trajectory.
- OPEN QUESTIONS: PLATFORM `authorized_count` = ACTIVE registered tenants?
  rename `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` now or later? explicit
  `"CUSTOMER"` on the approver accounts? confirm 6B-1b ordering.
- PERMANENT REQUIREMENT (unchanged): immediately after Tenant Authority
  closes, return to the Cisco Secure Endpoint / AMP Device Trajectory
  operational-clone target on real NivXForge evidence.
## 2026-06 · P0 TENANT AUTHORITY — FIX 6B-1b DONE (PLATFORM designation only)
- OWNER DECISIONS recorded: (1) PLATFORM `authorized_count` = tenants that are
  ACTIVE under an ACTIVE organization, informational ONLY — it never grants
  authority; (2) the six locked `SCOPE_BASES` stay unchanged in 6B-2, the
  `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` rename is CLEANUP DEBT for after the
  gate closes; (3) do NOT write `"CUSTOMER"` anywhere — absent/null/malformed
  ⇒ CUSTOMER is the least-authority default and PLATFORM stays exceptional and
  explicit; (4) 6B-1b runs as its own micro-step before 6B-2.
- `/app/scripts/fix6b1b_platform_designation.py` (idempotent; refuses unless
  the Fix 6B-1 grants are present and unchanged) wrote ONE field on ONE
  principal: `admin@nivxray.com` → `authority_scope: "PLATFORM"`.
- Proof: `tenant_ids` still ["default","nivx-live"]; role `admin` unchanged; no
  other field on the document changed; `authority_scope` holders = exactly
  {admin@nivxray.com: PLATFORM} across all 76 users; login 200 and
  `/api/edr/endpoints` (X-Tenant-Id: default) 200.
- CODE_CHANGED = NO (script only, no product code). Enforcement untouched —
  session-context still reports the legacy role-derived
  `all_tenants:true / tenant_ids:[]` with basis
  `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`, which is exactly the pre-6B-2
  baseline.
- NEXT: Fix 6B-2 enforcement (grants-first + `authority_scope`), then the
  audited switch, then picker-from-grants. PERMANENT REQUIREMENT unchanged:
  immediately after Tenant Authority closes, return to the Cisco Secure
  Endpoint / AMP Device Trajectory operational-clone target on real NivXForge
  evidence.
## 2026-06 · P0 TENANT AUTHORITY — FIX 6B-2 DONE (grants-first + PLATFORM scope + switch audit)
- `services/dashboard_lenses.py`: `_CROSS_TENANT_ROLES` DELETED as authority
  (retained only as the documentation constant
  `_LEGACY_ROLE_BREADTH_RETIRED`, read by no decision). New
  `authority_scope(user)` → PLATFORM iff the stored string is exactly
  "PLATFORM"; absent/null/"CUSTOMER"/"platform"/"platform_admin"/True/1/
  lists/dicts ⇒ CUSTOMER. `resolve_tenant_scope()` now returns
  `{authority_scope, all_tenants(=PLATFORM only), tenant_ids(=grants), role}`.
- `services/session_context.py`: breadth source is scope+grants (refusal codes
  and Fix 2 non-disclosure untouched); new `_authorized_universe()` makes
  `authorized_count` AUTHORITY-derived — CUSTOMER = grants that survive
  `authoritative_required()`, PLATFORM = tenants ACTIVE under an ACTIVE org
  (informational only, fail-closed to 0 on registry failure);
  `tenant_context()` now publishes `tenant_scope.authority_scope`.
- `routers/edr_session.py` (NEW, ~90 lines) + `server.py` wiring:
  `POST /api/edr/session/active-tenant`, authority via `Depends(edr_tenant)`,
  writes `TENANT_CONTEXT_SWITCHED` to the existing `xdr_audit_log` chain with
  principal, authority_scope, before/after tenant, basis, requested tenant,
  correlation_id and outcome. Previous context is read back from the audit
  chain (no new store); when unknown it records `NOT_AVAILABLE` rather than
  inventing it. A repeat of the same context writes nothing
  (`switch_recorded:false, reason:NO_CONTEXT_CHANGE`).
- FIXTURE REPAIRS (test-only, intent preserved, no live grant used):
  `test_a05_tenant_scope_contract.py` (U_ADMIN seeded
  `authority_scope:PLATFORM`; T_ACME/T_CONTOSO adopted into the registry so a
  PLATFORM universe can report them), `test_p01_response_evidence_write_
  tenant_authority.py`, `test_p0_response_execution_tenant_scope.py`,
  `test_s1_incident_subresource_authz.py` (each replaced the hardcoded
  `admin@nivxray.com` cross-tenant principal with its own prefixed PLATFORM
  fixture principal).
- TESTS: new `tests/edr/test_p0_tenant_authority_fix6b2.py` (A–X, 40 cases) →
  focused batch **215 passed, 0 failed**; `test_a05_tenant_scope_contract.py`
  **72 passed** (was 5 failed).
- LIVE PREVIEW: admin@nivxray.com → `authority_scope: PLATFORM` (not role),
  default + nivx-live 200, no header = 403 TENANT_REQUIRED (never "default"),
  switch nivx-live→default audited (2 rows, chained), repeat = NO_CONTEXT_
  CHANGE, unregistered tenant refused. `p0a-approver@` and `approver@` are now
  CUSTOMER/["default"]: default 200, nivx-live 403, probe-t-00bf71 403 (they
  previously had role-derived access to everything). Frontend untouched, login
  page smoke-verified.
- NOTE: `probe-t-00bf71` now returns 200 for admin because it is a REGISTERED
  ACTIVE tenant and admin is legitimately PLATFORM; the CUSTOMER-admin refusal
  of an ungranted tenant is proven hermetically (cases B/E/I), never with the
  live PLATFORM account.
- CLEANUP DEBT: `SCOPE_BASES` still says `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`
  for a PLATFORM principal (owner-decided rename after the gate closes);
  G6-7 `xdr_rbac.authorize_tenant` parity still deferred.
- NEXT: Picker From Grants (UI reflects grants/PLATFORM), then remaining
  closure items (live zero-tenant cell). PERMANENT REQUIREMENT unchanged:
  immediately after Tenant Authority closes, return to the Cisco Secure
  Endpoint / AMP Device Trajectory operational-clone target on real NivXForge
  evidence.
## 2026-06 · PICKER FROM GRANTS DONE (UI reflects the 6B-2 authority model)
- `services/session_context.py`: new `authorized_customers(email)` +
  `session-context.authorized_customers[]` — AUTHORITY-derived (CUSTOMER =
  registry-validated `tenant_ids[]`; PLATFORM = authoritative ACTIVE tenants
  under ACTIVE orgs), with display_name/slug/kind. Evidence-derived
  `customers[]` is unchanged for the queue panels.
- `components/CustomerPicker.jsx`: REWIRED. No `GET /api/xdr/tenants`, no
  `api.get` at all, no localStorage/`?tenant=`/"default"/role strings in the
  component. List = `authorized_customers` prop. Selection calls the audited
  `POST /api/edr/session/active-tenant` FIRST and only persists locally after
  the server confirms; a refusal renders `nvf-customer-refusal` and changes
  nothing. PLATFORM principals get a `nvf-platform-badge` and the menu header
  `AUTHORITATIVE ACTIVE CUSTOMERS · PLATFORM AUTHORITY`.
- `tenantContext.js`: added `authorityScope()`, `isPlatformPrincipal()`,
  `authorizedCustomers()`; PLATFORM is read ONLY from
  `tenant_scope.authority_scope` (breadth ≠ designation). Fix 4A/4B control +
  content gates untouched.
- TESTS: new `src/lib/__tests__/pickerFromGrants.test.js` (A–J) →
  **vitest 39 passed** (15 new + 24 existing); backend focused
  **59 passed**.
- LIVE: single-grant approver → EDR opens on `default`, NO picker and NO
  "SELECT CUSTOMER" even with `?tenant=probe-t-00bf71` + stale
  `nvx_tenant=nivx-live`. PLATFORM admin → picker + PLATFORM badge, 136
  authorized customers offered (60 rendered, filter works), selecting
  nivx-live wrote `TENANT_CONTEXT_SWITCHED` (3 chained rows, source
  `nivxforge-edr`) and the header now reads "Preview Live Sources"; PLATFORM
  with nothing selected stays PLATFORM and shows an honest TENANT_REQUIRED
  banner instead of silently using `default`.
- STILL OPEN (assess whether these are real closure blockers): live
  zero-tenant cell, `SCOPE_BASES` terminology cleanup, G6-7 XDR parity.
- PERMANENT REQUIREMENT: Device Trajectory (Cisco Secure Endpoint / AMP
  operational clone — process lifelines, parent/child, attached activity,
  before/after navigation, search/filter, event/detection focus, evidence/raw/
  provenance inspection, process/activity/behavior trees, bidirectional
  pivots) resumes IMMEDIATELY once Tenant Authority closes.
## 2026-06 · P0 TENANT AUTHORITY — GATE CLOSED (assessment only, no code/data change)
- Full assessment: `memory/production-gates/TENANT_AUTHORITY_CLOSURE_ASSESSMENT.md`.
- DECISION: **TENANT_AUTHORITY_CLOSED**. 24 of 25 invariants (A–Y) PROVEN with
  cited hermetic + live evidence; Y (PLATFORM does not bypass RBAC/response
  approval) is PARTIALLY_PROVEN — separate layers, RBAC untouched by 6B-2,
  one focused case would close it. GENUINE_SECURITY_BLOCKERS: NONE.
- ZERO_TENANT_LIVE_CELL = ACCEPTABLE_DEFERRED_LIVE_PROOF (zero-grant behaviour
  proven in fix1/fix2/6B-2; the live cell is env-gated by P0-PROD-1, and five
  zero-grant principals ALREADY exist so it could be filled without creating a
  credential).
- BASIS_RENAME = NON_BLOCKING_CLEANUP (`CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`
  affects no decision, audit row, enumeration or UI authority; 9 files).
- NON_BLOCKING_DEBT: zero-tenant live cell, basis rename, G6-7 XDR parity,
  invariant-Y focused case, 3 stale `bob-sec003-*` zero-grant live rows with a
  test-constant password + 2 a05 residue rows (deletion needs approval),
  picker renders 60 of 136 authorized customers, no `users` schema validator.
- NEXT IMPLEMENTATION TASK (owner-approved): **DT2-3 — VISIBLE DEVICE
  TRAJECTORY RELATIONSHIPS** (Cisco Secure Endpoint / AMP operational clone):
  horizontal time, process lifelines, parent/child rendering, attached DNS /
  NETWORK / FILE / REGISTRY activity, detection markers where real evidence
  exists, process selection, parent/child + before/after navigation, exact
  event/detection focus, evidence-backed WHY/basis, and NO invented
  relationships / process exits / activity. Trajectory Inspector follows as
  its own step; NIVX SUPER ADMIN CONTROL CENTER stays parked.
- Final manual acceptance identities to keep: PLATFORM Super Admin, Customer
  Admin, Customer Analyst, preferably a second-customer Analyst.
## 2026-06 · DT2-3 DONE — VISIBLE DEVICE TRAJECTORY RELATIONSHIPS
- Backend (additive, 1 hunk): `routers/edr.py` now serves the DT2-2E render
  contract at `dt2.graph` on `GET /api/edr/endpoints/{id}/trajectory`
  (process_nodes, activity_nodes, edges, root_node_ids, order, navigation,
  availability, ranges, focus). V1 keys untouched; no second engine.
- Frontend: new `trajectory/dt2/graphModel.js` (pure selectors: lane order,
  lifelineOf, activitiesFor, parentOf/childrenOf, edgeFor, whyOf, stepsOf/
  neighbourStep, focusOf, familiesPresent) + new
  `trajectory/RelationshipCanvas.jsx` (+`RelationshipBasis` rail) +
  `EdrDeviceTrajectoryPage.jsx` mode toggle
  "PROCESS / RELATIONSHIP / TIME" (default) vs "EVENT LANES".
- Semantics enforced: dashed span = OBSERVED_EVIDENCE_SPAN (exit only drawn
  when `exit_observed`); a connector is drawn ONLY where `edgeFor()` finds a
  server edge; activity glyphs (DNS ▲ / NETWORK ■ / FILE ◆ / REGISTRY ●) plot
  at their OWN ordering_time on the owning process; BEFORE/AFTER walks
  `navigation.ordered_step_ids` and surfaces `link_to_previous`
  (CAUSALITY_UNKNOWN stays unknown); focus is exact or explicitly unresolved;
  lanes capped by `MAX_RENDERED_LANES` (120) and the canvas issues no requests.
- Tests: new `dt2/__tests__/graphModel.test.js` (A–T, 24 cases) → vitest
  **115 passed**; new `tests/edr/test_dt2_3_graph_read.py` (10) + DT2-0/1/2E +
  6B-2 → **165 passed**. `vite build` clean.
- LIVE (real Windows endpoint `dev_0e10780f2c86` / WS-W1-1789575060, tenant
  default): GRAPH_READY, **16 process lanes, 13 parent/child connectors, 1
  FILE activity**; selecting `certutil.exe` showed WHY =
  `CANONICAL_PARENT_PROCESS_IDENTITY · IDENTITY DOWNGRADED · 3 evidence refs`;
  AFTER → `CAUSALITY_UNKNOWN`; PARENT nav moved selection to
  `pnode:proc_86dd9e202435`. Families on THIS evidence: FILE OBSERVED, DNS /
  NETWORK / REGISTRY **NOT_OBSERVED** (not fabricated).
- Known gaps (honest): this corpus stamps every event at 2026-06-01T10:00:00Z
  so lifelines have no temporal spread (axis works, evidence is flat);
  detection markers not yet on the lane (separate step); Inspector (raw /
  provenance) is the next separate step.
- NEXT: Trajectory Inspector, then detection markers / remaining AMP
  interaction gaps, then process/activity/behavior trees + bidirectional
  pivots. Super Admin Control Center still parked.

---

## 2026-06 · DT2-3 UI CORRECTION — STRICT CISCO AMP PARITY AUDIT (owner-directed)

Owner reset the phase: **PHASE 1 = reproduce the publicly verifiable Cisco
Secure Endpoint / AMP Device Trajectory analyst experience.** No NivXForge
enhancements visible until parity is accepted. Engines are NOT to be weakened —
only the presentation is corrected, with removed controls parked behind a flag.

Owner-selected constraints for this step:
1. PARITY TABLE ONLY — zero UI / code / data changes.
2. Removed controls: hide from AMP-parity presentation only; keep
   engines/handlers intact behind a parked flag.
3. Inventory scope: Device Trajectory page + its Amp*/dt2 components only.
4. No Cisco reference found ⇒ `REFERENCE_BEHAVIOR_NOT_VERIFIED` ⇒ propose
   REMOVE (owner may grant explicit exceptions).
5. Exact Cisco doc/page/section URL required per row.

Delivered: `/app/memory/production-gates/DT2_3_AMP_PARITY_TABLE.md`
- 136 visible elements audited across 9 groups.
- KEEP 33 · CHANGE 25 · REMOVE 62 · MISSING_IN_NIVXFORGE 16 ·
  REFERENCE_BEHAVIOR_NOT_VERIFIED 62.
- Cisco source register C1–C11 (Secure Endpoint User Guide p.401–411 verbatim,
  UW–Madison KB 90059 console walkthrough, Cisco TechNotes 222850 / 218067,
  Cisco Live TACSEC-2012). C11 is **negative evidence**: click-to-zoom is
  documented for Mobile App Trajectory, NOT Device Trajectory — so Zoom in /
  Zoom out are not parity controls.
- 7 ambiguous items escalated for owner decision (navigator +/- collapse
  reference, evidence-integrity messaging, tenant-boundary prose, theme toggle,
  disposition values, DNS/REGISTRY families, files-as-vertical-axis-rows).

STATUS: **BLOCKED ON OWNER LINE-BY-LINE REVIEW.** No UI work begins until the
table is approved. `git status` confirms the only change is the new document.

Backlog unchanged and still parked: DT2-4 Evidence Inspector V2, DT2-5
structured search + MATCH navigation, DT2-6 detection navigation, DT2-7
investigation pivots, DT2-8 virtualization/performance, DT2-9 analyst
acceptance, P2 wider Windows event coverage, P2 full investigation surface,
P2 Super Admin Control Center. All NivXForge-only trajectory surfaces move to
**PHASE 2 — NIVXFORGE ENHANCEMENTS** (post-parity).

### REV 2 amendment (same day) — owner navigator ruling accepted, two new Cisco sources
- Owner's citation verified verbatim: C12 = AMP for Endpoints User Guide p.171
  "The Navigator" — *"You can collapse the navigator by clicking the - button
  and expand it again by clicking on the ribbon or the + button."* Row #35
  reclassified DOCUMENTED, REMOVE → CHANGE. Trajectory Zoom In/Out (#36/#37/#62)
  stay REMOVE (C11 negative evidence). The two interactions are NOT conflated.
- C12 also establishes: 30-day upper ribbon, miniature line graph above it,
  RED DOTS = compromise events, SEARCH RESULTS = BLUE DOTS, dot size relative to
  events per day, 24-hour ribbon = selected day.
- C13 = current Secure Endpoint User Guide p.405 "Trajectory Indications of
  Compromise" — yellow highlighting of IOC events, a separate compromise event,
  BLUE HALO on the triggering events when clicked, and *"A description of the
  indicator and the tactics and techniques will also be displayed in the Event
  Details pane"*. This REVERSED row #115 (MITRE box): REMOVE → CHANGE, DOCUMENTED.
- New Group J (all MISSING): #137 yellow IOC highlighting · #138 separate
  compromise event · #139 blue halo · #140 search results as blue dots.
- REV 2 totals: 140 audited · KEEP 33 · CHANGE 27 · REMOVE 60 · MISSING 20 ·
  NOT_VERIFIED 60.
- Delivered additionally: DAY_TIME_NAVIGATOR_BEHAVIOR_MATRIX (N1–N11 — navigator
  is NOT a clone: 1 conforming, 4 partial, 2 non-conforming, 2 missing,
  1 conflicted) and the seven escalated ambiguities written out individually.
- NEW AMBIGUITY #8: the line graph above the dates has two conflicting Cisco
  definitions — cloud queries per day (C3 p.403) vs level of activity (C12
  p.171). NivXForge does not collect cloud-query volume.
- STATUS: still BLOCKED. CODE/UI/DATA unchanged; no Phase-2 flag designed.
  Awaiting owner rulings on ambiguities 2–7 and new #8.

### REV 3 (same day) — owner rulings recorded; DT2-3a BLOCKED on reference screenshots
- All 8 rulings recorded in the parity doc (#2 remove engineering wording,
  #3 remove tenant prose, #4 theme toggle OUT OF SCOPE, #5 disposition with
  no-falsification constraint, #6 DNS/REGISTRY preserved but not presented as
  Cisco parity, #7 files-on-axis = DT2-3b IN SCOPE, #8 hide the cloud-query
  line graph and record the data gap). Sequence fixed: DT2-3a → DT2-3b → DT2-3c.
- Owner adopted a SCREENSHOT EVIDENCE RULE: owner-supplied Cisco AMP screenshots
  are the PRIMARY visual reference and outrank prose. Anything visible in them
  is SCREENSHOT_VERIFIED. Therefore all 60 REFERENCE_BEHAVIOR_NOT_VERIFIED rows
  must be re-tested against those screenshots BEFORE anything is hidden.
- BLOCKER: the 1,660 job artifacts are mostly NivXForge captures with opaque
  names. Eight best Cisco-looking candidates were inspected: they are Cisco XDR,
  Cortex XDR, MS Defender (x2), SentinelOne, Elastic and one NivXray page — NOT
  AMP Device Trajectory. Proceeding would risk cloning the wrong product.
- ACTION REQUIRED FROM OWNER: identify the Cisco Device Trajectory screenshots
  by artifact URL / filename / re-attach. Then: region comparison A–Q → re-test
  the 60 rows → one DT2-3a pass.
- CODE/UI/DATA unchanged. No Phase-2 flag. No deletions.

### REV 4 (same day) — Cisco screenshot reference set ESTABLISHED; DT2-3a re-scoped, not executed
- The four owner ServiceNow URLs are behind Cisco SSO: REFERENCE ARTIFACT NOT
  ACCESSIBLE (auth_redirect → id.cisco.com SAML). Owner-authorised fallback used.
- Extracted Cisco's OWN figures from the official Secure Endpoint User Guide PDF
  and stored them: /app/memory/production-gates/cisco_ref/
  CISCO_DT_FULL_PAGE_p402.png (the complete Device Trajectory page),
  CISCO_DT_NAVIGATOR_p403.png, CISCO_DT_DEVICE_DETAILS_p404.png,
  CISCO_DT_IOC_TEXT_p405.png. No other vendor's screenshot used as evidence.
- A–Q comparison done: MISMATCH 7, PARTIAL 6, MISSING 1, NOT OBSERVED 3, MATCH 0.
  Header must be the DEVICE NAME + Show details + Actions + Inbox status + share
  + expand; search LEFT / Filters RIGHT; navigator = blue line + in-cell sized
  red dots + filled 24h band; gutter = right-aligned labels with [PE] type tag,
  pink highlight for malicious, System / Files & Network section headers; green
  lifeline with square glyphs; Activity pane has NO count and NO time column;
  and Cisco has NO trajectory toolbar at all.
- 60-row retest: 5 reclassified (fullscreen icon KEEP, [rowTag] CHANGE, navigator
  chevron CHANGE, triangle handles downgraded to REMOVE, compromise-events count
  relocated to the drawer); 55 remain NOT_VERIFIED; 1 excluded (theme).
  New totals: KEEP 34 / CHANGE 30 / REMOVE 55 / MISSING 20 / EXCLUDED 1.
- DT2-3a deliberately NOT executed: the retest re-scoped it, and running the old
  plan would have cloned the wrong layout. CODE/UI/DATA unchanged.
- NEXT: one DT2-3a pass on the corrected plan; acceptance on WS-W1-1789575060 /
  dev_0e10780f2c86 with real evidence only.

### DT2-3a EXECUTED (same day) — AMP-parity presentation correction, live
- 8 files changed: AmpFilterBar / AmpNavigator / RelationshipCanvas /
  AmpComputerHeader rewritten; AmpActivityPanel / AmpEventDetails /
  EdrDeviceTrajectoryPage edited; graphModel.test.js retargeted.
- Applied: KEEP 34 preserved · CHANGE 24 implemented · REMOVE 55 hidden behind
  `PARKED_NIVXFORGE_UI` (nothing deleted) · MISSING 3 implemented (Share > Copy
  URL, Copy SHA-256 ×2) · 5 deferred to DT2-3b · 4 deferred to DT2-3c.
- Header is now the DEVICE NAME + Show details + Actions + share + expand.
  Search LEFT / Filters RIGHT with Enter-to-submit. Navigator: day cells with
  sized red compromise dots, plain filled 24h band, `−`/`+` collapse and
  ribbon-click expand. Graph: Timeline gutter, date columns, rotated ticks,
  `Files & Network` section, right-aligned labels with `[PE]`, solid green
  lifelines, square glyphs. Activity pane: no count, no time column, ⚠ prefix.
  Toolbar, mode tabs, basis rail, all banners and tenant prose: gone.
- A–Q after: MATCH 12 / PARTIAL 3 / MISMATCH 2 (was 0 / 6 / 7 + 1 missing).
- Tests: 118/118 pass (was 115; 7 old presentation assertions retargeted to the
  engine or inverted into parity guards, 3 new parity tests added).
- Live acceptance: WS-W1-1789575060 / dev_0e10780f2c86, customer `default`,
  16 lanes, 15 activity rows, 1 compromise dot, 0 page errors. One crash found
  and fixed during acceptance (`Prop` title on explicit null).
- Truthful data gaps recorded, incl. CISCO FEATURE DATA SOURCE NOT AVAILABLE IN
  NIVXFORGE for the cloud-query line graph (omitted, not substituted).
- Reference figures kept at /app/memory/production-gates/cisco_ref/ as INTERNAL
  ENGINEERING REFERENCE ONLY — never bundled, served or shipped.
- STOPPED for owner visual review. DT2-3b / DT2-3c not started. No deployment.

### DT2-3a VISUAL REVIEW (same day) — 9 new visual defects found, nothing changed
- Built the side-by-side (Cisco p.402 figure above, live DT2-3a capture below):
  /app/memory/production-gates/cisco_ref/DT2_3A_SIDE_BY_SIDE.png (internal only).
- 19 elements ruled individually: 13 RESEMBLE, 5 PARTIAL, 1 NOT PRESENT (System).
- Five recorded differences ruled: #1 files→DT2-3b, #2 IOC→DT2-3c, #3 cloud-query
  line CLOSED BY OWNER RULING (no substitution; blue search dots move to
  DT2-3a.1), #4 filters→DT2-3a.1, #5 graph width RESOLVED.
- NEW defects F1–F9 found only by looking at the figure: Actions must be a
  FILLED blue primary; Filters must be a borderless blue text control with a
  filter glyph; navigator collapse belongs at the LEFT of the ribbon; section
  labels need Cisco weight/alignment and System must always show; time ticks are
  EVENT-ANCHORED plus hour marks, not 6 evenly spaced; graph scrollbars need
  ◀ ▶ / ▲ ▼ arrow buttons; graph card must size to content; the 24h window
  region should be a narrow sub-range; and the Cisco reference console is LIGHT
  while we default to dark.
- OWNER DECISIONS PENDING: F4 (permanent empty System band), F8 (narrower
  default window), F9 (light theme for parity review).
- Sequence fixed: close DT2-3a visual defects → DT2-3a.1 filters/search →
  DT2-3b files/process → visual review → DT2-3c IOC.
- CODE/UI/DATA unchanged in this step.

### DT2-3a(F1–F9) + 3a.1 + 3b + 3c EXECUTED (same day)
- Tests 122/122. Files: AmpComputerHeader, AmpFilterBar, AmpNavigator,
  RelationshipCanvas, AmpEventDetails, EdrDeviceTrajectoryPage, dt2/graphModel,
  graphModel.test.
- F1 filled Actions · F2 borderless Filters+glyph · F3 collapse left of ribbon ·
  F4 permanent Timeline/System/Files&Network (Cisco weight, centred) · F5
  event-anchored ticks + hour marks · F6 ▲▼ ◀▶ + return-to-row/event · F7
  content-sized graph · F8 evidence-bearing default window (no timestamps moved)
  · F9 light Cisco surface by default (dark still wins if chosen).
- 3a.1: five Cisco filter categories, one-per-category rule, Apply Filters,
  at:<timestamp> grammar, blue search-result dots. No CLEAN/flags/file-type
  values manufactured.
- 3b: axisRowsOf promotes FILE artefacts to first-class rows ONLY with canonical
  FILE evidence + the server process→artefact edge. Live: certutil.exe →
  C:\Users\Public\payload.exe file row with a real PROCESS_FILE stem (1 file
  row, 13 process stems, 17 rows).
- 3c: PARTIAL/BLOCKED. dt2.graph activity_nodes carry NO disposition/detection
  and no indicator contributor set, so yellow highlighting, the separate
  compromise event and the blue halo cannot be drawn truthfully. Wired but inert
  (isCompromise, dt2-ioc-mark-*). TO UNBLOCK: publish disposition/detection and
  the indicator's contributor evidence_refs on activity nodes in projection.py.
- Final A–Q: MATCH 14 / PARTIAL 2 / MISMATCH 1. Zero engineering-language leaks.
  Tenant isolation demonstrated. 0 page errors. Not deployed.
- Side-by-side: cisco_ref/DT2_FINAL_SIDE_BY_SIDE.png

### DT2-3a.2 · TIME DOMAIN / VIEWPORT PROJECTION (BLOCKER, same day)
- Owner rejected the vertical "comb". Root cause split proven:
  (1) primary viewport was the whole selected day (86.4M ms) while the evidence
      span is 0 ms → FIXED with `evidenceWindow()` (120 000 ms window here),
      viewport-derived ticks, and `rowsInWindow()` row relevance.
  (2) projection was NOT broken: rendered X = 238 + ((t−t0)/(t1−t0))×1000 =
      738.00 for every event, verified against the live DOM.
- NEW BLOCKER `TELEMETRY_TIMESTAMP_COLLAPSE`: all 15 observations of
  dev_0e10780f2c86 carry one identical timestamp (10:00:00Z, seq 0–14); no
  per-event UtcTime survives ingestion. Horizontal progression is impossible
  without fabricating time. Needs a collector/normalizer fix.
- Unknown process ×3: parent identity exists in the child's evidence
  (`event.process.parent_name = explorer.exe`) but dt2-2a does not propagate it.
- Acceptance record: memory/production-gates/DT2_3_CISCO_CLONE_ACCEPTANCE.md
- Tests 137/137 (122 + 15 new). DT2-3b/3c remain BLOCKED per owner ruling.

---

## 2026-09-29 · DT2-3a.2 CLOSED · DT2-3b SEMANTICS + CISCO PARITY (A-D)

Acceptance corpus switched to the REAL Windows corpus
`dev_2adbb41a04a4` / DESKTOP-A9HGFJJ (tenant `ten_f1a5479243e901cf159e230fa0`),
3298 genuine Sysmon/Security observations, 15:43-16:46 UTC on 2026-09-22.

**CORRECTION to the previous entry.** The claim *"NEW BLOCKER
TELEMETRY_TIMESTAMP_COLLAPSE — no per-event UtcTime survives ingestion, needs a
collector/normalizer fix"* is **WRONG**. Provenance traced end to end: the W1
harness `scripts/p0_w1_sysmon_onboarding_proof.py:132` hardcodes
`"UtcTime": "2026-06-01T10:00:00Z"` for all 15 records and the pipeline
preserved it exactly. Classified `SINGLE_INSTANT_SYNTHETIC_ACCEPTANCE_FIXTURE`.
No timestamp-collapse defect exists.

Delivered:
- **DT2-3a.2 CLOSED** — timestamp→X proven to 0.00 px on live DOM.
- **`TS_LEXICOGRAPHIC_WINDOW_EXCLUSION` fixed** (P0 correctness). `query_window`
  compared timestamps as STRINGS, so all 3333 genuine Sysmon observations
  (`2026-09-22 15:43:31.770` < `…T…Z`) were excluded from every windowed read.
  Now parsed instants (`edr_plane/instant.py`) for inclusion, sorting and cursor
  paging; new ingestion writes RFC 3339; **no backfill, evidence byte-identical**.
- **Lane axis grouped** — each file/network/dns lane now follows the process
  lane its own evidence names (`actor_process_iid`), so a windowed client can
  hold a process with its artefacts and render process→file stems.
- **Client instant parser** (`dt2/instant.js`) — `Date.parse` was reading
  Sysmon's space form as the analyst's LOCAL time.
- **Cisco file-type display rule** (`dt2/fileType.js`, TAC 118711 + p.401) —
  removed the `.ldb/.tmp/.log` explosion; `Other` restores it, nothing deleted.
- **Repeat-event suppression** (p.401 cache) — projection-layer only, labelled
  `+N suppressed`, reversible; fails to NO suppression where the disposition
  rule is undocumented (this corpus: 0 suppressed).
- **Process de-selection** — sixth filter category; no re-parenting.
- **Compromise navigation** — `compromise_authority` gate removed a
  FABRICATION: 3102 Sysmon registry events carried `kind=detection` and were
  drawing navigator compromise markers.

Records: `DT2_3A2_LIVE_RENDER_PROOF.md`, `DT2_3A2_TIMESTAMP_PROVENANCE.md`,
`DT2_3B_BLOCKER_TS_LEXICOGRAPHIC_WINDOW.md`, `DT2_3B_PROCESS_FILE_PROOF.md`,
`DT2_3B_CISCO_VISUAL_PARITY.md`, `CISCO_AMP_TRAJECTORY_ENGINEERING.md`,
`DT2_3B_CISCO_SEMANTICS.md`, `DT2_PARITY_BACKLOG.md`.

**NEXT: DT2-3c** (IOC parity). Blue halo blocked on
`IOC_CONTRIBUTOR_PROVENANCE = MISSING`. P1 backlog: file content identity,
file size, execution context, connector lifecycle telemetry, IOC contributor
contract, SHA-based process/file identity, sysmon registry `kind` defect.
P2: trajectory API parity. No production deployment.


## 2026-06 · STEP 1 DONE — EVENT ID PROPAGATION + INGESTION FALLBACK AUDIT
- Owner-approved scope: Step 1 ONLY (read-only diagnostic first,
  audit-and-fix ingestion/canonicalization only, existing 3,100+ records
  untouched, focused pytest + written report, then STOP).
- FIRST LOSS BOUNDARY = `v2/ingestion/telemetry_bridge.py::canonical_to_ces`,
  NOT the collector. Two canonical dialects funnel through it and only one
  was understood: the EDR sensor bridge (`additional_fields.winlog.event_id`,
  `registry.key`) vs the XDR DSM plane (`source_event_id`,
  `raw_ref.sysmon_event_id`, `RegistryEntity.key_path/target_object`). Every
  DSM-normalised record therefore reached the CES with `event_id=None` AND
  `registry_key=""`, so neither the authoritative branch nor the registry
  heuristic could fire and the catch-all took over — 3,120 Sysmon registry
  observations stamped `kind=detection`.
- FIX (forward-only, 2 product files): `source_event_id()` resolves the
  authoritative Event ID across both dialects in declared precedence and
  reports its origin; `channel` and `registry_key` likewise; one strict
  lossless coercion `canonical.event_id_int()` accepts `12`/`"12"` and
  REFUSES bool/float/hex/`"12abc"`/empty; `resolve_kind()` now returns
  `(kind, basis)` and stamps `provenance.kind_basis`
  (SOURCE_EVENT_ID / EVENT_ID_NOT_SUPPORTED / DERIVED_FROM_OBSERVED_FIELDS /
  UNCLASSIFIED_INSUFFICIENT_EVIDENCE); `raw_event.source_identity` preserves
  provider/channel/event_id/verbatim source value/record_id/computer/
  source_time so the projection stays traceable to the source observation.
- PERMANENT INVARIANT pinned: `SECURITY_CLAIM_KINDS` + a parametrised test —
  unknown/unclassified/unsupported/missing/malformed/parse-failure input can
  NEVER resolve to detection/malicious/ioc/compromise/clean/benign/blocked/
  contained/verified/alert.
- TESTS: new `tests/edr/test_event_id_propagation.py` **97 passed**; targeted
  regression 125 passed; whole `tests/edr` 1174 passed / 3 skipped / 7 failed
  where all 7 are PRE-EXISTING (6 reproduce at HEAD with the patch stashed;
  1 is a live-DB xdist flake that passes in isolation). Zero new ruff findings.
- EXISTING_3100_MUTATED = NO · DATA_CHANGED = NO · DEPLOYED = NO.
- FLAGGED FOR OWNER, NOT CHANGED: (a) `WINSEC_KIND` maps 4720/4732/4738
  (account created/member added/account changed) straight to
  `kind="detection"` from KNOWN input — ordinary account-management telemetry
  presented as a detection; (b) consequently the winsec provider gate is NOT
  extended to the DSM dialect's `"Windows Security Log"` product string
  (7 historical records), because doing so would immediately start minting
  those detections; (c) `trajectory_window.py` still reads
  `kind == "detection"` as a claim (compromise marker already gated behind
  `compromise_authority`).
- Report: `memory/production-gates/EVENT_ID_PROPAGATION_AND_FALLBACK_AUDIT.md`
- NEXT (needs owner authorisation, in this order): Step 2 clean re-projection
  of the retained raw G1 evidence into a NEW acceptance tenant/device →
  IOC contributor contract (`compromise_event.contributing_event_refs[]`) →
  DT2-3c IOC visual parity → final Cisco trajectory parity → Endpoint Engine
  Foundation. Owner must also rule on flagged item (a) to unblock (b).

## 2026-06 · WINSEC SEMANTICS + CLEAN REPROJECTION + CONTRIBUTOR CONTRACT
- Owner ruling executed in order: Account Event Ruling -> Clean Reprojection
  -> Contributor Contract. Classification Audit View recorded as a
  non-blocking backlog feature, NOT built. DT2-3c NOT started.
- WINSEC SEMANTIC AUDIT (all 17 entries reviewed; 7 changed, 6 of those were
  a security claim or a factual error): 4720 -> `user_account_created`,
  4732 -> `security_group_member_added`, 4738 -> `user_account_changed`
  (were all `detection`); 4672 -> `special_privileges_assigned` (was
  `privilege_escalation`); 1102 -> `audit_log_cleared` (was `alert`);
  4634 -> `logoff` (was `logon_success`); 4776 -> `credential_validation`
  (was `logon_success` — 4776 is logged for failures too); 4700 ->
  `scheduled_task_enabled` (was conflated with create); dead `"*"` catch-all
  key REMOVED. Names REUSED from the existing `windows_security_dsm`
  event_type vocabulary — no duplicate vocabulary.
- GOVERNANCE AMENDMENT: `v2/cem/v1/schema.py::EVENT_KINDS` 41 -> 50 (the new
  observation kinds + `unclassified_telemetry`, which the classifier already
  emitted while being absent from the locked enum); frozen count in
  `tests/test_v2_framework.py` amended deliberately. `_AUTH_KINDS` in
  `trajectory_window.py` + `trajectory/contract.py` gained
  `credential_validation`. Both lane maps already default to `system`.
- WINDOWS SECURITY PROVIDER GATE enabled on SOURCE evidence, never a display
  label: `source_provider()` resolves `winlog.provider` ->
  `raw_ref.System.Provider` -> `raw_ref.provider` -> privileged channel
  (Security / Sysmon Operational) -> and only then the vendor+product label,
  explicitly marked `VENDOR_PRODUCT_LABEL`. On the reprojected corpus 3,299
  of 3,299 resolved from a SOURCE-STATED provider; 0 fell back to the label.
  Also fixed: the Sysmon parser/normalizer discarded the record's own
  `Provider` and `EventRecordID`; both are now carried in `raw_ref`, so
  `source_identity.record_id` is populated on 3,299/3,299 rows.
- CLEAN REPROJECTION DONE via `/app/scripts/g1_clean_reprojection.py`.
  Replayed the BYTE-PRESERVED raw Windows Event XML retained in
  `xdr_canonical_events` (reached through each evidence document's own
  `provenance.ingest.raw_envelope_ref`) through the same decoder and the DSM
  named by the RECORDED routing decision (never re-resolved by content) into
  a NEW tenant `ten_3f7f772b353a6bbbb0ac8bc564` (slug `g1-acceptance-clean`,
  LAB, same ACTIVE org) and a NEW device identity `dev_f4b3fb82d7f3` (the
  source computer name is preserved verbatim; only the identity SCOPE is
  new). 3,299 replayable, 0 failures, 3,299 written.
  RESULT: 100% classified from a SOURCE-STATED Event ID —
  registry_value_set 2335 (Sysmon 13), registry_create 766 (Sysmon 12),
  file_create 107, network_connect 70, process_create 16,
  special_privileges_assigned 2 (4672), logon_success 2 (4624), dns_query 1.
  3,102 `detection` -> 0. UNCLASSIFIED_TO_DETECTION = 0,
  UNKNOWN_TO_SECURITY_CLAIM = 0, FALSE_COMPROMISE_FROM_CANONICAL_KIND = 0.
  OLD_CORPUS_MUTATED = NO (3298/3102 identical before and after).
  Every row carries a `reprojection` block including
  `detection_state: DETECTION_NOT_EVALUATED` ("NOT_EVALUATED is not CLEAN").
  4720/4732/4738 are proven by contract + a 17-case end-to-end test, NOT by
  the corpus — this host never emitted them in the G1 window (honest gap).
- CONTRIBUTOR CONTRACT DEFINED (not wired to any route, nothing persisted):
  `backend/edr_plane/compromise_contract.py` — compromise_event_id,
  indicator_id, authority, derivation_basis, description, tactics[],
  techniques[], contributing_event_refs[], evidence_refs[], observed_at,
  contributors_state. 3 authorities only (DETECTION_FABRIC_ATTRIBUTION,
  MITRE_ATTRIBUTED_EVIDENCE, IOC_CORRELATION_ENGINE); 19 FORBIDDEN_BASES
  rejected case-insensitively (temporal proximity, same PID, same lane, UI
  proximity, adjacent-in-render, inferred, guess...); contributor named by a
  different mechanism refused; raw dicts cannot be smuggled in; MITRE ids
  validated. Missing provenance stays missing via
  CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY, so DT2-3c's contributor emphasis is
  disabled BY DATA. Producers: `from_detection_derivation()` (only
  DETECTION_MATCHED; NO_MATCH and NOT_EVALUATED refused; contributors are
  exactly the subject observation + the derivation's own evidence_ids) and
  `from_mitre_attributed_evidence()` (proves exactly one contributor).
- TESTS: new `test_winsec_semantics.py` 87 + new
  `test_compromise_contributor_contract.py` 68 + `test_event_id_propagation`
  97; whole `tests/edr` 1316 passed / 3 skipped / 7 failed where all 7 are
  the SAME pre-existing failures proven at HEAD with the patch stashed.
  Zero new ruff findings. DEPLOYED = NO.
- Report: memory/production-gates/
  WINSEC_SEMANTICS_CLEAN_REPROJECTION_CONTRIBUTOR_CONTRACT.md
- OPEN FOR OWNER: (1) Sysmon proxy mappings — 255 -> `alert` is the last
  security-claim kind from a known Event ID (pinned by a shrink-only test);
  also 2/4/9/14/24/25 semantic proxies; (2) `event.iid` is a CONTENT hash and
  is NOT a unique observation identity (2,250 of 3,299 distinct records
  collide; the historical corpus shares this property); (3) go-ahead for
  DT2-3c and whether to wire the contributor contract into
  `GET /api/edr/endpoints/{id}/trajectory` first.

## 2026-06 · OBSERVATION IDENTITY · SYSMON RULING · CONTRACT WIRING · DT2-3c (PARTIAL)
- Owner order executed: Observation Identity -> Sysmon Proxy Ruling ->
  Contract Wiring -> DT2-3c. DT2-3c visual parity is NOT accepted yet.
- OBSERVATION IDENTITY: `event.iid` KEEPS its meaning as the CONTENT identity.
  New `observation_id` / `observation_identity_state` /
  `observation_identity_key` on every observation, from
  `canonical.observation_identity()`: tenant+device scoped, derived from
  authoritative source identity (provider|channel|computer|EventRecordID),
  else the STABLE retained raw row id. `canonical_event_id` is deliberately
  excluded (normalizers mint a fresh uuid4 per pass, so it cannot survive
  replay). No sequence counter is ever used for uniqueness; when the source
  carried nothing unique the state is `NOT_PROVEN_UNIQUE` and no uniqueness
  is claimed. `_event_iid` in trajectory_window now prefers it, and the DT2
  OBSERVATION evidence reference carries it.
  PROOF on the clean corpus: OBSERVATIONS 3299 / UNIQUE_OBSERVATION_IDS 3299
  / CONTENT_IID_COLLISIONS 2250 (1049 distinct content iids) / identity
  state 100% UNIQUE_BY_SOURCE_RECORD_IDENTITY / replay pass 2 wrote 0.
- SYSMON RULING (owner scope 255 + 2/4/9/14/24/25): 2 file_write ->
  `file_creation_time_changed`; 4 process_exit ->
  `sensor_service_state_changed`; 9 file_write -> `raw_disk_access_read`;
  14 registry_delete -> `registry_rename`; 24 file_write ->
  `clipboard_change`; 25 process_access -> `process_image_tampering`;
  255 `alert` -> `sensor_error`. NO Sysmon or WinSec Event ID now produces a
  security claim (both tables pinned by tests). EVENT_KINDS 50 -> 57 with
  lane mappings; the other 19 Sysmon ids were left untouched.
- CONTRACT WIRING: new `edr_compromise_events` + `edr_plane/compromise_store.py`.
  Only a validated `CompromiseEvent` can be persisted; every stored row is
  RE-VALIDATED through the contract on READ (a row written straight to Mongo
  with `SAME_PID` is rejected). `query_window` resolves
  `contributing_event_refs[]` against the projection's `observation_id`s and
  emits `compromise_events` + `compromise_contract`
  (`reference_identity=observation_id`, `resolved_server_side=true`,
  `frontend_may_infer_contributors=false`). Unresolvable ref -> explicit
  `UNRESOLVED_NOT_IN_PROJECTION`, never nearest-event substitution.
  Cross-tenant / cross-device -> never read.
- DT2-3c FRONTEND: `dt2/compromise.js` (no inference; `attachContributors`
  is an identity join on server-provided OBSERVATION refs), `isCompromise`
  (which inferred from detection flags and lit 3,100 rows) REPLACED by
  `isProvenContributor`, yellow IOC band + diamond marker,
  blue contributor halo, `AmpCompromisePanel` (indicator, description,
  authority, tactics, techniques, contributor/unresolved counts),
  Event Details "Indication of compromise" section, AmpCanvas bands now
  authoritative. Fixture: `scripts/dt2_3c_ioc_fixture.py`.
- PROVEN LIVE: fixture endpoint `ep_dt23cfixture01` renders 1 IOC band, 1
  marker, 3 blue halos at 3 DISTINCT X (each contributor's own timestamp and
  row); the content-identical TWIN is NOT emphasised. Real corpus returns
  `NO_AUTHORITATIVE_COMPROMISE_OBSERVED` — REAL_WINDOWS_COMPROMISE = NOT
  OBSERVED, which is not a clean claim.
- TESTS: backend `tests/edr` + framework + ingestion = 1438 passed / 3
  skipped / 9 failed, all 9 PRE-EXISTING (proven at HEAD with the patch
  stashed). Frontend vitest 189 passed (9 files). New suites:
  test_observation_identity (30), test_sysmon_semantics (56),
  test_contributor_contract_wiring (14, incl. the owner-required twin
  collision regression), dt2/__tests__/compromise.test.js (28).
- DT2-3c OPEN (owner review): (1) fixture has NO parent-process linkage so
  PROCESS_PROCESS edges = 0 and the causal story cannot be drawn —
  fixture gap, not a renderer gap; (2) compromise `observed_at` coincides
  with its subject contributor by fixture construction; (3) the yellow IOC
  geometry is a NIVXFORGE DESIGN DECISION, uncited against Cisco;
  (4) `?from=/?to=` deep-link time focusing is NOT honoured; (5) the four
  acceptance screenshots and the real-corpus DT2-3b regression pass are not
  done. Diagnostic: memory/production-gates/DT2_3C_GEOMETRY_DIAGNOSTIC.md
- FINDING: the endpoint resolver aliases on the physical computer name, so
  an acceptance endpoint for `DESKTOP-A9HGFJJ` merged the historical (3,298)
  and clean (3,299) corpora into one 6,597-row read. The projection is not
  tenant-scoped. I removed that misleading endpoint row rather than ship a
  merged view; the acceptance counts were proven directly from the store.

---

## 2026-09-29 · E1 EVIDENCE AUTHORITY = PASS · DT2 FROZEN · ENGINE-FIRST PROGRAM OPENED

Owner directive received: **engine-first**. Device Trajectory is now a
FROZEN consumer/projection. No cosmetic Cisco parity work until the
engine foundation reaches its gates. Not deployed.

### P0 · TRAJECTORY/EVIDENCE TENANT ISOLATION — CLOSED (was the blocker)
- Root cause: `services/edr/endpoint_query.endpoint_predicate()` keyed
  evidence reads on the ALIAS SET only, and `event.raw.computer` is not
  unique. Two customers both enrolling `DESKTOP-A9HGFJJ` produced ONE
  6,597-row read (3,298 + 3,299). Alias resolution was already
  tenant-constrained; the downstream evidence query was not.
- Fix: new `TENANT_PARTITIONED_STORES` (`v2_shadow_observations`,
  `edr_raw_events`, `edr_endpoints`) + `tenant_id=` kwarg. Predicate is
  now `{"$and":[{tenant}, {identity}]}` (the `$and` also stops a caller's
  own `$or` clobbering it). A partitioned store with NO tenant returns
  `_nivx_unresolved_tenant` — fail closed, never a cross-customer read
  and never a false-honest empty. `EndpointResolution.predicate()` takes
  the tenant from the AUTHORITATIVE resolved identity only, so an
  identity whose ownership failed closed (TENANT_CONFLICT / MISMATCH /
  UNATTRIBUTED_LEGACY) reads nothing.
- Call sites scoped: trajectory_window (5), response.py, xdr_search,
  edr_onboarding. Projection cache key now includes the tenant.
- LIVE PROOF: unscoped 6,597 → tenant A 3,298 / tenant B 3,299 /
  tenantless 0. Same hostname resolves to a DIFFERENT device per
  customer. Cross-tenant device id → `ENDPOINT_NOT_RESOLVED` (opaque).
- Tests: `tests/edr/test_trajectory_tenant_isolation.py` (32, A-K incl. a
  structural guard that no query site may address a partitioned store
  without a tenant). `test_p0_2c_alias_invariant.py` 2 cases retargeted
  (intent preserved, one new fail-closed case added).

### TWO FABRICATIONS REMOVED
1. Navigator compromise markers came from the per-observation
   `compromise_authority` classification: the clean corpus showed **70**
   compromise events for an endpoint whose contract says
   `NO_AUTHORITATIVE_COMPROMISE_OBSERVED`, while the fixture that holds a
   real one showed 0. New `_mark_compromises()` reads ONLY the
   contract-validated store. Marker and contract can no longer disagree.
   Test: `test_dt2_3c_compromise_marker_authority.py` (8, A-H).
2. `isRed()` painted red off a bare `is_detection` flag — 480/500
   historical rows are `kind=detection` + `UNKNOWN_NOT_ASSESSED`, so
   ordinary Sysmon telemetry rendered malicious. Now requires
   `ASSESSED_BY_DETECTION_FABRIC` or a MALICIOUS disposition. The red
   ATT&CK box is neutral when nothing is attributed.

### DT2-3c REV 2 (owner corrections, then FROZEN)
- Full-height yellow IOC column **REMOVED from strict parity** (it was an
  uncited NivXForge decision). Compromise is now a SEPARATE EVENT on its
  own `Compromise` band with a red marker, so it stays distinguishable
  from its contributors at the same instant — no timestamp altered.
- Surface switched to **DARK** (the owner's live Cisco console captures
  outrank the light User-Guide figure). Light palette retained.
- `?from=&to=` time focusing now HONOURED on first paint (proved exactly
  120,000 ms); auto-focus never overrides an explicit window.
- Fixture now AUTHORS parent-process evidence ⇒ explorer.exe →
  powershell.exe → updater.exe exists in evidence, drawn with
  `SYSMON_PARENT_PROCESS_GUID`, AUTHORITATIVE.
- Projection was DROPPING `parent_guid`/`parent_image`/`process_guid`;
  propagating them gave the REAL corpus 10 PROCESS_PROCESS + 7
  PROCESS_NETWORK + 1 PROCESS_DNS edges it had never shown.
- `LANE_PREFETCH` 14 → 90 (one row consumes many projection lanes), so a
  dense endpoint renders 28 rows instead of 8. Nothing fabricated.
- Search reports a match count ("9 matching observations") and reduces
  the axis; blue search dots in both ribbons.
- Tests: frontend vitest **204 passed** (new `dt2_3c_rev2_parity.test.js`,
  15). Focused backend DT2 regression **182 passed**.

### THE MATURITY GAP — DIAGNOSED
`docs/NIVXFORGE_EDR_ENGINE_MASTER_BLUEPRINT.md` (WAVE 0 inventory).
Headline: both acceptance corpora have **ZERO `edr_raw_events`** — they
were written straight into `v2_shadow_observations` by re-projection
scripts, bypassing ingestion and therefore the detection fabric. No raw
row ⇒ no derivations ⇒ no DETECTION_MATCHED ⇒ no ATT&CK / IOC /
compromise. The fabric WORKS (1,456 DETECTION_MATCHED platform-wide) and
`detection_content/library/registry.py` already holds **37 rules, 23
Windows, all ATT&CK-mapped**, including DET-PS-001 / T1547.001 — the
exact Run-key persistence the fixture hand-authored. E3 content is
present; E3 EXECUTION on the acceptance corpora is absent.

### ENGINE MATRIX (blueprint §1)
E1 PASS · E2 PARTIAL · E3 CONTENT PRESENT / NOT EXECUTED · E4 STUB ·
E5 PRIMITIVES ONLY · E6 PARTIAL · E7 CONTRACT COMPLETE, NO PRODUCER ·
E8 ABSENT · E9 COMPLETE+HARDENED · E10 STUB.
Duplicates to reconcile (not fork): `services/mitigation/evidence_driven/
rule_library.py` vs `detection_content/library/registry.py`;
`services/behavioral/sysmon_adapter.py` vs `edr_plane/windows_eventlog.py`.

### NEXT (awaiting owner authorisation)
WAVE 2 · E2 Process/Entity Graph — PID-reuse-safe identity, Sysmon 5
termination, SERVICE/TASK/MODULE entities, store GUIDs at ingest.
Then WAVE 3 · E3 — **P0: an evaluation path over EXISTING canonical
observations**, without which every re-projected corpus is permanently
undetectable.

### ACCEPTANCE IDENTITIES
- clean real Windows corpus: `dev_f4b3fb82d7f3` / tenant
  `ten_3f7f772b353a6bbbb0ac8bc564` (3,299)
- contaminated historical corpus (UNTOUCHED, audit): `dev_2adbb41a04a4` /
  `ten_f1a5479243e901cf159e230fa0` (3,298, 3,102 `kind=detection`)
- deterministic IOC fixture: `ep_dt23cfixture01` / `ten_61377adfb36187a579ce44574b`

### PRE-EXISTING failures (NOT caused by this work, proven by stash)
`test_p0_a2_adversarial_live` (1), `test_p0_f13_5_detection_handoff` (5),
`test_p0_f7_live_api` (9 errors — live preview 504 on
`/api/edr/campaign-story`), `test_iteration_82_activation` (fails 7 at
HEAD vs 2 with the patch; the legacy golden corpus is absent from this
preview DB).

---

## 2026-09-29 (later) · WAVE 3 / E3 · DETECTION REPLAY IMPLEMENTED

Owner directive: engine-first, Detection Replay FIRST, and it must invoke
the canonical fabric rather than become a second detection engine.
Not deployed.

### THE DIAGNOSIS WAS CORRECTED BY MEASUREMENT
My earlier "the corpus bypassed detection" was too crude. Measured:
- `xdr_canonical_evidence` holds **3,299 fully normalised rows** for
  DESKTOP-A9HGFJJ (with Sysmon `process_guid` + field provenance). It
  arrived via `POST /api/xdr/ingest/telemetry`, so `edr_raw_events` is 0.
- `xdr_detection_matches` / `edr_findings` / `edr_finding_evaluations`
  were **0 / 0 / 0**.
- Running `evaluate_detection()` over all 3,299: **3,299 ×
  `RULE_NO_MATCH`, zero errors.**
- POSITIVE CONTROL proves the rules DO bind to the canonical dialect:
  encoded PowerShell → DET-EX-001/T1059.001; regsvr32 →
  DET-EX-005/T1218.010; Run key → DET-PS-001/T1547.001; WMI →
  DET-EX-004/T1047. Two did NOT fire → real content gaps: IEX
  download-execute (T1105) and LSASS credential access (T1003).
- The real corpus is **genuinely benign**: 2,615/3,299 svchost.exe, only
  **16 rows carry any command line**, **0 interpreter/LOLBin processes**.
  CORRECTED (owner ruling): we may NOT claim Cisco would report the same.
  The defensible statement is that NivXForge's currently available
  telemetry and currently implemented rules produced no detections for
  this corpus. `RULE_NO_MATCH` is not a verdict of "clean".

So the actual defect was OUR negative-explainability invariant: nothing
recorded that the evidence HAD been evaluated, so no surface could tell
"evaluated, nothing matched" from "nobody has looked yet", and silence
read as benign.

### DELIVERED
- `edr_plane/detection_replay.py` + route
  `POST /api/edr/endpoints/{id}/detection-replay?apply=false`.
  - verdict from `detection_content.xdr_pipeline.evaluate_detection` —
    the IDENTICAL function live ingest calls; durability from
    `record_endpoint_detection` — the IDENTICAL function live ingest
    calls. Replay defines NO rule, predicate, threshold or match shape,
    enforced by a structural test. Live and replay cannot diverge.
  - enters at the DETECTION stage over already-canonical evidence, so it
    cannot re-run DSM/parser/normalizer or mint a duplicate canonical
    row; writes no `edr_raw_events` (that would claim sensor bytes we
    never received); `apply=false` is the default.
  - `xdr_canonical_evidence` is now a DECLARED tenant-partitioned
    endpoint-keyed store, so E1 governs the read.
  - TIME MODEL (the E8 contract, established here): `observed_at` = the
    endpoint instant, NEVER touched; `derived_at` = when the verdict ran.
- RESULTS: real corpus 3,299 evaluated / 0 matched (honest);
  fixture 6 evaluated / **4 matched** (DET-EX-001 ×4, DET-PS-001 ×2);
  same hostname other tenant → 0; no tenant → `TENANT_NOT_RESOLVED_FOR_REPLAY`.
- READ PATH: `assessment_state` now carries three distinct facts —
  `ASSESSED_BY_DETECTION_FABRIC` / `EVALUATED_NO_DETECTION` /
  `NOT_EVALUATED` (+ SUPPRESSED, EVALUATION_FAILED), each with a stated
  `evaluation_meaning`. `NO_DETECTION_CLAIMED_THIS_OBSERVATION` RETIRED
  (it read as "evaluated and nothing claimed it").
  New joins: `edr_finding_evaluations` + `edr_findings` by
  `canonical_event_id`, so a finding supplies rule id, version, severity
  and ATT&CK. `record_endpoint_detection` gained an optional
  `citations=` so the producing rule's OWN severity/ATT&CK survive
  instead of becoming `NOT_RECORDED_BY_SOURCE`.
- E6 BOUNDARY: `mitre_basis` = `RULE_DECLARED_BY_MATCHED_DETECTION` vs
  `SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION` vs `NOT_ATTRIBUTED`.
  A technique is a claim ONLY when the matched rule declared it.
- ACTIVITY DETAILS: new finding block (rule, version, severity, ATT&CK,
  engine, evaluated-at, finding id, basis); "Evaluated · no rule
  matched" vs "Not evaluated" are now different screens. The
  self-contradicting "Not evaluated" on a matched event is fixed.
- FIXTURE DEPENDENCY REVERSED: `scripts/dt2_3c_ioc_fixture.py` authors
  TELEMETRY only (canonical evidence, command lines, parentage). It no
  longer writes a detection derivation or a technique list. The engine
  produces the detection; the compromise is built from THAT finding —
  techniques from the matched rules, contributors = the exact
  observations those rules cited (4 proven, no proximity inference).

### TESTS
`tests/edr/test_e3_detection_replay.py` (22) ·
`dt2/__tests__/e3_detection_surface.test.js` (14) ·
`test_p0_detection_attribution.py` retargeted for the retired token +
a new three-state case. Frontend vitest **218 passed**; focused backend
DT2/E1/E3 **211 passed**; full `tests/edr` 1,469 passed / 8 failed, all
8 pre-existing (f7 flaky-live, a2 ×1, f13_5 ×5 — proven by stash).

### KNOWN GAPS (honest, recorded, NOT worked around)
- **SENSOR STARVATION — biggest limiter.** 16/3,299 real rows carry a
  command line, so content rules have almost nothing to read.
- 2 proven rule-content gaps: T1105 download-execute, T1003 credential
  access.
- `scripts/g1_clean_reprojection.py` wrote only the CEM shadow store, so
  the clean corpus `dev_f4b3fb82d7f3` has NO canonical evidence and
  replay honestly evaluates 0 there.
- ATT&CK Tactics still read "Not attributed": rules declare technique
  ids but a tactic NAME, not a TA id. No mapping was invented.

### NEXT (owner review gate)
WAVE 2 · E2 Process Identity — ProcessGuid-first identity, PID reuse,
parent/child continuity, Sysmon 5 termination, explicit UNKNOWN when
termination is not observed. Then E4 hashing/reputation, then E8
retrospection (its time model is already in place).

---

## 2026-09-29 (WAVE A) · TELEMETRY TRACE + COVERAGE MATRIX + 1 REAL RULE FIX

Owner-approved order: A widen/audit Windows process telemetry ·
B converge the normalizers · C one canonical vocabulary · plus build the
coverage matrix NOW from code+data. Not deployed. No endpoint touched.

### A · TRACED, NOT ASSUMED → `docs/WAVE_A_WINDOWS_TELEMETRY_TRACE_AND_RUNBOOK.md`
PROVEN: the collector applies **no event-ID filter** (`filters` empty in
all 4 profiles); **0 Sysmon deliveries were refused**; **24 Security + 1
System were BLOCKED** with `SOURCE_FORMAT_MISMATCH` /
`content_recognized_as: []` — which is why `Security:4688` is absent;
and the DSM is **not** the defect (a well-formed 4688 in the collector's
own `{channel,xml}` envelope passes `recognizes_format()` and
`supports()`).

**THE REAL P0 DEFECT (fixed): the refusal could not explain itself.**
`xdr_ingest.py` read only `raw["line"]`/`["message"]` for the excerpt,
but the Windows collector sends `{channel, xml}` — so **55
SOURCE_FORMAT_MISMATCH blocks across 4 tenants were written with an
empty excerpt**. New `_excerpt_evidence()` walks a declared ordered list
of content keys and records `payload_excerpt_source`, `_len`,
`_truncated` and, when nothing carried text, an explicit
`payload_excerpt_absent_reason` listing the keys that DID have a value —
so "empty payload" and "unread payload" are now different facts.
I do NOT claim why those 24 records were unrecognisable: that evidence
was never captured. It is diagnosable on the next occurrence.
Sysmon Event ID 1 = 16 for the window; nothing was lost at the collector
or at ingest, so the cause is upstream and **NOT PROVEN** — the runbook
asks for the endpoint's active Sysmon config and the channel's own
Event ID 1 count before ANY config change.

### COVERAGE MATRIX → `docs/E3_DETECTION_COVERAGE_MATRIX.md` + `.json`
`backend/scripts/e3_coverage_matrix.py`, every cell measured from the
rule registry + canonical schema + the rules' own fixtures + the REAL
corpus. Columns: technique · rule · required telemetry · canonical
event types/fields (via an explicit Sigma↔canonical vocabulary bridge) ·
sensor can observe · actually collected · canonical field populated ·
positive control in the FIXTURE dialect · positive control in the
CANONICAL dialect · negative control · real-corpus evaluated · verdict.

**Result: 22 SUPPORTED · 14 NOT_APPLICABLE · 1 PARTIAL · 0 UNSUPPORTED ·
0 dead rules.** Deliberately NOT an ATT&CK percentage.
It answers the owner's question directly — credential access: DET-CR-001
(LSASS) and DET-CR-002 (NTDS) SUPPORTED; DET-CR-004/005/006 are
identity-plane and out of scope for a Windows endpoint sensor.
Remaining PARTIAL: DET-LM-001 T1021.002 — fires on canonical evidence
but `registry.service_name` is never populated (service-creation
telemetry is not collected).

### THE ONE REAL DEFECT THE MATRIX FOUND (fixed)
`DET-CR-002` T1003.003 gated on the literal string `ntds.dit`, so it
could not fire on its OWN positive fixture: `ntdsutil "ac i ntds" "ifm"
"create full <dir>"` never names the file. That is a real evasion gap.
Predicate now also fires on the IFM instruction and on a shadow copy of
the NTDS volume, and still does not fire on `dir C:\Windows\NTDS` or
`ntdsutil /?`.

### REGRESSION → `tests/edr/test_e3_coverage_invariants.py` (116 tests)
Locks four invariants per rule: every rule satisfies its OWN fixtures ·
a rule that fires on the raw dialect MUST fire on the canonical dialect
(the dead-rule guard) · no rule fires on benign svchost/explorer/
taskhostw telemetry in either dialect · every declared telemetry
requirement is either mapped to a canonical field or declared
out-of-scope. Also caught an undeclared `hypervisor` platform.

### RETRACTIONS (measurement corrected me — all recorded in the runbook)
1. "Cisco would also show no detections" — WITHDRAWN, not establishable.
2. "0 file SHA-256 in the corpus" — WRONG; all 16 process_create rows
   carry MD5 + SHA-256 with `sysmon:EventData.Hashes` provenance.
3. "16/3,299 carry a command line ⇒ fields dropped" — WRONG; 16 is the
   process_create COUNT and 16/16 carry one.
4. "a dialect mismatch kills a rule" — WITHDRAWN; no rule compares
   `event_type` to `process_creation`.
5. "9 rules dead on canonical evidence" — WRONG, my own generator
   artefact (it overwrote already-canonical fixtures). Now 0.

### TESTS
`tests/edr` + `test_d12_cross_dsm_activity_time.py`: **1,659 passed /
7 failed**, all 7 pre-existing (f7 flaky-live ×1, a2 ×1, f13_5 ×5,
proven by stash). Frontend vitest 218 passed.

### ENGINE ASSESSMENT (blueprint §9, owner-required form)
E1 PASS · E2 PARTIAL · E3 FRAMEWORK OPERATIONAL / CONTENT INCOMPLETE /
REAL CORPUS EVALUATED NO MATCHES · E4 PARTIAL FOUNDATION (process-image
SHA-256 exists; file-create hashes + reputation missing) · E5 PARTIAL,
NOT OPERATIONALLY WIRED · E6 PARTIAL (techniques yes, tactic ids no) ·
E7 contract exists, real production incomplete · E8 ABSENT ·
E9 COMPLETE+HARDENED, not fed · E10 STUB.

### NEXT (awaiting owner)
B · converge the normalizers: `v2_shadow_observations` keeps only
name/image/iid/parent and drops the GUID, command line and hashes that
`xdr_canonical_evidence` already holds — the trajectory reads the poorer
store. Target: one canonical contract, the CEM store becomes a
non-lossy projection. Then E2 process identity, then E4 file identity +
reputation adapter.

---

## WAVE B · FOUNDATION (B1→B4) — 2026-06 · OWNER REVIEW PENDING

Full report: `docs/WAVE_B_FOUNDATION_REPORT.md`
Measured evidence: `docs/WAVE_B_FOUNDATION_MEASUREMENT.json`
(regenerate: `python3 backend/scripts/wave_b_foundation_measure.py`, read-only)

Scope honoured: Device Trajectory FROZEN · no deployment · no data
migration · no fabricated telemetry/hash/reputation/termination/causality
· no Cisco-parity claim · coverage matrix unchanged (0 rule rows moved).

### B1 · NORMALIZER CONVERGENCE — ACCEPTED
`xdr_canonical_evidence` is the authority; `v2_shadow_observations` is a
derived projection through ONE function (`observation_doc` →
`ces_to_cem_dict`). Eight real losses/divergences found and fixed:
`process_guid`+`parent_process_guid` (discarded after deriving an iid),
`original_file_name`, `parent_command_line`, full `parent_image` path,
`parent_pid` (DSM dialect's `ppid` was never read → parent PID lost for
EVERY DSM-normalised Sysmon event), `field_provenance` (dropped
wholesale), hash CASE divergence between the two dialects (IOC lookups
matched on one path, missed on the other), and provenance coverage
divergence. `raw.sha256` (the observation's own content digest) is now
also exposed as `raw.content_digest_sha256` so it cannot be misread as a
file hash. Measured: `B1_fields_still_lost = {}` over 3,299 observations.
Regression: `tests/edr/test_b1_normalizer_convergence.py` (51).

### B2 · PROCESS IDENTITY — ACCEPTED (limits stated)
`backend/edr_plane/process_identity.py`. Authority ladder
SOURCE_PROCESS_GUID → ENDPOINT_PID_START_TIME → PID_ONLY (NO key minted)
→ NOT_OBSERVED. Tenant + endpoint are identity boundaries. Parentage is
source-stated only (GUID resolves; parent-PID-only is described, never
joined); nothing inferred from time/name/adjacency. Lifetime:
START_OBSERVED / TERMINATION_OBSERVED / OBSERVED_EVIDENCE_SPAN /
PROCESS_LIFETIME_UNKNOWN — `last_seen` is never an exit. Windows 4689
was MISSING from `WINSEC_KIND` (a collected termination resolved to
`unclassified_telemetry`); now mapped to `process_exit`.
Measured: 54 processes, 54/54 by ProcessGuid, 16 parent edges all by
ParentProcessGuid, 4 unattributed, 0 PID-reuse cases (63-minute corpus),
54/54 `PROCESS_LIFETIME_UNKNOWN` because Sysmon EID 5 is NOT collected.
Regression: `tests/edr/test_b2_process_identity.py` (20).

### B3 · FILE IDENTITY — ACCEPTED as measurement + contract
`backend/edr_plane/file_identity.py`.
PROCESS_IMAGE_HASH != FILE_CREATE_HASH != FILE_CONTENT_IDENTITY.
Process-image SHA-256 was NOT missing and was NOT rebuilt: 16/16
`process_create` carry MD5+SHA-256 with provenance, now proven to survive
projection. FILE-create content identity: **0 of 107** — Sysmon EID 11
states path + writer + time, no hash, no size ⇒ `HASH_NOT_OBSERVED`,
`PATH_IDENTITY_ONLY`. The writer's image hash is never promoted to the
file. Identity ladder CONTENT_IDENTITY_SHA256 → non-SHA256-only →
PATH_IDENTITY_ONLY. Sensor-side hashing DESIGNED ONLY (not implemented,
no endpoint change): `docs/B3_SENSOR_SIDE_FILE_HASHING_DESIGN.md`, with
10 acquisition outcome states, TOCTOU/`content_version_state`,
rename/delete/repeat-write semantics, cache key
`(volume_guid,file_id,size,mtime)`, perf/privacy limits and **6 owner
decisions required before any code**. Regression:
`tests/edr/test_b3_file_identity.py` (13).

### B4 · REPUTATION FOUNDATION — ACCEPTED
`backend/edr_plane/reputation/` — provider-neutral adapter
(`ReputationProvider` Protocol), observable extraction that keeps the
SUBJECT (PROCESS_IMAGE / FILE_CONTENT / NETWORK_PEER / DNS_QUESTION /
URL_RESOURCE), verdicts KNOWN_MALICIOUS / KNOWN_GOOD / UNKNOWN /
LOOKUP_FAILED / NOT_SUPPORTED (UNKNOWN != benign, LOOKUP_FAILED !=
UNKNOWN, both enforced in code), aggregation states that are NOT
verdicts, disagreement retained, tenant-scoped cache with explicit
freshness and provenance, failures never cached. ONE provider
implemented — `LocalIOCProvider`, offline, reading the EXISTING `iocs`
authority, with positive AND negative controls. No secrets, no network,
no third-party dependency in the core path. Regression:
`tests/edr/test_b4_reputation.py` (18).

### TESTS
`pytest backend/tests/edr` → **1,697 passed / 3 failed / 3 skipped**
(baseline 1,587 / 7 failed). New Wave B tests: 102, all green.
5 of the 7 pre-existing failures were OBSOLETE-CONTRACT tests (fixed in
the tests, with OLD/WHY-WRONG/NEW/EVIDENCE recorded in-file; production
authorisation logic untouched). 1 was a live-edge 504 flake. The 2 still
failing are PRE-EXISTING and were reproduced at HEAD with all Wave B
source files stashed.

### OPEN / NEXT
1. **Owner-run Windows PRE-check** (READ-ONLY):
   `docs/WAVE_B_WINDOWS_PRECHECK_READONLY.ps1` on DESKTOP-A9HGFJJ. Closes
   the Sysmon EID 1 = 16 question and whether 4688/4689 exist locally.
   No endpoint-changing action until its output is reviewed.
2. **P0** Process TERMINATION telemetry is not collected (Sysmon 5 /
   Security 4689 absent) ⇒ every process is honestly UNKNOWN-lifetime.
3. **P0** File CONTENT identity unavailable for created files (0/107) —
   blocked on the 6 B3 hashing decisions.
4. **P1** EDR read-path performance: `device_identity.list_devices()`
   full-scans `v2_shadow_observations` (262,823 docs) per call;
   `/api/edr/device-trajectory` 14.3 s, `/api/edr/campaign-story` 11.2 s.
   Causes the 2 remaining live-test failures. NOT fixed in this wave
   (frozen surface, deserves its own measured change).
5. **P1** `windows-security-evd` DSM refusal (Wave A) — still unproven
   root cause; the ingest refusal logger fix means the NEXT occurrence is
   diagnosable.
6. Then: B5 read-only measurement surfaces, then the Cisco/Defender/
   CrowdStrike/SentinelOne/Sophos/Carbon Black capability study BEFORE
   finalising E4/E5.

---

## WINDOWS PRE-CHECK ASSESSMENT — 2026-06 · OWNER REVIEW PENDING
Full report: `docs/WAVE_B_WINDOWS_PRECHECK_ASSESSMENT.md`
Endpoint untouched · nothing deployed · trajectory frozen · no hashing implemented.

**HISTORICAL EID 1 = `NO_LONGER_PROVABLE_FROM_ENDPOINT_RETENTION`.** The
Sysmon channel is circular and its oldest retained record is
2026-09-29T09:27:09Z, so the 2026-09-22 15:43–16:46 UTC window has rolled
out (along with the EID 16 config-change records). 16 is the number that
REACHED canonical evidence — no longer provable as the number generated.
Replacement: a forward-looking read-only measured window (endpoint EID 1
count vs backend `process_create` count over the same UTC minutes).

**CURRENT EID 1 = HEALTHY.** Sysmon 15.22, ProcessCreate unfiltered,
MD5+SHA256, full identity field set present — exactly what B1/B2 need.

**EID 5 ROOT CAUSE = THREE independent blocks, all confirmed in-repo:**
(1) NOT GENERATED — our own `nivx-w1-sysmon.xml` has
`<ProcessTerminate onmatch="include"/>` with no rules (include-nothing);
(2) would be REFUSED — no `("sysmon", 5)` in `SUPPORTED`
(`edr_plane/windows_eventlog.py`) ⇒ `WINDOWS_EVENT_ID_NOT_SUPPORTED`;
(3) would NOT be canonicalised — no `5` in the `sysmon_dsm.py` kind map.
4689 is server-ready (B2 added it) but Windows auditing is No Auditing.
**Proposal: SERVER FIRST (B5a, two dict entries + gate + regression),
THEN one line on the endpoint (`include`→`exclude`, no service restart,
owner authorisation required).** ~0.5% telemetry increase. Do NOT use
4689 as the termination source: no ProcessGuid ⇒ PID-only guess.

**FILE HASHING.** `PROCESS_IMAGE_SHA256` proven and preserved (16/16).
`FILE_CREATE_CONTENT_SHA256` = 0/107 (`HASH_NOT_OBSERVED`); EID 15 is
also off. The six B3 owner decisions are now answered with
DECISION/OPTIONS/SECURITY/PERFORMANCE/RECOMMENDED/WHY. Recommended:
acceptance endpoint only · allow-list by type · privacy trees excluded ·
64 MiB & 120 files/min · 2 s settle window · retain `CHANGED_SINCE_EVENT`
labelled. NOT IMPLEMENTED.

**READ-PATH PERF ROOT CAUSE (measured, read-only).**
`v2_shadow_observations` = 264,241 docs / **606 MB** / 2,417 B avg, and
**TWO unfiltered full reads** in the path:
`device_identity.py:195` (`list_devices`) and `:446` (`observations`,
which filters in PYTHON). 4.45 s each ⇒ the 14.3 s trajectory request.
The serving indexes already exist and are unused. Measured fix:
indexed `$or` + `$gte` in `observations()` = 6,597 docs in **0.143 s**
(31×, docsExamined == nReturned), unresolved device 0.001 s vs 4.45 s;
`list_devices()` as a server-side `$group` = 63 rows in 0.47 s (9×) with
the cross-tenant fail-closed invariant preserved literally. NOT
IMPLEMENTED — awaiting authorisation.

**NEXT (proposed):** B5a termination readiness (server only) · B5b
read-path fix · B5c measured delivery-fidelity window · then the
Cisco/Defender/CrowdStrike/SentinelOne/Sophos/Carbon Black study.

---

## B5 · SERVER-SIDE READINESS — 2026-06 · OWNER REVIEW PENDING
Full report: `docs/B5_SERVER_READINESS_REPORT.md`
Endpoint UNCHANGED · Sysmon XML UNCHANGED · not restarted · auditing
UNCHANGED · 4688/4689 NOT enabled · NOT deployed · endpoint hashing NOT
implemented · trajectory presentation UNCHANGED.

**B5-1 EID 5 READINESS — DONE.** `("sysmon", 5) →
ACTIVITY_PROCESS_TERMINATION` in `edr_plane/windows_eventlog.py` (its own
branch: the PROCESS branch reads `UtcTime` as the START time, which on
EID 5 is the EXIT instant — reusing it would have fabricated a start
time) and `5 → process_exit` in `sysmon_dsm.py`. CEM kind resolution
already had it. Preserved: ProcessGuid, PID, Image, `exit_time` (+
`sysmon:UtcTime (EventID 5)` provenance), User. Declared absent:
CommandLine, Hashes, Parent*, `process.start_time`. Declared
unsupportable: `process.exit_code`. Exit binds to the SAME `process_key`
as the creation via ProcessGuid; an exit with no authoritative identity
mints no key and terminates NOTHING.
**DECLARED DEVIATION:** kind is `process_exit`, not `process_terminate` —
`process_exit` is already the CEM enum value, `SYSMON_KIND[5]`, the
reviewed gate value and what `trajectory_window`/`campaign_story`
consume. A second name for one fact is the B1 problem. Rename available
as its own governed change if the owner wants it.
**Convergence fix:** the sensor plane stated only the activity CLASS and
no `event_type`; it now states `event_type` from the SAME vocabulary as
the XDR plane.
Regression: `tests/edr/test_b5_process_termination.py` (18) — positive,
negative, malformed, replay/idempotency, cross-tenant, PID-reuse.

**B5-2 READ PATH — DONE, semantics proven identical.**
`observations()` now asks the DB which observations address the endpoint
(indexes already existed and were unused); needles come from the STORE
via indexed `distinct` filtered case-insensitively, and `_addresses()`
REMAINS the admissibility authority. Directory read projected to the
fields it consumes. Measured (`scripts/b5_read_path_proof.py`):
directory-wide 298,006 ms → **23,196 ms (12.8×)**; busiest device
index-only (256,418 examined / 256,418 returned, 387 ms); unresolved
endpoint 4,450 ms → **167 ms**; `/api/edr/device-trajectory` **14.3 s →
3.5 s**. Equivalence: **61/62 devices identical count + digest**; the one
difference was live-write drift on the continuously-ingesting device
(PRE == POST == 256,434 in the quiet rounds). Unchanged: tenant
isolation, endpoint authority, opaque cross-tenant refusal, observation
identity, time semantics, evidence content, response shape.

**B5-3 FILE HASHING — CONTRACT ONLY.**
`docs/B5_FILE_HASHING_SENSOR_CONTRACT.md`: state machine
(FILE_CREATE → eligibility → settle → identity revalidation → hash →
SHA-256+provenance OR explicit failure), 14 terminal states, additive
`file.content_acquisition` block, all nine owner-listed cases.
`PROCESS_IMAGE_SHA256` ≠ `FILE_CONTENT_SHA256` enforced. NOT IMPLEMENTED.

**B5-4 DELIVERY FIDELITY — PREPARED, NOT EXECUTED.**
`docs/B5_DELIVERY_FIDELITY_TEST_PLAN.md`: five separately-counted
boundaries (generated → observed → sent → accepted/refused →
canonicalized) per Event ID over one agreed 60-minute UTC window, with a
retention guard, config-stability check and dedupe counted separately
from refusal.

**TESTS: 1,757 passed / 0 failed** (tests/edr + ingestion_phase4 +
w1_sysmon_field_preservation). The two live-API tests that previously
timed out now PASS because the read path is fast — closed honestly, not
by weakening a test. Two PRE-EXISTING failures remain in
`tests/test_v2_framework.py` (adapter flag default; v2/engine isolation
walk), reproduced at HEAD with all B5 files stashed.

**OPEN:** (1) accept `process_exit` or authorise the rename; (2)
authorise the one-line Sysmon `ProcessTerminate` change (server is
ready); (3) `campaign-story` still 11 s — NOT the directory scan, cost
is inside the story engine, needs its own measured pass; (4) B3
implementation pending contract approval; (5) delivery-fidelity needs
sensor per-channel read/sent counters for boundaries B1/B2.

---

## B5.1 · PRE FIDELITY BASELINE · EID5 OWNER COMMAND · B3 DECISIONS · CAMPAIGN STORY PROFILE — 2026-06 · OWNER REVIEW PENDING
Report: `docs/B5_1_FIDELITY_BASELINE_AND_PROFILE.md`
`process_exit` ACCEPTED as the single canonical event type (owner
decision); `ProcessTerminate` stays source/provenance terminology.
Endpoint UNCHANGED · not deployed · trajectory frozen · no hashing code.

**FIDELITY · backend half BUILT AND RUN** (`scripts/b5_delivery_fidelity.py`),
**endpoint half PREPARED, NOT RUN** (`docs/B5_FIDELITY_ENDPOINT_COUNT_READONLY.ps1`,
read-only, PRE/POST labelled). Boundary availability stated, never
inferred: B0 endpoint-only · **B1 NOT MEASURABLE (the sensor exposes no
per-channel read counter)** · B2 PARTIAL · B3 accepted MEASURED · B3
refused MEASURED **but incomplete — a PARSE_ERROR is NOT recorded as a
routing block** (0 blocks logged while the collector state says "parser
failed on every event", received 1/parsed 0 — the same blindness that
made Wave A's `windows-security-evd` loss hard to find) · dedupe
MEASURED (3,299 suppressed — correct, NOT loss) · B4 MEASURED.
Baseline for 2026-09-22 15:43–16:46Z: EID 1=16, 3=70, 11=107, 12=766,
13=2335, 22=1, +2 winsec = 3,297.
**DESIGN-CHANGING MEASUREMENT: delivery is heavily spooled** —
sensor→collector p50 **59 min**, collector→NivX p50 **43 min**, max
**2.9 DAYS**. My original "wait 5 minutes" would have reported an entire
hour as LOSS when it was LATENCY. Corrected: compare at T+24 h, re-count
at T+72 h before calling anything lost.

**EID 5 OWNER COMMAND — exact, with rollback.** Backup →
`(Get-Content …) -replace '<ProcessTerminate onmatch="include"/>',
'<ProcessTerminate onmatch="exclude"/>'` → `Compare-Object` →
`Sysmon64.exe -c <file>` → verify with `Sysmon64.exe -c` dump. Rollback =
restore the .bak and re-apply. No service restart, no audit policy, no
registry, no other Sysmon setting. ~+0.5% telemetry. NOT EXECUTED BY ME.

**B3** six decisions presented as DECISION|OPTIONS|SECURITY|PERFORMANCE|
RECOMMENDED|WHY. No hashing code until they are approved as answers.

**CAMPAIGN STORY PROFILE (read-only, no code changed).** 10.99 s, 15
activities. Dominant stage = `campaign_story._activity()` doing up to two
`find_one`s per activity against `v2_shadow_observations` (256,944 docs)
on **UNINDEXED** fields: `canonical_event_id` (0.51 s, 256,944 examined)
and `event.provenance.ingest_job_id` (0.55 s, 256,944 examined) →
15 × 2 ≈ 8–16 s = the whole request. **Measured minimum fix: TWO INDEXES,
no code change** — `{tenant_id, canonical_event_id}` and
`{tenant_id, event.provenance.ingest_job_id}`. Proven with a reversible
probe: 0.51 s / 256,944 examined → **0.000 s / 0 examined**; probe
indexes then DROPPED and the original 12-index state verified restored.
**Second finding: `resolved_via` is None for ALL 15 activities** — no
detection in that incident binds to its canonical observation. An E1
LINKAGE gap, not performance; untouched, needs its own pass.

**OPEN:** owner to (1) run the PRE endpoint count, (2) apply the EID 5
one-liner after PRE, (3) approve the six B3 decisions, (4) authorise the
two campaign-story indexes. Platform gaps: sensor per-channel counters
(B1/B2), parse failures not recorded as refusals, detection→observation
linkage.

---

## B5.2 · PROVENANCE LINKAGE ROOT CAUSE + CAMPAIGN STORY INDEXES — 2026-06 · OWNER REVIEW PENDING
Report: `docs/B5_2_LINKAGE_ROOT_CAUSE_AND_INDEX_PROOF.md`

**CORRECTION OF MY OWN B5.1 CLAIM.** "resolved_via None for all 15" was
WRONG — I read a top-level key that does not exist. The field is
`provenance.process_identity_resolved_via`, and all 15 resolve, via
`raw_event_id`. The chain is NOT severed; it survives on its SECONDARY
reference.

**ROOT CAUSE = `REFERENCE_TRANSLATED_INCORRECTLY`, 1,674/1,674
detections (374 incidents).** Two minting schemes for one identity:
`canonical_bridge.py:508` (the AUTHORITY) mints
`f"cev_{raw_id[4:]}_{gen}"` (strips `raw_`, keeps the REPLAY GENERATION)
and agrees with `edr_raw_events.derivations[].event_id` and with the
shadow projection; `detection_content/telemetry/nivxforge_sensor_dsm.py:82`
mints `f"cev_{trace_id}_pl"` (keeps `raw_`, drops the generation).
Shadow holds ZERO `_pl` ids while `xdr_canonical_evidence` holds them ⇒
duplicate authority. Resolution: **0/1,674 by primary**, 1,460 (87.2%)
by secondary (`ingest_job_id`), **214 (12.8%) unresolved =
`REFERENCED_OBSERVATION_NOT_FOUND` / `RAW_EVENT_ABSENT`, ALL in 214
distinct synthetic `p0f-*` proof tenants, one each — ZERO in real
tenants.** No REFERENCE_NOT_EMITTED, no REFERENCE_DROPPED, no
CROSS_TENANT_REFUSED, no LEGACY_WITHOUT_REFERENCE. No evidence lost, no
mis-attribution: the fallback reference is itself authoritative.

**REPAIR PROPOSED, NOT IMPLEMENTED (needs approval):** R1 one exported
minting function on the authority (`canonical_event_id(raw_id, gen)`);
R2 CARRY the id, never `setdefault` over it; R3 resolver order
authority-id → legacy `_pl` → `ingest_job_id`, all authoritative, still
reporting which was used; R4 regressions incl. cross-tenant refusal and
`RAW_EVENT_ABSENT` staying unbound; R5 NO migration — the 214 synthetic
rows are reported, never back-filled. ~4 lines of code, no data change.
Third scheme noted for the same pass: the DSM planes mint
`sysmon-<eid>-<hash>`.

**CAMPAIGN STORY INDEXES — APPLIED (owner-authorised), declared in
`server.py`:** `obs_tenant_canonical_event_id`,
`obs_tenant_ingest_job_id`. **10.99 s → 0.311/0.295/0.301 s (~36×)**;
both lookups 256,944 docs examined → **0**; **response body
byte-identical to PRE**; 15 activities unchanged;
`process_identity_resolved_via` unchanged; cross-tenant still 403
TENANT_NOT_FOUND. No application logic changed. device-trajectory stays
3.5 s.

**OPEN:** (1) owner runs the read-only Fidelity PRE endpoint script —
PRE is NOT complete without that transcript; (2) then the EID 5
one-liner, POST validation at T+24 h (59-min p50 / 2.9-day worst-case
spool); (3) approve R1–R4; (4) approve the six B3 decisions; (5) sensor
per-channel counters + parse-failures-not-logged-as-refusals remain open.

## 2026-06 · CLOSURE WAVE DONE — identifier authority → parse/delivery
## observability → delivery counters → B3 file identity (STOPPED before EID5 PRE)
Full report: `docs/C_CLOSURE_WAVE_IDENTIFIER_DELIVERY_FILE_IDENTITY.md`.
- **R1–R4 IDENTIFIER AUTHORITY (P0) DONE.**
  `canonical_bridge.canonical_event_id(raw_id, generation)` is the SOLE
  minting authority on the affected canonical path; the bridge publishes it
  on `_authenticated_ingest.canonical_event_id`; the sensor DSM CARRIES it
  and publishes `provenance.canonical_event_id_basis`. `_pl` is never
  minted again (source-asserted); `canonical_bridge` holds exactly ONE
  `cev_` format string. End-to-end proof: bridge result,
  `v2_shadow_observations`, `edr_raw_events.derivations[].event_id`,
  `xdr_canonical_evidence` and the campaign detection row all name the
  SAME id and resolve via PRIMARY (the `xdr_canonical_evidence` duplicate
  authority is gone for new data).
- **READ RESOLUTION (R3) DONE.** New `edr_plane/evidence_resolution.py`:
  authority id → legacy `_pl` → `ingest_job_id`, authoritative references
  only, no heuristics, tenant in every query (cross-tenant resolves to
  nothing and discloses nothing). Campaign Story publishes
  `resolution_is_fallback`, `canonical_event_id_form`,
  `resolution_attempts[]`, `resolution_unresolved_reason`, and now raises
  `canonical_id_scheme_divergence` on ANY fallback. LIVE
  `inc_c253027ba781494684db`: 15/15 resolve, all LEGACY fallback, 0.367 s.
  Debt baseline measured: 1,680 legacy refs vs 4 authority refs; 254,943
  historical `_pl` rows in `xdr_canonical_evidence` — NOT migrated.
- **PARSE/REFUSAL VISIBILITY + DELIVERY COUNTERS DONE.** New
  `edr_plane/delivery_counters.py` (`edr_delivery_counters`, `$inc` only,
  keyed tenant/endpoint/channel, `evidence_authority:false`), wired into
  `/api/edr/agent/telemetry` with reason codes, published read-only on
  `GET /api/edr/wave0/raw-events/stats` as `delivery_boundaries`. Two
  accounting layers (storage / canonicalisation). LIVE tenant `default`:
  received 365, accepted 364, dedup_payload 1, parsed/canonicalized 363,
  parse_failed 1 (`PARSER_FAILED`, channel `UNPARSEABLE_ENVELOPE`),
  unaccounted_received 0, unaccounted_accepted 0.
- **SENSOR COUNTERS + B3 HASHING: CODE-COMPLETE, DEFAULT OFF, NOT
  DEPLOYED.** `agents/nivxforge-{linux,windows}/nivxforge_delivery_counters.py`
  (`NIVX_SENSOR_DELIVERY_COUNTERS`) and `nivxforge_content_acquisition.py`
  (`NIVX_SENSOR_FILE_HASHING`); heartbeat accepts additive
  `counter_epoch`/`delivery_counters` (422 `SENSOR_COUNTER_REFUSED` on
  anything malformed); epoch change keeps the previous snapshot instead of
  decreasing. Server contract `edr_plane/file_content_acquisition.py`:
  `PROCESS_IMAGE_SHA256 != FILE_CONTENT_SHA256 != RAW_PAYLOAD_CONTENT_DIGEST`,
  digest admitted only on ACQUIRED + declared content_version_state +
  acquired_at + 64-hex; torn read discarded; `CHANGED_SINCE_EVENT`
  retained and labelled; UNKNOWN never becomes BENIGN.
- **TESTS:** 70 new cases (`tests/edr/test_c1..c5`), `tests/edr` **1,759
  passed / 2 skipped**. Pre-existing, NOT caused by this wave (verified by
  stashing): 3 failures in `tests/test_b4b5_tenant_registry_authority.py`.
- **NOT CHANGED, CLASSIFIED:** the third identifier scheme
  (`sysmon_dsm.py:229` `sysmon-<eid>-<uuid4>`, `windows_security_dsm.py:639`
  `uuid4`) is a NON-DETERMINISTIC per-normalisation surrogate — it
  identifies a normalisation pass, not an immutable raw event. Converting
  it needs a stable raw identity on the XDR collector path: own decision.
- **DATA:** no evidence written/rewritten/migrated/deleted; only counter
  documents in the new collection + one index. **ENDPOINT: unchanged.
  DEPLOYED: no.**
- **OPEN / NEXT:** (1) owner runs the read-only EID5 **PRE** script and
  returns the transcript — PRE is not complete without it; (2) then the
  approved ProcessTerminate change, POST at T+24 h; (3) LIVE proof of
  primary-id resolution needs one new rule-matching detection;
  (4) then the owner's stated sequence E4 reputation/file intelligence →
  E3 detection expansion → E5 behavioural correlation (UEBA later).

## 2026-06 · EID5 BLOCKED (config authority gap) · OWNER CHOSE OPTION B
Reports: `docs/B5_EID5_SYSMON_XML_PROVENANCE_INVESTIGATION.md`,
`docs/B5_SYSMON_XML_RECOVERY_HUNT_READONLY.ps1`, `docs/E3_NEXT_STEP_PROPOSAL.md`.
- EID5 status: **BLOCKED_ON_EXACT_SYSMON_ROLLBACK_ARTIFACT**. `ProcessTerminate
  = include` (no child rules) => EID5_NOT_COLLECTED; `termination_state` stays
  `PROCESS_LIFETIME_UNKNOWN` everywhere. NOT a reason to weaken semantics.
- PRE accepted: DESKTOP-A9HGFJJ, run 621b79c3-bf4e-49ad-ad42-14bac02b2449,
  rules SHA `6eecc58c...0cba8f`, EID1=185 / EID5=0 in window, EID5 anywhere=0.
- The enablement script HALTED twice at G2 (config XML missing) - fail-closed
  worked. `C:\NivX\sysmon\nivx-w1-sysmon.xml` is gone from disk; Sysmon 15.22
  still names it, live ConfigHash `0BAE60B3...9C9A7AC`.
- WORKSPACE RECOVERY EXHAUSTED -> `ORIGINAL_XML_RECOVERED = NO`. Provenance is
  `memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md` S1.3 (single revision, the only
  writer anywhere; the Windows installer has zero Sysmon references). 96
  byte-level reconstructions, 2,245 commits (pickaxe + blob grep), 12,515
  workspace files and the handoff zip: no artefact hashes to `0BAE60B3...`.
  PRD history shows the same `0BAE60B3...` recorded at W1 Phase 1, so the
  deployed file never changed - only its bytes differed from the doc text.
- Semantic recovery is complete (19/19 event classes match the live `-c` dump)
  but semantic != byte-exact, so exact rollback is NOT guaranteed.
- OWNER DECISION: Option B (zero-apply hold). No `Sysmon64 -c <config>`, no
  registry import, no service restart, no reconstructed XML applied, no new
  baseline. Read-only endpoint hunt block delivered, awaiting owner run.
- TRACK SPLIT: Track A = recover exact config -> enable EID5 safely.
  Track B = E3 deterministic detection hardening (proposal measured and
  written): E3-A close the 9-rule declaration debt (28/37 declare today),
  E3-B partial-absence negative controls (66 negative fixtures test wrong
  values, never absent ones), E3-C collected-telemetry coverage map.
  Baseline measured: 0/37 rules fire or raise on an empty canonical event.
- ENDPOINT_CHANGED: NO · DEPLOYED: NO · DATA_CHANGED: NO.

## 2026-09-29 · B5 EID5 END-TO-END = WAITING_FOR_DELIVERY (read-only gate)
Report: `docs/B5_EID5_END_TO_END_ACCEPTANCE_REPORT.md`. Owner superseded the
old blocker: `OLD_ROLLBACK_BLOCKER = CLOSED` (v2 baseline `F5FFD2CA...16C9B9`,
EID5 candidate `9398464D...0362E3` applied, exit 0, EID5 generation PROVEN on
DESKTOP-A9HGFJJ with 10 GUID-identical EID1/EID5 pairs at ~14:48-14:50 UTC).
- GATE 1 code contract PASS 8/8 (`windows_eventlog.py:83,668-694`,
  `sysmon_dsm.py:241`, `process_identity.py:68,205-252`): EID5 -> process_exit,
  UtcTime -> exit_time only (start_time declared not_observed), ProcessGuid
  authoritative, no identity => no process_key, PID-only never joins.
  NUANCE: GUID key is tenant-scoped (`guid|tenant|guid`); cross-endpoint
  separation rests on the machine component inside the Sysmon GUID.
- GATE 2: NOTHING downstream. 0 WINDOWS_EVENT_LOG envelopes, 0
  `<EventID>5</EventID>`, 0 `process_exit` in either canonical store, 0/10
  ProcessGuids anywhere. Host has 3,300 canonical rows (EIDs 1/3/11/12/13/22/
  4624/4672, tenant `ten_f1a5479243e901cf159e230fa0`) but newest ingest is
  2026-09-25T15:35Z - FOUR DAYS BEFORE enablement - and they arrived on the
  XDR COLLECTOR path (`col-timecheck-*`), not the EDR agent path. The host is
  not in `edr_endpoints`. No collector seen in 7 days.
- B0 PROVEN (owner) · B1-B3 NOT_MEASURABLE (sensor counters OFF by design) ·
  B4-B9 NOT_YET_OBSERVED. NOT loss, NOT refused - nothing was refused anywhere.
- GATE 5 PASS: 38 focused tests (`test_b5_process_termination.py`,
  `test_b2_process_identity.py`). GATE 8: all processes correctly remain
  PROCESS_LIFETIME_UNKNOWN; no history reconstructed.
- GATE 6: tenant counters all 0 for the Windows tenant; `default` (Linux)
  received 1047 / accepted 1046 / canonicalized 1044 / parse_failed 2 /
  unaccounted 0-0. No boundary derived by subtraction.
- OPEN FOR OWNER: confirm which backend URL the laptop's sensor delivers to -
  the preview URL changed when this environment forked, so spool latency may
  not be the only explanation. Read-only; nothing run on the endpoint.
- ENDPOINT_CHANGED: NO · DEPLOYED: NO · DATA_CHANGED: NO · E3 NOT started.

### 2026-09-29 — B5 EID5 DELIVERY RECHECK (read-only, no changes)
- Owner supplied endpoint proof: sensor destination `https://nivxray.nivxforge.com`
  CONFIRMED, service Running/Automatic, outbox 238,920,951 / offset advancing
  +103,109 bytes over 120 s, backlog 15,030,785 bytes DRAINING. Old Sysmon
  rollback blocker CLOSED.
- Backend recheck in THIS environment (`https://greeting-app-5782.preview.emergentagent.com`,
  DB `test_database`): still 0 Sysmon EID5, 0 `ProcessTerminate`, 0 canonical
  `process_exit`/`ACTIVITY_PROCESS_TERMINATION`, 0 Windows sensor envelopes in
  `edr_raw_events`, `DESKTOP-A9HGFJJ` absent from `edr_endpoints`.
- Exact full-GUID lookup: 0/10 known ProcessGuids; the whole current Sysmon
  session suffix `-000000002100` appears 0 times. The 3,295 `9949e5f2` hits are
  the older session suffix `-000000002000` (2026-09-22).
- Newest Windows record: Sysmon EID 12, EventRecordID 3312734, activity
  2026-09-22 16:20:09.742, ingested 2026-09-25T15:35:33Z, connector
  `windows-eventlog-g1proof01` (XDR collector path, not the EDR agent path).
- `edr_delivery_counters` distinct tenants = ["default"] only; NO counter
  document exists for tenant `ten_f1a5479243e901cf159e230fa0` or the Windows
  endpoint. Sensor-side per-event counters: NOT_MEASURABLE (OFF by design).
  No loss inferred.
- Measured fact reported, not a conclusion: sensor destination hostname differs
  from this preview environment hostname; cross-environment store identity is
  not measurable from inside this pod.
- Identifier authority regression: 0 `_pl`-suffixed ids in newest 200
  `xdr_canonical_evidence` docs (Closure Wave holds).
- DECISION: `B5_EID5_END_TO_END = WAITING_FOR_DELIVERY`. Pending boundary =
  BACKEND RECEIVE. 16 EID1 remain `PROCESS_LIFETIME_UNKNOWN`, not backfilled.
- Report: `/app/docs/B5_EID5_DELIVERY_RECHECK_READONLY.md`
- ENDPOINT_CHANGED: NO · DEPLOYED: NO · DATA_CHANGED: NO · UI_CHANGED: NO ·
  E3 NOT started.


### 2026-09-29 — B5 STORE IDENTITY CHECK (read-only) → DIFFERENT_STORE_PROVEN
- `nivxray.nivxforge.com` → Cloudflare `162.159.142.117` / `172.66.2.113`, served by
  the DEPLOYED production runtime of app `greeting-app-5782` (in-repo deploy RCA:
  custom domain verified, frontend_type cloudflare, target-3, 2 replicas,
  nginx:8080, backend uvicorn:8001, tier_0). `GET /api/health` → 200 `nivxray-api`.
- This agent pod = PREVIEW: container `agent-env-630704a1-...`,
  `preview_endpoint=https://greeting-app-5782.preview.emergentagent.com`
  (Cloudflare `104.18.10.243/11.243`), job `486146a0-...`.
- Store queried by all prior B5 rechecks = `mongodb://localhost:27017` /
  `test_database`, a `mongod` (pid 278) running INSIDE this agent container with
  NO ingress exposure (only 3000 and 8001 are routed).
- **STORE_IDENTITY = DIFFERENT_STORE_PROVEN.** Traffic delivered to
  `nivxray.nivxforge.com` cannot physically write into a loopback-only mongod in
  the agent container. Therefore absence of EID5 in the preview store is NOT
  evidence of production receive failure. This also explains why only the old
  Sept 22 / Sept 25 XDR-collector rows are visible here.
- `PENDING_BOUNDARY = AUTHORITATIVE_RECEIVE_STORE_IDENTITY` (supersedes the
  earlier, imprecise "BACKEND RECEIVE"). No loss inferred.
- Authoritative read-only options identified, NONE executed, all need owner
  approval: (1) Emergent deployer in debug/diagnose mode (reads prod pod runtime,
  DB binding, secret presence; diagnoses only, cannot write prod data);
  (2) authenticated read-only API reads against the production domain using
  existing read endpoints; (3) owner-side deployment panel read of prod DB config.
- `B5_EID5_END_TO_END = WAITING_FOR_DELIVERY` (not PASS, not BLOCKED).
- Report: `/app/docs/B5_STORE_IDENTITY_CHECK_READONLY.md`
- ENDPOINT_CHANGED: NO · DEPLOYED: NO · DOMAIN_CHANGED: NO · DATA_CHANGED: NO ·
  DATA_COPIED: NO · UI_CHANGED: NO · E3 NOT started.


### 2026-09-29 — B5 SCOPE CORRECTION: PREVIEW IS OUT OF SCOPE (owner ruling)
- PERMANENT RULE: every telemetry acceptance proof MUST name the runtime/store it
  was measured against. Preview `mongodb://localhost:27017` / `test_database` is
  NEVER production evidence and must not be used for B5 or any later acceptance
  gate. Preview is not operational for this program.
- The only live, authoritative path:
  `DESKTOP-A9HGFJJ` -> `NivXForgeSensor` (`--backend https://nivxray.nivxforge.com`)
  -> PRODUCTION backend -> PRODUCTION database.
- All earlier B5 arrival findings (0 EID5, 0/10 ProcessGuids, no delivery counters)
  are hereby scoped to the PREVIEW store only and carry NO weight for B5.
- NO EID5 DEFECT IS DEMONSTRATED. The only real problem was that validation was
  measuring the wrong store.
- Read-only production diagnose dispatched to the Emergent deployer with
  `intent=debug` (diagnose, no deploy): deployer job ref
  `95e7e8cd-6528-4f50-8702-566d0dc3b0ce`, dispatched twice (initial brief +
  scope-clarification follow-up). Both queued; the deployer runs asynchronously
  and had NOT returned findings at the time of writing. No production result has
  been produced or assumed.
- Brief asked production for: deployment/run identity, runtime (pods/replicas/
  image/tier/health), DB type, safe DB name, MONGO_URL/DB_NAME binding PRESENCE
  only, which store receives `/api/edr/agent/telemetry`, any `DESKTOP-A9HGFJJ`
  EDR-agent telemetry, Sysmon EID5/`ProcessTerminate` presence, exact-value lookup
  of the 10 ProcessGuids, ingest-route log/status evidence, and production
  `edr_delivery_counters` (absence stated as absence, never as measured zeros).
- Conditional chain proof requested if EID5 present: receive -> acceptance/refusal/
  dedupe -> DSM/parser -> canonical `process_exit` -> ProcessGuid binding ->
  lifecycle termination -> canonical_event_id authority, including explicit
  `UtcTime -> exit_time` (correct) vs `UtcTime -> process.start_time` (defect).
- STATUS UNCHANGED: `B5_EID5_END_TO_END = WAITING_FOR_DELIVERY`
  (`PENDING_BOUNDARY = AUTHORITATIVE_RECEIVE_STORE_IDENTITY`). No loss inferred.
- ENDPOINT_CHANGED: NO · DEPLOYED: NO · PROD_RESTARTED: NO · CONFIG_CHANGED: NO ·
  DATA_CHANGED: NO · UI_CHANGED: NO · PROD_CREDENTIALS_USED: NO · E3 NOT started.


### 2026-09-29 — B5 PRODUCTION EID5 BLOCKER RESOLUTION (prod diagnose COMPLETE)
- AUTHORITATIVE PRODUCTION FACTS (store `greeting-app-5782-test_database`,
  Emergent-managed Atlas; deployment `96834a37-...`; **active run
  `d85f3698-86ec-4f79-ac6a-e1309f96cd13`, built 2026-09-27T09:52:56Z**, tier_3,
  target-6, image `greeting-app-5782:d85f3698-...`):
  - `POST /api/edr/agent/telemetry` -> collection `edr_raw_events` (runtime-proven).
  - DESKTOP-A9HGFJJ = `ep_1989031c8c1d0085812f`, tenant
    `ten_e759b7288598bd882e3dcac49d`, ENROLLED / REPORTING, 116,012 raw events,
    `last_telemetry_at 2026-09-29T15:28:33Z`, `outbox_queue_depth 7,181`,
    ingest 200 OK every 1-3 s to 15:33:23Z, no 401/403/413/429/5xx.
    **DESKTOP-A9HGFJJ_PROD_RECEIVE = PROVEN.**
  - Sysmon EID5 = 0 (control EID1 = 210 -> matcher valid); 0/10 ProcessGuids by
    exact lookup; 0 canonical `process_exit`. **Replay frontier ~2026-09-29T
    07:32:08Z** (`payload.observed_at` of newest ingested raw), ~7 h behind the
    14:48-14:50Z EID5 batch. NOT loss.
  - `edr_delivery_counters` collection ABSENT in prod (no counters, not zeros).
  - prod `derivations.parser_state`: OK 44,329 / FAILED 71,744 with
    `WINDOWS_EVENT_ID_NOT_SUPPORTED`, `WINDOWS_PROVIDER_NOT_SUPPORTED`,
    `WINDOWS_EVENT_XML_MALFORMED`.
  - Platform: 2nd replica Pending since 09-27, `FailedCreatePodSandBox` (no IPs in
    10.55.38.1-10.55.39.254). Serving 1/2. Emergent-side capacity item, no loss.
  - Legacy caution: the 44,282 `xdr_canonical_evidence` / 5 `xdr_canonical_events`
    docs came from the OLD connector route `POST /api/xdr/ingest/telemetry`
    (`nivx-sysmon-forwarder/1.0@DESKTOP-A9HGFJJ`, ~09-18), not the sensor path.
- **NEW DEMONSTRATED VERSION GAP (deployment currency, not source correctness):**
  prod build is 2026-09-27T09:52Z (last commit at/before: `fdb9c05a` 09-27T09:37),
  but `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` was introduced in
  `91e561f6` 2026-09-29T11:44Z (`git log -S`, and `91e561f6^` has no match).
  `process_identity.py` = `e66abc8f` 09-29T10:39; `canonical_bridge.py`,
  `delivery_counters.py`, `file_content_acquisition.py` = `6afab68a` 09-29T12:48.
  => When the frontier reaches 14:48Z, prod WILL refuse EID5 as
  `WINDOWS_EVENT_ID_NOT_SUPPORTED`. **B5 PASS is unreachable on run d85f3698.**
  Corroborated at runtime by the absent counters collection and the existing
  `WINDOWS_EVENT_ID_NOT_SUPPORTED` refusals. No evidence lost: prod retains raw
  bytes marked replayable, so refused EID5 can be replayed after a correct deploy.
- Workspace source is already correct (EID5 admitted; `UtcTime -> exit_time` with
  provenance `:UtcTime (EventID 5)`, never `start_time`; NOT_SUPPORTED/not_observed
  declared). Re-ran read-only: `test_b5_process_termination.py` +
  `test_b2_process_identity.py` = **38 passed**. NO PATCH WRITTEN, NONE NEEDED.
- CLASSIFICATION: CASE B. `B5_EID5_END_TO_END = WAITING_FOR_DELIVERY`
  (not PASS, not BLOCKED - EID5 never reached post-receive).
- OWNER DECISION PENDING: authorise a production deploy of the current workspace
  build (which closes the parser gap), then let the backlog drain / replay and
  re-verify. E3 remains HOLD.
- Report: `/app/docs/B5_EID5_PRODUCTION_BLOCKER_RESOLUTION.md`
  Deployer RCA: `/app/deployer-agent-docs/RCA_d85f3698-86ec-4f79-ac6a-e1309f96cd13.MD`
- DEPLOYED: NO · PROD_RESTARTED: NO · CONFIG/SECRET_CHANGED: NO · DATA_CHANGED: NO ·
  ENDPOINT_CHANGED: NO · SENSOR_CHANGED: NO · OUTBOX_TOUCHED: NO · UI_CHANGED: NO ·
  PREVIEW_EVIDENCE_USED: NO · E3: NOT STARTED.


### 2026-09-29 — P0 PRODUCTION REGRESSION AFTER PUBLISH 100 (tenant authorization)
- SYMPTOM: `edr.nivxforge.com` logged in as `admin@nivxray.com`, customer
  "Internal Validation": Computers / Events / Dashboard freshness all 403
  `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL ... basis NOT_AUTHORIZED · tenant
  ten_e759b7288598bd882e3dcac49d`. Worked on Publish 99, broke on Publish 100.
- ROOT CAUSE (PROVEN in source): Publish 99 was built from `fdb9c05a`
  (2026-09-27T09:37) where `dashboard_lenses.resolve_tenant_scope` granted
  `all_tenants: True` from ROLE alone
  (`_CROSS_TENANT_ROLES = {admin, platform_admin, soc_manager, mssp_operator}`).
  Publish 100 contains `730ec4f5` (2026-09-28T07:31, P0-FIX-6B-2) which RETIRED
  role-derived breadth: breadth now requires `users.authority_scope == "PLATFORM"`
  exactly, or the tenant to be inside explicit `users.tenant_ids[]`.
  The production `users` doc for admin@nivxray.com never received the explicit
  designation, because `scripts/fix6b1b_platform_designation.py` does
  `load_dotenv("/app/backend/.env")` -> it only ever ran against a NON-production
  store. PREVIEW (reference only) holds `authority_scope: "PLATFORM"`,
  `tenant_ids: ["default","nivx-live"]` — note ten_e759 is NOT in the grants, so
  Internal Validation access depended ENTIRELY on the retired role breadth.
  => New build fails closed, CORRECTLY. Boundary intact.
- Auth-plane diff P99->P100: `edr_tenancy.py` +179, `session_context.py` +119,
  `tenant_registry.py` +142, `server.py` +19 (P0-FIX-1 authorization-before-registry,
  P0-FIX-2 non-disclosing refusal, P0-FIX-5A unconditional registry, P0-FIX-6B-2).
- DATA_LOSS = NO: the 403 is raised in the `edr_tenant()` dependency before any
  evidence query runs. Last authoritative prod measurement (P99, 15:28-15:33Z):
  endpoint `ep_1989031c8c1d0085812f` present, 116,012 `edr_raw_events`, ingest 200 OK.
- REPAIR_CLASS = GRANT_RESTORE (production DATA/designation continuity, NOT a code
  fix, NOT rollback, NOT a broadening). Options proposed, NONE executed:
  (1) idempotent startup designation from an explicit env var
      (e.g. `NIVX_PLATFORM_PRINCIPAL`), server-side only, + deploy;
  (2) run the existing owner-approved `fix6b1b_platform_designation.py` against
      production (needs prod Mongo access; its `EXPECTED_GRANTS` guard must match);
  (3) add `ten_e759...` to `tenant_ids[]` (narrowest, but repeats per customer).
  FORBIDDEN and not considered: arbitrary tenant ids, default-tenant fallback,
  trusting frontend tenant, registry bypass, all-tenants-for-all, disabling the
  refusal code, changing fail-closed, frontend-hardcoded tenant, moving telemetry.
- ROLLBACK NOT RECOMMENDED / NOT DONE: P100 carries the EID5 foundation + the four
  P0 tenant-authority fixes; reverting would reinstate role-string breadth.
- Read-only deployer diagnose dispatched for prod confirmation (tenant/endpoint/event
  existence, the prod `users` doc fields, authority_scope holders, P99<->P100 store
  continuity, 403 log/audit rows, and whether `/api/edr/agent/telemetry` is still 200).
  Async, had NOT returned when this was written; all unconfirmed items = NOT_PROVEN.
- `B5_EID5_END_TO_END = HOLD_PRODUCTION_AUTH_REGRESSION` (EID5 replay NOT performed).
- Report: `/app/docs/P0_PROD_TENANT_AUTH_REGRESSION_PUBLISH100.md`
- DEPLOYED: NO · REPUBLISHED: NO · ROLLED_BACK: NO · REPAIR_APPLIED: NO ·
  DATA_CHANGED: NO · ENDPOINT/SENSOR/SYSMON/OUTBOX_CHANGED: NO · REPLAYED: NO ·
  TENANT_ISOLATION_WEAKENED: NO · E3: NOT STARTED.


### 2026-09-29 — P0 REPAIR (OPTION A): EXPLICIT PLATFORM DESIGNATION BOOTSTRAP
- NEW `backend/services/platform_designation.py`, called from `server.py` startup
  right after `seed_admin`, against the backend's own `db.users` (no second
  connection string). Reads explicit env `NIVX_PLATFORM_PRINCIPAL`; for exactly
  that one principal sets exactly one field `users.authority_scope = "PLATFORM"`
  when absent. Machine-readable outcomes: `NOT_CONFIGURED` / `UPDATED` /
  `ALREADY_CONFIGURED` / `REFUSED_MALFORMED_PRINCIPAL` /
  `REFUSED_PRINCIPAL_NOT_FOUND` / `REFUSED_PRINCIPAL_AMBIGUOUS` /
  `REFUSED_CONFLICTING_AUTHORITY_SCOPE` / `REFUSED_AUTH_STORE_UNREACHABLE` /
  `REFUSED_DESIGNATION_NOT_VERIFIED`. Writes nothing on any refusal, logs ERROR,
  never crashes startup, reads back and verifies after writing.
- `backend/.env` gained `NIVX_PLATFORM_PRINCIPAL=admin@nivxray.com`. THIS VAR MUST
  EXIST IN PRODUCTION or the designation is a documented NO-OP and the 403s persist.
- Does NOT reintroduce `_CROSS_TENANT_ROLES`; `role == "admin"` still confers no
  breadth; no wildcard/default-tenant fallback; never touches role, password,
  tenant_ids, tenants, endpoints, evidence, sensor, Sysmon, outbox or the frontend.
- Preview runtime proof (NOT production evidence): startup logged
  `[platform-designation] result=ALREADY_CONFIGURED principal=admin@nivxray.com`
  (this store was designated in June), /api/health ok — the idempotent branch works
  against a real MongoDB.
- TESTS: new `backend/tests/edr/test_p0_platform_designation.py` = 22 passed, covering
  owner requirements A-J (incl. exact `$set` payload assertion, ambiguity/conflict/
  malformed/unreachable fail-closed, no auto-grants, role-confers-nothing,
  `X-Tenant-Id` never self-authorises). Existing: fix6b2+fix1+fix2 = 83 passed;
  cross_tenant + trajectory isolation = 51 passed; a05 scope contract = 72 passed.
  Total 228 passed, 0 failed.
- DISCLOSED UNRELATED: `test_a05_tenant_scope_contract.py::test_the_guard_is_not_vacuous`
  passes but its module-scoped `_seed` fixture TEARDOWN errors with a litellm
  `APIConnectionError: cannot schedule new futures after interpreter shutdown`.
  Pre-existing artifact, untouched code path, not in any gate step list.
- PRODUCTION REPUBLISH DISPATCHED (owner-approved) with explicit no-rollback /
  no-routing / no-registry / no-telemetry / no-sensor / no-replay constraints and the
  `NIVX_PLATFORM_PRINCIPAL` requirement called out. Post-deploy read-only proof
  requested: run id + health, env var PRESENCE, verbatim `[platform-designation]` log
  line, production `users` read-back (`role`/`authority_scope`/`tenant_ids`/`status`
  only) with exactly one authority holder, EDR read-route status codes for
  `ten_e759b7288598bd882e3dcac49d`, sensor route health + newest ingest, startup
  errors, and `edr_raw_events >= 117,904`.
- Deploy is async and UNCONFIRMED at time of writing: `AUTHORITY_SCOPE_AFTER`,
  `COMPUTERS_ACCESS`, `EVENTS_ACCESS`, `DEVICE_TRAJECTORY_ACCESS`,
  `INTERNAL_VALIDATION_ACCESS`, `DESKTOP_A9HGFJJ_VISIBLE` = NOT_PROVEN.
- `B5_EID5_END_TO_END = HOLD` (authorization proof pending). No EID5 replay. No E3.
- Report: `/app/docs/P0_PLATFORM_DESIGNATION_OPTION_A.md`
- ROLLED_BACK: NO · ROUTING/DOMAIN_CHANGED: NO · REGISTRY_CHANGED: NO ·
  EVIDENCE/TELEMETRY_CHANGED: NO · ENDPOINT/SENSOR/SYSMON/OUTBOX_CHANGED: NO ·
  REPLAYED: NO · ISOLATION_WEAKENED: NO · UI_CHANGED: NO.


### 2026-09-29 — P0 PLATFORM DESIGNATION: PRODUCTION VERIFIED (PASS at the data layer)
- New prod run **`3bd64025-51ac-4d8b-a5e2-52c900a4c3b4`** live on cluster
  **target-7**, supersedes pre-repair `0aba534a`. PROD_HEALTH = HEALTHY, BOTH
  replicas Running/ready, restart_count 0. The old target-6 second-replica
  `FailedCreatePodSandBox` / node-IP-exhaustion problem is GONE on this run.
- `NIVX_PLATFORM_PRINCIPAL_PRESENT = YES` (secret present, non-empty,
  matches_expected=true; value never printed).
- Startup log, new run, 2026-09-29T17:21:04Z:
  `[platform-designation] result=UPDATED principal=admin@nivxray.com
   previous_authority_scope=ABSENT new_authority_scope=PLATFORM`
  Second replica 17:21:12Z: `result=ALREADY_CONFIGURED` — the idempotent NO-OP
  path proven across replicas. No `REFUSED_*` code anywhere.
- Production DB `greeting-app-5782-test_database`: `admin@nivxray.com`
  role=admin, **authority_scope=PLATFORM**; `tenant_ids` and `status` ABSENT;
  `PLATFORM_AUTHORITY_HOLDER_COUNT = 1` (distinct=["PLATFORM"], total users=1,
  users with non-empty tenant_ids = 0). No collateral field or principal changed.
- `DATA_LOSS = NO`: `edr_raw_events` 118,496 (>= 117,904), `xdr_canonical_evidence`
  45,666 (>= 45,355), `v2_shadow_observations` 45,674 cross-check, endpoint
  `event_count` 118,512. NB `xdr_canonical_events` holds only 5 docs and is NOT
  the canonical evidence store.
- `DESKTOP_A9HGFJJ_VISIBLE = YES` in `edr_endpoints`: `ep_1989031c8c1d0085812f`,
  tenant `ten_e759b7288598bd882e3dcac49d`, ENROLLED / REPORTING.
- `PLATFORM_REPAIR_PRODUCTION = PASS` (data layer).
- **NOT_PROVEN (not failed)**: `COMPUTERS_API`, `EVENTS_API`,
  `DEVICE_TRAJECTORY_API`, `SENSOR_RECEIVE`, the live tenant-scoped read PATH, and
  re-emission of `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`. Reason: ZERO post-rollout
  API/sensor traffic reached the new run, and per owner constraints the browser was
  not driven and no principal was manufactured. `CONSOLE_AUTHORIZATION` data
  precondition SATISFIED; end-to-end confirmation pending owner console refresh.
- WATCH ITEM: sensor telemetry is STALE relative to the new run — newest
  `ingest_time` / `last_telemetry_at` = 17:14:29Z, which PREDATES go-live
  (~17:19-17:21Z); `outbox_queue_depth` = 6,468 (was 7,181). Expected during a
  rollout (sensor retries + spools), but if the sensor does not resume reporting
  against run `3bd64025` this becomes a NEW issue to investigate. Nothing changed.
- UNRELATED PRE-EXISTING errors on the new run (NOT from the repair, not fixed):
  (1) threatfox TI feed 401 Unauthorized (abuse.ch `ABUSE_CH_AUTH_KEY`);
  (2) `nightly benchmark failed: can't subtract offset-naive and offset-aware
  datetimes` — a datetime bug in the benchmark job.
- `B5_EID5_END_TO_END` = still HOLD until the console is confirmed restored and the
  sensor is reporting to the new run. No EID5 replay. No E3.
- Deployer RCA: `/app/deployer-agent-docs/RCA_3bd64025-51ac-4d8b-a5e2-52c900a4c3b4.MD`
- DEPLOY/REDEPLOY/ROLLBACK/RESTART/WRITE during verification: NONE.


### 2026-09-29 — B5 TRAJECTORY FRESHNESS TRACE (prod run 3bd64025): H2 CONFIRMED, H1 REFUTED
- `SENSOR_FRESH_TELEMETRY = PASS`. 228 new `edr_raw_events` after the 17:14:29Z
  checkpoint; newest ingest 17:45:20.558821Z; newest raw doc
  `source=ep_1989031c8c1d0085812f`, `source_kind=sensor`, `trust_state=AUTHENTICATED`,
  IP 136.110.164.121, `sensor_version=0.2.0-windows`, `computer=DESKTOP-A9HGFJJ`.
  Endpoint `last_heartbeat_at=17:39:39Z`, `last_telemetry_at=17:40:33Z`,
  `event_count=118,613`, REPORTING/CONNECTED. Agent routes 200x39, 401x1 (the 401 at
  17:45:10 was followed by `/agent/session` 200 and telemetry resumed — normal
  session re-auth). `outbox_queue_depth` 6,468 -> **6,870 (GREW)**: the host is
  generating slightly faster than the spool drains.
- **H1 (identity split) REFUTED — my suspicion was wrong, recorded plainly.**
  `dev_2adbb41a04a4` IS the sensor stream normalised:
  `collector_id = connector_id = ep_1989031c8c1d0085812f`, adapter
  `nivxforge-linux-sensor/1.0.0`. The `origin=collector-live` tag is adapter
  provenance, NOT a second ingestion route. `ENDPOINT_IDENTITY_SPLIT = NO`.
- **H2 (window selection) CONFIRMED.** Per-day obs for `dev_2adbb41a04a4` by
  `captured_at` UTC: Sep25=208, Sep26=24,068, Sep27=16,251, Sep28=3,847, Sep29=503.
  The console URL pins `event=evt_df9d1ced51b6cc9c;349092413`, fixing the window to
  2026-09-20T17:23:33Z-17:53:33Z. The "45,666 / 45,666" counter is the DEVICE total,
  not window content — which is why nothing looked missing. NO backend change needed:
  clear the pinned `event=` param or move/widen the window to Sep 27-29.
- Latest canonical for the host: `event_time 2026-09-29T10:36:10.339487Z` /
  `ingest_time 17:41:09.611631Z` (`xdr_canonical_evidence`,
  `host.host_id=ep_1989031c8c1d0085812f`, 45,665 docs). Trajectory newest observation
  `captured_at 10:36:10Z`.
- **EID5 STILL NOT DELIVERED.** Sysmon EID5 = 0 (EID1 control = 212, matcher valid);
  all 10 ProcessGuids = 0 across raw/retained/canonical/shadow.
  **REPLAY FRONTIER (measured):** 15:32Z wall -> frontier 07:32:08Z (lag ~8h);
  17:45Z wall -> frontier **10:41:31Z** (lag ~7h04m). Frontier advanced 3h09m of
  event-time in 2h13m of wall-clock (~1.4x realtime) and is still ~4h07m short of the
  14:48-14:50Z EID5 batch.
- **DISAGREEMENT RECORDED:** the deployer recommended investigating Sysmon EID5
  collection/forwarding on the host. NOT acted on — premature and contradicted by the
  frontier measurement plus the owner's own local proof of EID5 generation and
  ProcessGuid pairing. DO NOT touch Sysmon / sensor / outbox.
- CANONICALISER COVERAGE NOW SATISFIED: run `3bd64025` was built from this workspace,
  which carries `("sysmon", 5): ACTIVITY_PROCESS_TERMINATION` (windows_eventlog.py:83)
  and `"exit_time": activity_time` (line 680). The old build's
  `WINDOWS_EVENT_ID_NOT_SUPPORTED` refusal for EID5 is closed on the live runtime.
  (Statement about the deployed COMMIT; the first arriving EID5 is the runtime proof.)
  winsec 5379 refusals are correct — that family genuinely is unsupported; records stay
  retained and replayable.
- `B5_EID5_END_TO_END = WAITING_FOR_DELIVERY` — not PASS (no genuine EID5 arrived),
  not BLOCKED (no defect anywhere: delivery active, identities converged, canonicaliser
  supports EID5, projection healthy).
- Report: `/app/docs/B5_TRAJECTORY_FRESHNESS_TRACE.md`
  Deployer RCA: `/app/deployer-agent-docs/RCA_3bd64025-51ac-4d8b-a5e2-52c900a4c3b4.MD`
- DEPLOYED/REPLAYED/BACKFILLED/RESTARTED/WRITTEN: NONE · ENDPOINT/SENSOR/SYSMON/OUTBOX:
  UNTOUCHED · UI_CHANGED: NO · E3: NOT STARTED.


### AGREED STANDING STATE (2026-09-29, owner-confirmed)
```
SENSOR DELIVERY        = PASS
IDENTITY CONVERGENCE   = PASS
TRAJECTORY PROJECTION  = PASS
EID5 END-TO-END        = WAITING_FOR_DELIVERY
B5                     = HOLD
```
- Console "stale trajectory" is CLOSED as a URL/window artifact. Owner verifies by
  opening `/edr/device-trajectory?device=dev_2adbb41a04a4` with NO `event=` param and
  jumping to Sep 29. No code change.
- The ONLY thing B5 waits on: the replay frontier reaching 14:50Z naturally.
  Last proven frontier 2026-09-29T10:41:31Z -> ~4h of event-time still ahead.
  DO NOTHING until then: no deploy, replay, backfill, Sysmon change, sensor restart
  or outbox modification.
- WHEN the frontier crosses 14:50Z, run ONE read-only check proving the full chain:
  EID5 received -> accepted -> canonicalized as `process_exit` -> `UtcTime` mapped to
  `exit_time` (never `start_time`) -> ProcessGuid bound -> lifecycle projected ->
  visible in Device Trajectory. That is the B5 closure proof.

### NEW BACKLOG ITEM (P2, AFTER B5) — sensor outbox drain rate
- `outbox_queue_depth` grew 6,468 -> 6,870 while the frontier advanced, i.e. the host
  generates telemetry faster than the sensor drains it at times. NOT evidence loss and
  NOT urgent, but a production sensor must not permanently accumulate backlog.
- Investigate after B5 closes: per-batch event count / report interval / payload size
  caps, server-side accept latency (raw ingest was ~700-3200 ms per POST on tier_0),
  and whether the single-replica period on target-6 depressed throughput. Compare
  generation rate vs delivery rate over a fixed window before changing any setting.


### 2026-09-29 ~18:00Z — B5 FRONTIER CHECK #1 (read-only, run 3bd64025)
- FRONTIER = `payload.observed_at` **2026-09-29T11:00:48.600109Z** (newest-ingested raw
  for `ep_1989031c8c1d0085812f`; that event = Sysmon EID 12 RegistryEvent,
  TimeCreated 09:39:55.70Z). Newest `ingest_time` = 17:58:13.154329Z.
- Endpoint: `outbox_queue_depth` **6,698**, `last_heartbeat_at` 17:53:29.295Z,
  `last_telemetry_at` 17:58:06.127Z, `event_count` **119,118**,
  `report_interval_seconds` 30, REPORTING.
- ADVANCEMENT: frontier 10:41:31Z -> 11:00:48.6Z = **+19m17.6s event-time** over
  **12m52.6s wall** => ratio **1.498 event-seconds per wall-second** (gaining).
- QUEUE TREND: 6,468 -> 6,870 -> **6,698**. Most recent step DECLINED (-172 in 772.6 s
  = -0.223 items/s) => immediate trend CONVERGING, still +230 above the first reading.
- EID5 STILL NOT RECEIVED: Sysmon EID5 = **0**, with THREE controls proving the matcher
  (Sysmon EID1 = 212, Sysmon EID12 = 22,663, and the ProcessGuid regex validated
  against a known present guid = 1,055 hits). 10 target ProcessGuids = 0 in
  `edr_raw_events`, `xdr_ingest_raw_retained`, `xdr_canonical_events`,
  `v2_shadow_observations`. Downstream zero is EXPECTED because raw is zero.
- Trajectory projection confirmed LIVE for `dev_2adbb41a04a4`; newest `captured_at`
  11:07:39.471Z = a winsec 4624 logon_success, NOT an EID5.
- REMAINING GAP to the 14:50:00Z target = **3h49m11.4s of event-time**.
  ETA (ESTIMATE, not a measurement; assumes constant 1.498 ratio, strictly in-order
  chronological delivery, steady cadence): ~**2h33m** => ~**2026-09-29T20:31Z**.
  NOTE the target is a FIXED event-time, so the ETA is gap / ratio; it is NOT
  gap / (ratio - 1), which would only apply to catching up to live wall-clock.
- DERIVED ARITHMETIC from the measured numbers (labelled derivation, not a measurement):
  `event_count` 118,613 -> 119,118 = **505 events delivered in 772.6 s = 0.654 ev/s**,
  covering 1,157.6 s of event-time => implied historical generation rate
  **0.436 ev/s**; net drain **0.217 ev/s (~13/min)**. At that net rate the queue would
  reach live in ~8.6 h, but only ~2h33m is needed for the frontier to cross 14:50Z.
- THROUGHPUT DIAGNOSTIC (read-only, for a LATER decision — no action taken):
  `POST /api/edr/agent/telemetry` = 14 sampled requests over 36.6 s, ALL HTTP 200,
  latency 1.57-5.44 s (mean ~2.68 s, one slow path 5,443 ms), frequency ~1 per 2.8 s
  (~21/min) i.e. effectively SERIALIZED back-to-back — the sensor is in catch-up mode,
  far faster than its 30 s report interval. Events-per-batch NOT_PROVEN (bodies not
  logged). Runtime tier_3 "Scale", replicas 2, **max_replicas 2, HPA DISABLED (cannot
  scale out)**, VPA enabled, cpu 1/limit 2, mem 4Gi/limit 8Gi; both pods Running/Ready,
  restart_count 0. History: VPA Updater evicted pods `rt59j`/`9gt7j` to apply resource
  recommendations, transient 503 probe failures ~17:20-17:42Z, now stable.
  => fixed 2 replicas + serialized ~2.68 s/request = marginal drain vs continuous
  generation, which matches the grow-then-slightly-converge queue pattern.
- `B5_EID5_END_TO_END = WAITING_FOR_DELIVERY`. No remediation. Endpoint / sensor /
  Sysmon / outbox untouched and not proposed for change. No deploy/replay/backfill.


### 2026-09-30 ~00:00Z — B5 EID5 FINAL CLOSURE CHECK (run 3bd64025): ENGINE PROVEN, TARGET SET ABSENT
- FRONTIER = `payload.observed_at` **2026-09-29T20:49:33.258293Z** (newest ingest
  23:43:04.183228Z) — ~5h59m of event-time PAST the 14:50Z target. Outbox
  6,698 -> **2,078** (draining), rate ~1.707 event-s/wall-s. Not stalled, not slower.
- **THE EID5 ENGINE IS PROVEN ON GENUINE PRODUCTION EVIDENCE: 17 real Sysmon EID5
  (ProcessTerminate), UtcTime 15:17:21 -> 17:40:10Z**, full chain:
  raw received -> accepted (`edr_rejected_telemetry` = 0 for the endpoint) ->
  **17 canonical `process_exit`, exactly 1:1** (`cev_6e18d93e1d9ab03a5b765548_0`,
  `obs_bffdd00b25b0`) -> `field_provenance process.exit_time = "sysmon:UtcTime
  (EventID 5)"` with `start_time = null` -> ProcessGuid binding
  `SOURCE_PROCESS_IDENTITY`, `process_iid = nivx:ProcessIdentity.mint(endpoint_id,
  ProcessGuid)` -> **>=4 EID1/EID5 pairs** (f7fa-2b1e, f7fa-271e, dd70-211d,
  dd70-221d) -> projected under `dev_2adbb41a04a4` (captured_at e.g. 17:40:10.707Z)
  -> tenant `ten_e759b7288598bd882e3dcac49d` preserved, no heuristic cross-device
  binding, **no `_pl` authority minted**, no backfill.
  => `PROCESS_TERMINATION_OBSERVED` is now real, not `PROCESS_LIFETIME_UNKNOWN`.
- **MATCHER CONFLATION CAUGHT — record this permanently:** a bare
  `<EventID>5</EventID>` match returns **249** for this endpoint, conflating
  `Microsoft-Windows-IsolatedUserMode` EID5 (Secure Trustlet start, NOT a termination)
  with genuine `Microsoft-Windows-Sysmon` EID5. GENUINE Sysmon EID5 = **17**. All future
  EID5 counts MUST filter on provider GUID `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}`.
  Controls: EID1 = 636, EID12 = 28,776, ProcessGuid regex validated on a known-present
  guid (193 hits) — so 0/10 below is real, not a query artifact.
- **THE 10 TARGET PROCESSGUIDS ARE ABSENT: 0/10** in `edr_raw_events`,
  `xdr_ingest_raw_retained`, `xdr_canonical_events`, `v2_shadow_observations`;
  `$in` over all 10 vs `process_exit` = 0; regex `9949e5f2-cfb6-6abb` vs
  `process_exit` = 0. Their start-segments (`cfb6 ... d018`) precede the earliest EID5
  in raw (`d54c` ~ 15:17:21Z).
- `FIRST_BROKEN_BOUNDARY = RAW RECEIVED`. **A ~28-minute coverage gap: NO Sysmon EID5
  exists for ~14:48-15:16Z UtcTime, while EVERY EID5 from 15:17:21Z onward is present
  and fully processed.** Not a refusal (0 rejections), not a canonicalization/identity/
  projection failure (proven on the 17), not a wait condition (frontier ~6h past the
  slot, post-gap neighbours present). The 10 never entered the delivered stream.
- HYPOTHESES (NOT verified, endpoint NOT inspected or touched): (1) collection
  START-POINT — EID5 was enabled ~14:48-14:50Z while the sensor's Sysmon channel
  subscription/bookmark predated the config change; first collected EID5 is 15:17:21Z,
  ~28 min later, consistent with a policy/channel-coverage refresh rather than
  in-transit loss; (2) DIRECT-READ vs COLLECTED STREAM — the 10 guids were captured by
  the owner reading the local Sysmon log (the enablement script's own verification), and
  events visible to a direct read need not be inside the sensor's collected stream if
  they precede its coverage start point; (3) log position/rollover at config-change time.
  Distinguishing them needs a READ-ONLY endpoint look (do the 10 guids still exist in the
  local Sysmon log; what is the sensor's EID5 channel start point) — owner's call.
- `B5_EID5_END_TO_END = BLOCKED: target proof-set absent (engine PROVEN on 17 genuine EID5)`
- **OWNER DECISION PENDING.** Option 1 (RECOMMENDED): close B5 on the 17 genuine EID5 —
  the acceptance requirement was "genuine endpoint-generated EID5 reaches canonical
  evidence and binds by authoritative ProcessGuid", which IS satisfied; the 10 guids were
  only the chosen sample, not the capability. Option 2: keep B5 BLOCKED if the gate is
  defined strictly as those 10 guids — they cannot be made to appear, and re-emitting or
  reconstructing them is forbidden fabrication that would also destroy the
  ordinary-delivery-path property. Recommendation = Option 1 + open a named finding:
  **`B5-GAP-1` · Sysmon EID5 collection start-point coverage gap (14:48-15:16Z,
  DESKTOP-A9HGFJJ)**.
- Report: `/app/docs/B5_EID5_FINAL_CLOSURE_CHECK.md`
  Deployer RCA: `/app/deployer-agent-docs/RCA_3bd64025-51ac-4d8b-a5e2-52c900a4c3b4.MD`
- DEPLOYED/WRITTEN/REPLAYED/BACKFILLED: NONE · ENDPOINT/SENSOR/SYSMON/OUTBOX: UNTOUCHED ·
  E3: NOT STARTED.


### 2026-09-30 — OWNER DECISION: B5 CLOSED (Option 1) + EID5 COUNTER CONTRACT FIXED
```
B5_FINAL_STATUS      = PASS
B5_GAP_1_STATUS      = OPEN / ROOT CAUSE NOT YET PROVEN
EID5_PROVIDER_FILTER = IMPLEMENTED
REGRESSION_TEST      = 18 new PASS · full EDR gate suite 1,738 passed, 0 failed
B5_READY_TO_LEAVE    = YES
```
- **B5 = PASS** on the 17 genuine production Sysmon EID5 (UtcTime 15:17:21 -> 17:40:10Z,
  run 3bd64025, store `greeting-app-5782-test_database`): raw -> accepted (0 refusals)
  -> 17 canonical `process_exit` 1:1 -> `exit_time = "sysmon:UtcTime (EventID 5)"`,
  `start_time` null -> ProcessGuid via `nivx:ProcessIdentity.mint(endpoint_id,
  ProcessGuid)` -> >=4 EID1/EID5 pairs -> lifecycle termination observed -> projected
  under `dev_2adbb41a04a4` -> tenant preserved, no `_pl`, no backfill.
- The original 10 ProcessGuids are NOT required for the capability gate and MUST NEVER
  be replayed, reconstructed, backfilled or synthesized. None was.
- **B5-GAP-1 OPEN**: Sysmon EID5 collection start-point coverage gap ~14:48-15:16Z on
  DESKTOP-A9HGFJJ. Measured: no Sysmon EID5 in that 28-min window; every EID5 from
  15:17:21Z on is present and processed; 0/10 guids anywhere; 0 refusals; frontier
  passed the window by ~6h. The "sensor subscription predated the Sysmon config change"
  story is a HYPOTHESIS ONLY — NOT root cause. Proving it needs READ-ONLY endpoint
  evidence (do the 10 guids still exist in the local Sysmon log; where does the sensor's
  EID5 coverage start). Deferred by owner; endpoint/sensor/Sysmon/outbox untouched.
- **EID5 MEASUREMENT CONTRACT CORRECTED** in `backend/edr_plane/windows_eventlog.py`:
  - `SYSMON_PROVIDER_GUID = "5770385F-C22A-43E0-BF4C-06F5698FFBD9"`.
  - `FAMILY_PAYLOAD_REGEX["sysmon"]` now also matches the provider GUID
    (`"provider_guid"` JSON key, XML `Guid='...'`), XML `<Channel>` and XML
    `Provider Name='...'`. Every alternative stays KEYED to a field/attribute, so a
    command line merely mentioning Sysmon cannot qualify a record.
  - NEW `event_id_regex(event_id)` (JSON **and** event-XML shapes).
  - NEW `sysmon_event_clause(event_id, payload_field="payload")` = THE sanctioned
    find() clause, provider AND event id; works on other fields e.g. `raw.xml`.
  - NEW `is_sysmon_event(payload, event_id)` for corpus counting.
  - `payload_event_id_regex` docstring now says **PROVIDER-BLIND — never use alone to
    COUNT a Sysmon event id**.
  - NOTE: product queries (`activity_query_clauses`, `activity_projection_expr`) were
    ALREADY provider-qualified, so no live query was ever wrong — the defect lived in
    ad-hoc measurement. A bare `EventID=5` count returned 249 vs 17 genuine (the rest
    `Microsoft-Windows-IsolatedUserMode` EID5 Trustlet starts) = 14x overstatement.
- NEW `backend/tests/edr/test_b5_sysmon_provider_qualified_counting.py` (18 tests):
  genuine Sysmon counts in 4 payload shapes; IsolatedUserMode EID5 does NOT count in
  either shape; provider-less event id does not count; "sc query Sysmon" in a command
  line is not provenance; wrong event id on right provider does not count; `5` not
  matched inside `5379`; **the 249-vs-17 defect in miniature** (3 Sysmon + 16 Trustlet
  + noise => exactly 3, and asserts a provider-blind count overstates); sanctioned
  clause shape; canonicaliser maps Sysmon EID5 -> ACTIVITY_PROCESS_TERMINATION and
  REFUSES IsolatedUserMode EID5; and the B5 invariant `exit_time` <- UtcTime with
  `start_time` null re-proved.
- DISCLOSED SELF-INFLICTED DEFECT, FIXED: the platform-designation tests added in the
  previous step used `asyncio.get_event_loop().run_until_complete(...)`, which fails
  once another async test replaces/closes the loop — 17 failures in a full-suite run
  though green in isolation. Replaced with a fresh `asyncio.new_event_loop()` per call
  closed in `finally`. Full suite now 1,738 passed / 0 failed. The provider-qualified
  matcher caused none of those failures.
- Invariants re-verified: `UtcTime -> exit_time` only · never `start_time` · ProcessGuid
  authoritative · no PID/time/name heuristic binding · EID5 never leaves
  PROCESS_LIFETIME_UNKNOWN · no historical backfill · tenant isolation · no new `_pl`.
- Report: `/app/docs/B5_CLOSURE_RECORD.md`
- E3: **NOT STARTED** (owner order: review first, then B5-GAP-1, then E3).
  NOT DEPLOYED — the corrected matcher reaches production on the next ordinary publish.
  No endpoint/sensor/Sysmon/outbox contact · no replay/backfill/synthesis · no UI change.


---

## 2026-06 · B5-GAP-1 — WINDOWS SENSOR LOSSLESS ACQUISITION + LOCAL EVIDENCE JOURNAL
### IMPLEMENTED · LOCAL/FOCUSED TESTS PASS · **NOT DEPLOYED** · owner-review gate open

**B5 remains CLOSED / PASS.** B5-GAP-1 was a separate, and far larger, defect.

**Root cause — `B5_GAP_1_ROOT_CAUSE = PROVEN`.** NOT EID5-specific. A GENERAL
Windows acquisition / scheduling / durability defect in
`agents/nivxforge-windows/nivxforge_sensor.py` @ `6afab68a`:
hardcoded `/c:100` page (L265), **no pagination** — one query per channel per cycle
(`collect()` L334-336), acquisition serialized behind up to **200 sequential POSTs**
(`_drain` L487, `run()` L552-587) at a measured ~2.68 s each => cycle period
~10-22 min, capacity ~0.1 rec/s against ~20 rec/s Sysmon production; the circular
64 MiB EVTX (`retention=false`) then rotated past the cursor and **nothing compared
the returned RecordID against cursor+1**, so the loss was SILENT and every cycle
reported `collected: 100`.
Production signature: 100 records @14:45Z (8470086-8470185), ZERO for ~22 min,
100 records @15:07Z (8496595-8496694) — a 26,410 RecordID jump.
Read-only review: `/app/docs/B5_GAP_1_ROOT_CAUSE_READONLY.md`.

**EARLIER HYPOTHESIS CORRECTED AND PRESERVED:** the cursor never jumped to the
channel tail. It advanced only to `max(record_id parsed)`, and enqueue+fsync already
preceded the cursor commit. Both correct properties were KEPT, not replaced.

**What was built**
- **NEW `agents/nivxforge-windows/nivxforge_journal.py`** (741 lines) — LOCAL EVIDENCE
  JOURNAL. `sqlite3` stdlib + WAL + `synchronous=FULL` + `auto_vacuum=INCREMENTAL`,
  chosen because the endpoint artifact is a PyInstaller bundle: no new dependency, no
  broker, no service-account or ACL change. Kafka/Redis/Mongo on the endpoint rejected.
- **PRIMARY INVARIANT enforced structurally:** evidence rows + detected gaps + the
  channel cursor are **ONE `BEGIN IMMEDIATE ... COMMIT`**, so the source cursor can
  never advance beyond the last record durably owned by NivXForge. A failed write
  rolls back and the cursor does not move; `UNIQUE(channel, source_record_id)` makes
  the re-read idempotent. Crash case A is structurally impossible, not merely handled.
- **PAGED acquisition** (`acquire()` replaces `collect()`): page loop per channel,
  round-robin one page per pass for fairness, `/rd:false` oldest-first asserted by
  test (`/rd:true` would be the tail-jump defect everyone assumed this was).
- **WALL-CLOCK budgets** per stage (acquire 15 s, deliver 30 s, legacy outbox 7.5 s at
  interval 30) — a message count cannot bound time at 2.68 s/POST, which is exactly
  how delivery came to own the whole cycle. Gate 7 exclusion adjudication is fsynced
  BEFORE the cursor advances, so Gate 7 semantics are unchanged.
- **ACQUISITION GAP AUTHORITY**: LEADING + INTERIOR discontinuity detection, contract
  `{expected_next_record_id, first_observed_record_id, missing_start/end,
  missing_record_id_count, cause: "NOT_PROVEN", classification:
  "SOURCE_RECORD_DISCONTINUITY"}`. Production case verified: 8470186..8496594 = 26409.
  Cause is NEVER labelled `LOG_ROLLOVER`. `SOURCE_ROLLOVER_RISK` is emitted ONLY when
  a measured head/tail probe shows the source's oldest surviving record is newer than
  our cursor — never deduced from a delivery backlog.
- **BOUNDED capacity** judged on `journal_live_bytes` (not the SQLite file high-water
  mark, which never shrinks and would fabricate a permanent outage) + real
  `min_free_bytes`. 512 MiB / 70% warn / 90% critical / 1 GiB free-disk floor. At
  critical: reclaim accepted rows, re-measure, then **HALT acquisition** with
  `ACQUISITION_HALTED_JOURNAL_FULL`. Never overwrites or drops unacknowledged evidence.
- **SENT != ACCEPTED.** `BACKEND_ACCEPTED` only on a 2xx for that row; that response is
  the named acknowledgement authority and the only thing authorising reclamation.
  There is deliberately no `RECLAIMABLE` row state.
- **Integrity monitor** — machine-readable `acquisition_integrity.json` (0600, atomic
  replace) every cycle + health states HEALTHY / DEGRADED / ACQUISITION_LAGGING /
  ACQUISITION_GAP / ACQUISITION_HALTED_JOURNAL_FULL / JOURNAL_PRESSURE /
  JOURNAL_CRITICAL / JOURNAL_CORRUPT / DELIVERY_BACKLOG / BACKEND_UNREACHABLE /
  CHANNEL_UNAVAILABLE / SOURCE_ROLLOVER_RISK. Per-channel `query_ms_last/max` recorded
  so the unindexed `EventRecordID>N` scan question is decided on evidence later.
- **Migration** idempotent, guarded by `meta.legacy_migrated_at`: adopts the live
  cursors (Security 284760 / System 22702 / Sysmon 8969348) with `MAX()` so a stale
  bookmark cannot drag one backwards; NO reset, NO Event Log replay, NO history import;
  `outbox.jsonl`/`outbox.offset` untouched and still drained; `channels.json` kept as a
  NON-AUTHORITATIVE mirror so rollback works. Corruption is renamed+preserved with
  `journal_fault.json`, never deleted or truncated.
- **NO BACKEND CONTRACT CHANGE.** `HeartbeatBody` and `TelemetryBody` are both
  `extra="forbid"`, so publishing integrity fields would 422 every production
  heartbeat. Integrity stays local; gaps are journaled `reported=0` awaiting an
  approved transport.

**Incidental defect corrected in the rewritten call site:** `nvx_excl.partition()`
returns `(kept, suppressed_count: int)`; the old `run()` called `len(excluded or [])`
on it, raising `TypeError` the moment a COLLECTION-scoped exclusion actually matched
(masked because `0 or []` yields `[]`).

**Tests — 57 NEW, all pass; `backend/tests/edr/` full suite 1885 passed / 3 skipped**
- `fixtures_b5_gap1_source.py` — deterministic circular-channel harness (no wevtutil,
  no HTTP, no endpoint; all TEST/SYNTHETIC).
- `test_b5_gap1_paged_acquisition.py` (24) — paging 0/1/99/100/101/200/201/1000/10000,
  page-size + `/rd:false` argv assertion, per-channel ceiling as a PAUSE not a skip,
  gap matrix incl. the production 26409 case, fairness, channel-failure isolation.
- `test_b5_gap1_journal_durability.py` (28) — crash cases A-E with a genuinely
  read-only connection (not a mock), corruption quarantine, delivery
  normal/slow/down/retry/recovery/ordering, pressure + halt + live-bytes capacity,
  identity/tenant/credential-absence, EID1+EID5 with ProcessGuid and
  provider-qualified counting through the journal, migration idempotency.
- `test_b5_gap1_stress_and_silent_loss.py` (5) — §23 stress 10,000 (acquired ==
  journaled == accepted == 10000, 0 gaps, 0 duplicates), §24 failure injection
  (1,500 records/cycle x 8 cycles against a trickling backend: backlog GROWS, zero
  gaps, zero loss), rotation declared not hidden, rollover risk measured not deduced,
  and a **pre-fix counterfactual** reproducing 100 -> 26,410 jump -> 100 then proving
  the fixed path takes all 26,609.
- Synthetic throughput (NOT a production claim): ~28,900 acquire/s, ~615 deliver/s.

**Remaining risks (full list in the doc)**
1. Acquisition integrity not visible in the console — needs an approved backend
   contract. 2. `wevtutil` scan cost still unproven in production; now measured.
3. **Delivery is still ~11 msgs/cycle at 2.68 s/POST — a 20 rec/s endpoint holds a
   growing journal backlog; 512 MiB ~= 270,000 records ~= 3.7 h of headroom before
   JOURNAL_PRESSURE. This makes backlog Issue 2 (telemetry POST latency/batching) the
   next production-critical item.** 4. B3 file hashing still inside acquisition
   (capability-gated OFF; surfaces as ACQUISITION_LAGGING). 5. Tail probe adds 6 cheap
   wevtutil calls/cycle (disableable). 6. The historical B5-GAP-1 records remain
   unrecoverable — nothing backfills or reconstructs them, by design. 7. Not yet
   exercised on real Windows; the frozen bundle must be rebuilt so `sqlite3` is packed.

**Files:** `agents/nivxforge-windows/nivxforge_journal.py` (new),
`nivxforge_sensor.py` (0.2.0 -> 0.3.0-windows), `build/build_windows_installer.ps1`
(`--hidden-import nivxforge_journal`, `sqlite3`), 4 new test files,
`/app/docs/B5_GAP_1_ACQUISITION_DURABILITY_FIX.md`.
No backend route/model/tenancy/response-authority/Device-Trajectory change. E3 NOT
STARTED. No deploy, no endpoint contact, no sensor restart, no Sysmon or channels.json
or outbox change, no replay, no backfill.

### Next (owner-gated)
- P0: owner approval -> Windows build -> canary acceptance (procedure §25 of the doc).
- P0: telemetry POST latency / batching (backlog Issue 2) — now the binding constraint
  on delivery, and the reason the journal backlog grows.
- P1: approved backend contract to publish ACQUISITION_GAP + integrity to the console.
- P1: E3 deterministic detection engine hardening (after the above).

---

## 2026-06 · B5-GAP-1 PRE-PRODUCTION HARDENING · GATES A-D
### GATES B/C/D PASS · GATE A WIRED BUT NOT RUN (needs a Windows runner) · **NOT DEPLOYED**

Record: `/app/docs/B5_GAP_1_PREPROD_HARDENING_GATES_A_D.md`. `DESKTOP-A9HGFJJ`
untouched (no install, no restart, no Sysmon/channels.json/outbox change, no
replay, no backfill). B5 remains CLOSED/PASS. Owner review gate open.

**GATE A — WINDOWS_ARTIFACT_BUILD = NOT_RUN (blocked, not failed).** PyInstaller
cannot cross-compile a Windows PE from Linux; `windows-sensor-installer.yml` runs on
`windows-latest` and there is no Windows runner in this workspace. Instead the
artifact now proves the journal ABOUT ITSELF: NEW frozen CLI subcommand
`NivXForgeEDRSetup.exe journal-selftest` (`nivxforge_setup.journal_selftest`) checks
sqlite3 importable + library version, `nivxforge_journal` importable, DB create/open,
`PRAGMA journal_mode=wal`, `PRAGMA synchronous==2`, `auto_vacuum==2`, all five tables,
durable commit, cursor commit, replay idempotency, integrity snapshot, gap contract.
Wired as **ACCEPTANCE GATE 0** in the Windows workflow and it REQUIRES `"frozen": true`
so a system-Python pass can never be mistaken for an artifact pass. Verified locally:
`result: PASS`, `frozen: false` (honest — not the frozen binary). Gate wiring is itself
under test. Items 9/10 PASS by inspection: sqlite3 is stdlib, requirements/pip list/
spec/signing/ACL/service definition all unchanged; only two `--hidden-import` flags
added. **To close Gate A: one Windows CI run.**

**GATE B — DELIVERY_ROOT_CAUSE = PROVEN. THREE causes, measured not assumed**
(`scripts/b5gap1_delivery_latency_probe.py`, live preview ingress + loopback, enrolled
synthetic endpoint):
  fresh connection per POST (pre-fix sensor) 176.6 ms = **5.7 ev/s**
  one persistent connection, 1 event/POST    103.3 ms = **9.7 ev/s**
  loopback 1 event/POST (backend+DB only)     38.6 ms = 25.9 ev/s
  batch 10 / **batch 50** / batch 100        43.1 / **48.3** / 33.5 ev/s
Decomposition per event pre-fix: DNS+TCP+TLS ~73 ms (41%, discarded every event) +
ingress/WAN ~65 ms (37%, paid per event) + backend/auth/Mongo ~39 ms (22%,
irreducible). **Batch default = 50, chosen from measurement**: past ~50 amortisation is
spent, server per-event work dominates, and batch 100 is WORSE (33.5 ev/s) on a 3.0 s
request with more ingress-timeout exposure. `MAX_BATCH_EVENTS=100` server cap retained.
DELIVERY_THROUGHPUT = 48.3 ev/s = 2.4x the ~20 ev/s source → DELIVERY_SUSTAINABILITY
PASS. **CAVEAT: preview numbers. Production was 2.68 s/POST (~15x worse); the absolute
ceiling must be RE-MEASURED on the canary — it is step 3 of the acceptance procedure,
not an assumption.**
- Sensor: NEW `_Transport` (one persistent `http.client` connection, reconnects ONCE on
  a stale socket so it is not mistaken for an outage), `_post`/`_get` routed through it,
  `_deliver_batch`, batch-aware `_drain_journal` (404/405 → permanent single-event
  fallback; 413 → halve batch; 401/403 → refresh session), `BATCH_SUPPORT`.
- Backend: `_ingest_one` extracted so single-event and batch share ONE ingest path
  (asserted by test); NEW `POST /api/edr/agent/telemetry/batch`.
- **DURABILITY NOT WEAKENED. `SENT != ACCEPTED` survives batching**: the response is an
  ORDERED PER-EVENT verdict, never a batch verdict; only accepted indices are released.
  Proven E2E — 59 of 60 released, exactly the refused one retained, 0 duplicates.
  Idempotency INHERITED from `raw.append` `(tenant_id, dedup_key)`, no new identity
  scheme. 413 ingests nothing so the endpoint still owns everything. Liveness recorded
  once per batch, and not at all if nothing was accepted.

**GATE C — INTEGRITY_BACKEND_CONTRACT = PASS · BACKWARD_COMPATIBILITY = PASS.**
`HeartbeatBody`/`TelemetryBody` NOT touched (both `extra="forbid"`; adding fields would
422 the whole fleet) — asserted by test. NEW `backend/edr_plane/acquisition_integrity.py`
+ `POST /api/edr/agent/acquisition-integrity` (SENSOR_SCOPED, own versioned contract) +
`GET /api/edr/enrollment/acquisition-integrity` (TENANT_SCOPED read). All three routes
classified in `ROUTE_CLASSIFICATION` (the matrix fails closed on an unclassified route).
Neither new body carries tenant_id/endpoint_id — identity from the authenticated session.
**The semantic chain is SERVER-ASSERTED, not trusted.** Proven LIVE through the real
ingress: a sensor claiming `classification: MALWARE_EVASION`, `cause: LOG_ROLLOVER`,
`missing_record_id_count: 999999`, health `TOTALLY_FINE` was stored as
`SOURCE_RECORD_DISCONTINUITY` / `NOT_PROVEN` / `is_detection: false` / recomputed
**26409** / health `[ACQUISITION_GAP, DELIVERY_BACKLOG]` / `claim_basis:
SENSOR_REPORTED`. Every gap carries its own absence semantics (not benign, not
malicious, not a detection, no-event-observed != did-not-occur). Gaps append-only and
idempotent; the sensor marks a gap reported ONLY after the platform has it. No console
or Device Trajectory work.

**GATE D — all nine PRE_CANARY scenarios PASS**
(`test_b5_gap1_pre_canary_acceptance.py`, full cycle against a fake backend running the
REAL batch + integrity contracts): NORMAL, BURST (3,000 in one opportunity, 7+ pages),
BACKEND_SLOW (backlog grows, next cycle still journals 1,000), BACKEND_DOWN (500 held,
sent 0, acquisition continues), RECOVERY (600/600, 0 duplicates), RESTART, GAP (26,409
declared, reaches platform, reported once, nothing invented), MULTI_CHANNEL (hot Sysmon
5,000 does not starve Security/System), PRESSURE (halts, keeps every unacknowledged row,
AND recovers). Plus partial refusal, batch-route-absent fallback, oversize halving, and
transport reuse/reconnect. Ownership is asserted as the UNION of still-journaled and
backend-accepted, because accepted rows are reclaimed.

**Tests: 89 B5-GAP-1 tests (24+28+5+16+16). Full `backend/tests/edr/`: 1917 passed,
3 skipped, 0 failed.**

**A REAL FAULT THE EXISTING SUITE CAUGHT:**
`test_p0prod2_enrollment_hardening::test_agent_routes_never_depend_on_a_platform_user`
failed because the admin read route was first placed INSIDE the agent block of
`edr_enrollment.py`, where that guard scans for `get_current_user`. Admin identity must
not appear in the agent surface — the route was moved above the agent section. The guard
was right.

**Remaining risks:** (1) Gate A needs one Windows CI run. (2) Production throughput
unmeasured — 48.3 ev/s is preview. (3) **Server-side per-event cost ~39 ms is now the
ceiling; if the canary needs >~25 ev/s per endpoint the next lever is inside
`_ingest_one` (2-4 counter writes/event look batchable), NOT the transport.** (4)
Integrity stored but not rendered (no console work, by instruction). (5) Batch fallback
is permanent for the process once a 404 is seen. (6) Two synthetic endpoints
(`ep_1badb6e4ec82b016f808`, `NIVX-PROBE-2`) now exist in the PREVIEW db, tenant
`probe-t-00bf71`, from the probe and the live contract check — revoke at will. (7)
Historical B5-GAP-1 records remain unrecoverable, by design.

### Next (owner-gated)
- P0: run `windows-sensor-installer.yml` on a Windows runner → close Gate A.
- P0: one-endpoint canary per §"PROPOSED ONE-ENDPOINT CANARY PROCEDURE" — step 3
  re-measures production delivery throughput.
- P1: if the canary needs more throughput, batch the per-event delivery-counter writes
  inside `_ingest_one`.
- P1: render acquisition integrity / gaps in the console.
- P1: E3 deterministic detection engine hardening (after the above).

---

## 2026-06 · B5-GAP-1 WINDOWS ACCEPTANCE GATE 0 + §5 INGEST COST PROFILE
### FROZEN SELFTEST PASS (Linux bundle) · PACKAGING_REGRESSION PASS · COUNTER_PROFILE COMPLETE
### WINDOWS_ARTIFACT_BUILD = NOT_RUN · CANARY_STARTED = NO · **PRODUCTION_DEPLOYED = NO**

Record: `/app/docs/B5_GAP_1_WINDOWS_GATE0_AND_COST_PROFILE.md`. `DESKTOP-A9HGFJJ`
untouched (no install, no restart, no Sysmon/channels.json/outbox change, no journal
migration, no generated load, no canary). B5 remains CLOSED/PASS.

**TWO HARD LIMITS, STATED NOT HIDDEN.** (1) I cannot trigger CI — git write actions go
through the chat's "Save to Github" control; no tool can start `windows-sensor-installer.yml`.
(2) PyInstaller cannot cross-compile a Windows PE from Linux. So
`WINDOWS_ARTIFACT_BUILD = NOT_RUN`: blocked, not failed, not faked. **The Windows run is
the owner's to trigger and is the ONLY outstanding Gate 0 item.**

**FROZEN SELFTEST = PASS, in a REAL frozen binary.** Built an actual PyInstaller
**onefile** ELF using **PyInstaller 6.11.1 — the exact version pinned in
`build_windows_installer.ps1`** and the same hidden-import set minus `win32*`, then ran
`NivXForgeEDRSetup-linuxproof journal-selftest` FROM THE BINARY (not Python):
`result: PASS`, **`frozen: true`**, sqlite3 importable (lib 3.40.1), journal module,
DB create/open, `wal_mode`, `synchronous_full`, `auto_vacuum_incremental`, five tables,
durable commit, cursor commit, replay idempotency, integrity snapshot, gap contract —
all 13 TRUE, exit 0. Byte scan confirms `_sqlite3` (native ext), `sqlite3` and
`nivxforge_journal` are packed.
- PROVES: the freeze mechanism, the hidden-import list, `sys.frozen` detection, that
  PyInstaller 6.11.1 packs stdlib sqlite3 + its native extension with no extra hook, and
  that WAL/FULL/INCREMENTAL behave inside a bundle.
- DOES NOT PROVE (and not claimed): the Windows bootloader, `_sqlite3.pyd`/`sqlite3.dll`,
  NTFS, or the Windows SERVICE context (LocalSystem, `C:\ProgramData` ACLs).
  **SQLite inside the shipped PE remains genuinely unproven.**
- ARTIFACT_SHA256 for the real artifact DOES NOT EXIST YET — it comes from the Windows
  run. The Linux proof binary was built to /tmp and is disposable; it is NOT shippable.
  Not signed (Authenticode is inapplicable to an ELF). No signing secret was read.

**PACKAGING_REGRESSION = PASS, proven by diff vs the reviewed baseline `6afab68a`:**
`Install-NivXForgeSensor.ps1` **byte identical (no diff at all)**;
`build/build_windows_installer.ps1` **+2/-0** (only the two `--hidden-import` lines);
`nivxforge_setup.py` **+75/-0** (pure addition — the selftest);
`backend/requirements.txt` **byte identical**. **Zero deletions and zero modified lines
anywhere.** Therefore unchanged: service identity, service permissions, installer ACLs,
state-dir ACLs, auth-material handling, enrolment, tenant binding, startup command,
backend origin, signing. Also guarded by the three green installer suites. PyInstaller
was installed in THIS CONTAINER ONLY and deliberately NOT added to requirements.txt.

**§5 COUNTER PROFILE COMPLETE — THE COUNTER HYPOTHESIS WAS WRONG.**
Real local Mongo + pymongo `CommandListener`, warmed to steady state, measure-only:
```
ingest per accepted event   30.3 ms | 19 Mongo commands | 24.6 ms in Mongo (81.4%)
                                    | 5.7 ms CPU (18.6%)
DELIVERY-COUNTER WRITES      3 of 19 commands = 1.25 ms = 3.8% of ingest
canonical bridge            30.7 ms (~90%) | raw.append 1.01 | mark_reported 0.49
                                            | get_endpoint 0.42
```
Commands/event: `edr_delivery_counters` update x3; `edr_raw_events` findAndModify+insert
+update x2+find = 5; `edr_endpoints` find+update = 2; `v2_shadow_observations` find+insert
= 2; `xdr_canonical_evidence` insert; **`xdr_correlation_rules` aggregate + find PER
EVENT**; +~4 more. cProfile agrees independently: 0.726s of 1.189s across 25 events was
`select.epoll.poll` — I/O WAIT, not CPU — and showed YAML/regex work consistent with the
per-event rule reads.
**RECOMMENDATION: do NOT batch the delivery counters on their own** — 3.8% is a rounding
error on the acceptance path. Ranked, NONE IMPLEMENTED: (1) cache the correlation rule
set (2 cmds/event; rules are configuration not evidence; also removes the YAML/regex
cost) — best value-to-risk, needs a decision on how fast a rule edit must take effect;
(2) reduce `edr_raw_events` to <5 cmds — touches the immutable-bytes + dedup guarantee,
needs its own design review; (3) aggregate 3 counter writes into 1 (`counters.record`
already accepts a delta dict) — ~4%, only worth doing ALONGSIDE (1). Items 1+3 ≈ 19→16
cmds, 30.3→~27 ms (+12%) — real but far smaller than the banked transport win
(5.7→48.3 ev/s). Counters stay operational metrics (`authority: SERVER_OBSERVED`,
`evidence_authority: false`) and batching must not change WHEN an event is accepted.
**CAVEAT: 30.3 ms is local loopback preview Mongo with no HTTP/TLS/auth in the number —
re-profile on the canary before changing anything.**

**No product code changed in this pass** (the selftest + GATE 0 workflow step landed in
the previous pass). NEW: `scripts/b5gap1_ingest_cost_profile.py`. Regression spot-check
after the pass: 137 passed (pre-canary + 3 installer suites + enrolment hardening).

### Next (owner-gated, in order)
- P0: Save to Github -> run `windows-sensor-installer.yml` on `windows-latest`. GATE 0
  fails the build unless `result: PASS` AND `frozen: true` AND `wal_mode: true` AND
  `synchronous_full: true`. Capture artifact SHA256 + run id.
- P0: canary on a DISPOSABLE validation Windows endpoint FIRST, not `DESKTOP-A9HGFJJ`
  (owner's call, and correct): hammer Sysmon, cut/restore backend, restart service,
  grow/drain journal. Procedure in `B5_GAP_1_PREPROD_HARDENING_GATES_A_D.md`.
- P1: rule-set caching (profile item 1), optionally with counter aggregation (item 3).
- P1: render acquisition integrity / gaps in the console.
- P1: E3 deterministic detection engine hardening.

## 2026-06 · B5-GAP-1 WINDOWS GATE 0 — DETERMINISTIC CI CONTRACT (owner-gated)

Owner decision accepted: close Windows Gate 0 BEFORE any backend optimization. No
correlation-rule cache, no counter batching, no `edr_raw_events` change, no integrity UI,
no Sysmon change, no canary, `DESKTOP-A9HGFJJ` untouched, nothing deployed.

Gate 0 status: **BLOCKED_PENDING_REAL_WINDOWS_CI** (not claimed PASS). The container
cannot run GitHub Actions or a `windows-latest` runner, so this pass made the owner's
single CI run self-verifying instead of log-interpreted.

Implemented:
- `agents/nivxforge-windows/nivxforge_setup.py` — `journal-selftest` rewritten into the
  full Gate-0 evidence emitter: module provenance (nivxforge_sensor / nivxforge_journal /
  sqlite3 / _sqlite3 must resolve INSIDE the frozen bundle), native `_sqlite3` binary on
  disk, SQLite runtime binaries found, volume filesystem (NTFS assertion), `-wal` file
  creation, WAL reopen/recovery, state-dir write access, service-permission (icacls)
  check, plus the existing WAL/FULL/INCREMENTAL/schema/durable-commit/cursor/replay/
  integrity-snapshot/gap-contract checks. New `--json-out` and `--restart-check` flags;
  `--restart-check` re-opens the SAME dir in a NEW process (the only honest frozen-restart
  proof) and refuses to guess a directory. Off Windows, Windows-only checks report the
  literal `N/A_NON_WINDOWS` — never PASS, so Linux can never be promoted to Windows
  evidence. A `gate0` verdict map emits the owner's exact field names.
- `.github/workflows/windows-sensor-installer.yml` — Gate 0 split into (a) run both
  selftest phases from the frozen EXE, (b) an `if: always()` report step that FAILS CLOSED:
  every mandatory field must be PRESENT and exactly `PASS`, both phases must report
  `WINDOWS_FROZEN = TRUE`, restart recovery must come from the RESTART phase, packaging
  provenance is re-checked, and a missing field is a failure. Produces
  `dist/gate0/GATE0_WINDOWS_REPORT.json` (verdicts + artifact filename/version/SHA256/
  service-host SHA256/commit/run id/timestamp/PyInstaller version/signing status +
  the standing NO flags), printed, written to the job summary, and uploaded.
- `docs/B5_GAP_1_WINDOWS_GATE0_CI_CONTRACT.md` — the contract + paste-back procedure.
- `docs/B5_GAP_1_CANARY_PLAN.md` — PREPARED, NOT RUN: 11-stage measurement pipeline,
  per-stage metric list, 10-scenario failure matrix, acceptance invariants, rollback
  criteria, STOP conditions, post-canary optimization decision rule.
- `backend/tests/edr/test_b5_gap1_windows_gate0_ci_contract.py` (14 tests) + updated
  workflow-wiring assertion in the pre-canary suite. 102 passed / 2 skipped for
  `-k b5_gap1`. A local PyInstaller ONEFILE freeze ran both phases from a genuinely
  frozen binary (frozen=true, provenance in-bundle, restart phase PASS) — mechanics only,
  NOT Gate-0 proof.

### Next (owner-gated, in order)
- P0: Save to GitHub -> run `windows-sensor-installer.yml` on `windows-latest` -> paste
  `GATE0_WINDOWS_REPORT.json` back. Gate 0 closes only on `GATE0_VERDICT = CLOSED_PASS`.
- P0: only then, disposable Windows canary per `B5_GAP_1_CANARY_PLAN.md`.
- P1: optimize ONLY what canary measurements prove dominant (rule-read caching is a
  candidate, not an approved change).
- P1: acquisition-integrity surfacing in the console; E3 detection-engine hardening.

## 2026-06 · B5-GAP-1 WINDOWS GATE 0 CLOSED + DISPOSABLE CANARY PACKAGE (prepared, NOT run)

Owner supplied the authoritative `gate0/GATE0_WINDOWS_REPORT.json` from the real
`windows-latest` run (run 36663297037, commit 2cb841db, PyInstaller 6.11.1, sensor
0.3.0-windows, UNSIGNED_INTERNAL_VALIDATION_BUILD). Recorded:
`WINDOWS_GATE_0 = CLOSED_PASS`, `PROBLEMS = []`, all 21 mandatory Windows assertions
PASS (SQLite + native binary, NTFS create, WAL create + reopen/recovery,
synchronous=FULL, auto_vacuum=INCREMENTAL, schema, durable commit, cursor commit,
replay idempotency, integrity snapshot, gap contract, frozen restart, state-dir access,
service permissions, packaging regression). Evidence written into
`docs/B5_GAP_1_WINDOWS_GATE0_CI_CONTRACT.md` §8. No inference from the green job was
accepted; the previous turn deliberately reported UNVERIFIED until the JSON arrived.

Phase 2 (prepared, NOT executed):
- `scripts/canary/b5gap1_canary_collector.py` — READ-ONLY collector. Samples SOURCE ->
  ACQUISITION -> JOURNAL -> NORMALIZATION -> BATCH TRANSPORT -> BACKEND INGEST -> RAW
  ACCEPTANCE -> CANONICAL -> ACK -> JOURNAL RELEASE into a timestamped CSV (48 columns,
  one row per sample per channel) plus a verdict JSON. Journal opened `mode=ro`, falling
  back to an untouched copy of db/-wal/-shm; unreadable numbers are `NOT_PROVABLE`, never
  estimated. Read token from `NIVX_CANARY_READ_TOKEN`, never printed or stored.
  Invariants enforced: SILENT_LOSS, UNEXPLAINED_ACQUISITION_GAPS, DUPLICATES,
  WRONG_TENANT_EVIDENCE, UNACKNOWLEDGED_DELETION, CURSOR_MONOTONIC,
  SOURCE_CURSOR<=DURABLY_OWNED, acquisition-continues-while-impaired, backlog drain,
  all-channels-progress, explicit journal pressure, JOURNAL_NOT_CORRUPT. Reports
  DELIVERY_HEADROOM without asserting a threshold (owner decision).
- `scripts/canary/b5gap1_canary_load.ps1` — real source records on the canary; REFUSES
  `DESKTOP-A9HGFJJ` and any host not named `NVX-CANARY*` without `-Confirm`.
- `scripts/canary/b5gap1_canary_impair.py` — transparent TCP relay (`normal|slow|down|
  cut`); TLS stays end-to-end, no credential held, reversible via hosts entry.
- `docs/B5_GAP_1_CANARY_PLAN.md` rewritten as an executable plan: 10 scenarios with exact
  commands, CSV + verdict schemas, acceptance invariants, rollback criteria, STOP
  conditions, post-canary optimization rule.
- Backend cost measurement REUSES `scripts/b5gap1_ingest_cost_profile.py`. No ingest
  middleware, no sensor hot-path instrumentation, no product semantics changed.
- `backend/tests/edr/test_b5gap1_canary_harness.py` (20 tests) proves the harness fails
  closed on cursor regression, cursor beyond durable ownership, unacknowledged deletion,
  unexpected duplicates, an absorbed discontinuity, an undrained backlog, foreign-tenant
  evidence, stalled acquisition under impairment and journal corruption — and that the
  collector leaves the journal bytes untouched while a live writer holds the WAL.
  Regression: 122 passed / 2 skipped for `-k "b5_gap1 or b5gap1"`.

Boundary preserved: CANARY_STARTED = NO, CORRELATION_CACHE_IMPLEMENTED = NO,
COUNTER_BATCHING_IMPLEMENTED = NO, RAW_EVENT_PATH_MODIFIED = NO,
DESKTOP_A9HGFJJ_TOUCHED = NO, PRODUCTION_DEPLOYED = NO.

Lifecycle: B5_STATUS = CLOSED_PASS · B5_GAP_1_IMPLEMENTATION = PASS ·
B5_GAP_1_WINDOWS_ARTIFACT = PASS · B5_GAP_1_DISPOSABLE_CANARY = PENDING.
B5-GAP-1 is NOT fully closed until the canary passes.

### Next (owner-gated, in order)
- P0: owner authorises a named disposable Windows host -> run the 10 canary scenarios.
- P0: owner review of canary CSV/verdicts; only then decide any optimization.
- P1: correlation-rule cache ONLY if canary profiling proves it material.
- P1: acquisition-integrity surfacing in the console; E3 detection-engine hardening.

## 2026-06 · B5-GAP-1 CANARY PHASE C0 CONTRACT (host KUSHU authorised; nothing installed yet)

Owner authorised KUSHU as the disposable canary (baseline verified CLEAN: no NivXForge
service, no Sysmon service/channel/binaries, no C:\NivX, no C:\Program Files\NivXForge,
no C:\ProgramData\NivXForge, x64, ~190 GB free). DESKTOP-A9HGFJJ remains out of scope.

Repository-authoritative answers recorded in `docs/B5_GAP_1_CANARY_PLAN.md` §0:
- The NivXForge installer does NOT install or configure Sysmon (no Sysmon logic in
  `nivxforge_setup.py` or `Install-NivXForgeSensor.ps1`).
- Authoritative Sysmon config = the W1 baseline XML (`memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md`
  §1.3) written to `C:\NivX\sysmon\nivx-w1-sysmon.xml`, with the single validated B5 change
  `ProcessTerminate onmatch="exclude"` so EID 5 is ON from the start. `docs/B5_EID5_ENABLE_AND_VERIFY.ps1`
  is pinned to DESKTOP-A9HGFJJ and must never run on the canary.
- Artifact: Gate-0 run 36663297037 / commit 2cb841db, sensor 0.3.0-windows, expected SHA256
  from that run's SHA256SUMS.txt; C0 halts on mismatch. Sysmon binary integrity is gated on
  the Authenticode signature (no pre-known hash exists in-repo); its SHA256 is recorded as
  provenance for owner pinning.
- Backend origin: https://nivxray.nivxforge.com only (production-origin guard).
- Read credential: NIVX_CANARY_READ_TOKEN, never printed or stored.
- No reboot required. Defender never weakened, no exclusions added.

Guard hardened (canary script only, no product code): the `-Confirm` bypass was REMOVED from
`scripts/canary/b5gap1_canary_load.ps1`. Load generation now requires all three: host not on
the forbidden list, host named NVX-CANARY* OR on the explicit `$authorized` list (KUSHU), and
an owner-written `C:\NivXForgeCanary\CANARY_DESIGNATION.json`. Test added; 122 passed / 2
skipped for `-k "b5gap1 or b5_gap1"`.

C0 block order (one at a time, each fail-closed, owner review between blocks):
C0.1 designation + read-only preflight · C0.2 Sysmon staging + signature gate ·
C0.3 config + apply + prove EID1/EID5 · C0.4 artifact SHA256 gate ·
C0.5 install + enrol + service/journal/backend proof · C0.6 read-only collector dry sample.

State: CANARY_STARTED = NO · LOAD_GENERATED = NO · DESKTOP_A9HGFJJ_TOUCHED = NO ·
PRODUCTION_CHANGED = NO. C0.1 issued for owner review; nothing has been run.

## 2026-06 · DEVICE TRAJECTORY CHECKPOINT 1 — PRELIMINARY READ-ONLY GAP LIST (no code change)

Owner approved: KUSHU C0 -> canary -> B5-GAP-1 CLOSED -> Device Trajectory Checkpoint 1
(structural/evidence-presentation parity only, PREVIEW ONLY) -> freeze -> E3/E4/E5/E6 ->
Checkpoint 2 (intelligence surfaces). Owner explicitly REJECTED adding "ENGINE NOT PRESENT"
labels to the frozen renderer: engine absence is recorded in the audit, the UI keeps showing
backend truth.

Produced `docs/DEVICE_TRAJECTORY_CHECKPOINT1_PRELIMINARY_GAPS.md` (read-only):
- §A 18 structural rows located in code, classified PASS_PENDING_VISUAL (owner's side-by-side
  decides parity; no parity claimed from code reading).
- §B 10 proven divergences: B2 coverage bands NOT RENDERED although `CoverageInterval` +
  `dt2/density.js::coverageOf` exist (P0 for an evidence-truth product); B5 no RAW payload
  surface though `GET /api/edr/events/{raw_id}` exists (pure wiring); B1 inspector fixed at
  394 px, not resizable; B7 `dt2/repeatCache.js` has no consumer -> owner ruling needed on
  Cisco's per-file event cache (display suppression would hide held observations); B3 no
  keyboard handling; B4 match count but no MATCH n OF m cursor; B6 no per-process
  de-selection; B8 PID surrogate identity vs Cisco SHA-256; B9 dashed-open lifelines are
  correct and KUSHU's EID 5 will exercise closed lifelines for the FIRST time; B10 Back does
  not step investigation states.
- §C 7 surfaces NOT_EVALUABLE_YET (E3 detections, E4 reputation/IOC, E5 contributor halo,
  E6 ATT&CK, typed relationship edges awaiting real artefact evidence).
- §D Checkpoint 1 preconditions: canary PASS, then a DECLARED benign CANARY/VALIDATION
  density pass on KUSHU (EID 1/5/3/11/22, zero fabricated findings, run AFTER the canary
  result so it cannot contaminate acceptance), preview-only, screenshot pairs per row.

State: DEVICE_TRAJECTORY_CODE_CHANGED = NO · FIXES_APPLIED = NO · PRODUCTION_UI_DEPLOYED = NO
· FIXTURES_ADDED = NO · CANARY_STARTED = NO · DESKTOP_A9HGFJJ_TOUCHED = NO.
Active gate unchanged: KUSHU C0.1 -> B5-GAP-1 disposable canary.

### 2026-06 · OWNER CORRECTION + RULINGS (recorded, NOT authorised for implementation)
- Device Trajectory is NOT blocked on KUSHU. Two independent tracks now:
  Track A = B5-GAP-1 on KUSHU (C0.1 -> C0.x -> stress scenarios -> close canary);
  Track B = Device Trajectory structural/Cisco-parity evaluation over DESKTOP-A9HGFJJ's
  existing canonical observations, which is a READ-ONLY projection (no endpoint contact,
  no sensor restart, no Sysmon change). KUSHU later adds EID5 closed lifelines + the new
  journal/acquisition architecture proof.
- B7 RULING: collapse repeated equivalent events VISUALLY ONLY, never discard. Explicit
  count (e.g. x17); expanding must expose every underlying observation with its
  observation_id and timestamp. Ingest- or query-level suppression is NOT authorised.
- B5 CONFIRMED P1: canonical observation -> original/raw evidence view (wiring over the
  existing GET /api/edr/events/{raw_id}).
- B2 coverage visualisation affirmed as important: absent coverage must be visually
  distinct from "observed and nothing happened".
- NOTHING authorised for implementation yet. Gap inventory is sufficient for now.
  DEVICE_TRAJECTORY_CODE_CHANGED = NO · FIXES_APPLIED = NO · PRODUCTION_UI_DEPLOYED = NO.
- Lifecycle: B5 = PASS · B5-GAP-1 implementation = PASS · Windows artifact = PASS ·
  disposable canary = PENDING · Device Trajectory = foundation exists, gap audit complete,
  fixes not accepted · E3-E6 = pending after the canary.
- WORDING CORRECTION (owner): do NOT state that Cisco "destroys/discards" repeated events.
  Sourced fact is only that Cisco documents a per-file event CACHE preventing another event
  from being TRIGGERED within the window, and that its trajectory reads comparatively
  sparse/collapsed. No documentation exists that its backend discards recorded events.
  NivXForge requirement stays deliberately stronger: visual collapse only, underlying
  observations intact and individually retrievable. Corrected in the B7 audit row.

### 2026-06 · KUSHU C0.3 PREP (C0.1/C0.2 PASS; config staged in repo, nothing applied)
- C0.1 = PASS, C0.2 = PASS (Sysmon 15.22, zip SHA256 00ECF1B4..., Sysmon64 SHA256 83D31F24...,
  Authenticode Valid / Microsoft Windows Publisher; staged, NOT installed).
- Created the repository-authoritative canary config:
  `agents/nivxforge-windows/sysmon/nivx-b5gap1-canary-sysmon.xml` = the W1 baseline
  (memory/W1_PHASE1_WINDOWS_LAPTOP_PREP.md §1.3) with ONLY the B5-validated token swap
  `<ProcessTerminate onmatch="include"/>` -> `<ProcessTerminate onmatch="exclude"/>` (EID 5 ON).
  No new XML was invented. Stale "LOG NOTHING" comment left byte-faithful on purpose.
  Pinned hashes (UTF-8, no BOM): CRLF 452E331298DF9A3DF3314E2CF707F153891DCE0BCE625B4EE99548D8D5E479AB
  / LF 60F585860CFBEA3D62888B6CCB90C15F28A49D91832D4FC4526EBEEAA316C67C.
- `docs/B5_GAP_1_CANARY_PLAN.md` §0: C0.3 SPLIT into C0.3a (stage + validate, no install) and
  C0.3b (apply + prove EID1/EID5 live), so rules are owner-reviewed before the driver loads them.
- 3 new tests pin the config hash, assert EID1/EID5 ON, assert every DSM-unsupported event id
  stays OFF, assert no rule carries children, and assert the one-token derivation from W1.
  `test_b5gap1_canary_harness.py` = 23 passed.
- Sysmon has no offline config validator, so C0.3a validation is XML + rule level; live rule
  proof happens in C0.3b.
- State: SYSMON_INSTALLED = NO · SYSMON_CONFIG_APPLIED = NO · NIVXFORGE_INSTALLED = NO ·
  ENROLLED = NO · LOAD_GENERATED = NO · DEFENDER_MODIFIED = NO ·
  DESKTOP_A9HGFJJ_TOUCHED = NO · PRODUCTION_CHANGED = NO · CANARY_STARTED = NO.
- C0.3a PATH CORRECTION (owner review caught it before execution): C0.2 as executed staged
  Sysmon at C:\NivXForgeCanary\stage\sysmon\Sysmon64.exe (zip at ...\stage\Sysmon.zip), NOT
  C:\NivX\sysmon. Path contract now recorded in docs/B5_GAP_1_CANARY_PLAN.md §0: staged binary
  is the source of truth; C0.3a explicitly creates C:\NivX\sysmon, re-verifies the staged
  SHA256 against 83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352, copies the
  binary, then re-hashes and re-verifies Authenticode on the COPY, and creates the directory
  before writing the XML. Repository-authoritative XML and its pinned hashes unchanged.
- C0.3a HALTED on KUSHU at the config hash gate (correct, fail-closed; Sysmon never
  installed). Diagnosis: KUSHU file 1851 CRLF bytes vs repo artifact 1842 CRLF-equivalent
  (1810 LF) -> +9 CONTENT bytes with identical line-ending counts and no BOM, so NOT a
  newline/BOM issue. Root cause class: the block embedded a hand-copied PowerShell here-string
  literal - a second copy of an artifact that is supposed to be authoritative - transported
  through chat + a console paste, which is not byte-safe. The artifact has exactly ONE
  non-ASCII character (U+00B7 MIDDLE DOT, 0xC2 0xB7, line 2). The observed hash was NOT
  blessed.
- Fix: added `agents/nivxforge-windows/sysmon/nivx-b5gap1-canary-sysmon.xml.b64` (pure-ASCII
  base64 of the exact repository bytes). C0.3a recovery decodes it with
  [Convert]::FromBase64String + WriteAllBytes, so KUSHU's file is BYTE-IDENTICAL to the repo
  artifact and the single gate is the repository file hash
  60F585860CFBEA3D62888B6CCB90C15F28A49D91832D4FC4526EBEEAA316C67C. The CRLF hash
  452E3312...E479AB is retained as documentation only, no longer a gate. Rejected file is
  preserved as REJECTED-*.xml in the evidence dir, never deleted.
- 3 new tests: base64 decodes byte-identical to the config and is pure ASCII; per-line byte
  lengths pinned (used by the block's per-line diff to NAME the divergent line); the only
  non-ASCII byte is the line-2 separator. test_b5gap1_canary_harness.py = 26 passed.
- KUSHU state unchanged: SYSMON_INSTALLED = NO, CONFIG_APPLIED = NO, binaries still match
  83D31F24..., NIVXFORGE_INSTALLED = NO, ENROLLED = NO, LOAD_GENERATED = NO,
  DEFENDER_MODIFIED = NO, DESKTOP_A9HGFJJ_TOUCHED = NO, PRODUCTION_CHANGED = NO.
- C0.3a-R = PASS on KUSHU. Config byte-identical to the repo artifact
  (60F585860CFBEA3D62888B6CCB90C15F28A49D91832D4FC4526EBEEAA316C67C, 1810 bytes, no BOM),
  EID1/EID5 ENABLED, 0 child filters, Sysmon NOT installed. Rejected 1851-byte literal
  preserved (94306BC7...403DA); per-line diagnosis showed divergence on lines 22-30, proving
  the hand-copied-literal root cause. The expected hash was never changed to force a pass.
- C0.3b acceptance definition recorded in docs/B5_GAP_1_CANARY_PLAN.md §0: pre-exec binary
  re-verify, pre-apply config re-verify, install on canary only, service/driver/channel proof,
  SHA256 of the driver's active Rules blob (HKLM\...\SysmonDrv\Parameters\Rules) as the only
  authoritative "same rules" comparator, one benign uniquely-marked process, genuine EID 1,
  genuine EID 5 for the SAME ProcessGuid, correlation on ProcessGuid (PID asserted additionally,
  never instead), EventRecordID/UTC/Image/ProcessId/ProcessGuid preserved, fail closed,
  rollback path stated. C0.3b block issued for owner review; NOT executed.
- C0.3b attempt 1 = NOT_PASSED, KUSHU stayed CLEAN (no service, no driver, no channel, no
  driver parameters, 0 Sysmon events; binary + config hashes unchanged). ROOT CAUSE: the block
  used `& $bin -accepteula -i $cfg 2>&1 | Out-String` under $ErrorActionPreference='Stop';
  PowerShell converts native stderr into error records, so the merged stream raised
  NativeCommandError and terminated the script BEFORE $LASTEXITCODE was read. Sysmon writes
  its banner to stderr even on success, so the script aborted at the invocation and no install
  was attempted. NO repository code or config changed; XML and all pinned hashes untouched.
- FIX (capture mechanism only, no acceptance condition weakened): binding native-invocation
  rule recorded in docs/B5_GAP_1_CANARY_PLAN.md §0 - every native call goes through
  Invoke-NativeCaptured (Start-Process -Wait -PassThru with stdout/stderr redirected to files),
  giving the real exit code and both streams; non-zero still halts. C0.3b-R issued for owner
  review, not executed.
- C0.3b-R = PASS on KUSHU. Sysmon 15.22 installed (exit 0), service Running, SysmonDrv present,
  channel enabled, ACTIVE_RULES_SHA256 = C134F0F3046A2D1690C42CBE682C251DC11C18F01D9BEF7B5B4B15EFF75BC384
  (480 bytes, driver Rules blob - NOT the file hash). FIRST observed closed process lifetime in
  this system: cmd.exe pid 34300, EID1 record 3991 @06:17:14.768Z -> EID5 record 4005
  @06:17:14.857Z (~89 ms), SAME ProcessGuid {7446d477-a96a-6abc-f215-00000000aa00}, correlated on
  ProcessGuid with PID asserted additionally => PROCESS_TERMINATION_OBSERVED. This will later
  exercise the Device Trajectory closed-lifeline path instead of END_NOT_OBSERVED.
- C0.4 BLOCKED ON OWNER INPUT: the authoritative ARTIFACT_SHA256 for NivXForgeEDRSetup.exe is
  NOT retrievable from this container (it lives in Gate-0 run 36663297037's artifact /
  GATE0_WINDOWS_REPORT.json / SHA256SUMS.txt; the owner's earlier paste omitted the value, and
  grep confirms no 64-hex artifact hash exists anywhere in the repo or docs). It was NOT guessed.
  C0.4 block issued parameterised: $EXPECTED_ARTIFACT_SHA256 must be filled from the Gate-0
  evidence and the block HALTS on the unfilled placeholder - there is deliberately no
  "accept observed" path. C0.4 is hash-gate + staging only; installation and enrolment remain
  C0.5 per the canary plan. No execution of the artifact in C0.4.
- C0.5 = HOLD by owner. BLOCKER = ENROLLMENT_TOKEN_COMMAND_LINE_EXPOSURE. The installer
  accepted the one-time enrolment secret as `--token <plaintext>`, and Sysmon EID 1 records
  process command lines, so the secret would have become endpoint telemetry delivered to the
  backend it authenticates against. The interface was fixed instead of the procedure.
- ENROLMENT SECRET IS NOW STDIN-ONLY (Windows only). `--token-stdin` is the sole accepted
  input; `--token`/`-token`/`--enrollment-token`/`--enrolment-token` and any argv element with
  the `nvxenr_` shape are REFUSED before argparse can echo them. The secret is never written to
  disk, printed, or placed on any command line the installer builds (service binPath carries
  --backend/--interval/--state-dir only). A rejected enrolment is redacted and re-raised OUTSIDE
  the except block, so no `__context__` retains the value. `Install-NivXForgeSensor.ps1` takes a
  SecureString and delivers it on the child's stdin (ZeroFreeBSTR after use).
  Files: agents/nivxforge-windows/{nivxforge_sensor.py,nivxforge_setup.py,Install-NivXForgeSensor.ps1},
  .github/workflows/windows-sensor-installer.yml, docs/B5_GAP_1_ENROLMENT_SECRET_STDIN.md,
  docs/B5_GAP_1_CANARY_PLAN.md, backend/tests/edr/test_b5gap1_enrolment_secret_stdin.py (+3
  existing installer test files updated). 24 new tests; full tests/edr suite 1979 passed.
  LIVE argv proof on this pod via /proc/<pid>/cmdline of a real child process.
- STILL OWED (cannot be produced from this container: no push rights, no Actions dispatch):
  commit SHA, windows-sensor-installer run ID, new NivXForgeEDRSetup.exe SHA256, signing status.
  Gate-0 artifact for commit 2cb841db10e4262bba89c115bfa8c3058f61fda4 left UNTOUCHED. KUSHU and
  DESKTOP-A9HGFJJ not touched. Sysmon/Defender unchanged. E3 not started. C0.5 stays HOLD until
  the NEW artifact is owner-reviewed and a new artifact-hash gate passes; the real Sysmon EID 1
  absence check is specified in docs/B5_GAP_1_ENROLMENT_SECRET_STDIN.md §6.
- DECLARED RESIDUAL: agents/nivxforge-linux/nivxforge_sensor.py still accepts `enrol --token
  <secret>` (scripts/nivxforge_sensor_supervise.py passes it that way), so the same exposure
  exists on Linux endpoints. OUT OF SCOPE of this directive, NOT fixed, recorded as open.
- enr_ PREFIX GAP FIXED (owner-approved second build cycle). The argv secret-shape heuristic
  checked only `nvxenr_`; the platform mints `enr_<token_urlsafe(32)>`
  (edr_plane/enrollment/security.py PREFIX_ENROLLMENT="enr"), so it could not fire for a real
  token. Named-flag refusals were always correct. Now: ENROLMENT_SECRET_PREFIXES = ("enr_",
  "nvxenr_"), single decision point looks_like_enrolment_secret(), whole argv scanned (a secret
  behind an UNKNOWN flag is refused too). Windows workflow now probes the FROZEN BINARY three
  ways: localhost origin guard, `--token x` must be refused with "is REMOVED", and
  `--provisioning-key=enr_ci_probe...` must be refused with "looks like an enrolment secret".
  Tests: 37 in test_b5gap1_enrolment_secret_stdin.py (production + legacy shapes x 8 argv
  placements); full tests/edr = 1993 passed, 3 skipped.
- ARTIFACT 16c82fcafd6aec30039e64f385672f7b803c391c / run 36689911602 / SHA256 DA33A54E...C300
  is OBSOLETE for C0.5 and MUST NOT BE EXECUTED. Staged copy on KUSHU left in place, unexecuted.
  A NEW artifact + NEW hash gate is required before C0.5.
- ENROLMENT TOKEN MINT PROCEDURE (read-only inspection, nothing minted): POST
  /api/edr/enrollment/tokens (routers/edr_enrollment.py:94) with platform-user JWT +
  Depends(edr_tenant) and X-Tenant-Id; body {label, ttl_seconds 60..86400}. Plaintext returned
  ONCE, never stored (digest only), never re-readable. Single-use burned atomically by
  consume_enrollment_token(); TTL default EDR_ENROLLMENT_TOKEN_TTL_SECONDS (900s in this pod;
  the DEPLOYED value governs). Console path: /xdr/admin/edr-enrollment (adminMeta key
  edr-enrollment). Canary tenant id must come from GET /api/xdr/tenants (needs tenants.read) or
  the console selector - there is no hardcoded tenant anywhere by design.
- LINUX ARGV EXPOSURE remains SEPARATE P0 SECURITY DEBT (agents/nivxforge-linux enrol --token,
  scripts/nivxforge_sensor_supervise.py). Deliberately NOT in this change's scope.
- PHASE 0 DEPLOYMENT & ENROLLMENT FOUNDATION (owner-directed, 2026-06). Delivered:
  docs/NIVXFORGE_DEPLOYMENT_ENROLLMENT_ARCHITECTURE.md (15 sections: inventory, industry
  pattern, authoritative model, EDR + XDR lifecycles, credential/identity/policy/health/
  offboarding/audit models, UI IA, invariants, gap matrix, phased plan).
- AUDIT HEADLINE: the control plane is far more complete than the "token generator" screen
  suggests. EXISTS_AND_AUTHORITATIVE: tenant registry/orgs, PLATFORM vs CUSTOMER authority,
  bootstrap token (single-use/TTL/atomic burn/digest-at-rest), per-device agent_credential +
  rotate/revoke, endpoint identity (hostname is metadata), inventory, policies+versions+11-state
  lifecycle, groups, GROUP-BOUND DEPLOYMENT CONTEXT (routers/edr_connector.py::create_deployment
  binds group_id/release_id to the minted token; edr_enrollment.py:298-311 honours it =
  Cisco-style group-in-package without touching the artifact), release catalog + SHA256,
  telemetry acceptance, SensorState, acquisition integrity, canonical evidence, audit,
  xdr_data_sources + xdr_collectors + normalization.
  MISSING: tags; route to move an endpoint between groups; composed READY verdict; one unified
  Deployment & Enrollment surface. PARTIAL: deployment PROFILE (only one-shot context),
  heartbeat->health composition, rejected-sensor alarm surfacing, offboarding, clone handling.
- NEW P0 GAP FOUND, NOT CHANGED (out of approved scope): create_deployment still returns a
  Windows invocation string `-EnrollmentToken <ENROLLMENT_TOKEN>`, contradicting the mandatory
  stdin-only contract. Needs owner decision. Other P0s: no composed READY verdict; clone
  collision (two hosts one machine_guid) has no signal/policy; Linux argv exposure (existing).
- B8-SCOPE-1 REPAIR IMPLEMENTED (additive, no predicate changed):
  backend/routers/xdr_scope.py::authorized_scope now publishes `authorized_tenants` =
  ctx["authorized_customers"] (AUTHORITY) alongside unchanged `tenants` (EVIDENCE/incident
  corpus with open_incidents). Frontend: XdrScopeNavigator.jsx offers authorized_tenants and
  uses `tenants` only for the "N open" annotation ("no XDR incidents" when absent);
  AdminTenantGate.jsx offers authorized_tenants + auto-adopts a single authorised tenant.
  Tests: backend/tests/test_b8_scope_authorized_tenants_contract.py (11 tests, A-H matrix)
  = 11 passed; tests/test_a05_tenant_scope_contract.py 72 passed (no regression).
  NOT DEPLOYED - production still shows the defect until the owner authorises a deploy.
- C0.5 STILL BLOCKED. Installer SHA256 FE05C4A8E7246DBBB6D9850F9C4B80DDBFECE3175770B30D4A373D95FA6EDB7B
  staged on KUSHU, NOT executed. Intended tenant: "NivXForge Canary", kind LAB - NOT CREATED.
  Sequence agreed: deploy repair -> verify selector -> create LAB tenant -> mint ONE token ->
  C0.5 -> Sysmon EID1 absence check.
- P0 ENROLMENT-INSTRUCTION CONTRADICTION CLOSED (pre-deployment, owner-directed).
  Root cause: three surfaces each composed their own Windows instruction and drifted.
  routers/edr_connector.py::create_deployment INTERPOLATED THE MINTED PLAINTEXT into
  `install_invocation` (`-EnrollmentToken <secret>`); routers/edr_onboarding.py PACKAGES
  taught `-EnrollmentToken <token>` (ps1) and `--token <enrollment-token>` (exe, which the
  hardened binary now refuses); EdrAddDevicePage.jsx rebuilt the same argv command in the
  browser with the real token.
  Fix: NEW single authority backend/edr_plane/enrollment/instructions.py
  (windows_exe_invocation = Read-Host -AsSecureString -> BSTR -> pipe -> --token-stdin ->
  ZeroFreeBSTR; windows_script_invocation = SecureString via @args SPLATTING so no
  -EnrollmentToken pair is ever typed; linux_invocation UNCHANGED and declared as debt;
  ARGV_SECRET_FORMS + WINDOWS_SECRET_CONTRACT exported for tests/UI).
  install_invocation is now SECRET-FREE; response adds install_invocation_carries_secret=False
  and secret_handling. EdrDownloadsPage.jsx shows the secret in its OWN CopyBlock
  (edr-deployment-secret) and labels the command "carries NO secret".
  Tests: backend/tests/test_w1_windows_enrolment_instruction_contract.py (13, W1-W7) = 13 passed.
  Regression: 112 passed across onboarding/p0prod2/windows-installer/stdin suites.
  PRE-EXISTING unrelated failures (proven by git stash, not caused here):
  test_edr_onboarding_v1.py::test_the_package_catalog_reports_only_what_exists_on_disk expects
  sensor_version 0.1.0-windows but the sensor is 0.3.0-windows; and
  ::test_protection_never_claims_enforcement_the_sensor_cannot_do (lifecycle.assigned False).
- NEXT IDENTITY P0 (owner-elevated, AFTER KUSHU acquisition closure, BEFORE broader UI work):
  CLONE COLLISION - two hosts sharing a machine_guid silently merge into one endpoint_id,
  which can corrupt Device Trajectory, detections, policy state, response targeting and
  evidence attribution. Needs identity-semantics design, not a quick patch.
- STILL NOT DEPLOYED. Awaiting final owner deployment authorization for the combined
  selector + enrolment-instruction patch.
- PRE-DEPLOYMENT KNOWN-RED CLOSURE (test-only, no production behaviour changed).
  F1: routers/edr_onboarding.py::_sensor_version reads SENSOR_VERSION from the SHIPPED
  agents/nivxforge-windows/nivxforge_sensor.py = "0.3.0-windows" (authoritative). The test's
  hardcoded "0.1.0-windows" was stale. Replaced with a comparison against that authoritative
  source + a shape check, so it cannot go stale again and still fails if catalog and artifact
  disagree. Sensor version NOT altered.
  F2: GATE 5 moved policy_lifecycle.assigned onto the policy authority's own record
  (policy_state.assigned_policy_id); the test asserted assigned is True merely because a
  policy OBJECT was passed - the exact configuration-implies-assignment conflation the
  invariant forbids. Production is CORRECT and stricter: with no policy_state evidence,
  assigned=False. Test updated to assert that, plus a NEW test proving
  ASSIGNED != DELIVERED != ACKNOWLEDGED != APPLIED != VERIFIED != ENFORCED (enforced is
  hardcoded False because the released connector enforces nothing). No production code touched.
  Scoped regression: 187 passed, 0 failed (onboarding, W1 instruction contract, B8 selector,
  A0.5 tenant authority, p0prod2 enrollment hardening, stdin secret, exclusion scope).
  BASELINE IS NOW CLEAN for the deployment gate.
- PRODUCTION DEPLOY DISPATCHED (owner-authorized) for the combined changeset: B8 selector
  repair + centralized Windows stdin-only enrolment instruction authority + the 4 closed argv
  secret paths + frontend + test-only known-red closure. Backend and frontend MUST ship
  together (new frontend reads a field the old backend does not send; old frontend would keep
  composing an argv command with a live secret). No migration, no data mutation.
  Deploy job id 95e7e8cd-6528-4f50-8702-566d0dc3b0ce. Awaiting pipeline outcome.
  AFTER acceptance passes (8 read-only checks) and ONLY on owner review: create NivXForge
  Canary (LAB) -> mint ONE token -> KUSHU C0.5. UI/UX baseline audit to precede any broader
  UI redesign decision (owner sequencing note); it does NOT block the LAB tenant or KUSHU.
  Recorded, non-blocking: GATE 5 policy lifecycle needs its own test suite before the
  composed READY phase.
- PRODUCTION ACCEPTANCE (Publish 100) = FAIL AT GATE 0. Read-only evidence:
  * PRODUCTION TOPOLOGY DISCOVERED: xdr.nivxforge.com and edr.nivxforge.com are BOTH served by
    VERCEL (`server: Vercel` response header) from apps/nivxray-xdr (it has .vercel/ +
    vercel.json). The Emergent publish pipeline builds /app/frontend, NOT apps/nivxray-xdr.
    The production BACKEND is https://nivxray.nivxforge.com (healthy: /api/health 200,
    unauth GETs correctly 403).
  * THE REVIEWED FRONTEND IS NOT LIVE. Deployed bundles fetched and inspected:
    xdr.nivxforge.com XdrShell-CxJL9WXQ.js contains "authorized_count" but NOT
    "authorized_tenants"; EdrAddDevicePage-DJayq9b7.js still contains "EnrollmentToken";
    EdrDownloadsPage-B9DnrKlR.js lacks "carries NO secret". edr.nivxforge.com is a SEPARATE,
    also-old Vercel build (XdrShell-LH9QX3xl.js, EdrAddDevicePage-CDkw308R.js — same findings).
    => the two consoles are two independent Vercel deployments, both pre-change.
  * CONSEQUENCE: even if the backend half shipped, the live consoles still read `tenants`
    (selector stays empty) and EdrAddDevicePage still rebuilds the argv enrolment command in
    the browser. This is the owner's "backend/frontend versions are incompatible" STOP
    condition. No workaround attempted, no code changed, no redeploy.
  * BLOCKER 2: the production admin credential in the handoff (admin@nivxray.com) returns 401
    at https://nivxray.nivxforge.com/api/auth/login - it is PREVIEW-ONLY. So checks 1, 5, 7
    (authenticated GETs) and 2, 3 (UI) are NOT_VERIFIED. NOTE for future: routers/auth.py
    login performs NO DB write (in-memory rate limiter only), so a login is not a data
    mutation.
  * Deployer agent asked (read-only, intent=debug) for publish number, both commit SHAs,
    which frontend the pipeline builds, hostnames served, whether the deployed image contains
    edr_plane/enrollment/instructions.py, pod health/ImportError, and Mongo binding. Response
    pending at time of writing.
  * TO FIX THE DEPLOYMENT GAP the owner must decide how apps/nivxray-xdr is released (Vercel
    project rebuild from the new commit for BOTH hostnames) - that is a platform/release
    decision, not a code change.
- DEPLOYER RCA CONFIRMS (RCA_c0062f89-b97c-455a-9102-f893a9f00ccc.MD):
  * Emergent deploy run c0062f89, live 2026-09-30T11:42:42Z UTC. No publish number and NO
    commit SHA is recoverable - the pipeline packages a SOURCE SNAPSHOT, not a git checkout.
  * DEPLOYED BACKEND CONTAINS ALL REVIEWED CHANGES: xdr_scope.py returns authorized_tenants;
    edr_plane/enrollment/instructions.py exists and imports cleanly (NO ImportError);
    edr_connector.py sets install_invocation_carries_secret=False. Backend healthy. Mongo
    binding unchanged (DB greeting-app-5782-test_database, 95 collections). Build SUCCESS.
  * EMERGENT BUILDS ONLY /app/frontend (CRA/craco) and serves greeting-app-5782.emergent.host
    + nivxray.nivxforge.com. apps/nivxray-xdr (Vite) is NOT in the pipeline; xdr.nivxforge.com
    and edr.nivxforge.com are Vercel (project prj_Pk0K..., host redirects in its vercel.json).
    => the reviewed FRONTEND can only reach production via a SEPARATE Vercel re-publish of
    apps/nivxray-xdr. Re-running the Emergent publish will NOT update those consoles.
  * RELEASE-PATH DEBT (P0, owner decision): the approved changeset is HALF-LIVE. Production
    backend is new, both production consoles are old. Until the Vercel re-publish happens the
    XDR selector stays empty and EdrAddDevicePage still builds the argv enrolment command.
  * Benign pre-existing prod noise confirmed: threatfox 401 (ABUSE_CH_AUTH_KEY), transient
    warm-up /health timeouts.
- RELEASE-PATH DISCOVERY (read-only, nothing changed). PROVEN:
  * apps/nivxray-xdr = Vite app. vercel.json: installCommand `yarn install --production=false`,
    buildCommand `bash scripts/vercel-build.sh`, outputDirectory `dist`, framework null,
    SPA rewrite, host-based redirects (/ -> /xdr for xdr.nivxforge.com, / -> /edr for
    edr.nivxforge.com).
  * TWO VERCEL PROJECTS, one root directory, one build command, differentiated ONLY by env var
    NIVX_PRODUCT_SCOPE (unset|xdr -> XDR host; edr -> EDR host). Documented in
    scripts/vercel-build.sh. The scope var is load-bearing: without it ProductScopeGuard stops
    working and either product can render on either host.
  * LIVE PROVENANCE from each host's own /build-info.json (written by the build script):
    xdr.nivxforge.com product_scope=xdr built_at 2026-09-26T18:19:37Z
    edr.nivxforge.com product_scope=edr built_at 2026-09-26T18:20:24Z
    both api_origin=https://nivxray.nivxforge.com, cross_product_origins=0.
    47 seconds apart => two projects built back-to-back. Both predate the reviewed frontend
    commits (3aeef2f2 2026-09-30 10:53Z, 5b968379 2026-09-30 11:09Z) by 4 days.
  * APPROVED SOURCE: /app HEAD a3523a8891a086fa2e97a38ddea8492863195d3b contains ALL FOUR
    frontend fixes with ZERO uncommitted drift.
  * NESTED REPO TRAP: apps/nivxray-xdr has its OWN .git with remote
    https://github.com/jpreddy017/nivxray-xdr.git, branch main, HEAD 6b1441c dated
    2026-08-31, and that tree does NOT EVEN CONTAIN XdrScopeNavigator.jsx. It is ~1 month
    stale and tracks the app at its own root (no apps/ prefix). /app has NO git remote
    configured (Emergent-managed). Which repo the Vercel projects build from is NOT provable
    from the repo: the Root Directory comment implies the monorepo, the nested remote implies
    the standalone repo. NOT INFERRED - owner must read the Vercel dashboard.
  * apps/nivxray-xdr/.env is git-tracked and points REACT_APP_NIVXRAY_API_URL at the PREVIEW
    backend BY DESIGN; vercel-build.sh overrides it with XDR_PROD_API_ORIGIN (default
    https://nivxray.nivxforge.com) as a real env var, and scripts/verify-production-build.js
    guards the artifact. Do not "fix" that .env.
  * No GitHub workflow in this repo deploys Vercel - the trigger is Vercel's own Git
    integration or a manual `vercel --prod`.
  * PRODUCTION AUTH = BLOCKED. Mechanism: POST /api/auth/login, bcrypt against users.password
    in the production DB, JWT signed with production JWT_SECRET; no SSO; a
    must_change_password gate exists. Owner must supply a valid production PLATFORM password
    (or run the GETs). I will NOT retry the invalid credential.
- VERCEL RELEASE RECONCILIATION (read-only; fetched the two production branches from GitHub):
  * github.com/jpreddy017/nivxray-xdr holds the MONOREPO (both prod branches contain agents/,
    backend/, apps/...). Not a standalone app repo.
  * release/xdr-w1-candidate HEAD 9ae7bdac 2026-09-18 08:44Z "Auto-generated changes"
    phase2/edr-production     HEAD e9d71354 2026-09-09 11:48Z "Auto-generated changes"
    ON BOTH BRANCHES ALL FOUR REVIEWED FILES ARE ABSENT ENTIRELY - not stale versions,
    the files do not exist: XdrScopeNavigator.jsx, AdminTenantGate.jsx, EdrAddDevicePage.jsx,
    EdrDownloadsPage.jsx. Both branches are weeks behind.
  * LIVE artifacts are built 2026-09-26T18:19/18:20Z = NEWER than both branch HEADs and DO
    contain EdrAddDevicePage/EdrDownloadsPage chunks + /build-info.json (written ONLY by
    scripts/vercel-build.sh). => the live production deployments were NOT built from these
    branch HEADs. Most consistent explanation: a manual `vercel --prod` from a working
    directory (apps/nivxray-xdr/.vercel/project.json is a CLI link), which also explains the
    "production deployment config differs from project settings" warning on BOTH projects.
  * a3523a88 is NOT in the GitHub repo (upload-pack: "not our ref") => Emergent-local snapshot
    lineage. Save to GitHub would create a NEW commit; the target branch is chosen in the
    Emergent UI (no branch is pinned in .emergent/emergent.yml).
  * BUILD MODEL: XDR (`yarn build` -> dist) only makes sense with Root Directory =
    apps/nivxray-xdr; EDR (`cd apps/nivxray-xdr && vite build` -> apps/nivxray-xdr/dist) only
    makes sense with Root Directory = repo root. ROOT DIRECTORY WAS NOT IN THE SCREENSHOTS =
    the one missing fact. CRITICAL: vercel.json is only honoured at the project Root
    Directory, and ONLY vercel-build.sh sets XDR_PROD_API_ORIGIN/NIVX_PRODUCT_SCOPE, writes
    build-info.json and runs verify-production-build.js. A build that bypasses it points the
    console at the PREVIEW backend and drops ProductScopeGuard.

- XDR SELECTOR RELEASE-DIFF PREPARATION (read-only; no merge, no push, no deploy). PROVEN:
  * ACCEPTED SOURCE COMMIT: 3aeef2f2 ("DEPLOYMENT_ENROLLMENT_FOUNDATION"), /app lineage.
    Release scope = exactly 2 files, +28/-6:
      apps/nivxray-xdr/src/xdr/admin/AdminTenantGate.jsx        (+14/-3)
      apps/nivxray-xdr/src/xdr/components/XdrScopeNavigator.jsx (+20/-6... net +20/-3)
    Patch exported to /tmp/b8-selector.patch (239 lines).
  * PRODUCTION SOURCE IDENTIFIED (owner's premise corrected): production was NOT built from
    release/xdr-w1-candidate. That branch (9ae7bdac, 2026-09-18) does not contain
    AdminTenantGate.jsx, XdrScopeNavigator.jsx, IntelligencePolicyBody.jsx,
    src/lib/scopeApi.js, src/xdr/nx/apiError.js or any EdrAddDevicePage/EdrDownloadsPage -
    yet the LIVE artifacts ship EdrAddDevicePage-*.js, EdrDownloadsPage-*.js and a
    XdrAdminPage chunk containing data-testid "xdr-admin-tenant-gate".
    REAL PRODUCTION BASE = github feature/rc2-alignment @ 6523ba1d (2026-09-26 18:15:11Z,
    "PHASE 0 PROMOTION - STAGE 3 ... promotion is an owner-only Vercel action"); the two
    Vercel projects built 18:19:37Z (xdr) and 18:20:24Z (edr) - 4 min later.
    BLOB-LEVEL PROOF: 6523ba1d:AdminTenantGate.jsx = d905d42a = 3aeef2f2^:AdminTenantGate.jsx
    and 6523ba1d:XdrScopeNavigator.jsx = e200cdf5 = 3aeef2f2^:XdrScopeNavigator.jsx.
    The accepted patch's parent blobs ARE the production blobs.
  * LIVE PRODUCTION IS PRE-FIX (confirmed by artifact, not inference): the live
    XdrAdminPage-DdCw8LHM.js contains "scope/authorized" and "xdr-admin-tenant-gate" but
    ZERO occurrences of "authorized_tenants" => it still reads the evidence-derived list.
  * CHERRY-PICK SAFETY: `git apply --check` of /tmp/b8-selector.patch onto a worktree of
    6523ba1d = CLEAN, zero fuzz, no unrelated changes. Onto release/xdr-w1-candidate it is
    IMPOSSIBLE and UNSAFE: both target files are absent, their imports
    (@/lib/scopeApi, @/xdr/nx/apiError) do not exist on that branch, XdrShell there renders
    XdrContextBar (never XdrScopeNavigator) and no surface imports AdminTenantGate - so the
    two files would be dead code AND the vite build would fail on unresolved imports.
    release/xdr-w1-candidate IS a strict ancestor of 6523ba1d and of rc2; fast-forwarding it
    would drag 1005 changed files (267 frontend) incl. EDR work - rejected as not minimal.
  * DELTA RISK IF RELEASING FROM rc2 TIP INSTEAD OF PROD BASE: 6523ba1d..b42c34c7 = 138
    commits, 303 files, 41 frontend source files (tenant.js, CustomerPicker, whole AMP/DT2
    trajectory set). Not part of this release.
  * ALREADY ON GITHUB: branch fix-authorized-tenant-selector (03f8e10, PR #2) = rc2 tip
    b42c34c7 + 3 commits carrying the SAME authority contract (backend xdr_scope.py +
    the same 2 frontend files). It differs from the accepted /app version only cosmetically
    (display_name rendering, "no XDR incidents" volume label, comments). It is NOT based on
    the production base, so merging it releases the 138-commit delta too.
  * BUILD PROOF (local only, nothing published): NIVX_PRODUCT_SCOPE=xdr
    bash apps/nivxray-xdr/scripts/vercel-build.sh -> 2228 modules, built in 6.31s,
    "XDR PRODUCTION BUILD GUARD . PASSED", api_origin https://nivxray.nivxforge.com,
    product scope declared "xdr". `git status` CLEAN afterwards - no lockfile or tracked
    file changed (dist/ is gitignored). Fresh artifact contains "authorized_tenants" in
    XdrAdminPage-*.js and XdrShell-*.js.
  * STILL OWNER-ONLY (not provable from the repo): which Git branch/project the two Vercel
    projects are linked to, and whether promotion is Git-integration or `vercel --prod`.
    The 4-minute gap + apps/nivxray-xdr/.vercel/project.json CLI link + the "production
    deployment config differs from project settings" warning all point to a manual
    `vercel --prod`. Vercel Root Directory must be apps/nivxray-xdr so vercel.json and
    scripts/vercel-build.sh are honoured; a build that bypasses the script points the console
    at the PREVIEW backend and drops ProductScopeGuard.
  * NOTHING MERGED, PUSHED OR DEPLOYED. EDR untouched. phase2/edr-production untouched.
    No tenants/users/tokens. Backend authority unchanged.

- B8-SCOPE-1 CANDIDATE PREPARED (2026-09-30). Owner-approved base feature/rc2-alignment@6523ba1d.
  * Branch release/xdr-b8-selector-candidate, local commit c927f626, tree
    b3e26825529022990dd6ca30b2474f18876108d8. diff --name-only 6523ba1d..candidate = exactly
    AdminTenantGate.jsx + XdrScopeNavigator.jsx, 2 files +28/-6, byte-identical to 3aeef2f2.
  * Build guard on the candidate tree: 2209 modules, 6.28s, XDR PRODUCTION BUILD GUARD PASSED.
  * PUSH BLOCKED: /root/.git-credentials stale ("Invalid username or token"); /app/.tok is a
    JWT, not a GitHub PAT. Branch creation on GitHub is an OWNER action. Patch + exact recipe
    persisted at docs/releases/B8_SCOPE_1_xdr_selector.patch and
    docs/releases/B8_SCOPE_1_XDR_SELECTOR_CANDIDATE.md.
  * SECURITY DEBT: .tok (a JWT) is committed at repo root on every branch inspected.
  * NEXT GATE: Vercel XDR project Root Directory = apps/nivxray-xdr + branch linkage, then
    deploy the isolated candidate, acceptance, then move to KUSHU enrollment.
  * GITHUB BRANCH release/xdr-b8-selector-candidate EXISTS (owner-created): f8d48349 +
    983f5680 on base 6523ba1d229004abc38f23a9d36be8d278e65e99. It is a RECONSTRUCTION, not
    the reviewed bytes: 2 files but +15/-6 (missing the 13 reviewed comment lines, different
    local variable names, and `t.display_name || t.customer` where the reviewed AdminTenantGate
    renders `display_name · customer`). Functionally equivalent (authority list + volumes Map)
    except that one admin option label.
  * AGENT CANNOT PUSH: `git push` -> "could not read Username for https://github.com". No
    usable GitHub credential in the pod. "Save to GitHub" would push the /app workspace tree
    (different lineage), NOT a 2-file diff, so it is not a valid release path either.
  * REALIGNMENT PATCH PROVIDED: docs/releases/B8_SCOPE_1_align_github_branch_to_reviewed_bytes.patch
    (+21/-8 on top of 983f5680). Applying it makes the branch byte-identical to the reviewed
    candidate, and the diff vs base becomes exactly 2 files / +28/-6. Verified in a worktree.

- KUSHU C0.5 PRE-ENROLMENT READINESS (read-only; nothing minted, enrolled, executed or
  deployed). VERDICT = HOLD on three owner-verifiable items; NO DEFECT FOUND.
  * Production health PASS: GET https://nivxray.nivxforge.com/api/health ->
    {"status":"ok","service":"nivxray-api"}.
  * Enrollment control plane LIVE and auth-enforced (403 "Not authenticated" unauthenticated):
    POST/GET /api/edr/enrollment/tokens, POST /api/edr/enrollment/tokens/{id}/revoke,
    GET /api/edr/enrollment/endpoints. All TENANT_SCOPED via explicit X-Tenant-Id.
    /api/edr/onboarding/downloads does NOT exist (404) - the packages route is
    /api/edr/onboarding/packages.
  * TOKEN INVENTORY NOT VERIFIABLE BY THE AGENT: production auth is owner-only
    (admin@nivxray.com is PREVIEW-only). OLD_UNLABELED_TOKEN_ACTIVE = UNVERIFIED.
    By design GET /tokens is metadata-only ("No route returns a token's plaintext or its
    stored digest") and mint returns the plaintext exactly once, in the mint response.
  * INSTALLER PROVENANCE PASS: GH run 36695465379 = workflow "NivXForge Windows Installer
    (V1)", branch feature/rc2-alignment, head_sha b42c34c7, status completed /
    conclusion success, created 2026-09-30T09:20:16Z. Artifact
    NivXForgeEDRSetup-windows-x64, 19,825,130 bytes, expired=false, expires
    2026-10-30T09:21:28Z. Expected exe SHA256
    FE05C4A8E7246DBBB6D9850F9C4B80DDBFECE3175770B30D4A373D95FA6EDB7B (owner-recorded;
    re-verify on KUSHU, the agent cannot read run logs unauthenticated).
  * STDIN-ONLY CONTRACT PASS, with blob proof that the SHIPPED binary carries it:
    b42c34c7:agents/nivxforge-windows/nivxforge_sensor.py = d0593501 = /app HEAD, and
    nivxforge_setup.py = de994624 = /app HEAD. sensor.refuse_secret_on_command_line scans
    the WHOLE argv before argparse, rejects LEGACY_TOKEN_FLAGS and any enr_/nvxenr_ shaped
    value (name or =value) without echoing it; read_enrolment_secret reads stdin only;
    setup.install raises unless --token-stdin (required=True on the sensor parser).
    Workflow gates assert the argv refusal and the --token-stdin help text.
    backend/edr_plane/enrollment/instructions.py windows_exe_invocation emits
    Read-Host -AsSecureString -> SecureStringToBSTR -> PtrToStringBSTR | exe --token-stdin
    -> finally ZeroFreeBSTR + Remove-Variable. No --token/-EnrollmentToken plaintext form.
  * NO LATER CODE INVALIDATES C0.5: zero commits touch agents/nivxforge-windows between
    b42c34c7 and /app HEAD. NOTE instructions.py was created in 3aeef2f2 (AFTER b42c34c7)
    so it is absent from the installer build commit, but the deployer RCA confirmed it IS
    present and importable in the DEPLOYED production backend - instruction text and binary
    behaviour agree.
  * OWNER DECISION CHANGE RECORDED: target tenant moved from "NivXForge Canary" (kind LAB,
    never created) to "Internal Validation" ten_e759b7288598bd882e3dcac49d. Canary telemetry
    will therefore land in a REAL validation tenant, not a disposable LAB tenant.
  * TERMINOLOGY CORRECTION for acceptance: enrollment_state, credential_state and
    sensor_state are THREE INDEPENDENT dimensions, not a chain. ENROLLED + ACTIVE +
    ENROLLED_NEVER_REPORTED is a legal state and means nothing was collected.

- DESKTOP-A9HGFJJ ACCIDENTAL REVOCATION — READ-ONLY RECOVERY ANALYSIS (nothing modified,
  no token minted/revoked, no state changed, no restart, KUSHU untouched).
  VERDICT: DESKTOP_CREDENTIAL_RECOVERY = SAFE_EXISTING_PATH.
  * endpoint ep_1989031c8c1d0085812f, WINDOWS, 157,226 events, last telemetry
    2026-10-01T02:22:52Z. UI now REVOKED/REVOKED/REVOKED + NOT TRUSTED.
  * IDENTITY IS DETERMINISTIC, SO RE-ENROLMENT CANNOT DUPLICATE IT.
    EndpointIdentity.mint (backend/edr_plane/contracts/identity.py:98) = pure
    _iid("ep", tenant_id, kind, value) over precedence hardware processor_id > machine_guid >
    device_iid > hostname. Same host + same tenant => the SAME ep_1989031c8c1d0085812f. The
    agent never proposes an endpoint_id (router enroll() mints it server-side).
    CLONE COLLISION NOT TRIGGERED: one physical host re-presenting its own processor_id is
    the intended merge. The clone risk needs TWO hosts with no processor_id sharing a
    machine_guid; it is unrelated to this recovery.
  * RE-ENROLMENT PRESERVES THE SERVER-SIDE DELIVERY RECORD BY DESIGN (store.enroll, the
    "P0-3 DEFECT FIX"): sensor_state/last_telemetry_at/event_count/last_heartbeat_at/
    report_interval_seconds/cadence_basis/lifecycle_reported/outbox_queue_depth are written
    $setOnInsert ONLY; identity + credential fields are $set. It then explicitly HEALS
    sensor_state REVOKED -> REPORTING (or ENROLLED_NEVER_REPORTED if nothing was ever
    delivered) and returns delivery_history_preserved=true.
  * ROTATE IS NOT A RECOVERY PATH AFTER REVOKE. store.rotate_credential requires an ACTIVE
    credential and raises NO_ACTIVE_CREDENTIAL (404). revoke_endpoint set every ACTIVE
    credential to REVOKED and $inc auth_epoch, and killed all sessions. The UI's "Rotate"
    button on a REVOKED row will therefore fail. Re-enrolment with ONE fresh token is the
    only supported recovery.
  * LOCAL EVIDENCE IS SAFE. sensor.enrol() writes ONLY identity.json (mkdir + write + chmod).
    setup.install() stages the exe, ACLs the state dir, enrols, then
    stop/delete/create/start the service. NOTHING in install touches outbox.jsonl,
    outbox.offset, channels.json or the SQLite journal. ONLY `uninstall --purge` deletes the
    state dir - it must never be used here.
  * WHY THE BACKLOG IS INTACT: _drain advances OFFSET_FILE only AFTER a 2xx accept; on
    401/403 it clears the session and re-seeks to the unadvanced offset; any other failure
    prints "[journal] held at offset N" and breaks WITHOUT advancing. Write-after-accept =
    no silent discard. The journal's cursors table is committed in the same transaction as
    the evidence and advances with MAX(), so it cannot regress.
  * ⚠ A SERVICE RESTART IS REQUIRED, AND IS THE ONE NON-OBVIOUS STEP. run() calls
    _read_identity() ONCE before its loop, so the LIVE service holds the REVOKED credential
    in memory for its whole lifetime. Re-writing identity.json alone will NOT resume
    delivery. setup.install --re-enrol performs the restart itself (step 4), so no manual
    restart is needed if recovery is done through the installer.
  * SECURITY INCIDENT RAISED SEPARATELY: an enrolment token PLAINTEXT
    (tok_dfa2e77665974af7, expiry 2026-10-01T03:00:29Z) was rendered by the UI, captured in
    a screenshot and pasted into chat. Treat as COMPROMISED: confirm EXPIRED or revoke.
    Second token tok_d9b4ad08c07249b0 expires 02:56:10Z. Neither may be used for recovery.
  * TO VERIFY AFTER RECOVERY (possible classification gap, not asserted): the rejected-sensor
    alarm reads "0 of 231 refused attempts came from an agent that HAD standing and lost it"
    while DESKTOP is exactly such an agent. Check whether post-revoke session-open refusals
    are classified as lost-standing rather than ENROLLMENT_TOKEN_INVALID.
- OWNER-APPROVED PRODUCT REQUIREMENT (RECORDED, NOT IMPLEMENTED): reversible endpoint
  DISABLE/ENABLE lifecycle, separate from destructive REVOKE CREDENTIAL and from
  DELETE/OFFBOARD, with a second confirmation dialog naming the endpoint, consequence text,
  visual separation of enrolment-token actions from endpoint-credential actions, and an
  explicit Recover/Re-enrol action on a REVOKED row.
  GAP CONFIRMED: no reversible authority exists today. EnrollmentState =
  NEVER_ENROLLED|ENROLLMENT_PENDING|ENROLLED|REVOKED|RETIRED; CredentialState =
  NONE|ACTIVE|ROTATION_PENDING|REVOKED; SensorState =
  NO_SENSOR|ENROLLED_NEVER_REPORTED|REPORTING|SILENT|REVOKED. There is NO DISABLED/SUSPENDED
  member and no enable/disable/reinstate route anywhere in edr_plane/enrollment or
  routers/edr_enrollment.py. Minimum change set is recorded in the turn response.
  INVARIANT TO PRESERVE: DISABLED != REVOKED != OFFBOARDED/DELETED.

- DESKTOP RECOVERY --token-stdin FAILURE (read-only RCA; nothing modified, no mint/revoke,
  no restart, no deploy, KUSHU untouched).
  VERDICT: STDIN_RECOVERY_PATH = ARTIFACT_MISMATCH (+2 real code defects found).
  * ROOT CAUSE, PROVEN BY EXACT STRING: the observed refusal "--token is required to enrol.
    The installer carries no credential by design." is the PRE-HARDENING text, present up to
    fe08077e (2026-09-30 03:06:55Z) and REPLACED in 572fa3ed (08:19:48Z) with "--token-stdin
    is required to enrol ... and <STDIN_ONLY_NOTICE>". The exe on DESKTOP was therefore built
    from a commit <= fe08077e and predates the stdin hardening. It is NOT the audited
    artifact of run 36695465379 (head_sha b42c34c7, built 09:20:16Z) whose exe SHA256 is
    FE05C4A8E7246DBBB6D9850F9C4B80DDBFECE3175770B30D4A373D95FA6EDB7B.
  * WHY IT DID NOT SAY "unrecognized arguments": main() uses
    build_parser().parse_known_args(raw)[0]. At fe08077e the install subparser has --token
    and NO --token-stdin, so parse_known_args SILENTLY DISCARDED --token-stdin, args.token
    stayed None, STAGE and PROTECTED STATE ran, and enrolment refused. Reproduced locally
    with the fe08077e parser definition: strict parse_args exits 2 with "unrecognized
    arguments: --token-stdin", parse_known_args returns token=None. The hardened build's own
    comment predicted the mirror image of this trap.
  * NO STDIN CONSUMER EXISTED. There is no subprocess: setup calls sensor.enrol() in-process
    and only the HARDENED sensor.read_enrolment_secret() reads sys.stdin. In the old build
    nothing reads stdin at all, so the piped plaintext was never drained and was discarded
    when the process exited. It never reached argv, disk, the registry, the service binPath
    or Sysmon EID1. stdin was NOT consumed earlier by PyInstaller.
  * ⚠ THE SERVICE WAS ALMOST CERTAINLY LEFT STOPPED - ACQUISITION GAP FORMING.
    install() STAGE runs BEFORE enrolment and stops the service twice: once when
    source != INSTALLED_EXE (sc stop, then copy2 over INSTALLED_EXE) and again inside
    _stage_service_host() (sc stop, then copytree over SERVICE_DIR). Step 3 then raised
    SystemExit, so step 4 (sc create + sc start) NEVER RAN. A clean `sc stop` does not
    trigger the configured failure/restart actions, and AUTO_START only applies at boot.
    The on-disk service image was ALSO overwritten with the OLD build's onedir payload.
  * EVIDENCE IS STILL SAFE: nothing in STAGE or _protect_state_dir touches identity.json,
    outbox.jsonl, outbox.offset, channels.json or the SQLite journal; _protect_state_dir only
    re-applies ACLs. Only `uninstall --purge` deletes state.
  * RECOVERY TOKEN: unused, so still ACTIVE until TTL. Not consumed by the failed run.
    Treat as spent for hygiene; revoke or let it expire. Do not reuse it.
  * DEFECT 1 (P0, NOT FIXED): install() must not stop the running service during STAGE
    before enrolment has succeeded, and must restart it on ANY failure. Today a failed
    re-enrolment silently blinds a previously healthy endpoint. Fix = stage to a temp dir,
    do enrolment first, or wrap steps 1-4 in try/finally that restarts the service.
  * DEFECT 2 (P1, NOT FIXED): the install subcommand should reject unknown flags
    (strict parse_args) while keeping the SERVICE_FLAG carve-out, so a wrong-version binary
    says "unrecognized argument" instead of a misleading credential refusal.
  * DEFECT 3 (P1, NOT FIXED): no build/version provenance check. install should print its
    own build commit/SHA256 at STAGE and refuse a downgrade over a newer installed state.

- P0 FIX IMPLEMENTED (2026-10-01): WINDOWS RE-ENROL STAGING RACE / SERVICE FILE LOCK.
  WINDOWS_REENROL_STAGING_FIX = HOLD (code+tests PASS; the Windows ARTIFACT cannot be built
  from this pod - no GitHub push credential, and PyInstaller cannot cross-compile a PE).
  * ROOT CAUSE: `sc.exe stop` is asynchronous. install() STAGE stopped the service and
    immediately replaced its image, racing the dying process ->
    "Permission denied: C:\Program Files\NivXForge\sensor\service\NivXForgeSensor.exe".
    Step 3 then aborted, so step 4 (sc create + sc start) never ran and a healthy endpoint
    went dark.
  * agents/nivxforge-windows/nivxforge_setup.py:
      _service_state()            SCM state by NAME (localisation-safe), "" if absent
      _wait_for_service_state()   deterministic poll to a target state
      _image_is_released()        same-directory rename probe = honest proof no handle
      _wait_for_image_release()   bounded wait for the handle to go
      _stop_service_and_wait()    stop, PROVE STOPPED, PROVE released; FAILS CLOSED
      _restore_service()          rollback; restarts ONLY a service that WAS running
      _replace_tree()             bounded-retry copytree for the post-exit lock window
      build_identity()            baked commit/run provenance (nivxforge_build.py)
      self_digest()               SHA256 of the running artifact, printed at STAGE
      _sc()                       a missing sc.exe is a failed command, never an exception
      _stage_service_host()       NO LONGER drives the SCM; REFUSES over a RUNNING service
      install()                   reads prior service state first, wraps steps 1-4 in
                                  try/except BaseException -> ROLLBACK -> re-raise
      main()                      unknown args now REFUSED (an ignored flag is how the
                                  pre-hardening build pretended to accept --token-stdin)
      version                     reports build_commit/build_run_id/artifact_sha256/state
  * build_windows_installer.ps1 generates nivxforge_build.py (commit/time/run id) and
    PyInstaller carries it (--hidden-import nivxforge_build). .gitignore excludes it.
  * windows-sensor-installer.yml: artifact contract now asserts build provenance,
    artifact_sha256 and unknown-argument refusal; NEW GATE 4 "Re-enrol against a RUNNING
    service · stop race + rollback" proves, against the real SCM and real NTFS locks:
    RUNNING-guard, stop-and-prove, restore idempotence, and that a FAILED frozen
    `install --re-enrol` (stdin closed, no token) leaves the service RUNNING.
  * TESTS: backend/tests/edr/test_p0_windows_reenrol_staging_race.py - 18 passed, incl. the
    exact live PermissionError reproduction, stop timeout fail-closed, locked image,
    staging-failure rollback, enrolment-failure rollback with NO token read/consumed,
    operator-stopped service NOT silently started, state/outbox/offset/cursors byte-identical
    after failure AND after a successful re-enrol (endpoint_id preserved), resume without a
    token, unknown-flag refusal, --token not reintroduced, provenance + digest.
  * TWO STALE TESTS UPDATED to the new contract (they asserted the defective behaviour):
    test_windows_installer_scm_entrypoint::test_staging_refuses_to_overwrite_a_running_service_image
    test_windows_installer_service_stage4::test_running_service_is_stopped_AND_PROVED_before_the_binary_is_replaced
  * REGRESSION: cd /app/backend && pytest tests/edr + the 4 windows suites + B8 scope ->
    2122 passed, 3 skipped, 0 failed (226s).
  * NOT DONE, OWNER ACTION: trigger workflow_dispatch on windows-sensor-installer.yml to
    produce the new exe + SHA256. DESKTOP and KUSHU untouched, no token minted/revoked/used,
    nothing deployed.

- P0 OWNER GITHUB HANDOFF PREPARED (2026-10-01). Nothing pushed, merged, deployed or
  triggered. DESKTOP and KUSHU untouched. No token minted/used/revoked.
  * The platform auto-commit had already folded the P0 work into
    4b6a08b7 on feature/rc2-alignment TOGETHER WITH unrelated files
    (apps/nivxray-xdr-response/data/executions.db-shm, executions.db-wal, memory/PRD.md).
    That commit was NOT altered, reset or discarded.
  * CLEAN ISOLATED COMMIT, built in a temporary worktree so /app was never checked out:
      branch  fix/windows-reenrol-staging-race   (local only, lives in /app/.git)
      commit  a0e402af3f357f749e46bca4d428939da8a802dc
      parent  ee0348e260930b49e970d514879cb1afe37f90df
      7 files, +855/-56, and all 7 blobs are BYTE-IDENTICAL to 4b6a08b7.
      Excluded: the two SQLite artifacts and memory/PRD.md.
  * PATCH: .git/handoff/P0_WINDOWS_REENROL_STAGING_RACE.patch (also /tmp, which gets wiped)
      1150 lines, 52,657 bytes,
      sha256 dd74074a41d5a4dbc01eb17a711e8f9c5b45c3f8cef1b18ea5172005cb1fe83f
      Secret-scanned: clean (only test placeholders nvx_placeholder_value_for_test_only,
      a-single-use-secret, ten_ci_gate4_not_a_real_tenant). Kept OUTSIDE version control
      under .git/, so it can never enter a commit.
  * GITHUB BASE VERIFIED: refs/heads/feature/rc2-alignment =
    b42c34c7964869c62baf1c1340154401a752e348 (ls-remote). All 6 modified files are
    byte-identical at b42c34c7 and at the patch parent, and `git apply --check` of the
    patch on a worktree of b42c34c7 is CLEAN, zero fuzz. Applying it = 1 commit ahead of
    the verified GitHub base. The 15 commits between b42c34c7 and ee0348e2 are NOT needed.
  * NOTE: refs/heads/release/xdr-b8-selector-candidate has moved to e2f15a25 (was 983f5680).
  * NO DOWNLOAD LINK IS POSSIBLE from this pod: the preview host does not serve
    frontend/public (even pre-existing tracked files under /downloads/ return index.html),
    and adding a backend route would be an implementation change. Owner must copy the patch
    out of .git/handoff/.
  * Build workflow for the new artifact: .github/workflows/windows-sensor-installer.yml,
    trigger workflow_dispatch (no inputs), job runs-on windows-latest, artifact
    NivXForgeEDRSetup-windows-x64 (exe + SHA256SUMS.txt + build-info.json + gate0/*.json),
    retention 30 days. NOT TRIGGERED.
  * EVIDENCE STATUS UNCHANGED: 2122 passed / 3 skipped / 0 failed is PREVIOUSLY REPORTED
    Linux evidence. NO new run. GATE 4 HAS NOT RUN. WINDOWS_REENROL_STAGING_FIX = HOLD.
  * PUSH CAPABILITY RE-TESTED 2026-10-01 after the remote branch was created: STILL
    UNAVAILABLE. /root/.git-credentials is now 0 BYTES (was 124 and stale), no git remote in
    /app, no gh CLI, no GitHub env token; `git push` -> "could not read Username". Anonymous
    READ works: ls-remote confirms refs/heads/fix/windows-reenrol-staging-race =
    b42c34c7964869c62baf1c1340154401a752e348 exactly as the owner created it.
    Platform answer: GitHub is OAuth-only, "the agent cannot commit or push on its own";
    all pushes are owner-initiated via Save to GitHub. No PAT path exists.
  * EXPORT ROUTE PREPARED (no repository code changed): the patch is now also at the repo
    ROOT as /app/P0_WINDOWS_REENROL_STAGING_RACE.patch, kept untracked via
    .git/info/exclude (a LOCAL file that is never committed), so it is visible in the VS
    Code "Code" view for right-click -> Download. `git status` stays clean and the file can
    never enter a commit. Copy also at .git/handoff/.
  * ALTERNATIVE (owner choice): Save to GitHub publishes the workspace branch
    feature/rc2-alignment incl. 4b6a08b7, whose 7 P0 blobs are BYTE-IDENTICAL to a0e402af,
    so `git checkout <that commit> -- <the 7 paths>` reproduces the implementation
    bit-exactly with zero retyping. SIDE EFFECTS TO ACCEPT: it also publishes the 15
    session commits and the 3 unrelated files to rc2, and because
    windows-sensor-installer.yml has a push trigger on agents/nivxforge-windows/** with NO
    branch filter, that push would ALSO start a Windows build on rc2.
  * SAVE-TO-GITHUB SCOPE CHECK (asked before the owner clicks): ANSWER IS NO, NOT GUARANTEED.
    Save to GitHub publishes the WORKSPACE snapshot of the current branch
    (feature/rc2-alignment @ feaa702d), not the isolated commit a0e402af. Targeting
    fix/windows-reenrol-staging-race (= b42c34c7) it would write 26 FILES and carry 18
    COMMITS, including every forbidden item: apps/.../executions.db-shm, executions.db-wal,
    memory/PRD.md, docs/releases/*.patch, the B8 selector files, backend enrollment files,
    deployer-agent-docs/RCA_*.MD. DO NOT CLICK IT for this release.
  * The handoff patch was MOVED to /app/dist/P0_WINDOWS_REENROL_STAGING_RACE.patch, which is
    ignored by the COMMITTED .gitignore (line 58 "dist"), so no packaging route can publish
    it; it is still visible for VS Code right-click -> Download. The repo-root copy was
    removed and .git/info/exclude restored to stock. git status is clean.

- GATE 4 CI STDIN FIX - PATCH HANDOFF (2026-10-01). Nothing pushed/saved. HOLD unchanged.
  * Gate 4 of run 36835748946 failed at PowerShell PARSE time on `--token-stdin < NUL`
    ("The '<' operator is reserved for future use."), so the re-enrol rollback was NEVER
    exercised. The generated artifact must NOT go near DESKTOP.
  * CI-HARNESS-ONLY correction, one file, one hunk:
    Start-Process -RedirectStandardInput with a 0-byte file (a valid EMPTY stream, so
    read_enrolment_secret() is really entered and refuses), splatted parameters (no line
    continuations - that is where the parse error lived), Resolve-Path for FilePath, plus
    THREE STRICTER assertions: non-zero ExitCode, stdout+stderr concatenated, and the
    refusal must be "stdin carried no enrolment secret" which only
    sensor.read_enrolment_secret() raises AFTER stage 1 stopped the service (an early
    argument refusal would also print ROLLBACK and make a pass vacuous).
  * COMMIT BUILT ON THE REAL GITHUB TIP, not on the workspace:
    refs/heads/fix/windows-reenrol-staging-race = d5467994ede50f228e4e7c736d71b7d9560730d6
    (owner's push of the P0 commit; verified to contain exactly the 7 P0 files, and its
    workflow file is byte-identical to the reviewed pre-image).
    local branch gate4/ci-stdin-fix, commit daa033400c61d7e139365872c9d7d33c534f12cf,
    diff-tree = exactly 1 file. `git apply --check` on d5467994 = CLEAN.
  * PATCH: dist/GATE4_CI_STDIN_FIX.patch - 5,758 bytes, 108 lines,
    sha256 3b330a7aaf90e979f295f45bc1a7586e33395fc3fb51278723b65789fdae166d
    (copy at .git/handoff/). Ignored by the committed .gitignore line 58 "dist", so no
    publishing route can include it. The earlier .diff was removed.
  * nivxforge_setup.py untouched; --token-stdin preserved; no --token; no real token;
    DESKTOP and KUSHU untouched; no production/backend/frontend change.

- GATE 4 RUN #13 (commit 7897346d, run 36838666449) - READ-ONLY DIAGNOSIS. Nothing edited,
  committed, pushed or saved. HOLD unchanged; the artifact must NOT go near DESKTOP.
  * The PowerShell fix WORKED: Gate 4 executed for the first time and printed
    "GATE4 PRECONDITION: RUNNING". The `< NUL` parse error is gone.
  * NEW, DIFFERENT HARNESS DEFECT (not an installer defect): gate4_race.py imports the
    SOURCE module and calls s._stage_service_host(). _service_payload_dir() reads
    sys._MEIPASS, which exists ONLY in the frozen exe, so from source it returns None and
    _stage_service_host() raises "this build carries no Windows service host payload" at
    nivxforge_setup.py:387 - BEFORE reaching the RUNNING guard the gate exists to prove.
    The harness then re-raised it as AssertionError on `assert "RUNNING" in text`, so the
    step failed with "GATE 4 lifecycle checks failed". The later end-to-end section was
    never reached; it correctly uses the FROZEN dist/NivXForgeEDRSetup.exe.
  * PROPOSED MINIMAL REPAIR (one hunk, same Gate 4 step, 18 added lines): hand the source
    module a byte-copy of the service host that the UPSTREAM "Service host unpacks from the
    installer" gate already staged from the frozen artifact via `stage-host`
    (shutil.copytree(s.SERVICE_DIR, payload); s._service_payload_dir = lambda: payload).
    Payload packaging is already proved by that upstream gate; Gate 4 is about the SCM race.
    No assertion removed, relaxed or bypassed; staging stays content-identical so the real
    service image is not clobbered. The copy is taken BEFORE _install_service, so the image
    is not locked.
  * LOCAL VERIFICATION of the proposal: proposed YAML parses (12 steps); the extracted
    gate4_race.py block compiles (53 lines); and a Linux simulation shows the exact
    transition - before: "no Windows service host payload"; after: the RUNNING guard is
    reached ("refusing to overwrite the image of a RUNNING NivXForgeSensor") and staging
    then succeeds once STOPPED with byte-identical content.
  * nivxforge_setup.py NOT modified. No production behaviour change. DESKTOP/KUSHU untouched.

- READ-ONLY DEPLOYMENT READINESS CHECK for fix/edr-durable-ack-boundary @ 9273c964
  (2026-10-01). NOTHING changed, deployed, restarted or mutated. Gate 4 still HOLD.
  * Branch verified: 9273c964d959f942186d5f1ecee6ba896b15d0ce, parent 53287b82 (the Gate 4
    payload fix - its workflow blob 8bcd04bb is IDENTICAL to the approved e793b9cf), on top
    of 7897346d. Diff vs 7897346d = 6 files, +1077/-28: NEW
    backend/edr_plane/processing_queue.py (506 lines), backend/routers/edr_enrollment.py
    (ACK boundary), backend/server.py (+31 startup/shutdown), 2 new test files.
  * PREVIEW RUNTIME OBSERVED (the only runtime the agent can inspect):
    supervisor program [backend], command
    /root/.venv/bin/uvicorn server:app --host 0.0.0.0 --port 8001 --workers 1 --reload,
    directory /app/backend, autostart=true. ONE app process (pid 275) + 2 multiprocessing
    helper children; SINGLE event loop confirmed. DB = local mongod (supervisor program
    [mongodb], /usr/bin/mongod --bind_ip_all), MONGO_URL mongodb://localhost:27017,
    DB_NAME test_database, NIVX_DEPLOYMENT_ENV=preview, edr_raw_events = 274,123 docs,
    edr_processing_queue DOES NOT EXIST yet. /app is on feature/rc2-alignment, NOT 9273c964.
  * ⚠ RETRACTED - MY EARLIER P0 CLAIM WAS WRONG. I claimed processing_queue.ensure_indexes()
    would be skipped because `_ensure_raw_indexes` fails. PROOF IT IS NOT SKIPPED:
    in 9273c964 server.py the try block runs
      926  await _ensure_raw_indexes(_raw_db)
      927-929  await _ensure_processing_queue_indexes(_raw_db)   <-- runs HERE
      989-992  v2_shadow_observations.create_index(name="obs_device_identity_facts",
               sparse=True)                                     <-- THIS is the thrower
      999-1000 except -> log.warning("[startup] edr_raw_events indexes failed: ...")
    The except message NAMES edr_raw_events but labels the WHOLE block; the raising
    statement is 989, which is AFTER the queue indexes. Proof the thrower cannot be line
    926: edr_plane/raw_events.py has COLLECTION = "edr_raw_events" and never touches
    v2_shadow_observations, and the string obs_device_identity_facts exists ONLY at
    server.py:988-992. Empirically, every index created BEFORE 989 exists in the preview DB
    (edr_raw_events 8 indexes, obs_device_ts / obs_collector_ts / obs_deviceiid_ts all
    present), i.e. the block executes up to the thrower. The ONLY statement lost is the
    success log.info at 997 - nothing operational follows 992. So uniq_tenant_raw WOULD be
    created and enqueue() idempotency is NOT compromised. P0 CLAIM: NOT CONFIRMED.
  * The IndexKeySpecsConflict is still a REAL but COSMETIC preview-only defect: an existing
    obs_device_identity_facts on v2_shadow_observations has no `sparse` flag, so the sparse
    re-declaration is rejected (code 86). Production shows NO "[startup] ... failed:" lines.
  * Design review of the new module (read-only): enqueue() is an idempotent
    $setOnInsert upsert on (tenant_id, raw_id); claim() is an atomic
    find_one_and_update over PENDING/RETRY plus EXPIRED PROCESSING leases with $inc
    attempts and sort by created_at; start_workers() clamps worker_count to 1..8 and
    guarantees one supervisor per PROCESS. Therefore N replicas x 1 worker-set is SAFE
    (no double-processing), but N replicas means N x worker_count consumers.
    stop_workers() has a 15s bounded drain on shutdown.
  * ACK boundary in _ingest_one now: persist raw -> processing_queue.enqueue ->
    mark_reported -> count RECEIVED, and the synchronous canonical bridge() call is
    REMOVED from the request path. So a queue-write failure means NO ACK, which is the
    intended fail-closed behaviour.
  * PRODUCTION ANSWERS ARE UNKNOWN FROM THIS POD. nivxray.nivxforge.com is the
    Emergent-deployed production backend; its deployed branch/commit, replica count,
    worker count, entrypoint, database name and scale-to-zero behaviour are not visible
    from the preview pod. A read-only deployer inspection was dispatched and returned
    "queued" (asynchronous), so no production evidence was available in this turn.
    DO NOT infer production from the repository.
  * PRODUCTION INSPECTION (deployer agent, read-only, run e8a40ab2, nothing mutated):
    Kubernetes, cluster target-7, namespace customers-app, 2 PODS, each
    `uvicorn server:app --workers 1` => 2 processes / 2 event loops. /api/* -> nginx ->
    127.0.0.1:8001. Frontend via Cloudflare. DB = MANAGED ATLAS
    "greeting-app-5782-test_database" (NOT the preview local mongod/test_database).
    EDR startup indexes COMPLETE with no "[startup] ... failed:" lines.
    Deployed git branch/commit = UNKNOWN (the pipeline builds a source snapshot with no git
    metadata; image tag = run_id, digest sha256:41a001b5..., build f8fe5481).
    All EDR-plane env vars present and non-empty. Rollback = Deployment Panel -> Overview ->
    history, prior images retained, ~1-2 min, no rebuild.
    TWO REAL PRODUCTION RISKS RAISED: (1) 2 replicas => TWO independent supervisors
    => 2 x worker_count = 4 concurrent consumers; claim() is atomic so no job is processed
    twice, but any singleton/scheduled work inside the supervisor would double-fire and
    needs a DB lock / leader election; (2) production already logs intermittent /health 503s
    and 1s nginx upstream timeouts on the single event loop - if liveness restarts a pod the
    supervisor dies with it, so /health must stay non-blocking.
    UNRELATED, OBSERVED: threatfox 401 + otx pull failures => stale ABUSE_CH_AUTH_KEY /
    OTX_API_KEY.

- READ-ONLY DESIGN CHECK on 9273c964 for the 2-pod production topology (2026-10-01).
  Nothing changed/committed/pushed/deployed/restarted/scaled; no Mongo write. HOLD stands.
  * worker_count=2 is HARDCODED at the server.py call site (not env-driven); with 2 pods
    that is 4 workers + TWO supervisors. start_workers() clamps 1..8 and is one-per-PROCESS.
  * FOUR-WORKER SAFETY: worker loop idle_seconds=1.0, so an EMPTY queue costs only ~1
    atomic find_one_and_update per worker per second (4/s total) and claim() is covered by
    the claimable_work index. Lease 600s, retry 30s. No correctness problem; the cost is
    canonical_bridge concurrency, which is now 4-way instead of the previously serial
    in-request path.
  * RECONCILER MULTI-POD SAFETY = CORRECT, NO LOCK NEEDED. enqueue() is a
    $setOnInsert upsert on (tenant_id, raw_id) and uniq_tenant_raw makes a concurrent
    double-insert fail at the STORAGE layer; the code counts that as already_present. The
    only penalty for running it in both pods is DUPLICATED COST, not duplicated work.
  * ⚠ THE REAL BLOCKER IS THE RECONCILER'S SCOPE, NOT THE WORKER COUNT (new finding):
    pipeline = $match{trust_state:"AUTHENTICATED"} -> $lookup -> $match{job==[]} -> $sort
    {ingest_time:1} -> $limit -> $project. Measured on the PREVIEW DB:
      - NO INDEX on trust_state (edr_raw_events has 8 indexes, all tenant_id-prefixed), so
        the $match is a COLLSCAN of 274,214 docs / 546.6 MB;
      - 275,500 docs are AUTHENTICATED, and on first start NONE has a job, so ALL of them
        pass the anti-join into a $sort of FULL documents ($project is AFTER the sort):
        ~549 MB versus the 100 MB aggregation sort limit, and allowDiskUse is NOT set
        => QueryExceededMemoryLimitNoDiskUseAllowed (code 292);
      - the supervisor runs reconcile_missing_jobs() IMMEDIATELY at startup, before its
        first wait, and catches it with a bare `except Exception: pass` - NO LOG AT ALL, and
        its {scanned, created, already_present} return value is discarded. So it would fail
        SILENTLY every 60s in both pods, on the same event loop that production already
        shows /health 503s and 1s nginx upstream timeouts on.
      - ingest_time is stored as an ISO STRING, not a BSON date, so a time-window $match
        would be a string comparison (lexicographic, which is still correct for ISO-8601
        UTC) - relevant to any bounded-window fix.
      - INVERSE RISK where the sort DOES fit (a smaller production collection): reconcile
        would succeed and enqueue EVERY historical authenticated raw event, turning a
        crash-window repair into a mass re-canonicalisation of the entire history.
    Production collection size is UNKNOWN (managed Atlas greeting-app-5782-test_database,
    a different DB from preview); the SHAPE of the defect is identical because it is in the
    pipeline, not the data.
  * RECOMMENDED INITIAL CONFIG: worker_count=1 per pod (2 total) for the first
    KUSHU backlog drain - minimal one-token change at the server.py call site, no new
    dependency, no leader election, no Redis, no K8s job.
  * DEPLOYMENT BLOCKER: YES - the reconciler scope/silence, not the worker count.

- BOUNDED-RECONCILER PATCH DESIGN (prepared for review 2026-10-01, NOT applied).
  Nothing edited/committed/pushed/deployed; no Mongo write. KUSHU stopped, Gate 4 HOLD.
  * BOUNDARY = a PERSISTED DEPLOYMENT WATERMARK, not a wall-clock window.
    edr_processing_queue_state doc _id="reconcile_floor" written ONCE with $setOnInsert at
    the first startup of the new build; every pod/restart READS the same value, so there is
    no clock-skew divergence and the floor never moves backwards.
    Effective window = [max(floor, now - lookback), now - settle],
    lookback 15 min (crash-window repair, survives a pod restart),
    settle 60 s (do not race an in-flight request that has written raw but not yet the job).
    WHY "last 10 minutes" ALONE IS WRONG: at deploy time the 10 minutes of raw events
    ingested immediately BEFORE the rollout are pre-feature - they were ACKed under the old
    contract and already canonicalised inline - yet they have no queue row, so a pure
    relative window would mass-enqueue them for re-canonicalisation. The floor excludes
    them by construction.
    WHY A PROCESS-START WATERMARK ALONE IS WRONG: if a pod dies between the raw write and
    the queue write, the replacement process's start time is LATER than the orphan's
    ingest_time, so the orphan would never be repaired - which is the exact crash window
    the reconciler exists for. Hence floor (fixed, persisted) AND lookback (relative).
  * QUERY REDESIGN: the $lookup anti-join and the $sort of FULL documents are DELETED.
    Because the window is minutes wide, a plain
    find({trust_state:"AUTHENTICATED", ingest_time:{$gte:lo,$lte:hi}},
         {_id:0, tenant_id:1, raw_id:1, ingest_time:1}).sort(ingest_time).limit(n)
    plus a blind idempotent enqueue() per row is strictly correct and cheaper: enqueue's
    upsert result already distinguishes created vs already_present, so no anti-join is
    needed at all.
  * INDEX REQUIRED (new, on edr_raw_events): (trust_state, ingest_time) name
    "reconcile_window" - equality then range, added to raw_events.ensure_indexes which runs
    at server.py:926, BEFORE the known v2_shadow_observations thrower at 989. ingest_time is
    an ISO-8601 UTC STRING, so a lexicographic range is correct and index-supported.
  * OBSERVABILITY: `except Exception: pass` in _supervisor is replaced by a rate-controlled
    warning (first failure, then at most 1 in N cycles) and the {scanned, created,
    already_present} summary is logged when created > 0. No payloads, no credentials.
  * worker_count 2 -> 1 at the server.py call site (+ the log string). 2 pods => 2 workers.
  * TEST PLAN: A historical pre-floor events not reconciled; B recent orphan repaired;
    C existing job not duplicated; D failure surfaces a warning instead of silence;
    E worker_count is 1 per process; F the 27 existing ACK-boundary tests stay green.

## 2026-06 · §d PRODUCTION WIRING DONE (local, NOT deployed) — verdict NOT_PRODUCTION_READY
Branch `integration/e3-dt`, from `1da71197`. Full report:
`docs/e3/SD_PRODUCTION_WIRING_REPORT.md`.

- OWNER DECISION IMPLEMENTED: evidence-first §11. **Option A** (existing authoritative
  stored observation time) at the query layer + **Option B** (derive `observed_ms` at the
  adapter boundary). Options C/D NOT implemented and NOT pre-authorised. No schema
  change, no backfill, no canonical-authority decision, no production index.
- PROVEN READ-ONLY: `observed_ms` is stored in **0** of 277,684 canonical / 283,789
  shadow / 287,447 raw docs — it is a derived millisecond rendering, never a stored field.
  Canonical `event_time` 100% populated but had NO index; shadow `event.ts` already indexed.
- NEW: `backend/edr_trajectory/production_adapter.py` (§d evidence adapter) +
  `production_service.py` (assembly) + 24 hermetic tests. `routers/edr.py` gains ONE
  additive `e3` key on `GET /api/edr/endpoints/{id}/trajectory`, inside try/except, with
  new params `e3_page_size` / `e3_cursor` / `e3_event_id`. V1 and `dt2` untouched.
- WHY THE MERGE IS IN THE ADAPTER: the authoritative `endpoint_predicate()` `$or` gets
  SORT_MERGE only while branch×ref stays under the planner's enumeration limit; one extra
  alias flips it to a blocking sort (measured 276,031 docs / 4,401 ms). The adapter issues
  one bounded index-served query per declared identity branch (200 docs / 1 ms) and merges.
- **P0 DEFECT FOUND AND FIXED — sub-millisecond evidence loss.** Stores record
  microseconds, `observed_ms` is milliseconds, so distinct observations collapsed into
  fake ties and the resume boundary skipped their members: measured **16 observations
  returned at page_size=3 and never at page_size=7**. Order + cursor now use full source
  precision (`observed_us`); after the fix missing=0 at page sizes 3/7/25/100. Also fixed:
  branch-overlap key relied on frequently-absent fields; adapter mutated the source doc.
- PROOFS: `/app/scripts/sd_production_adapter_acceptance.py` **16/16 PASS on real
  evidence** (newest-first, page1∩page2=∅, no boundary loss, strict total order, tenant
  fail-closed, cross-tenant leak NO, deep link exact/explicit-miss/cannot-cross-endpoint,
  provenance on every row). Order identical at page sizes 3/7/25/100/300 from a fixed
  cursor on shadow-only, canonical-only AND the union.
- TESTS: `tests/edr` 2051 passed + `tests/edr_trajectory` 78 passed = **2129 passed,
  12 skipped, 0 failed**. Gate 16 5/5. Repaired a pre-existing TEST_HARNESS_FAILURE:
  8 E3 tests ERRORED at setup (async fixture without the asyncio marker) so they were
  reporting as no-coverage while never executing — test-only change, now run and pass.
- PREVIEW INDEX (owner-authorised, preview only): 3 REQUIRED on
  `xdr_canonical_evidence` (`pvw_sd_*_eventtime`) because it had no `event_time` index at
  all. 7 shadow duplicates were trialled, measured to add nothing, and DROPPED.
  Rollback: `python /app/scripts/sd_preview_index_experiment.py drop`.
  **Production index = OWNER_DECISION_REQUIRED, not created.**

### VALIDATION PATH CONSTRAINT (owner-stated, binding)
EDR must be proven INSIDE EDR: `NivXForge EDR → EDR auth/authorized customer →
Computers/Endpoint → Device Trajectory → /edr/device-trajectory → EDR trajectory API →
real endpoint evidence`. NEVER via the "Investigate in NivXRay XDR" pivot, XDR workspace
routes, XDR Device Trajectory, or the standalone E3 preview shell
(`/e3shell-*/index.html`, customer "Synthetic Preview Customer", host `SYN-LT-0427`,
footer "Synthetic data · Debug") which is FIXTURE DATA. Never weaken auth/tenant checks
or change routing to make automation pass.

### BLOCKERS (verdict NOT_PRODUCTION_READY)
- **P0 · Blocker 1 — the analyst still cannot see the newest evidence.** `VITE_E3_DT_V3`
  is OFF, so `/edr/device-trajectory` renders `EdrDeviceTrajectoryPage` on the V1
  contract, whose page selection is OLDEST-FIRST (pinned by E3's own `stale_trace`
  characterisation test). Measured: V1 newest row `14:17:47` vs the endpoint's real
  newest `14:37:33` — ~20 min of the most recent evidence unreachable in the UI, while
  the new `e3` key on the same request returns it. OWNER DECISION:
  (A) make V1 page selection newest-first — smallest, but changes an established shared
  contract read by dt2 and other surfaces; or (B) adopt the proven `e3` contract in the
  EDR DT page — architecturally correct per §4/§13, real frontend work.
  **Recommended: (B).**
- **P0 · Blocker 2 — A–T not validatable against real KUSHU from this pod.** KUSHU is a
  PRODUCTION endpoint; the preview DB holds ZERO KUSHU rows in all four collections.
  Production shows KUSHU 258 obs. No production Mongo path is authorised here, so every
  KUSHU-dependent A–T row is INSUFFICIENT_REAL_EVIDENCE. No substitute endpoint was used
  to manufacture a PASS. The adapter IS proven on a real 275,902-observation Windows corpus.
- **P0 · Blocker 3 — an EDR route is served by an XDR-namespaced component.**
  `App.jsx:75` imports `EdrTrajectoryResolver` from `@/xdr/pages/` and binds it to
  `/edr/trajectory` (`App.jsx:367`), linked from 7 EDR surfaces. Gate 16 passes only
  because it does not cover this case — the gate is narrower than the invariant. Likely
  source of XDR chrome on an EDR path. Fix: move the resolver out of the XDR layer and
  widen Gate 16 to assert no `/edr/*` route resolves to an `@/xdr/*` component.
  (Class B, reversible, no owner decision needed.)

### STILL OPEN (unchanged)
- KUSHU sensor stopped (`DELIVERY_CEASED`, production dashboard FLEET BLIND) — owner-gated.
- SENSOR: REPORTING stale-badge defect (freshness vs sticky lifecycle flag).
- Threatfox 401 / OTX pull failure (stale production API keys).
- 3 corrupt `event.ts` offsets + null canonical `event_time` rows → truthful unplaceable state.

### 2026-06 · Blocker 3 RESOLVED — EDR independence (route + shell + redirect)
- `/edr/trajectory` (linked from 7 EDR surfaces) was bound to
  `@/xdr/pages/EdrTrajectoryResolver`, which rendered `XdrShell` and redirected to
  `/xdr/endpoints/:device/trajectory` — carrying the analyst out of NivXForge EDR into
  NivXRay XDR. That is the mechanism behind XDR chrome on an EDR investigation path.
- FIXED: resolver moved to `@/nivxforge/pages/EdrTrajectoryResolver.jsx`, renders
  `NivXForgeConsole`, redirects to `/edr/device-trajectory?device=<ref>`, unresolved-state
  links now `/edr/computers` + `/edr/detections`. The explicit "Investigate in NivXRay XDR"
  pivot is untouched and stays legitimate.
- Gate 16 widened 5 -> 7: `test_no_edr_route_is_served_by_an_xdr_component` works from the
  ROUTE TABLE (the old test only scanned files already under the EDR dir, so an XDR-layer
  component was invisible to it). Proven to catch the regression by restoring the old import.
- VERIFIED LIVE on the EDR path only: stays on `/edr/*`, NivXForge EDR chrome + sidebar, no
  "PLANE XDR investigation". The TENANT_REQUIRED panel is CORRECT fail-closed behaviour
  (PLATFORM principal with no customer selected). Auth/tenant not weakened; routing not
  changed to satisfy automation. `yarn build` clean; 2131 passed / 12 skipped / 0 failed.
- RESIDUAL: 11 EDR pages import `apiErrorText` from `@/xdr/nx/apiError` (Gate-16
  SHARED_*_SAFE, sanctioned); `apps/nivxray-xdr/.git` is a NESTED repo inside the outer repo
  so `git mv` from inside it silently fails — pre-existing hygiene debt, not altered.

---

## 2026-06 · CORE V3 REAL-EVIDENCE INTEGRATION — COMPLETE (phase result)

Full change ledger, defect log, gate-by-gate evidence and declared gaps:
**`memory/CHANGELOG.md`** (newest entry at the top) and
**`docs/e3/BEHAVIOR_ML_INVESTIGATION_READINESS.md`** (§19 inventory, nothing activated).

`CORE_V3_REAL_EVIDENCE_INTEGRATION = PASS`, with `REAL_ENDPOINT_VALIDATION = BLOCKED_ENVIRONMENT`
by owner decision. `PRODUCTION_DEPLOYED = NO`.

The exact E3 V3 Device Trajectory (`trajectory_v3/**`, 15/18 files byte-identical to handoff
`258c8854`; the 3 diffs are 2 shared-ATT&CK import paths + 4 directed edits in `TrajectoryPage.jsx`) now renders at `/edr/device-trajectory` in the integration build, backed by an
additive `v3` presentation contract derived from the §d real-evidence adapter with no second
evidence read. 2181 passed / 12 skipped / 0 failed (+50 gates over the 2131 baseline).

### OWNER DEPLOYMENT INTENT — edr.nivxforge.com (RECORDED, NOT EXECUTED)
The owner has authorized PREPARING the tested build for promotion to the existing production EDR
surface `edr.nivxforge.com`, to stop depending on the unstable Emergent preview. Promotion is
authorized ONLY when the mandatory gate list passes AND no new owner-gated production change is
required. The gate list passes today EXCEPT that real-endpoint validation is
`BLOCKED_ENVIRONMENT`, which must be preserved as a stated limitation and never reported as a
pass. Before any promotion the following must be reported and owner-approved:
`PRE_DEPLOY_SHA`, `DEPLOY_SHA`, `ROLLBACK_SHA`, `PRODUCTION_BUILD_CONFIG`,
`V3_ROUTE_CONFIGURATION`, `DATABASE_MIGRATION_REQUIRED`, `PRODUCTION_INDEX_CHANGE_REQUIRED`,
`PRODUCTION_ENV_CHANGE_REQUIRED`.

**Known blocker for promotion with V3 enabled:** V3 is currently enabled via
`apps/nivxray-xdr/.env.development` only. Serving V3 in production would require a PRODUCTION
BUILD CONFIG change (`PRODUCTION_ENV_CHANGE_REQUIRED = YES`), which is owner-gated. Promoting
without it deploys the hardened backend plus the LEGACY trajectory page.

### NEXT PHASES (owner's stated sequence, unchanged)
1. Behavior Engine — settle the tenant boundary, emit through `findings_intake`, shadow only.
2. ML — per-customer baseline isolation is an owner data-boundary decision first.
3. Investigation / Hypothesis — consumes §d lineage + durable findings; needs a truthful "unknown".
4. Richer TI / retrospection · response validation · sensor & coverage gaps · performance/scale ·
   complete real-endpoint acceptance · release & security hardening.

### STILL OPEN (carried forward)
- KUSHU sensor stopped (`DELIVERY_CEASED`) — owner-gated; 0 KUSHU rows in all four stores here.
- SENSOR: REPORTING stale-badge defect (freshness vs sticky lifecycle flag) — NOT addressed.
- Threatfox 401 / OTX pull failure (stale production API keys).
- 3 corrupt `event.ts` offsets + null canonical `event_time` rows (already truthfully unplaceable).
- MITRE "defense-evasion" → "stealth" consumer impact (visible as `Stealth TA0005` in the strip).
- 3 production indexes on `xdr_canonical_evidence` — measured as needed, owner-gated, NOT created.

---

## STEP 27 — BEHAVIOR SHADOW RUN RECORD ONLY (2026-06, completed)

Additive, isolated engineering/audit record for a FUTURE Behavior shadow invocation. No engine
execution, no evidence read, no checkpoint touch, no detection/Fabric write, no index creation,
no production/Vercel/KUSHU/DESKTOP contact.

- `backend/edr_plane/behavior_shadow_run.py` — record contract + `InMemoryShadowRunStore` /
  `MongoShadowRunStore`. Identity `(tenant_id, shadow_run_id)`; binds `endpoint_id`,
  `ruleset_id`/`ruleset_version`/`ruleset_content_hash`, `replay_id`, `invoked_by`, `reason`,
  `started_at`, `completed_at`, `state`.
- Closed lifecycle: `STARTED` → `COMPLETED` | `TRUNCATED` | `INTERRUPTED` | `FAILED`; terminals
  immutable. `completed_meaning = BOUNDED_SHADOW_INVOCATION_COMPLETED_ONLY` — COMPLETED is NOT a
  clean/benign/no-threat claim.
- Step-24 measurements persisted (counters, per-outcome MATCH/NO_MATCH/INSUFFICIENT_EVIDENCE/
  BUDGET_EXCEEDED/SUPPRESSED, adapter refusals by reason, durations, resume cursor). Zero-target
  counters `cross_tenant_reference_count` and `matches_without_valid_evidence_refs` always
  materialised at 0. Quality/verdict fields (TP/FP/precision/accuracy/malicious/benign) refused.
- Shadow markers forced on every write: `shadow=true`, `analyst_visible=false`,
  `detection_source_claim="NONE"`; tampered markers refused on read.
- Index DESIGN only: `(tenant_id, shadow_run_id)` UNIQUE on `e3_behavior_shadow_runs`. NOT created.
- G-3 stated, not solved (app-level revision ≠ Mongo CAS; `supports_atomic_cas` advertised per
  store). G-4 untouched.
- Tests: `backend/tests/edr_trajectory/test_shadow_run_record.py` — 64 passed. Scoped regression
  `tests/edr_trajectory tests/edr tests/edr_behavior` = 2500 passed / 12 skipped / 4 PRE-EXISTING
  failures in `tests/edr/test_p0_f13_5_detection_handoff.py` (unrelated; only 2 new files added).

### NEXT (owner-gated, do not start without approval)
- Step 28: DESIGN ONLY of the shadow runner orchestration (§d provider → adapter → engine →
  measurement → persistence → checkpoint advance). Owner wants to review transaction/checkpoint
  ordering BEFORE any engine execution: a checkpoint must never advance past evidence that was
  not successfully evaluated AND persisted.


---

## STEP 28 — BEHAVIOR SHADOW RUNNER ORCHESTRATION CONTRACT (DESIGN ONLY, 2026-06)

No code, no tests, no engine execution, no DB access. Design recorded for owner review.

**Primary invariant proved structurally:** the checkpoint is ALWAYS the last durable write for an
item. Ordering per item: engine evaluate (+ engine-internal shadow-detection persist, verified) →
run-record measurement write → `frontier.advance(expected_revision=R, item_resolved=True)`.
Everything before the advance is idempotent (deterministic `detection_id` + `merge()` +
`material()` equality ⇒ `duplicates_prevented`), so any crash degrades to at-least-once
re-processing, never to an unevaluated skip.

**Structural findings that shape the design (read from existing code):**
- `SequenceEngine._emit` persists the detection INSIDE evaluation via the injected
  `DetectionStore`; the runner cannot separate evaluate from persist. The injected store must
  therefore be a shadow-specific wrapper.
- `_emit` exhausting `MAX_PUT_RETRIES` increments `rule_errors` but STILL returns
  `OUTCOME_MATCH`. ⇒ **`outcome == MATCH` is NOT proof of persistence.** The runner must observe
  persistence through the shadow store wrapper and through engine `Metrics` deltas.
- `process()` swallows per-rule `ValueError/KeyError/TypeError` into `rule_errors` and omits the
  rule from the returned list ⇒ a missing result is an engine failure, not a NO_MATCH.
- `_evaluate` already prefers BUDGET/INSUFFICIENT over NO_MATCH (engine.py 111–132): budget and
  truncation can never become NO_MATCH. Preserved, not re-implemented.
- `provider.window()` reads ±`rule.time_window_seconds` around the trigger and therefore legally
  reads evidence BEFORE the frontier. That is window CONTEXT, not a trigger, and is not replay.
- Cost multiplier: per item, per candidate rule, `SdEvidenceProvider` may consume up to
  `MAX_PAGES=8` §d pages. Budgets are set against this, not against row counts alone.

**Checkpoint eligibility per outcome:** advance only on NO_MATCH, MATCH (persist-verified) and
SUPPRESSED (persist-verified). INSUFFICIENT_EVIDENCE, BUDGET_EXCEEDED, engine exception, detection
persist failure, run-record persist failure and checkpoint failure all leave the frontier where it
is and end the run (TRUNCATED / INTERRUPTED / FAILED) with a resume cursor.

**Adapter refusals:** refused §d rows never become `EvidenceRecord`s, so they have no sort key —
they cannot block the stream, but advancing past a later good row implicitly passes them. Silent
skip is forbidden; design requires a bounded durable quarantine entry (raw_ref + observed time +
reason) before advancing. This needs the provider to surface refusal IDENTITY, which it currently
does not (counts only) ⇒ owner decision E9.

**Owner decisions required before any runner code:** E5 additive `MODE_SHADOW`; E6 separate
`e3_behavior_shadow_detections` + shadow store wrapper; E7 refuse NO_EVIDENCE streams in v1 (vs
additive `scanned_through` checkpoint field); E8 adapter-refusal quarantine policy; E9 provider
refusal identity; E10 initial budgets; E11 frontier initialization stays a separate operator act.

**Gap status:** G-3 carried (no Mongo CAS at store layer). G-4 UNSOLVED, blocker stated: a
NO_EVIDENCE stream has no durable upper scan bound, so first-evidence eligibility cannot be
defined without one additive checkpoint field. G-5 solved at DESIGN level (runner-derived
measurement mapping; callers cannot supply metric values). G-6 carried (overlapping-invocation
guard is advisory + optimistic only). G-7 carried (`evidence_lag_ms` is a scalar).

SAFE_TO_IMPLEMENT_RUNNER = NO until E5–E9 are decided.
NEXT: owner decisions, then Step 29 = shadow detection store wrapper + additive `MODE_SHADOW`
ONLY (no runner, no engine execution).


---

## STEP 29 — SHADOW DETECTION BOUNDARY ONLY (2026-06, completed)

Owner decisions applied: E5 YES (MODE_SHADOW), E6 YES (separate collection + dedicated store),
E7 v1 refuses NO_EVIDENCE streams (Step 26 unamended, G-4 explicit), E8 v1 refuses the whole
invocation/page on any adapter refusal, E9 HOLD (provider untouched), E10 budgets are design
ceilings only, E11 frontier initialization stays a separate operator act, E12 no real endpoint.

- `backend/edr_behavior/contracts.py` — additive `MODE_SHADOW = "SHADOW"` and
  `EXECUTION_MODES = {LIVE, RETRO, SHADOW}`. LIVE/RETRO semantics unchanged; no engine or replay
  code path references MODE_SHADOW (asserted by test).
- `backend/edr_plane/behavior_shadow_detection_store.py` — `ShadowDetectionStore`
  (`get`/`find_overlapping`/`put` only) plus `InMemoryShadowDetectionBackend` and
  `MongoShadowDetectionBackend`. Routes exclusively to `e3_behavior_shadow_detections`; the string
  `e3_behavior_detections` does not appear in executable source.
- Non-overridable markers on every doc: `shadow=true`, `analyst_visible=false`,
  `detection_source_claim="NONE"`, `status="SHADOW_ONLY"`, plus `shadow_run_id`, `replay_id`,
  `ruleset_id`, `ruleset_version`, `ruleset_content_hash`. Caller attempts to set the three shadow
  markers or any stream-identity field fail closed. **`status` is FORCED, not refused**, because
  `detection.build` always computes OPEN/TESTING/SUPPRESSED; the engine value is preserved as
  `engine_status` for audit so no reader ever sees OPEN.
- Evidence integrity validated, never repaired: resolved tenant + platform endpoint, non-empty
  `evidence_refs`, every ref tenant-owned with a durable `raw_id` and a `stable_key`,
  `evidence_keys` == ref key set, and (when declared via `expect_trigger`) the trigger key must be
  represented. A refused document leaves no trace.
- Per-write observable outcome CREATED / MERGED / DUPLICATE_UNCHANGED / FAILED_CONFLICT with a
  `verified` flag, plus `verify(detection_id)` read-back. Every successful write is read back and
  compared before being reported; a backend that claims success without storing raises
  `SHADOW_DETECTION_READBACK_VERIFICATION_FAILED`.
- Isolation: tenant-keyed, endpoint-scoped, and ruleset-stream-scoped overlap search; a doc from
  another ruleset content hash can neither be merged into nor found; a non-shadow document is
  never adopted.
- Index DESIGN only (4 specs, incl. `(tenant_id, detection_id)` UNIQUE). Nothing created.
- Tests: `backend/tests/edr_trajectory/test_shadow_detection_store.py` — 62 passed. Scoped
  regression `tests/edr_trajectory tests/edr tests/edr_behavior` = 2562 passed / 12 skipped /
  the SAME 4 pre-existing failures in `tests/edr/test_p0_f13_5_detection_handoff.py`.

### GAP introduced and recorded (G-8)
Because `status` is rewritten to SHADOW_ONLY, the engine's internal
`material(merged) == material(existing)` check in `_emit` will never match for shadow writes, so
the engine's `duplicates_prevented` counter under-reports. The store's `DUPLICATE_UNCHANGED`
outcome is the authority for shadow duplicate suppression, and the runner must source
`duplicates_prevented` from the store's write outcomes, not from engine metrics.

### NEXT (owner-gated)
Owner review of Step 29, then the runner (Step 30) may be considered. Runner must still honour:
refuse NO_EVIDENCE streams, refuse the page on any adapter refusal, checkpoint advance LAST,
MATCH persistence proven only via the store's verified write outcome.


---

## STEP 30 — BEHAVIOR SHADOW RUNNER, SYNTHETIC ONLY (2026-06, completed)

**First authorized SequenceEngine execution. Hermetic evidence only** — in-memory §d collection,
in-memory checkpoint/run/detection stores. No production Mongo, no real endpoint, no KUSHU, no
DESKTOP, no sensor, no Fabric Finding, no ledger, no index/collection creation, no deploy, no flag.

- `backend/edr_plane/behavior_shadow_runner.py` — `run_shadow(...)`, `ShadowBudgets`,
  `_BoundedProvider` (per-call timeout + aggregate §d page ceiling; `SdEvidenceProvider` untouched,
  E9 hold), `ruleset_digest()`, `_FixedRegistry`.
- Ordering per item: `expect_trigger` → `engine.process(mode=MODE_SHADOW)` → classify →
  verified shadow-detection persistence (for MATCH/SUPPRESSED) → durable run-record measurement →
  `frontier.advance()` LAST. Proven by a journal test asserting
  `["detection", "run_record", "checkpoint"]`.
- Advances only on NO_MATCH / MATCH / SUPPRESSED (the latter two only after a VERIFIED store write
  and a read-back whose refs are tenant-owned, raw_id-bearing and contain the trigger key).
  INSUFFICIENT_EVIDENCE → INTERRUPTED, BUDGET/truncation → TRUNCATED, engine exception or any
  persistence failure → FAILED. In every case the frontier stays put and a resume cursor is
  recorded. Never NO_MATCH for an unevaluated item.
- G-8 honoured: `duplicates_prevented` is counted from `DUPLICATE_UNCHANGED` store outcomes; a
  test asserts the engine's own counter stays 0 while the record reports 1.
- G-9 honoured: `expect_trigger` precedes every `engine.process`, proven by trace order, by a
  put-time spy, and by source order.
- Budgets are runner-local dataclass defaults (25 trigger rows / 100 page size / 24 §d pages /
  500 window events / 2000 matcher budget / 50 rules / 6 h span / 8 s per §d call / 60 s wall
  clock, soft 20 s). No env var, no config. The wall-clock value is PROVISIONAL pending hermetic
  measurement; the earlier "below the ~35 s ingress" justification was withdrawn as incoherent.
- Tests: `backend/tests/edr_trajectory/test_shadow_runner.py` — 47 passed (all 21 mandated
  synthetic scenarios + crash/retry assertions). Full suite
  `tests/edr_trajectory tests/edr tests/edr_behavior` = 2609 passed / 12 skipped / the SAME 4
  pre-existing `test_p0_f13_5_detection_handoff.py` failures. Backend healthy (/api/health 200).

### GAP-10 (NEW, HARD BLOCKER for real-evidence shadow) — field namespace mismatch
The Step-22 §d adapter emits a FLAT field namespace (`image`, `command_line`, `user`, `file_path`,
`dest_ip`, …). The engine requires the CANONICAL NESTED namespace: `predicates.FIELD_PREFIXES`
only permits dotted paths (`process.image`, `user.name`, …) and `get_field` walks nested dicts, and
`detection.build` reads `(e.fields.get("user") or {}).get("name")`. Consequences, both observed:
1. No predicate can ever match §d-sourced evidence except `detection.*` (the only nested key the
   adapter emits).
2. Any row carrying `process.user` CRASHES `detection.build` with
   `AttributeError: 'str' object has no attribute 'get'`.
The runner fails closed on (2) — FAILED, no detection, no advance — and that behaviour is tested.
But a real KUSHU-class row carries a user on essentially every process event, so **real-evidence
shadow validation is not possible until the adapter namespace is reconciled.** Fixing it means
amending Step 22, which is owner-gated.

### Step-29 amendment made (needed for retry idempotency)
`shadow_run_id` is write PROVENANCE, not stream identity. The engine's merge path legitimately
carries a previous run's id, which the original Step-29 check refused
(`SHADOW_DETECTION_MARKER_OVERRIDE_REFUSED`), breaking crash-retry. The store now re-stamps
`shadow_run_id` to the current run and retains the earliest as `first_shadow_run_id`;
`replay_id`/`ruleset_id`/`ruleset_version`/`ruleset_content_hash` remain caller-forbidden
(`STREAM_FIELDS`).

### NEXT (owner-gated)
Owner review of Step 30. Then Step 31 candidate: reconcile the §d adapter field namespace
(GAP-10) with hermetic tests only — still no real evidence, no production, no real endpoint.


---

## STEP 31 — §d → BEHAVIOR CANONICAL FIELD NAMESPACE RECONCILIATION (2026-06, completed)

HERMETIC ONLY. No production DB, no production §d query, no real evidence, no KUSHU/DESKTOP/
sensor, no deploy, no Vercel, no collection/index creation, no replay, no Fabric Finding.

**Contract authority (established read-only, Phase A, not inferred from a failing test):**
`edr_behavior/normalize.py` (`NORMALIZER_ID = edr_behavior.normalize.canonical_v1`) is the
producer of the canonical `EvidenceRecord.fields`; `edr_behavior/predicates.py`
(`FIELD_PREFIXES` + `get_field`, which walks NESTED dicts) is the resolver; the shipped rules in
`edr_behavior/content/starter_rules.json` address `process.name` (23x),
`process.command_line` (11x), `network.dest_ip`, `process.executable_path`, `process.signer`,
`file.path`, `file.operation`, `registry.key`, `network.dest_hostname`, `dns.query_name`.
`detection.build`, `detection._summary` and `normalize.scope_key` consume the same nested shape
(`user.name`, `file.path`, `file.sha256`, `dns.query_name`, `network.dest_ip`). The contract is
CONSISTENT across all four consumers — so there was one authority to satisfy, not a choice to make.

**Change: `backend/edr_plane/behavior_evidence_adapter.py` `_fields()` only.** It now emits the
canonical nested namespace via a collision-safe `_put(tree, path, value)`:
process.{executable_path,name,command_line,sha256} · parent.{executable_path,name} · user.name ·
file.{path,name,previous_path,operation,sha256} · network.{dest_ip,dest_port,src_ip,protocol,
initiated} · dns.query_name · detection (verbatim object).
`process.name`/`parent.name`/`file.name` are basenames derived exactly as the normalizer derives
them (`_base`). §d's own `kind`/`severity` moved OUT of `fields` into provenance
(`sd_activity_family`, `sd_severity`) — no predicate can address them, so keeping them in `fields`
was a second, unreachable namespace.

- RULES / MATCHER / PROVIDER / RUNNER: unchanged. No flat-field fallback anywhere.
- Absent stays absent: §d carries no registry, auth, signer, integrity level, current directory,
  DNS answers, dest_hostname or direction, so those canonical paths are OMITTED (predicate reads
  UNKNOWN). Nothing invented.
- Types preserved: `dest_port` stays int, `initiated` stays bool, detection stays an object with
  its arrays. No stringification.
- Collisions fail closed: a §d container present but not an object →
  `SOURCE_FIELD_STRUCTURALLY_INCOMPATIBLE`; two source values on one canonical path →
  `SOURCE_FIELDS_COLLIDE_ON_ONE_CANONICAL_PATH`. Never overwritten, never coerced.
- Unchanged invariants: resolved tenant, `ep_…` endpoint identity, stored-observation-time
  authority, `EvidenceRef.raw_id`, `stable_key`, provenance, refusal semantics, Step-25 provider
  path, Step-26 frontier, Step-27 run record, Step-29 shadow boundary, Step-30 checkpoint-last.

**GAP-10 CLOSED.** The two observed symptoms are gone: a §d row carrying `process.user` no longer
crashes `detection.build` (it resolves `user.name` and appears in `involved_entities`), and a
shipped-shape rule (`process.name`, `process.command_line`) now MATCHES an ordinary
`PROCESS_START` row end to end: §d row → adapter → canonical EvidenceRecord → SequenceEngine →
ShadowDetectionStore (verified) → ShadowRunRecord → checkpoint LAST.

**New, smaller gaps recorded:**
- G-11: `file.previous_path` and `network.initiated` are additive canonical paths not emitted by
  `normalize.py` (real §d data with no canonical home). Addressable, consumed by no rule.
- G-12: §d carries no registry/auth data, so registry and auth rules can only ever return
  INSUFFICIENT_EVIDENCE on §d evidence. Truthful, but it bounds shadow coverage.
- G-13: `network.direction` is not derived from §d `initiated` (that would be invention), so
  direction predicates stay UNKNOWN.
- G-3/G-4/G-6/G-7 carried, untouched.

Tests: `tests/edr/test_behavior_evidence_adapter.py` (canonical process/parent/user/file/network/
DNS/detection resolution, absent domains, shape + collision refusals, type preservation),
`tests/edr_trajectory/test_sd_behavior_provider.py` (2 namespace assertions updated),
`tests/edr_trajectory/test_shadow_runner.py` (50 passed, incl. 3 new canonical-evaluation
scenarios). Scoped suite `tests/edr_trajectory tests/edr tests/edr_behavior` = 2617 passed /
12 skipped / the SAME 4 pre-existing `test_p0_f13_5_detection_handoff.py` failures.
Backend healthy (/api/health 200).

### NEXT (owner-gated)
Owner review of Step 31. A bounded real-evidence shadow run is NOT authorized by this step.


---

## STEP 32 — BEHAVIOR ADAPTER NAMESPACE CONFORMANCE GUARD (2026-06, completed)

TEST-ONLY regression lock. No runtime file changed. Hermetic: no engine execution, no real
evidence, no production, no KUSHU/DESKTOP/sensor, no deploy/Vercel, no collection/index change.

- `backend/tests/edr/test_behavior_namespace_conformance.py` (new, 16 tests).
- Both namespaces are read from their OWN SOURCE, not a hand-written list:
  `authoritative_paths()` = every canonical path `edr_behavior/normalize.py` labels for itself
  (`b.s(value, "process.executable_path")`, incl. `from_detection_observation`);
  `emitted_paths()` = every `_put(tree, "<literal>", ...)` path in the adapter (also pins paths to
  literals — a computed path would make the guard unenforceable). `addressable()` applies the
  resolver's own rule (`predicates.FIELD_PREFIXES` + nested walk).
- Asserts: every emitted path is addressable AND accepted by the real `parse_rule` gate; emitted ⊆
  authoritative ∪ G-11 allow-list; AST view == runtime output for a maximal §d row; nested paths
  resolve through `predicates.get_field`.
- G-11 (owner decision): `file.previous_path` and `network.initiated` are KEPT as the only
  explicit additive exceptions. Tests assert they are genuinely additive (absent from the
  normalizer), addressable, type-preserving (`initiated` stays a real bool incl. `False`), and
  consumed by NO shipped rule in `content/starter_rules.json` — i.e. non-authoritative for rule
  semantics.
- Negative proof executed: re-introducing `_put(tree, "image", image)` makes 4 independent tests
  fail; the adapter was then restored byte-identical and all 16 pass again.
- Also locked: registry/auth stay missing (and no `registry.`/`auth.` path is emittable);
  `network.direction` is never inferred from `initiated`; unavailable canonical paths are absent
  rather than empty; only the adapter shapes fields (provider and runner contain no `_put(`,
  `.fields[` or `fields=`); `FIELD_PREFIXES` and `NORMALIZER_ID` unchanged; `raw_id`/`stable_key`
  determinism and `STORED_OBSERVATION_TIME` authority unchanged.
- Scoped suite `tests/edr_trajectory tests/edr tests/edr_behavior` = 2633 passed / 12 skipped /
  the SAME 4 pre-existing `test_p0_f13_5_detection_handoff.py` failures. Backend healthy.

### Blockers standing before any real-evidence shadow run (owner-acknowledged)
1. `xdr_canonical_evidence.event_time` index still missing — measured ~35 s / 504 risk on a real
   §d read (P1, owner-gated).
2. Runner wall-clock budget (60 s) remains PROVISIONAL and unmeasured.
3. G-12 bounds coverage: §d carries no registry/auth data.


---

## STEP 33 — FIRST REAL-EVIDENCE BEHAVIOR SHADOW GATE (DESIGN ONLY, 2026-06)

No execution. No production query, no real evidence, no KUSHU/DESKTOP access, no index,
no frontier init, no engine run, no deploy. Design recorded for owner authorization.

**Query risk re-assessed from source, and it is better than feared.** `page_device_evidence`
(`edr_trajectory/production_adapter.py::_branch_page`) puts the time range ON THE SAME FIELD THAT
PROVIDES THE SORT and applies `.limit(page_size + 64)` PER IDENTITY BRANCH, 10 branches in
parallel (7 shadow + 3 canonical identity fields from `ENDPOINT_KEYED_STORES`). Work is
O(branches x fetch), never O(endpoint history). The unbounded reader is
`providers.MongoStoreProvider`, which filters time IN PYTHON after streaming the whole cursor —
it is NOT on the Behavior path and remains forbidden. So the residual risk is narrow: the 3
`xdr_canonical_evidence` branches (equality on identity + tenant, range+sort on `event_time`)
may plan a BLOCKING SORT without the deferred index. That is what preflight must measure.

**Proposed first invocation:** one tenant, one platform `ep_…` (KUSHU as canary, owner-supplied
id; DESKTOP-A9HGFJJ excluded by name in the guard), a 10-minute recent window, `page_size = 25`,
`max_trigger_rows = 25`, `max_sd_pages = 4`, 8 s per §d call, Step-30 budgets otherwise unchanged
(60 s wall clock stays PROVISIONAL and untuned).

**Rule selection by availability, not convenience** (fields available through §d:
process.name/executable_path/command_line/sha256, parent.*, user.name,
file.path/name/operation/sha256, network.dest_ip/dest_port/src_ip/protocol, dns.query_name):
- ELIGIBLE: E3-SEQ-001, -002, -003, -004, -006, -007, -008
- NOT ELIGIBLE: E3-SEQ-005 (needs `registry.key`, G-12)
- SELECTED FIRST: **E3-SEQ-001 ALONE** — needs only `process.name`, `entity_scope: device`,
  `time_window_seconds: 120` (the smallest window that can exercise any rule: runner requires
  span >= 2x rule window = 240 s, so 10 min gives 2.5x headroom), and its
  `parent_child / min_linkage: PID_SURROGATE` relationship is satisfiable from §d parent pid/guid.
  Process-scope rules (-002, -004) and file-scope (-006) are deferred to avoid a second-order
  `scope_key` dependency on the first run; -007 needs a 1 h span.
  No rule is created or weakened. NO_MATCH is a valid PASS. INSUFFICIENT_EVIDENCE stays distinct.

**Preflight gate (read-only, separately authorized):** per-branch `explain()` + one timed
`page_device_evidence` call. ABORT BEFORE ENGINE EXECUTION if any branch > 2000 ms, total page
> 5000 ms, any plan shows a blocking SORT, `totalDocsExamined > 10 x fetch`,
`excluded_outside_window > 10 x rows`, or `state != PAGE_READY`. On abort: report the missing
`xdr_canonical_evidence.event_time` index as a MEASURED blocker. NEVER widen the query.

**Owner decision E13 (optional mitigation, not implemented):** `SdEvidenceProvider` does not
expose the `stores` parameter `page_device_evidence` already supports, so the first run cannot be
restricted to `v2_shadow_observations` (avoiding the unindexed store entirely) without a small
additive provider parameter.

### NEXT
Owner authorization for Step 34 = preflight measurement, then (only if preflight passes) ONE
bounded real-evidence shadow invocation. Otherwise the index becomes the declared production
blocker.


---

## STEP 34A — §d BOUNDED-READ PREFLIGHT (2026-06) — BLOCKED, two reasons, both measured

READ-ONLY throughout. Zero writes, no engine, no frontier, no checkpoint, no shadow document,
no index creation, no collection creation, no response, no sensor, no deploy.
Tool (reusable, read-only): `backend/tools/preflight_34a.py`.

### BLOCKER 1 — the authorized target is not reachable from this container
`backend/.env` → `MONGO_URL=mongodb://localhost:27017`, `DB_NAME=test_database`: this is the
PREVIEW database. KUSHU does not exist in it — `edr_endpoints` matching /KUSHU/i = 0,
`v2_shadow_observations` with `event.computer` ~ KUSHU = 0, `xdr_canonical_evidence` with
`host.hostname` ~ KUSHU = 0. Production was NOT accessed and must not be from here.

### BLOCKER 2 — a measured adapter-refusal blocker that would abort Step 34b anyway
On a real 25-row bounded page, 13 rows converted (all NETWORK) and **12 refused with
`ACTIVITY_FAMILY_NOT_SUPPORTED_BY_BEHAVIOR_CONTRACT`** — they normalize to §d kind `OTHER`
(`providers._kind` fallback) and `KIND_MAP` accepts only PROCESS_START/END, the 5 FILE kinds,
NETWORK_CONNECT, DNS_QUERY, REGISTRY_SET, AUTH, DETECTION. Under owner decision E8 (refuse the
whole page on ANY adapter refusal) the first real run would abort before the engine executes.
**`REFUSED_KIND` is categorically different from `REFUSED_NO_RAW_REF` / `REFUSED_TENANT_CONFLICT`:
the first means "out of Behavior's scope" (benign, deterministic, lossless to skip), the others
mean "defective or unsafe evidence" (must block).** E8 currently conflates them. Owner decision
E14 required.
Also: that window contained ZERO process evidence, so E3-SEQ-001 (`process.name`) had nothing to
evaluate — rule/window selection must be driven by a measured activity-family census, not by
rule elegance (G-21).

### What the preflight DID prove (preview, tenant `default`, busiest endpoint
`ep_2d57cbe6f80152062109`, 10-minute window, page_size 25)
All 10 branches index-served, **NO blocking sort anywhere**:
`LIMIT → FETCH → SORT_MERGE → IXSCAN` on every branch; max docs examined 78 (ceiling 890);
max branch 11 ms (ceiling 2,000); **one bounded page = 22.9 ms** (ceiling 5,000);
rows 25, has_more true, `state = PAGE_READY`, suppressed_duplicates 0, unplaceable 0,
excluded_outside_window 0, raw_ref missing 0.
The three canonical branches used `pvw_sd_collector_eventtime`,
`pvw_sd_hostid_eventtime`, `pvw_sd_hostname_eventtime` — i.e.
`(tenant_id, <identity>, event_time:-1)`. **These are the three deferred indexes, present in
PREVIEW ONLY (note the `pvw_` prefix) and absent in production.** So this run does not clear
production; it proves the query SHAPE is right and that those three indexes are exactly what make
the canonical branches index-served. That is the measured justification the owner asked for.

### Disclosure
`DESKTOP-A9HGFJJ` appeared in a COUNT-ONLY aggregate ranking endpoints by document volume
(3,299 canonical docs, tenant `ten_f1a5479243e901cf159e230fa0`). No DESKTOP document content was
read, projected, converted or targeted by any query; no branch explain, no page and no adapter
conversion touched it. Reported rather than omitted.

### NEW GAPS
- G-20: preview carries the 3 `pvw_sd_*` indexes, production does not — preview latency numbers
  are NOT transferable to production. Only a production explain can answer it.
- G-21: evidence-family composition is unmeasured; a window can be full of evidence yet contain
  nothing a selected rule can evaluate.
- G-22 (E14): E8's "any adapter refusal refuses the page" is unworkable against real telemetry
  because benign out-of-scope activity families are routine.

### NEXT (owner-gated)
E14 (split benign `REFUSED_KIND` from defect refusals), then a production-side read-only preflight
(the same tool, run where production `MONGO_URL` is resolvable), then the index decision from
production explain output.


## STEP 34B — OUT_OF_SCOPE vs DEFECT CLASSIFICATION (E14) — 2026-06 — DONE (HERMETIC)

Owner decision E14 APPROVED and implemented. Adapter non-conversion now has exactly two semantic
classes, with no generalized "skip adapter errors" behaviour.

- `behavior_evidence_adapter.py`: added `OUT_OF_SCOPE_REASONS = {ACTIVITY_FAMILY_NOT_SUPPORTED_BY_BEHAVIOR_CONTRACT}`,
  an explicit `DEFECT_REASONS` set (tenant/endpoint/time/raw-ref/field-shape/field-collision) and
  `is_out_of_scope()`, which is fail-closed: any unknown/new reason is a DEFECT. Conversion logic,
  supported families and `KIND_MAP` unchanged. No OTHER support added.
- `behavior_sd_provider.py`: out-of-scope rows go to a separate `out_of_scope` counter and
  `counters["rows_out_of_scope"]`; they never touch `refusals`/`rows_refused`, no EvidenceRecord is
  manufactured, the §d row is left untouched and nothing reaches the engine. `snapshot()` now
  reports `out_of_scope` alongside `adapter_refusals`.
- `behavior_shadow_run.py`: `rows_out_of_scope` added to `COUNTERS` (materialized at zero).
- `behavior_shadow_runner.py`: `_read_page` measures the per-page `rows_out_of_scope` delta and
  continues; only DEFECT refusals still set `STATE_INTERRUPTED/STOP_ADAPTER_REFUSAL` before the
  engine runs (E8 intact). `_finalize` now flushes any pending measurement so a page that yields no
  processable item (e.g. only out-of-scope rows) is still accounted for.
- Frontier semantics unchanged: out-of-scope rows are never acknowledged individually, and the
  forward `after`-key read naturally progresses past them once later supported rows are processed.
  Checkpoint stays the LAST durable operation; MATCH/NO_MATCH/INSUFFICIENT/BUDGET untouched.

Tests (hermetic, synthetic only): mixed page supported→unsupported→supported = 2 engine-eligible
records, 1 `rows_out_of_scope`, 0 adapter defects, frontier at the last supported row; out-of-scope
row creates no shadow detection and no outcome; supported→defect→supported still refuses the page
with zero engine work; reason-class invariants asserted. Full `tests/edr_trajectory` = 380 passed,
9 skipped. `tests/edr` = only the 4 pre-existing `test_p0_f13_5_detection_handoff` failures remain.

No production access, no real KUSHU evidence, no DESKTOP, no index creation, no deploy, no shadow
run started. G-22 (E14) is now CLOSED. G-20/G-21 remain open.

### NEXT (owner-gated)
Hold. Likely 34C: read-only production explain preflight, run where production `MONGO_URL` is
resolvable. No index creation until that output is reviewed.

## STEP 34C — PRODUCTION §d QUERY-PLAN PREFLIGHT — 2026-06 — BLOCKED (ACCESS BOUNDARY)

Authorized scope: P1 explain("executionStats") only, on the 10 Step-33 branch queries, KUSHU only,
10-minute window. No page read, no family census, no adapter, no engine, no frontier, no index,
no writes, DESKTOP prohibited.

ACCESS MEASUREMENT (read-only, this container):
- `backend/.env` MONGO_URL = mongodb://localhost:27017, DB_NAME = test_database.
- No production connection string exists in the process environment or in any `.env` (repo-wide
  search for `mongodb+srv` returns documentation and export artifacts only).
- The single reachable mongod is localhost:27017, whose databases are all local/CI/preview
  (`test_database`, `xdr`, `nivxray_ci*`, probe/temp DBs). No production cluster is routable.
=> Production explain CANNOT be executed from here. Preview was NOT substituted.

DELIVERED INSTEAD (so running it elsewhere is one command, and preview substitution is impossible
BY CODE rather than by discipline): `backend/tools/preflight_34c.py` — explain-only, reusing
`branches()`, `_window_bounds()` and `OBSERVATION_TIME_KEY` verbatim from the §d production adapter.
Hard refusals, each verified by running the tool: PROD_MONGO_URL unset -> BLOCKED
NO_EXPLICIT_PRODUCTION_URI; a localhost/127.0.0.1 URI -> BLOCKED
REFUSED_PREVIEW_OR_LOCAL_DATABASE_SUBSTITUTION; a URI equal to the container MONGO_URL -> refused;
PROD_DB_NAME unset -> refused; hostname != KUSHU -> refused; any ref containing DESKTOP -> refused.
It issues `explain` commands only, reports per-branch index/stage-chain/blocking-SORT/keys/docs/
nReturned/executionTimeMillis, and prints PASS only when no branch shows a blocking SORT.

NEW GAPS
- G-23: the preview/dev container has no credential path to the production cluster, so NO
  production-plane measurement (explain, census or bounded page) is executable from here. This is
  an environment/authorization gap, not an engineering one.

### NEXT (owner-gated)
Owner supplies a shell with the production MONGO_URL resolvable (PROD_MONGO_URL/PROD_DB_NAME) and
runs `python backend/tools/preflight_34c.py`, or authorizes another route to obtain the production
explain output. G-20/G-21 stay OPEN. No index decision, no bounded page, no family census.

## STEP 34C-A — SAFE PRODUCTION PREFLIGHT EXECUTION ROUTE — 2026-06 — DISCOVERY ONLY

No secret requested, printed, copied or stored. No query executed. No deploy, no config/secret
change, no index, no Behavior.

Evidence read (repo/deployment config + this program's own prior production record):
- `.emergent/emergent.yml` — this app is an Emergent-platform job/deployment (no DB URI present).
- `backend/.env` in this container is the PREVIEW binding only (loopback mongod, no ingress).
- `deploy/docker-compose.yml` + `docs/DEPLOYMENT.md` describe an ALTERNATIVE self-host VPS route
  (Docker Compose + Atlas, secrets in a VPS-side `.env`). That is NOT the live production runtime
  for this program and must not be used as the access path.
- `vercel.json` / `apps/nivxray-xdr` — Vercel hosts the FRONTEND only; it holds no DB binding.
- PRD 2026-09-29 production diagnose (already-proven facts): the live backend is the Emergent
  deployment with an Emergent-managed Atlas store; MONGO_URL/DB_NAME are injected by the platform
  into the production pod. Credentials have never been exposed to this plane, and that is correct.
- `backend/routers/` has NO Mongo `explain`/index-diagnostic endpoint today.

CONCLUSION: a safe route exists and does NOT require disclosing the URI.
1. PRIMARY — Emergent deployer, `intent=debug` (read-only production diagnose). Runs inside the
   authorized production context, reads pod runtime, DB binding and secret PRESENCE, and has
   already been used successfully on this program (job ref 95e7e8cd-..., 2026-09-29). It diagnoses
   only and cannot write production data. Lowest blast radius; no secret ever leaves the platform.
2. FALLBACK (only if the deployer cannot return per-branch explain plans) — add an admin-only,
   read-only diagnostic endpoint that runs the Step-34C explain set SERVER-SIDE inside production
   using the already-injected binding, returning plan metadata only (index, stage chain, blocking
   SORT, keys/docs/nReturned/ms). KUSHU-only and DESKTOP-prohibited guards are reused from
   `tools/preflight_34c.py`. Costs one deploy; still zero secret disclosure, zero writes.
REJECTED: exporting production credentials to any other machine (incl. the owner's Mac) or pasting
a URI into a shell/chat. `tools/preflight_34c.py` stays the local/one-off form and is unchanged.

### NEXT (owner-gated)
Owner picks route 1 or route 2. Nothing executed until then. G-20/G-21/G-23 remain OPEN.

## STEP 34C-B — PRODUCTION EXPLAIN VIA DEPLOYER DIAGNOSE — 2026-06 — DISPATCHED (AWAITING RESULT)

Owner chose the zero-deploy route. Read-only production diagnose dispatched to the Emergent
deployer with `intent=debug`; job ref `95e7e8cd-6528-4f50-8702-566d0dc3b0ce` (queued, runs
asynchronously). No result has been produced or assumed.

Brief (verbatim scope): resolve KUSHU in production (`edr_endpoints.hostname = "KUSHU"` ->
tenant_id/endpoint_id/device_iid/collector_id), build REFS from those platform identifiers, derive
END = newest KUSHU `xdr_canonical_evidence.event_time` and START = END - 10 min, then run EXACTLY
10 `explain("executionStats")` commands — the 7 `v2_shadow_observations` identity branches
(event.device_iid, device_iid, collector_id, connector_id, event.computer, event.raw.computer,
event.raw.hostname; time key `event.ts`) and the 3 `xdr_canonical_evidence` branches
(provenance.collector_id, host.host_id, host.hostname; time key `event_time`), each
`{identity: {$in: REFS}, tenant_id, time: {$gte,$lte}}` sorted newest-first with limit 89
(25 + TIE_MARGIN 64). Report per branch: collection, identity field, index used, winning-plan stage
chain, blocking SORT y/n, totalKeysExamined, totalDocsExamined, nReturned, executionTimeMillis;
plus `xdr_canonical_evidence` index NAMES and key patterns (names only).

Prohibited in the brief and restated to the deployer: no page read, no evidence content, no family
census, no adapter, no engine, no frontier, no shadow run, no index creation/change, no production
write, no deploy, no restart, no secret values returned or logged, DESKTOP-A9HGFJJ explicitly
prohibited, no sensor/Windows/Mac action. Stop after the ten explains; do not fix a poor plan.

### NEXT (owner-gated)
Await the deployer's production plan report, then the owner decides: healthy plan -> bounded KUSHU
page + family composition; weak plan -> strengthen that exact index/query boundary first.
G-20/G-21/G-23 remain OPEN. Family Composition = HOLD. Index Decision = HOLD.

### 34C-B RESULT (2026-06) — EXPLAIN BLOCKED BY TOOLSET, BUT A HARDER FACT MEASURED

Deployer diagnose returned (run `f1c94ac6-...`, prod store `greeting-app-5782-test_database`,
Emergent-managed Atlas). RCA: `/app/deployer-agent-docs/RCA_f1c94ac6-f853-4a32-80ef-eb51577ac230.MD`.

NOT MEASURED: the 10 `explain("executionStats")` commands. The deployer's production-DB tool is
read-only `mongo_query` limited to find|count|distinct|list_collections|list_indexes — no
`explain`/`runCommand` surface. It stopped at the boundary and substituted nothing. (G-24)

MEASURED IN PRODUCTION (read-only, metadata only):
- KUSHU: tenant `ten_e759b7288598bd882e3dcac49d`, endpoint `ep_a67be48d5b4e01d4d9e8`,
  hostname KUSHU, **device_iid = null, collector_id = absent/null** -> REFS = {ep_..., "KUSHU"}
  only. No DESKTOP ref; DESKTOP never queried.
- `xdr_canonical_evidence` production indexes = EXACTLY TWO: `_id_` and
  `tenant_id_1_ingest_time_-1` = `{ingest_time: -1, tenant_id: 1}`.
  => NO index on `event_time` (the §d sort key) and NO index on ANY §d identity field
  (`host.host_id`, `host.hostname`, `provenance.collector_id`). The preview `pvw_sd_*` indexes are
  confirmed ABSENT in production.
- Confirmations: PRODUCTION_WRITES=NONE, INDEX_CREATED=NONE, PAGE_READ=NO, ENGINE_EXECUTED=NO,
  FRONTIER_CREATED=NO, DESKTOP_ACCESSED=NO, DEPLOYED=NO, RESTARTED=NO, SECRETS_DISCLOSED=NO.

CONSEQUENCE (structural, not inferred from any plan): the three canonical §d branches filter on an
unindexed identity field and sort newest-first on an unindexed `event_time`. With only
`{ingest_time, tenant_id}` available, no index can both select the branch and provide the order, so
those branches cannot be index-served as written — the exact latency the preview `pvw_sd_*` indexes
were hiding (G-20 now has a measured production cause). G-25: production KUSHU carries no
`device_iid`/`collector_id`, so §d addressing for KUSHU rests on `endpoint_id` + `hostname` alone.

NOT DONE, deliberately: no index created, no query rewritten, no explain route added, nothing
deployed. The owner's rule stands — strengthen the boundary on evidence, do not work around it.

### NEXT (owner choice, one only)
(a) authorize a temporary admin-only read-only explain route on the production backend to obtain
    the real plans (one deploy), or
(b) accept the structural finding and design the canonical index/query strengthening first
    (then verify with (a) afterwards), or
(c) operator-side Atlas explain by the owner, outside this plane.
Family Composition = HOLD. Index Decision = HOLD until the owner picks.

## STEP 34D — CANONICAL §d INDEX/QUERY STRENGTHENING DESIGN — 2026-06 — DONE (HERMETIC)

No production change. Nothing in production was read, written or indexed in this step; the only
database touched is a scratch DB (`nivx_34d_hermetic_scratch`) created and dropped by the
measurement script on the local mongod.

### Identity contract (G-25 investigated BEFORE any index was proposed)
Writers (code, not inference):
- `edr_plane/canonical_bridge.py` — authenticated EDR sensor path: `host.host_id = <platform
  endpoint_id>` (L561), `host.hostname = hostname` (L561), `provenance.collector_id =
  <platform endpoint_id>` (L650/L713), and `additional_fields.endpoint_id = <platform endpoint_id>`
  (L591).
- `detection_content/telemetry/nivxforge_sensor_dsm.py` — XDR DSM path: `host.host_id =
  raw.endpoint_id OR collector_id`, i.e. may legitimately hold a VENDOR/collector id rather than a
  platform id.
Preview census (read-only, 297,832 canonical docs; field presence only, no DESKTOP targeting):
- 293,873 docs have `host.host_id == provenance.collector_id == additional_fields.endpoint_id`
- 293,834 `host.host_id` values are platform `ep_…`; 1,236 docs have `provenance.collector_id =
  ep_…` while `host.host_id` is NOT a platform id (legacy/other path)
- 270,715 docs carry a hostname; 26,757 docs have a platform `host.host_id` and NO hostname
- 0 docs have a hostname that is a substituted `ep_…` string
=> THE AUTHORITATIVE PLATFORM ENDPOINT FIELD ON CANONICAL EVIDENCE IS
   `additional_fields.endpoint_id` (with `host.host_id` carrying the same value on the
   authenticated path). It is NOT a declared §d identity field and NOT indexed. Recorded as an
   IDENTITY-CONTRACT GAP (G-26), NOT solved here and NOT worked around by overloading hostname.
   KUSHU addressability: production registry has device_iid = null and collector_id = null, so
   REFS = {ep_a67be48d5b4e01d4d9e8, "KUSHU"}; KUSHU's authenticated canonical rows are therefore
   addressable through `host.host_id` / `provenance.collector_id` (both = the ep_ value) and
   through `host.hostname`. No identifier was invented.

### Declared contract + guard
- NEW `backend/edr_plane/canonical_index_contract.py` — DECLARATION ONLY, creates nothing. Derives
  one spec per declared canonical identity field from `ENDPOINT_KEYED_STORES`,
  `TENANT_PARTITIONED_STORES` and `OBSERVATION_TIME_KEY`:
    sd_canonical_collector_eventtime  {tenant_id: 1, provenance.collector_id: 1, event_time: -1}
    sd_canonical_hostid_eventtime     {tenant_id: 1, host.host_id: 1,            event_time: -1}
    sd_canonical_hostname_eventtime   {tenant_id: 1, host.hostname: 1,           event_time: -1}
  Also records `PRODUCTION_INDEXES_MEASURED` (the 2026-06 production fact) and `missing_against()`.
- NEW `backend/tests/edr_trajectory/test_canonical_index_contract.py` — 7 pure tests: one spec per
  declared field, tenant partition is the LEADING equality prefix, identity second, `event_time`
  last and DESCENDING, every filter `branches()` actually builds has a matching spec, no spec
  addresses an undeclared field, the measured production index set satisfies NONE of the specs, and
  a complete set reports complete. Full `tests/edr_trajectory` = 387 passed, 9 skipped;
  `tests/edr/test_p0_2c_alias_invariant.py` = 11 passed.

### Hermetic explain proof (`backend/tools/measure_34d_canonical_index.py`, scratch DB, 36,000 docs)
- BEFORE (production index set reproduced: `_id_` + `{ingest_time: -1, tenant_id: 1}`): all three
  canonical branches = `SORT + COLLSCAN`, 36,000 docs examined, 0 keys. The production weakness
  reproduced exactly.
- AFTER (the three proposed indexes): `LIMIT → FETCH → SORT_MERGE → IXSCAN×2`, no COLLSCAN, no
  blocking SORT, keys = docs = 3, max 2 ms. (`SORT_MERGE` is an index-ordered merge of the `$in`
  scans, not an in-memory sort.)
- BOUNDEDNESS: widened to a window holding 5,400 matching rows -> keys = docs = nReturned = 89, the
  exact `25 + TIE_MARGIN 64` fetch bound. The index bounds the read; it does not scan the corpus.
- NECESSITY: with the hostname index dropped, the hostname branch falls back to the collector index
  and reintroduces a BLOCKING SORT (`SORT → FETCH → IXSCAN`). All three are required while §d
  addresses all three fields.
- TENANT ISOLATION: the same refs under a different tenant return 0 rows, 0 docs examined, still
  index-served — the equality prefix holds.
- ORDER/WINDOW: rows return newest-first and entirely inside the window.
- COST (measured on the scratch sample): each index ≈ 920 KiB for 36,000 docs ≈ 26 B/doc; three
  ≈ 2.7 MiB ≈ 15.7% of data size ≈ 79 B/doc. Extrapolated to a preview-sized corpus (~300k docs)
  ≈ 23 MB total. Write amplification = 3 extra short index entries per insert on an append-mostly
  collection. Justified; the alternative is a per-branch collection scan plus an in-memory sort on
  every Device Trajectory page.
- QUERY CHANGES REQUIRED: NONE. The §d query shape is already correct and needs no rewrite, no
  hint and no broadening.

### NEW GAPS
- G-26 (identity contract): `additional_fields.endpoint_id` is the authoritative platform endpoint
  identity on canonical evidence but is neither a declared §d identity field nor indexed, so §d
  addresses three derived fields instead of one hard key. A future strengthening could reduce the
  canonical branch set to one authoritative key plus a legacy-name branch — that is an identity
  decision plus a backfill proof, NOT an index decision, and is explicitly deferred.
- G-27: `host.host_id` is overloaded across ingest paths (platform `ep_…` on the authenticated
  path, vendor/collector id on the XDR DSM path), which is why the collector branch is not
  redundant (1,236 preview rows).

### NEXT (owner-gated)
Owner decides whether to (a) authorize applying the three declared indexes to production
(idempotent, background, additive — no schema or query change), and/or (b) authorize the temporary
read-only explain route to prove the plans in production before/after. Family Composition and the
bounded KUSHU page remain HOLD.

## STEP 34E — G-26 AUTHORITATIVE ENDPOINT IDENTITY CONTRACT — 2026-06 — DESIGN DONE (HERMETIC)

No production change, no migration, no deploy, no index created anywhere real. Preview was read
(counts/field-presence/classification only, no evidence content, no DESKTOP targeting, zero writes);
the explain proof ran in a scratch DB created and dropped by the script.

### Writer coverage (read from code)
- `detection_content/xdr_pipeline.py:394` is the ONLY canonical writer. The document it inserts is
  whatever the selected DSM normalizer produced.
- `detection_content/telemetry/nivxforge_sensor_dsm.py:151` is the ONLY normalizer that stamps
  `additional_fields.endpoint_id` (= `raw.endpoint_id or collector_id`). No other DSM (snort,
  windows_security, defender, auditd, cloudtrail, powershell…) stamps it at all.
- `edr_plane/canonical_bridge.py:711` calls the pipeline with `collector_id = <platform
  endpoint_id>` and `_authenticated_ingest.authenticated_endpoint_id` for AUTHENTICATED endpoint
  ingest. So on that path `provenance.collector_id` carries an authenticated platform id even when
  a non-sensor DSM normalizes the event.
=> ROOT CAUSE of G-26: the authoritative identity is stamped by ONE DSM instead of by the
   authenticated ingest BOUNDARY, so DSM selection decides whether canonical evidence carries a
   platform endpoint identity.

### Measured coverage (preview corpus, 299,865 canonical rows, classified by the new pure classifier)
  ENDPOINT_IDENTITY_AUTHORITATIVE            294,189   98.1%   (af.endpoint_id, platform-minted)
  ENDPOINT_IDENTITY_UNRESOLVED_NAME_ONLY       3,552    1.2%   (hostname only, no platform id)
  ENDPOINT_IDENTITY_AUTHENTICATED_BOUNDARY     1,236    0.4%   (collector_id = ep_, af absent)
  EVIDENCE_NOT_ENDPOINT_SCOPED                   801    0.3%   (no host object; collector sources)
  ENDPOINT_IDENTITY_UNRESOLVED                    88    0.0%
  DETERMINISTICALLY_BACKFILLABLE               1,236    0.4%
Additional facts that change the migration order:
- 0 rows exist where `af.endpoint_id` is present and `host.host_id` differs from it -> `host.host_id`
  is a COPY, never an independent identity.
- 1,230 of the 1,236 authenticated-boundary rows have NO hostname at all. So retiring the collector
  branch BEFORE the backfill would make them unreachable. The backfill is a PREREQUISITE, not an
  optimisation.
- 9 distinct hostnames appear under MORE THAN ONE tenant (G-28) — proof that a name is only
  meaningful inside the tenant equality prefix and may never be an identity.

### Target contract (declaration only)
NEW `backend/edr_plane/canonical_identity_contract.py`: `AUTHORITATIVE_FIELD =
additional_fields.endpoint_id`; `AUTHENTICATED_BOUNDARY_FIELD = provenance.collector_id` (the only
fallback, and only when platform-minted); `LEGACY_NAME_FIELD = host.hostname` (a NAME, never an
identity); `NEVER_IDENTITY = host.host_id, host.hostname, device_iid, event.computer, host.ip`.
Pure `classify(row)` and `backfill_candidate(row)`; nothing is wired into any read or write path.
NEW `TARGET_CANONICAL_INDEXES` in `canonical_index_contract.py`:
  sd_canonical_endpointid_eventtime {tenant_id:1, additional_fields.endpoint_id:1, event_time:-1}
  sd_canonical_hostname_eventtime   {tenant_id:1, host.hostname:1,                 event_time:-1}

### Hermetic proof (`backend/tools/measure_34e_identity_contract.py`, scratch DB, 20,000 docs)
Both target branches: `LIMIT → FETCH → IXSCAN`, no COLLSCAN, no blocking SORT. Wide window holding
4,250 matching rows -> keys = docs = nReturned = 89 (the exact 25 + TIE_MARGIN bound). Coverage: the
target pair reached the SAME row set as the three legacy branches, with 0 rows reachable only the
legacy way once the backfill is applied. Tenant isolation: same id under another tenant -> 0 rows,
0 docs, still index-served. Order/window: newest-first, all inside the window. Cost: 2 target
indexes ≈ 53.5 B/doc ≈ 10.9% of data size, versus 21.9% for the 34D three-index set + target.

### Options compared
- A (authoritative + all three legacy branches): 4 indexes, keeps the ambiguity. REJECTED.
- B (authoritative + one bounded legacy NAME branch): 2 indexes — but UNSAFE ALONE, because 1,230
  authenticated-boundary rows have no hostname and would become unreachable.
- C (deterministic backfill, then authoritative only): 1 index — UNSAFE, it would strand the 3,552
  name-only rows that have no platform identity at all.
RECOMMENDED = B + the bounded deterministic backfill, executed in this ORDER:
  1. writer fix: stamp the authoritative field at the AUTHENTICATED INGEST BOUNDARY for every DSM
     (never from the event's shape) — new writes then always carry it;
  2. create the 2 target indexes (additive, background) and KEEP the collector branch transitionally;
  3. deterministic backfill of exactly the 1,236 rows: copy `provenance.collector_id` into
     `additional_fields.endpoint_id` ONLY when platform-minted (no hostname, no vendor id, no
     device_iid, no inference), recorded with its basis;
  4. verify 0 remaining backfillable rows, then retire the `host.host_id` and
     `provenance.collector_id` branches and their indexes.
Minimum production index set under the target contract = 2 (transitional = 3 until step 4).
`host.host_id` is never needed: 0 rows disagree with the authoritative field and its remaining
values are hostnames already covered by the name branch.
KUSHU: its evidence comes from the authenticated sensor path, so it carries the authoritative field
and is reachable by the authoritative branch alone.

### Regression guard
NEW `backend/tests/edr_trajectory/test_canonical_identity_contract.py` (14 pure tests): only a
platform-minted value is an identity; authoritative field first, authenticated boundary second;
hostname / vendor host_id / device_iid / IP are NEVER promoted; a non-platform value in the
authoritative field is UNRESOLVED; collector-sourced evidence is NOT endpoint-scoped; the backfill
copies only an authenticated platform id and refuses names, vendor ids and already-stamped rows;
target set is one authoritative key + one legacy name branch, keeps the tenant equality prefix and
the descending event_time, and drops the two copy branches. `tests/edr_trajectory` = 401 passed,
9 skipped.

### NEW GAPS
- G-28: 9 hostnames are shared across tenants in preview — names are tenant-local, never identities.
- G-29: the writer fix (step 1) is an ingest-boundary change and needs its own hermetic step before
  any backfill; not started.

### NEXT (owner-gated)
Owner decides: implement the G-26 strengthening in the recommended order (next step = the
boundary writer fix, hermetic), or fall back to applying the 34D three-index set now and defer the
identity work. Family Composition, the bounded KUSHU page and the production explain route remain
HOLD.

## STEP 34F — AUTHENTICATED INGEST-BOUNDARY ENDPOINT IDENTITY STAMPING (G-29) — 2026-06 — DONE

Implements G-29 only. No production change, no backfill, no index, no §d query-branch change, no
deploy, no engine/frontier/shadow, no sensor/Windows/Mac action, DESKTOP untouched.

### Change
- `edr_plane/canonical_identity_contract.py` (+): `BOUNDARY_AUTHORITY = AUTHENTICATED_INGEST_BOUNDARY`,
  `boundary_identity()` and `stamp_boundary_endpoint_identity()`. Identity may come from exactly two
  BOUNDARY-supplied places, in trust order: `authenticated_ingest.authenticated_endpoint_id`
  (envelope the authenticated handler attaches) then `ingest_boundary.collector_id` (explicit call
  argument). Both require `trust_state == AUTHENTICATED`, and both must be PLATFORM-MINTED (`ep_…`).
  Nothing is read from the event body, a hostname/vendor host_id/device_iid/IP/collector string is
  never promoted, and the decision is recorded under `provenance.endpoint_identity`
  (`{state, authority, source|reason, refused_claim?}`).
- `detection_content/xdr_pipeline.py`: the stamp is applied after the normalizer and BEFORE
  `insert_one` into `xdr_canonical_evidence`, for EVERY DSM, and reported as its own pipeline stage
  (`endpoint_identity`).
- `detection_content/telemetry/nivxforge_sensor_dsm.py`: no longer stamps
  `additional_fields.endpoint_id` (it previously used `raw.endpoint_id or collector_id`, i.e. event
  content). DSMs now normalize content only.
- A claim already sitting in the authoritative field carries no authority: it is OVERRIDDEN when the
  boundary resolves an identity and REMOVED + recorded as refused when it does not.

### Proof
- `tests/edr/test_34f_boundary_endpoint_identity.py` (12 hermetic tests): four DSM-family document
  shapes (NivXForge sensor, a windows DSM writing a hostname into host_id, a network DSM with no
  host object, a cloud DSM keyed on an account id) all receive the SAME boundary identity; envelope
  beats boundary argument; boundary argument used when the envelope names none; identity is never
  taken from event content; a DSM claim is refused/overridden and RECORDED; unauthenticated calls
  (no envelope, empty envelope, `UNVERIFIED` trust) produce NO platform identity; a non-platform
  boundary value fails closed; stamping touches nothing but the identity and its record (tenant,
  host, hostname, event_time, raw_ref, prior provenance stamps all verified unchanged); the sensor
  DSM and EVERY registered telemetry DSM contain no authoritative-field stamping (source-level
  guard against future DSM-specific authority); the writer stamps before persisting.
- End-to-end through the REAL writer in a scratch DB (`tools/check_34f_pipeline_stamping.py`,
  dropped afterwards): authenticated -> `af.endpoint_id = ep_a67be…`, record
  `{RESOLVED, AUTHENTICATED_INGEST_BOUNDARY, authenticated_ingest.authenticated_endpoint_id}`; the
  SAME event without the envelope -> no `af.endpoint_id`, record
  `{UNRESOLVED, NO_AUTHENTICATED_INGEST_BOUNDARY}`, even though the event body claimed `ep_…`;
  third-party collector -> same UNRESOLVED outcome. Tenant, host, collector_id and raw refs
  preserved in all three.
- Regression: `tests/edr` = 2,200 passed (only the 4 known pre-existing `test_p0_f13_5` failures),
  `tests/edr_trajectory` = 413 passed / 9 skipped, plus the pipeline-driving suites
  (`test_xdr_round11_pipeline`, `test_d15_declared_source_routing`, `test_d11_ingest_provenance`,
  `test_xdr_round12_investigation`, `test_xdr_round23_traversal_completion`,
  `test_n2_endpoint_process_attribution`, `test_p0_dedupe_hardening`, `test_d13_json_ingest_shape`)
  = 192 passed.

### NEW GAPS
- G-30: `host.host_id` is STILL event-derivable — the sensor DSM sets it from `raw.endpoint_id or
  collector_id`, so an unauthenticated event can put an `ep_…`-shaped string there (observed in the
  scratch run). Harmless under the target contract, which declares `host.host_id` NEVER_IDENTITY and
  retires it as an addressing field, but it must not be trusted anywhere before then.
- G-31 (artifact, not investigated): in the scratch run the canonical `event_time` took an
  ingest-time value for the synthetic event shape used. Possibly just the synthetic payload missing
  the field the parser reads; NOT a finding, flagged so it is re-checked with a real sensor payload
  rather than forgotten.

### NEXT (owner-gated)
Review 34F, then the likely sequence: create the 2 target indexes -> bounded deterministic backfill
of the 1,236 authenticated-boundary rows -> verify 0 remaining -> retire the ambiguous §d branches
-> production explain -> KUSHU family composition -> first real Behavior run.

## STEP 34G — CLOSE G-30: host.host_id IS NOT AN IDENTITY — 2026-06 — DONE (HERMETIC)

Implements G-30 only. No production change, no index, no backfill, no §d query-branch change, no
deploy, no engine/frontier/shadow, no real KUSHU evidence, no family census, no sensor/Windows/Mac
action, DESKTOP untouched.

### Invariant now enforced
`additional_fields.endpoint_id`, stamped by the authenticated ingest boundary (34F), is the SOLE
authoritative platform endpoint identity. `host.host_id` can no longer acquire platform-identity
meaning from event-controlled data, and no reader promotes it.

### Writers
- `detection_content/telemetry/nivxforge_sensor_dsm.py`: `host.host_id` is now taken ONLY from a
  host identifier the SOURCE itself declares (`raw.host_id`). The event's own `endpoint_id` claim is
  no longer written there, and neither the collector id nor the hostname is substituted for one.
  The endpoint SCOPE passed to `bind_process_identity` now comes from
  `canonical_identity_contract.boundary_identity()` instead of `raw.endpoint_id or collector_id`.
- Other DSMs (windows_security, defender, auditd, cloudtrail…) write `host_id = hostname/account id`
  = SOURCE_ATTRIBUTE, unchanged and never promoted.
- `edr_plane/canonical_bridge.py:561` still sets `host_id = endpoint_id` on ITS OWN canonical dict
  (shadow-observation / address-observation plane). That value is BOUNDARY-sourced, not
  event-controlled, so it satisfies the invariant; logged as G-32 to retire once the §d legacy
  branches go.
- Fixtures/seeds/tools (`prodshape.py`, `platform_seed.py`, `fixtures.py`, the 34D/34E measurement
  scripts) are test material.

### Readers — every use classified
AUTHORITATIVE outside `additional_fields.endpoint_id` = ZERO. Four uses were found and FIXED:
  `edr_plane/process_identity.py` · `edr_plane/file_identity.py` ·
  `edr_plane/reputation/observables.py` (all dropped the `host.host_id` endpoint-scope fallback) and
  `detection_content/xdr_incident.py::_endpoint_scope` (incident campaign scope now requires the
  authoritative field; an event-forged `ep_…` in `host.host_id` no longer creates or consolidates an
  endpoint incident).
LEGACY_LOOKUP (addressing refs resolved against the validated alias set, never identity):
  `services/edr/endpoint_query.ENDPOINT_KEYED_STORES`, `edr_trajectory/providers.py:81` (frame
  device id) and `:153`, `routers/edr_trajectory_v3.py:196`,
  `edr_plane/detection_replay.CANONICAL_ENDPOINT_FIELDS` and `_endpoint_ref` (now
  authoritative-FIRST, then the refs).
SOURCE_ATTRIBUTE: the DSM-written vendor host identifiers; `services/entity_resolution.py:197`
  already adds host_id/hostname as DECLARED context, explicitly "not identity".
ARTIFACT_SCOPED (different plane, not event-controlled): `edr_plane/authority.py::_approved_endpoint`
  reads `host_id|endpoint_id|device_id` from a RESPONSE APPROVAL artifact. Logged as G-33 for the
  response plane; not changed here.
INVALID_IDENTITY_USE remaining = none.
RAW EVENT CLAIM PRESERVED: the original payload (incl. any `endpoint_id` claim) is untouched in
`edr_raw_events` and in the parsed `raw` block; claims are refused and RECORDED
(`provenance.endpoint_identity.refused_claim`), never erased.
§d LEGACY DEPENDENCY: new authenticated rows will carry `host.host_id = null`; §d still reaches them
via `provenance.collector_id` (= the platform id on the authenticated path) and `host.hostname`, and
the target contract reaches them via the authoritative field. No addressability loss — which is why
the collector branch stays until the backfill is verified.

### G-31 recheck (`tools/check_34g_g31_event_time.py`, hermetic, parser/normalizer only)
With the documented sensor field `observed_at`, canonical `event_time` PRESERVES the sensor
observation to the microsecond and `event_time_basis = OBSERVATION_TIME`. The 34F scratch payload
carried `ts`/`timestamp` instead, which the sensor parser does not read, so the platform honestly
recorded `event_time_basis = INGEST_TIME_SUBSTITUTED`. **G-31 = malformed synthetic-fixture
artifact, CLOSED. No timestamp defect.** Worth noting: a payload with no readable observation time
is LABELLED as substituted rather than silently presented as observed.

### Tests
NEW `tests/edr/test_34g_host_id_is_not_an_identity.py` (10 tests): an event-body `ep_` claim never
reaches `host_id`; the collector id is not substituted into `host_id` (it stays collector
provenance); a source-declared host identifier is preserved as an attribute and is still not an
identity; the authoritative field still comes only from the boundary (authenticated vs forged);
the raw claim is never deleted; process/file/reputation identity never scope themselves from
`host_id` (plus a source-level guard that no `edr_plane` identity module reads `.get("host_id")`);
the incident endpoint scope requires a platform identity.
Two PRE-EXISTING tests encoded the OLD weaker contract and were corrected rather than the rule
weakened: `test_phase0_windows_canonical_bridge` asserted `host.host_id == ep_…` from a direct
normalizer call; `test_p0_f_endpoint_detection::_sensor_ev` simulated the authenticated path WITHOUT
the `_authenticated_ingest` envelope, so after 34F it no longer had an endpoint scope — it now
attaches the envelope exactly as `canonical_bridge` does on the real path.
Regression: `tests/edr` + `tests/edr_trajectory` = 2,611 passed, 12 skipped, only the 4 known
pre-existing `test_p0_f13_5` failures; pipeline-driving suites = 185 passed.

### NEW GAPS
- G-32: `canonical_bridge.py:561` still writes the platform id into `host.host_id` on the
  shadow-observation plane (boundary-sourced, so safe) — retire with the legacy §d branches.
- G-33: `authority.py::_approved_endpoint` accepts `host_id` from a response-approval artifact;
  review on the response plane.

### NEXT (owner-gated)
Identity architecture work is complete. Next: create the 2 target indexes -> bounded deterministic
backfill of the 1,236 authenticated-boundary rows -> verify 0 remaining -> retire the legacy §d
branches -> production explain -> KUSHU family composition -> first real Behavior run.

## STEP 34H — APPLY TARGET CANONICAL INDEXES IN PRODUCTION — 2026-06 — BLOCKED (WRITE-ACCESS BOUNDARY)

Authorized scope: create exactly `sd_canonical_endpointid_eventtime`
{tenant_id:1, additional_fields.endpoint_id:1, event_time:-1} and `sd_canonical_hostname_eventtime`
{tenant_id:1, host.hostname:1, event_time:-1} on production `xdr_canonical_evidence`, additive,
idempotent, non-disruptive, nothing else changed.

NOT APPLIED. Boundary (re-measured, not assumed):
- this container has NO production connection string (`backend/.env` = loopback preview; no Atlas
  credential in the environment or repo) — same boundary as 34C/34C-A;
- the Emergent read-only diagnose route CANNOT write: its production-DB tool is limited to
  find|count|distinct|list_collections|list_indexes (measured in 34C-B). An index build is a
  production write, so that route is structurally unable to perform it (G-24 extends to writes).
No substitution of any kind was attempted.

DELIVERED INSTEAD: `backend/tools/apply_34h_target_indexes.py` — idempotent, additive, with
refusals in CODE: `PROD_MONGO_URL` must be supplied explicitly, localhost/127.0.0.1 and the
container's own `MONGO_URL` are refused, `PROD_DB_NAME` required, and `--apply` is mandatory to
write (default is report-only). It creates ONLY the two declared specs, reads the index list back to
verify name + exact key pattern, never drops/modifies/renames anything, and reports a same-name
different-key collision as `NAME_CONFLICT_REFUSED` instead of resolving it. Build mode is chosen from
the live server version (hybrid non-blocking on >= 4.2, legacy `background=True` below that; the
local check reported MongoDB 7.0.43).
SELF-CHECK = PASS on a scratch DB (dropped afterwards), four passes: report-only -> WOULD_CREATE ×2;
apply -> CREATED_VERIFIED ×2 with the exact key patterns; re-run -> ALREADY_PRESENT_VERIFIED ×2
(idempotent); injected name conflict -> NAME_CONFLICT_REFUSED. `EXISTING_INDEXES_CHANGED = NO` in
every pass, with a pre-existing `tenant_id_1_ingest_time_-1` surviving untouched. Refusal paths
verified by running the tool with no URI and with a localhost URI.

### The two routes to actually apply it (owner choice)
(a) OPERATOR-SIDE, zero deploy: run the tool where production resolves —
    `PROD_MONGO_URL=… PROD_DB_NAME=… python backend/tools/apply_34h_target_indexes.py` (report),
    then `--apply`. The URI never enters this chat, this repo or any committed file.
(b) APP-SIDE ROUTE, needs one deploy: an admin-only, authenticated, idempotent ensure-index endpoint
    (or a lazy ensure on the §d read path — the established pattern in this codebase, e.g.
    `routers/correlations.py::_ensure_indexes`, `routers/edr_saved_views.py::ensure_indexes`), which
    runs inside the production pod using the already-injected binding, so no credential moves.
Production writes other than index metadata: NONE in either route. Collector branch stays
transitionally; §d queries unchanged; no backfill; no Behavior; no frontier; no family census; no
endpoint/sensor action; DESKTOP untouched.

### NEXT (owner-gated)
Pick route (a) or (b). After the two indexes verify in production: bounded 1,236-row deterministic
backfill -> verify 0 remaining -> retire the legacy §d branches -> production query proof -> KUSHU
family composition -> first real Behavior run.

## STEP 34H-A — BOUNDED PRODUCTION MIGRATION CONTROL ROUTE — 2026-06 — DONE (NOT EXECUTED IN PROD)

Implements the control plane for G-34. No production execution, no production index, no backfill,
no §d change, no Behavior/frontier, no KUSHU/DESKTOP/Mac/sensor action, no deploy.

### What was built
- NEW `backend/edr_plane/migration_control.py` — a CLOSED REGISTRY of named operations. There is no
  caller-supplied collection, index spec, filter, update, pipeline, command, database or URI
  anywhere in the module; the collection and both index specifications come from the compiled
  `canonical_index_contract`. First and only operation: `ensure_canonical_identity_indexes`
  (`sd_canonical_endpointid_eventtime`, `sd_canonical_hostname_eventtime`).
  Per-index outcomes: `WOULD_CREATE` / `CREATED_VERIFIED` (read back and compared) /
  `ALREADY_PRESENT_VERIFIED` / `NAME_CONFLICT_REFUSED` / `CREATED_BUT_UNVERIFIED`. Nothing is ever
  dropped, renamed or altered — the module contains no `drop_index`/`drop`/`rename`/`delete_many`/
  `update_many`/`aggregate`/`command` call (asserted by test).
  Build mode follows the live server version: hybrid non-blocking on >= 4.2, legacy
  `background=True` below it.
- NEW `backend/routers/edr_migration_control.py` — `GET /api/internal/admin/migrations` (allowed
  operations, modes, recent runs), `POST …/ensure-canonical-identity-indexes`, and
  `POST …/{operation}` which refuses any unregistered name. Auth/authorization REUSE the existing
  admin principal (`deps.require_admin` → `get_current_user` JWT + `role == "admin"`); no new auth
  logic. The whole request model is `{mode: "report"|"apply"}` with `extra: forbid`, so any attempt
  to pass a collection, index, filter, pipeline, command, db or uri is a 422.
- `server.py`: router registered under the existing `/api` prefix.
- Audit: `e3_migration_runs` records REQUESTED → RUNNING → COMPLETED | FAILED | REFUSED with
  `migration_run_id`, operation, mode, authenticated actor, timestamps and the result; refusals
  record the reason. Secrets, tokens and connection details are never read, returned or logged.
- Concurrency: single-writer lock document in `e3_migration_locks` keyed by operation; a duplicate
  concurrent request gets HTTP 409 `MIGRATION_ALREADY_RUNNING` with the holder and a staleness flag
  (a stale lock is REPORTED, never stolen). The lock is released in a `finally`, so a failure is
  retry-safe and observable (HTTP 500 + a durable FAILED record).
- A future bounded identity-backfill operation registers in the same registry; it was NOT
  implemented or registered in this step.

### Security tests — `backend/tests/edr/test_34h_a_migration_control.py`, 18 passed
unauthenticated → 401/403 (all three routes) · invalid token → 401 · non-admin → 403 and NO audit
record written · arbitrary operation → 400 REFUSED + audited with the actor · unknown mode → 400 ·
collection/index/filter/pipeline/command/uri/db in the body → 422 (×7 payloads) · registry is the
only operation source and the module contains no destructive call · the route module performs no DB
write of its own · report mode changes nothing and names the exact specs · two runs are idempotent
with distinct run ids · apply → `CREATED_VERIFIED` once, re-apply → `ALREADY_PRESENT_VERIFIED`, and
an injected same-name/different-key spec → `NAME_CONFLICT_REFUSED` with the original index intact
(proven on a THROWAWAY collection via a temporarily registered scratch operation) · concurrent
duplicate → 409 with holder + stale flag and a REFUSED record · the lock is released so the next run
proceeds · a failing operation → FAILED record, released lock · every lifecycle field durable ·
no secret/connection string in any response (scanned for mongodb://, mongodb+srv, password,
jwt_secret, bearer, mongo_url, api_key, secret) · the listing exposes only registered operations.
Regression: `tests/edr_trajectory` + 34F/34G + the two earlier corrected suites = 488 passed,
9 skipped. Live preview check after restart: `GET /api/health` 200, and an unauthenticated POST to
the migration route returns 403 `Not authenticated`.

### NEXT (owner-gated)
Security review of 34H-A, then a controlled DEPLOY of the control plane, then a SEPARATE
authorization to execute `ensure_canonical_identity_indexes` in production — first `mode=report`,
then `mode=apply`.

## STEP 34H-B — DEPLOY MIGRATION CONTROL PLANE — 2026-06 — DEPLOY DISPATCHED (AWAITING RESULT)

Owner authorized DEPLOYMENT ONLY. Dispatched to the Emergent deployer (job
`95e7e8cd-6528-4f50-8702-566d0dc3b0ce`); the pipeline runs asynchronously and the panel reports the
outcome. No result assumed, no migration invoked.

Deployed content: the reviewed migration control plane (`edr_plane/migration_control.py`,
`routers/edr_migration_control.py`, one import + one `include_router` in `server.py`) plus the
already-regression-tested identity hardening (34F/34G) and the declaration-only
`canonical_index_contract` / `canonical_identity_contract`. No .env change, no new dependency, no
new environment variable, no DB-binding change.

Post-deploy verification requested (read-only): pod health + replica readiness + no crash loop; no
sustained 5xx increase; the migration routes PRESENT in production (unauthenticated POST and GET
must return 401/403 and NOT 404 — a 404 would mean the router failed to register); existing
functionality still healthy; production Mongo binding unchanged (mechanism/presence only); no secret
or connection string in output or logs; run id / commit / image digest / replica count.

Explicitly prohibited in the run and restated to the deployer: no `mode=apply` and no `mode=report`
invocation, no index creation, no backfill, no production data write, no Behavior engine, no
frontier/checkpoint/shadow run, no KUSHU evidence read, no family census, DESKTOP prohibited, no
sensor/Windows/Mac action.

### NEXT (owner-gated)
Review the deploy report, then a SEPARATE authorization for a production `mode=report` run, and only
after reviewing that, `mode=apply`.

### 34H-B POST-DEPLOY VERIFICATION (2026-06) — EXTERNAL PROOF PASS; PIPELINE FACTS PENDING

Publish reported by the panel as "Publish 100 / b6055ae". Read-only verification performed by me
against production `https://nivxray.nivxforge.com` (no authentication used, no migration invoked):
- `GET /api/health` -> 200
- `GET /api/internal/admin/migrations` (unauth) -> **403** `{"detail":"Not authenticated"}`
- `POST /api/internal/admin/migrations/ensure-canonical-identity-indexes` (unauth) -> **403**
- `POST /api/internal/admin/migrations/ensure_canonical_identity_indexes` (unauth) -> **403**
- same route with an INVALID bearer token -> **401** `{"detail":"Invalid or expired token"}`
- control probe `GET /api/internal/admin/migrations-nonexistent` -> **404**
  => the router IS registered in production (403, not 404, while a sibling path genuinely 404s) and
     IS guarded by the existing admin principal.
- existing surface healthy: `/api/edr/endpoints` -> 403, `/api/auth/me` -> 403, app shell `/` -> 200.
- No response body contained any secret, token or connection string.
NOT invoked: `mode=report`, `mode=apply`. No index, no backfill, no Behavior, no frontier, no family
census, no endpoint/sensor action, DESKTOP untouched.

PENDING (dispatched to the deployer, read-only, job `95e7e8cd-6528-4f50-8702-566d0dc3b0ce`):
deployment run id, full commit SHA, image digest, desired-vs-ready replicas and per-pod restart
count, this revision's startup log health (incl. clean import of `routers/edr_migration_control`),
sustained-5xx comparison and top repeated errors, confirmation that the production Mongo binding is
UNCHANGED (mechanism/presence only), confirmation that no secret appears in build/deploy output, and
— tracked separately, not fixed — whether the startup ThreatFox 401 is recurring and predates this
rollout.

### 34H-B CLOSED — 2026-06 — PASS (DEPLOY VERIFIED, NOTHING MIGRATED)

Deployer read-only report (run `b6055ae4-25bc-4220-8c04-ebb74853f056`; RCA
`/app/deployer-agent-docs/RCA_b6055ae4-25bc-4220-8c04-ebb74853f056.MD`):
- 2/2 replicas Ready, `restart_count = 0` on both pods, no crash/restart loop (the early `:8080`
  connection-refused probe warnings were the normal pre-listen boot window, then both passed);
  "Application startup complete." on both pods with no import/registration error.
- `routers/edr_migration_control` imported and registered cleanly, serving
  `/api/internal/admin/migrations` and `.../{operation}` as guarded 403/401, never 404.
- No 5xx since rollout; the only 401/403 are my own auth probes.
- Mongo binding UNCHANGED (`mongodb_migrate` ran 0s, no restore); `MONGO_URL` and `DB_NAME` present
  and platform-injected, values never read. No secret or connection string in build output
  (grep MONGO_URL/mongodb/SECRET = no match; caveat: Cloud Build shows the last 500 lines) or pod logs.
- Image digest `sha256:69b8bba7ef42299122f16c9213b623a5dc18fb9e64d697bb5758fd5607968a9c`
  (build `d4618159`). IMPORTANT: `b6055ae` is the run-id-derived IMAGE TAG, not a git commit SHA —
  the pipeline records no git SHA (G-38: if the acceptance checklist needs a commit SHA, it must come
  from the build-trigger/source side).
- G-37 (tracked, NOT fixed): the ThreatFox 401 at `threatfox-api.abuse.ch/api/v1/` is RECURRING and
  PREDATES this rollout (identical hourly 401s in the earlier run across 05:40-09:53 UTC). The
  "7/7 live" line reflects provider REGISTRATION, not a successful pull — TI sync records
  `threatfox:0` every cycle. `ABUSE_CH_AUTH_KEY` is set but rejected; fix = verify/refresh the
  abuse.ch key in the Deployment Panel secrets and redeploy, when the owner reaches TI hardening.

Migration state unchanged: `mode=report` and `mode=apply` NOT invoked, no index created, no backfill,
no Behavior, no frontier/shadow, no family census, no endpoint/sensor action, DESKTOP untouched.

### NEXT (owner-gated)
Exactly ONE production `mode=report` invocation of `ensure_canonical_identity_indexes`, as a separate
authorization. Apply, backfill, branch retirement, production explain, KUSHU family composition and
the first real Behavior run all remain frozen behind it.

## THREAT-INTELLIGENCE ARCHITECTURE DECISION — 2026-06 — RECORD ONLY (NOT IMPLEMENTED)

Owner decision, recorded so no future step "fixes" G-37 by coupling the product harder to a single
external feed. Industry-reference classification: **INDUSTRY-ALIGNED** (mature EDRs combine native/
platform intelligence, endpoint telemetry, customer indicators and third-party intelligence instead
of making endpoint verdicts depend on one external IOC provider).

### G-37 decision (deferred, DO NOT ACT)
Do NOT troubleshoot, refresh, replace, request, expose or modify the ThreatFox/abuse.ch credential
in this stage. Do NOT redeploy for ThreatFox. Do NOT introduce a dependency from NivXForge EDR to a
separate NivX Machines threat-intelligence service. The current ThreatFox 401 (recurring, predating
the Publish 100 rollout, `threatfox:0` every TI sync cycle) and the misleading "7/7 live" wording are
recorded as DEFERRED TI-HARDENING FINDINGS.
Also recorded: **provider registration/configuration is NOT provider health**, so "7/7 live" is
semantically incorrect while ThreatFox pulls return 401. Not fixed here; carried into TI hardening.

### Target architecture (future, NOT to be implemented now)
Threat Intelligence is a NATIVE NivXForge EDR subsystem; external providers are PLUGGABLE enrichment
sources, never product authorities and never mandatory runtime dependencies.
  TI sources (NivX-native · external connectors · customer/private indicators)
    -> source adapters -> normalization -> deduplication -> provenance
    -> confidence / freshness / lifecycle
    -> correlation with CANONICAL ENDPOINT EVIDENCE
    -> detection · investigation · hunting · assessment
ThreatFox, VirusTotal, URLhaus, MalwareBazaar and any other provider must remain REPLACEABLE.
Customer/private indicators must be supportable with no external provider present.
Provenance must always answer: which source supplied it · when observed · when retrieved ·
confidence / source assessment · expiration or freshness · which canonical evidence it enriched.

### Critical invariants (binding on all future work)
1. **TI_MATCH != MALICIOUS_VERDICT.** A TI match is SUPPORTING EVIDENCE. Final assessment stays
   evidence-driven and may require behavior, causality, endpoint context, contradictory evidence and
   analyst/investigation state. Assessment space stays TP / FP / SUSPICIOUS / UNKNOWN.
2. **Provider failure must never silently become "clean", "benign" or "no threat."** It must surface
   as an explicit state: UNAVAILABLE · STALE · RATE_LIMITED · AUTH_FAILED (or equivalent).
3. Provider registration is not provider health; status surfaces must distinguish them.
4. The differentiator is the CORRELATION layer — TI + behavior + process ancestry + identity +
   network + prevalence + temporal/causal evidence, explaining WHY the intelligence matters to THIS
   endpoint — not a local re-implementation of VirusTotal/ThreatFox.

Nothing in the TI plane was touched by this record: no secret, no provider, no TI synchronization, no
canonical evidence, no Behavior, no frontier/shadow, no KUSHU, DESKTOP prohibited, no
sensor/Windows/Mac action, no `mode=apply`, no index, no backfill.

### 34H-B CLOSEOUT
STEP34H_B_STATUS = PASS accepted. G-35 CLOSED. No further 34H-B implementation.

### PREPARED, AWAITING SEPARATE AUTHORIZATION — one production report-mode call
  POST https://nivxray.nivxforge.com/api/internal/admin/migrations/ensure-canonical-identity-indexes
  Headers: Authorization: Bearer <production admin token — NEVER pasted into chat or this repo>
           Content-Type: application/json
  Body:    {"mode":"report"}
Report mode only LISTS indexes and returns per-index WOULD_CREATE / ALREADY_PRESENT_VERIFIED /
NAME_CONFLICT_REFUSED plus `indexes_before` / `indexes_after` / `existing_indexes_changed`. It writes
no index and no evidence; the only write is the migration AUDIT record in `e3_migration_runs`.
EXECUTION PATH: this plane holds no production admin credential, and I will not accept one through
chat. The secure path is OWNER-EXECUTED (your authenticated production admin session or your own
shell), with the JSON pasted back for review -> `SECURE_ADMIN_EXECUTION_PATH_NOT_AVAILABLE_FROM_THIS_PLANE`.
NOT EXECUTED pending the owner's separate authorization.

## STEP 34H-C — ONE PRODUCTION REPORT-MODE EXECUTION — 2026-06 — AUTH PATH BLOCKED / OBSERVATION DISPATCHED

Authorized: exactly one `{"mode":"report"}` call to
`POST /api/internal/admin/migrations/ensure-canonical-identity-indexes` in production, as an
inspection gate before mutation.

ROUTE EXECUTION = NOT PERFORMED. `SECURE_ADMIN_EXECUTION_PATH_NOT_AVAILABLE` from this plane: the
route requires a bearer JWT for a production user with `role == "admin"`, and this plane holds no
production admin credential. Per the owner's constraints I did NOT request a token, cookie, key or
connection string in chat, and I did NOT create a bypass, debug route, auth exception, service
credential, alternate admin endpoint or any weaker authorization path to run it. Nothing about
authentication was changed.

Minimum safe OWNER-EXECUTED method (run from your authenticated production admin session/shell; the
token never enters chat or the repo):
  curl -sS -X POST \
    https://nivxray.nivxforge.com/api/internal/admin/migrations/ensure-canonical-identity-indexes \
    -H "Authorization: Bearer $NVX_ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d '{"mode":"report"}'
(`mode=report` lists indexes only; its single production write is the audit record in
`e3_migration_runs`, which the owner permitted.)

IN PARALLEL, to satisfy the gate's PURPOSE with strictly LESS privilege and ZERO writes, a read-only
production index-metadata observation was dispatched to the Emergent deployer (job
`95e7e8cd-6528-4f50-8702-566d0dc3b0ce`): the complete current index list for
`xdr_canonical_evidence`, and for each of the two target names one of ABSENT /
PRESENT_WITH_EXPECTED_KEY / PRESENT_WITH_DIFFERENT_KEY (quoting the actual key), plus whether any
other index already carries one of the expected key patterns under a different name. Its tool is
limited to find/count/distinct/list_collections/list_indexes, so it cannot create, alter or drop
anything. This is direct observation of production, NOT inference from preview, code or config.

Untouched: no index created/modified/dropped, no backfill, no canonical-evidence mutation, no
Behavior, no frontier/shadow, no TI/ThreatFox work, no deploy/redeploy, no endpoint or sensor action,
no KUSHU access, DESKTOP prohibited, no Windows/Mac action, no `mode=apply`.

### NEXT
Read the production index list, then: all ABSENT -> the owner may consider authorizing
`mode=apply`; any PRESENT_WITH_DIFFERENT_KEY -> **HOLD** (a name conflict is a stop condition and is
never auto-repaired).

### 34H-C RESULT (2026-06) — PRODUCTION INDEX STATE OBSERVED DIRECTLY — NO CONFLICT

Read-only observation returned (production DB `greeting-app-5782-test_database`, collection
`xdr_canonical_evidence`, `list_indexes` only, zero writes):
- COMPLETE current index list = exactly TWO:
    `_id_`                        {_id: 1}
    `tenant_id_1_ingest_time_-1`  {ingest_time: -1, tenant_id: 1}
- `sd_canonical_endpointid_eventtime` = **ABSENT**
- `sd_canonical_hostname_eventtime`   = **ABSENT**
- No OTHER index carries either expected key pattern under a different name.
- => no NAME_CONFLICT condition exists; the equivalent report-mode outcome for both targets is
  WOULD_CREATE. `indexes_before` == `indexes_after` == [`_id_`, `tenant_id_1_ingest_time_-1`];
  `existing_indexes_changed` = false.
- Confirmed: no index created/modified/dropped, no document read beyond index metadata, no document
  modified, no collection created, no production write of any kind, no credential printed.
- This also re-confirms the 34C-B measurement independently: production still has NO index on
  `event_time` and none on any §d identity field (G-20 cause unchanged).

The ROUTE-BASED report-mode call itself remains UNEXECUTED
(`SECURE_ADMIN_EXECUTION_PATH_NOT_AVAILABLE` from this plane; authentication was not weakened). The
inspection gate's PURPOSE is nevertheless satisfied by direct production observation, with strictly
less privilege and no audit-record write.

### NEXT (owner-gated, mutation)
A separate authorization for `{"mode":"apply"}` — owner-executed against production, or via the
deployed control plane with the owner's admin session. After it: verify both indexes
CREATED_VERIFIED with exact key patterns, then the bounded 1,236-row backfill, verification, legacy
branch retirement, production explain, KUSHU family composition, first real Behavior run.

## STEP 34H-D — APPLY THE TWO APPROVED CANONICAL INDEXES — 2026-06 — BLOCKED (PRODUCTION WRITE ACCESS)

Authorized: create exactly `sd_canonical_endpointid_eventtime` and `sd_canonical_hostname_eventtime`
via the deployed control plane in `mode=apply`, then verify independently from production index
metadata; HOLD on any conflict or mismatch.

NOT EXECUTED. Same boundary as 34H-C, now on the write side (G-34/G-36): the control plane requires a
bearer JWT for a production `role == "admin"` user and this plane holds no production admin
credential; the platform's diagnose mechanism is read-only (find/count/distinct/list_collections/
list_indexes) and cannot create an index. Per the standing constraints I did not request a token or
connection string, and created no bypass, debug route, auth exception, service credential, alternate
endpoint or weaker authorization. `SECURE_ADMIN_EXECUTION_PATH_NOT_AVAILABLE` from this plane.

OWNER-EXECUTED APPLY (one call; token stays in your shell/session):
  curl -sS -X POST \
    https://nivxray.nivxforge.com/api/internal/admin/migrations/ensure-canonical-identity-indexes \
    -H "Authorization: Bearer $NVX_ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d '{"mode":"apply"}'
EXPECTED (pre-computed from the 34H-C observation, so any deviation is a HOLD):
  state = COMPLETED · mode = apply · collection = xdr_canonical_evidence
  indexes[0] = sd_canonical_endpointid_eventtime · CREATED_VERIFIED ·
    [[tenant_id,1],[additional_fields.endpoint_id,1],[event_time,-1]]
  indexes[1] = sd_canonical_hostname_eventtime · CREATED_VERIFIED ·
    [[tenant_id,1],[host.hostname,1],[event_time,-1]]
  existing_indexes_changed = false · refusals = [] · ok = true
  indexes_after = [_id_, tenant_id_1_ingest_time_-1, sd_canonical_endpointid_eventtime,
                   sd_canonical_hostname_eventtime]
HOLD CONDITIONS (no auto-repair, by contract): any NAME_CONFLICT_REFUSED ·
CREATED_BUT_UNVERIFIED · a key pattern differing in field, order or direction ·
existing_indexes_changed = true · refusals non-empty · HTTP 409 (lock held) · HTTP 500 (FAILED
record) · `tenant_id_1_ingest_time_-1` or `_id_` missing or altered afterwards.

INDEPENDENT VERIFICATION, ready to run after the apply: a read-only production `list_indexes`
observation through the platform diagnose mechanism (zero writes, no credential movement) to confirm
both names exist with the exact approved key patterns and that the two pre-existing indexes are
untouched — i.e. verification does NOT come from the same call that made the change.

Untouched this step: no index created/modified/renamed/dropped, no backfill, no legacy-index removal,
no §d branch retirement, no canonical-evidence mutation, no Behavior, no frontier/shadow, no TI work,
no deploy/redeploy, no KUSHU access, DESKTOP untouched, no Windows/Mac/sensor action.

## PRODUCTION-ADMIN AUTHENTICATION PATH — 2026-06 — READ-ONLY INVESTIGATION (NOTHING CHANGED)

No token minted, no user created or reset, no credential read or exposed, no code/config/database
change, no weakening of authentication.

### The one legitimate flow (as implemented)
1. `POST /api/auth/login` (`routers/auth.py:32`) with `{email, password}` -> `{access_token, email}`.
   Passwords are verified against `users.password` (hashed); the endpoint is rate-limited per
   `(email, client_ip)` with HTTP 429 + `Retry-After` on lockout, and a failed attempt returns 401.
2. The token is a JWT signed with `JWT_SECRET`, `sub = email`, expiry `JWT_EXPIRE_HOURS`
   (default 24) — `deps.py:283`.
3. `deps.get_current_user` decodes it, loads the user, and returns 428 `password_change_required`
   if `must_change_password` is set (that gate must be cleared via `/api/auth/change-password`
   before any other authenticated route works).
4. `deps.require_admin` then demands `user.role == "admin"` -> 403 otherwise. The migration routes
   use exactly this.
5. The admin account itself is seeded idempotently from the platform secrets `ADMIN_EMAIL` /
   `ADMIN_PASSWORD` (`deps.seed_admin`), and an EXISTING admin's password is never re-set by the
   seed (SEC-001). So the production admin credential is the owner's, held in the Deployment Panel
   secrets — not something this plane can or should read.
6. Frontend: `POST /api/auth/login` via `apps/nivxray-xdr/src/lib/auth.jsx`, token stored in
   `localStorage["nvx_token"]` (email in `nvx_email`), attached as
   `Authorization: Bearer <token>` by `src/lib/api.js`. Login pages: `/login` and `/edr/login`.

### Safest owner-executed method for the already-approved migration call
Use the EXISTING browser session, so the token never leaves the browser and never appears in chat,
a file or shell history:
  1. sign in at `https://nivxray.nivxforge.com/login` with the production ADMIN account;
  2. confirm the principal: DevTools Console ->
     `await (await fetch('/api/auth/me',{headers:{Authorization:'Bearer '+localStorage.getItem('nvx_token')}})).json()`
     and check `role === "admin"`;
  3. run the approved call from the same console:
     `await (await fetch('/api/internal/admin/migrations/ensure-canonical-identity-indexes',{method:'POST',headers:{Authorization:'Bearer '+localStorage.getItem('nvx_token'),'Content-Type':'application/json'},body:JSON.stringify({mode:'report'})})).json()`
     (swap `report` for `apply` only when the owner authorizes the mutation);
  4. paste ONLY the returned JSON back — never the token.
Alternative if the console is not desired: the same request from the owner's own shell with the token
in an environment variable they set themselves. Rejected alternatives (not implemented, not
recommended): minting a token, adding a debug/bypass route, a service credential, relaxing
`require_admin`, or reading `ADMIN_PASSWORD` from anywhere.

### If the production admin login is unknown
It is the `ADMIN_EMAIL`/`ADMIN_PASSWORD` pair in the production Deployment Panel secrets; the owner
can read/rotate it there. Rotation is a platform action, not a code change, and the seed will not
overwrite an existing admin.
