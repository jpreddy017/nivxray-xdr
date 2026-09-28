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
