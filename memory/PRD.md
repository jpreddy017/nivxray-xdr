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
