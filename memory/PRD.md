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
