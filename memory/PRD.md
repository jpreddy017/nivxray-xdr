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
