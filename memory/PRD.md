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

## Backlog
- P0: push `56a4d130`, read the Actions run, report run ID / commit SHA /
  EXE SHA-256 / build-info / gate evidence. No laptop action until approved.
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
