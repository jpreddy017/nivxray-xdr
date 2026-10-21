# P0 · Windows Sensor Installer Upgrade Repair — R1 → R5

Branch: `fix/p0-installer-upgrade` (linked worktree `/app/.worktrees/upg`)
Production base: `phase2/edr-production` @ `e534002bed6049a8d26688a9e9ff22e6cf28460b`

## Original defect
    Permission denied: C:\Program Files\NivXForge\sensor\service\_internal\win32\servicemanager.pyd

The pre-repair installer copied a new service payload file-by-file ON TOP of
the live image, so every upgrade had to win a write race against every DLL/PYD
Windows may still have MAPPED. The failure occurred AFTER the service was
stopped and BEFORE it could be started again, leaving a healthy endpoint dark.

## Architecture of the repair
- A new build is NEVER written into the live image: it is staged into its own
  content-addressed directory under `…\sensor\versions\`, validated file by
  file, and only then is the SCM re-pointed at it.
- The previous COMPLETE image is retained as the rollback source.
- `active.json` is written atomically and only after the LIVE process has been
  proved to be the staged executable.
- Identity, credentials, policy cache, protected state directory, journal,
  cursors and queued evidence live outside the versioned image and are never
  touched by an upgrade or a rollback.

## Release history
| Rev | Commit | What it fixed |
|---|---|---|
| R1 | `f6077d5b` | Versioned side-by-side images, staged validation, active metadata, rollback |
| R2 | `9f83e073` | SCM configuration captured/restored independently of run state; Windows Gate 5 (real mapped PYD) |
| R3 | `04873da3` | Post-activation rollback stops and proves stopped the image it activated, before restoring config |
| R4 | `9c5a09bb` | `binPath` via argument list (`_sc_argv`, no hand-escaping); activation and rollback refuse MISMATCH *and* UNVERIFIED live images |
| **R5** | **`a14c6693`** | **Pre-mutation snapshot safety (below)** |

## R5 · pre-mutation snapshot safety (2026-06)
Reproduced P0: the installer accepted an INCOMPLETE Windows service
configuration snapshot and could later report a rollback it had not performed.

Two halves:
1. `_service_exists()` was two-state. `ERROR_ACCESS_DENIED` (5),
   `RPC_S_SERVER_UNAVAILABLE` (1722) and `ERROR_SERVICE_MARKED_FOR_DELETE`
   (1072) answered False exactly as `ERROR_SERVICE_DOES_NOT_EXIST` (1060) did.
   An UNREADABLE service was therefore indistinguishable from an ABSENT one —
   and rollback treats an absent-before service as debris and DELETES it.
2. `_service_config()` discarded the `sc.exe qc` exit code, so a failed or
   truncated query became an EMPTY configuration. Every field was then filled
   from a default (`start= auto`, `obj= LocalSystem`, `binPath= ""`), and the
   drift check skipped any field the snapshot did not hold
   (`and snapshot.get(key)`), so a snapshot that captured NOTHING compared
   equal to EVERYTHING. With a previously STOPPED service this printed
   `ROLLBACK STATUS: COMPLETE` while the entry still pointed at the image the
   failed attempt had staged.

Repair, in `agents/nivxforge-windows/nivxforge_setup.py`:
- `WINDOWS`, `_ERROR_SERVICE_DOES_NOT_EXIST`, `_service_lookup()` →
  `ABSENT` / `PRESENT` / `UNREADABLE`.
- `_service_qc()` reads the exit code; `_service_config()` keeps its string
  contract for existing callers.
- `_capture_service_config()` returns a verdict in `snapshot`
  (`ABSENT` / `COMPLETE` / `FAILED`) plus `reason`, `detail`, `missing`, and
  validates `_REQUIRED_SNAPSHOT_FIELDS` (12), the restorable `sc config` form
  of every enum (`type_sc`, `start_type_sc`, `error_control_sc`), the parsed
  image path, the run state, and the identity `qc` itself reports (`qc_name`).
- `_require_service_snapshot()` is the PREFLIGHT: nothing is stopped, deleted,
  reconfigured, staged or activated until the snapshot is COMPLETE or the
  service is proved genuinely absent. Called first in `install()` under a new
  `=== 0 . PREFLIGHT ===` section.
- `_restore_service_config()` restores type, error control, start type
  (incl. `delayed-auto`), account, display name and the exact binPath with its
  arguments, and refuses to write a guessed default.
- `_verify_restored_config()` reads the SCM back and proves
  `_VERIFIED_SNAPSHOT_FIELDS` (6) identical to the snapshot. An unreadable or
  incomplete read-back is a ROLLBACK FAILURE, never a match. A `FAILED`
  snapshot can never be reported as restored.

## Verification (local, Linux simulation)
| Check | Result |
|---|---|
| `test_p0_installer_upgrade_repair.py` on R5 | **65 passed** (49 → 65) |
| Same file on R4 `9c5a09bb` | **16 failed, 49 passed** |
| `backend/tests/edr` full, R5 | 2074 passed; 6 failures + 24 errors identical to R4 (pre-existing, unrelated) |
| Journal selftest | `result: PASS`, `failed: []` |
| Workflow static check | 14 steps, 9 embedded python blocks, all compile, braces balanced, no indented here-string terminator after YAML dedent |

Reproducer kept at `/tmp/r5_repro.py` (not committed):
`python /tmp/r5_repro.py <repo-root> [STOPPED|RUNNING]`
- On R4 with `prior=STOPPED`: rollback returns True and the binPath still
  points at the NEW image.
- On R5: preflight REFUSES before any mutation.

## Artifacts
| Rev | Bundle | SHA-256 | Size |
|---|---|---|---|
| R4 | `NIVXFORGE_P0_INSTALLER_UPGRADE_R4.bundle` | `f2722816002b788b8fa8314fc28c7fc294ec78c63de1964e5f62703bc6a5d013` | 51,209 B |
| R5 | `NIVXFORGE_P0_INSTALLER_UPGRADE_R5.bundle` | `c2011ac9fc5ccc290faff7a0ac8a13ebdf72329fcb4249f29ca2a95f1a069dd5` | 62,075 B |

Thin bundles; prerequisite `e534002bed6049a8d26688a9e9ff22e6cf28460b`.
`https://greeting-app-5782.preview.emergentagent.com/<filename>`

## Verdict: HOLD — unverified on Windows
No Windows runner has executed Gates 5 or 6 for R3, R4 or R5. No R5 installer
artifact has been built, so there is no installer SHA-256 or build provenance.

### P0 backlog
1. Publish `fix/p0-installer-upgrade` @ `a14c6693` and run the Windows workflow
   on a real Windows runner.
2. Confirm Gates 5 and 6 pass: real SCM `BINARY_PATH_NAME` round trip,
   mapped-PYD tolerance, staged activation, post-activation rollback, live
   process image verification, and the new preflight section
   (PRESENT / ABSENT-1060 / UNREADABLE / partial qc).
3. Build the R5 installer artifact; record SHA-256 and provenance.
4. Independent review of CI results and artifact contents.
5. Owner approval before any publish, deploy, KUSHU operation, service stop,
   install, telemetry reset or enrolment action.

### P1
- Gate 5 injects Windows codes 5/1722/1072 for the UNREADABLE classifier
  because an Administrator runner cannot be denied its own service. A genuinely
  access-denied service would be stronger evidence.
- Consider removing `_restore_service_config()`'s legacy empty-snapshot
  fallback now that the preflight guarantees a verdict-carrying snapshot.

## Standing restrictions
No push, merge, deploy, KUSHU access, re-enrolment, telemetry reset, cursor
operation or evidence deletion. Linux simulation is never Windows-native proof.
Candidate B F1–F4 delivery behaviour and the `DELIVERY_QUARANTINE` health state
are preserved untouched (not in any R1–R5 diff).
