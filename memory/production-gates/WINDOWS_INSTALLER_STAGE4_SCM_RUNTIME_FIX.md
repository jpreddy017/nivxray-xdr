# WINDOWS INSTALLER · STAGE-4 SCM RUNTIME DEFECT — SOURCE FIX

Owner instruction: fix source only. No production backend deployment, no DB
change, no production data mutation, no new enrolment token, no
re-enrolment, no credential replacement, no response-authority change, no
weakening of tenant isolation or authentication. None of those were touched.

Live evidence from the enrolled validation endpoint `ep_1989031c8c1d0085812f`:
enrolment resumed with no token consumption, `sc.exe create` succeeded,
`sc qc` proved WIN32_OWN_PROCESS / AUTO_START / LocalSystem with the
expected binPath, yet the service failed with Windows 1053 and the SCM
command line run by hand produced:

    NivXForgeEDRSetup: error: argument cmd: invalid choice:
    'https://nivxray.nivxforge.com' (choose from 'install','uninstall','status','version')

## ROOT CAUSE (two defects, both in the service runtime path)

1. **Argument processing order.** `main()` parsed the SCM command line with
   the INSTALLER's subcommand parser. `--backend` is not a top-level option
   there, so `parse_known_args` set it aside as unknown and then offered the
   NEXT token — the backend URL — to the subparsers as the positional
   command. argparse exited 2 before `StartServiceCtrlDispatcher()` was ever
   reached, so the process never connected to the SCM → 1053.
   `--service-run` existed; it was simply never reached.

2. **The service image was a PyInstaller ONE-FILE binary.** Its bootloader
   unpacks to a temp directory and re-executes itself as a CHILD process, so
   the process the SCM launched is not the process that would call
   `StartServiceCtrlDispatcher()`. That is a documented cause of 1053 and
   would have produced a third Stage-4 failure even after fix (1).

## FIX

`agents/nivxforge-windows/nivxforge_setup.py`

- `main()` detects `--service-run` in the RAW argv and dispatches to the
  service entrypoint **before any argparse work**. The installer parser can
  no longer see an SCM command line.
- Real SCM runtime: `servicemanager.Initialize()` →
  `PrepareToHostSingle()` → `StartServiceCtrlDispatcher()`, hosting a
  `win32serviceutil.ServiceFramework` subclass that reports
  START_PENDING → RUNNING, handles STOP **and SHUTDOWN**, signals its stop
  event, leaves the run loop and reports STOPPED cleanly.
- Backend/interval are parsed from the argv the SCM passed (no global
  `sys.argv` read at construction time); the production-origin guard still
  applies, and a refusal is recorded before the dispatcher starts.
- Event-log writes are best-effort — a missing message resource can no
  longer prevent a start.
- A failing cycle no longer kills the service: `sensor.run()` raises
  SystemExit when the host is not enrolled, so the loop catches
  `(Exception, SystemExit)`, logs and retries.
- `%ProgramData%\NivXForge\sensor\service.log` records
  entrypoint/START_PENDING/RUNNING/STOP/STOPPED and any refusal, so a
  future 1053 is never silent again.
- **Service host is now a onedir build** staged to
  `C:\Program Files\NivXForge\sensor\service\NivXForgeSensor.exe` and
  carried as a payload inside the one-file installer (download UX
  unchanged). `_install_service` refuses to register a service whose image
  does not exist.
- Collection is REUSED (`sensor.run(..., once=True)`); no second
  implementation. Enrolment/credential behaviour untouched: resume still
  skips enrolment, consumes no token and never rewrites `identity.json`.

`agents/nivxforge-windows/build/build_windows_installer.ps1`
- Two-stage freeze: onedir service host, then the one-file installer with
  `--add-data <host>;service`. `build-info.json` now records
  `service_host=ONEDIR_PAYLOAD`, `service_exe` and `service_host_sha256`.
  PE check, credential/preview-origin scan and SHA256SUMS.txt unchanged.

## ACCEPTANCE GATES (CI is the gate, not the laptop)

`.github/workflows/windows-sensor-installer.yml` on `windows-latest`:

1. Artifact contract (PE, frozen CLI answers, ONEDIR_PAYLOAD declared,
   production-origin guard refuses localhost).
2. `stage-host` proves the service host unpacks from the one-file installer.
3. The staged service image accepts the exact SCM command line: the run
   FAILS if `invalid choice` or the CLI usage text appears, and requires
   proof the dispatcher was reached (error 1063 when run by hand).
4. **Real SCM lifecycle**: `_install_service` (production code path) →
   `sc.exe start` → poll to **RUNNING** → `sc qc` → `sc.exe stop` → poll to
   **STOPPED** → `sc.exe delete`, with `service.log` printed. The runner is
   deliberately NOT enrolled, so this also proves a failing sensor cycle is
   retried instead of stopping the service. Cleanup runs `if: always()`.

A build that compiles and passes unit tests but fails any gate produces NO
accepted artifact.

## DETERMINISTIC TESTS

`backend/tests/edr/test_windows_installer_scm_entrypoint.py` (new, 22 tests)
derives the invocation from the command line `_install_service` ACTUALLY
writes (binPath parsed, image/arg split reproduced) and proves:
the installer parser rejects that argv (root cause), `main()` routes it to
the dispatcher, the parser is never even constructed for it, service args
come from the passed argv, non-production backends are refused and logged,
the binPath points at the onedir host and never at the one-file installer,
staging is idempotent and stops a running service first, a payload-less
build is refused, and the CI workflow contains the real lifecycle gate.

Local result: `tests/edr/test_windows_installer_*` 73 passed.
Full suite: 608 passed, 3 skipped, 1 unrelated flake
(`test_sensor_runtime_state_is_never_committed` — a git-invoking test that
passes in isolation; no production code involved).

## STATUS

Source fix committed locally. Push requires the owner's "Save to Github"
click; after that the workflow run ID, commit SHA, EXE SHA-256, build-info
and gate evidence are reported. No laptop action requested until then.
