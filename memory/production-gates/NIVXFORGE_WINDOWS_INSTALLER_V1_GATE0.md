# NIVXFORGE WINDOWS SENSOR — INSTALLER V1 · GATE 0 INVENTORY + GAP ASSESSMENT

Mode: **READ-ONLY**. No code written, no build attempted-and-faked, no production write,
no token minted. Reporting existing state and a hard blocker before any implementation.

RESULT: **INSTALLER V1: PARTIAL — a working reusable installer EXISTS, but a genuine
`NivXForgeEDRSetup.exe` cannot be produced inside this Linux pod. STOP for owner decision.**

## 1 · What already exists (inventory)

| # | Concern | Location | State |
|---|---|---|---|
| 1 | Windows sensor source | `agents/nivxforge-windows/nivxforge_sensor.py` (537 L, `SENSOR_VERSION=0.2.0-windows`) | **WORKS** — `enrol` / `run` / `status` subcommands |
| 2 | Enrollment | sensor `enrol()` → `POST /api/edr/agent/enroll` (P0-PROD-2 authority) | **REUSES existing authority** — platform mints `endpoint_id` from durable machine facts; single-use token |
| 3 | Endpoint credential storage | `identity.json` in `%ProgramData%\NivXForge\sensor`, `chmod 600`, installer applies SYSTEM+Administrators ACL | ACL-hardened; **no DPAPI/TPM** |
| 4 | Heartbeat | `_heartbeat()` → `POST /api/edr/agent/heartbeat` | **WORKS** — liveness, never counted as telemetry |
| 5 | Policy fetch/ACK | `_sync_policy()` → fetch + acknowledge exact config digest | **WORKS** |
| 6 | Telemetry journal/outbox | `outbox.jsonl` + `outbox.offset`, fsync-before-send, offset advances only after accept | **WORKS** — replays on outage, never loses evidence. Cap/rotation still deferred (unbounded) |
| 7 | Sysmon acquisition | `wevtutil qe Microsoft-Windows-Sysmon/Operational` | **WORKS** — no third-party package needed |
| 8 | Security Event Log | `wevtutil qe Security` / `System` | **WORKS**; missing channel reported, never faked |
| 9 | Startup mechanism | `Install-NivXForgeSensor.ps1` registers `schtasks … /SC ONSTART /RU SYSTEM` | **SCHEDULED TASK, not a real Windows Service** |
| 10 | Uninstall / re-enroll / upgrade | PS1 `-Uninstall` / `-Purge` / `-ReEnroll` | **PRESENT** and documented |
| 11 | Packaging / build scripts | none for `.exe`/`.msi`; PS1 + raw `.py` only | **NO EXE/MSI EXISTS** |
| 12 | Architecture support | onboarding package `windows-x64` released (PREVIEW); `arm64`/`x86` = `NOT_BUILT` | x64 only |
| 13 | Backend download/enroll APIs | `routers/edr_onboarding.py` (`GET /api/edr/onboarding/packages`, `.../file/{name}`), `routers/edr_enrollment.py`, `routers/edr_connector.py` | **WORKS** — serves the reusable artifact; scans it for embedded secret shapes before offering |
| 14 | EDR Computers / Add Computer UI | onboarding computers grid + connector download in the EDR console | present (console); download offers the PS1 + py |
| 15 | Production API origin | consoles/build guard bake `https://nivxray.nivxforge.com`; sensor takes `--api` at runtime | correct |

Backend advertises the package honestly today:
`release_status: PREVIEW`, `signing_status: UNSIGNED`,
`requires: ["Python 3.11+ on the endpoint", "elevated PowerShell for installation"]`.

## 2 · Gap vs the owner's V1 target (`NivXForgeEDRSetup.exe`)

| V1 requirement | Today | Gap |
|---|---|---|
| Single `NivXForgeEDRSetup.exe` | PS1 + `.py` files | **must bundle runtime into an EXE** |
| No Python prerequisite on target | needs Python 3.11+ | **must embed a Python runtime** |
| Real Windows Service | ONSTART scheduled task | **must install a true service** |
| Signed | UNSIGNED | no code-signing certificate present |

## 3 · The hard blocker (why I stopped instead of building the EXE)

**A genuine Windows x64 `.exe` cannot be built in this environment.**
- This pod is **Linux**. Producing a Windows executable that embeds a Python runtime
  (PyInstaller / py2exe / Nuitka) requires the build to run **on Windows** — none of these
  cross-compile from Linux to a Windows PE.
- Verified: `pyinstaller` is **not installed**, `wine` is **not present**, and there is no
  Windows build toolchain in the pod.
- There is **no Windows code-signing certificate** available.

Fabricating a file named `NivXForgeEDRSetup.exe` on Linux would be a fake, not an installer.
Per Gate 0 ("if a production-usable installer already exists, prove it and STOP") and the
service instruction ("if converting materially expands this gate, STOP and show the smallest
safe alternative"), the correct action is to stop here and let you choose the path.

## 4 · Smallest safe alternatives

**Option A — validate the first machine TODAY with the existing reusable installer.**
Zero new build infrastructure. On your one controlled validation PC:
1. install Python 3.11+ (one-time, only on that box),
2. run `Install-NivXForgeSensor.ps1` elevated with `-BackendUrl https://nivxray.nivxforge.com
   -TenantId ten_e759b7288598bd882e3dcac49d -EnrollmentToken <owner-supplied>`.
This reuses P0-PROD-2 enrollment, ACL-protects the credential, and streams Sysmon/Security
into the Phase 0 bridge — it proves the whole production pipeline now. Accepted V1 limitations
for this path: **scheduled task, not a service; Python prerequisite; unsigned.** Perfectly
adequate for an owner-controlled internal-validation endpoint, and it does **not** need the
production token minted during development (you supply it at install time).

**Option B — build the real `NivXForgeEDRSetup.exe` (the commercial V1).**
Requires infrastructure this pod does not have:
- a **Windows build runner** (e.g. GitHub Actions `windows-latest`) running **PyInstaller**
  to bundle sensor + Python runtime into one EXE;
- a **real Windows Service** wrapper (pywin32 `win32serviceutil`, or `sc.exe`/NSSM around the
  bundled EXE) replacing the ONSTART task;
- optionally a **code-signing certificate** (otherwise ships as
  `UNSIGNED_INTERNAL_VALIDATION_BUILD`).
I can author all the build/service/packaging **source and CI workflow** here, but the actual
EXE must be produced by that Windows job — I cannot emit the binary from Linux.

## 5 · Counters (nothing was mutated)

```
CODE CHANGED: 0        BUILD ATTEMPTED: 0 (blocker identified first)
PRODUCTION WRITES: 0   TOKENS MINTED: 0   ENDPOINTS ENROLLED: 0
PRODUCTION TELEMETRY: 0  DB CHANGES: 0    SECRETS CHANGED: 0
DEPLOYMENTS: 0         RESPONSE AUTHORITY: FAIL-CLOSED (unchanged)
```

**Decision needed:** Option A (validate now with the existing installer) or Option B (author
the Windows-CI EXE build first, accepting it needs a Windows runner + signing cert).

---

# TRACK B · AUTHORED (owner decision: BOTH tracks)

Source, packaging, service host and Windows CI are written and contract-tested. **No EXE
exists yet** — it can only be produced by the `windows-latest` runner.

| Artefact | Path | Purpose |
|---|---|---|
| Installer + Service host | `agents/nivxforge-windows/nivxforge_setup.py` | `install` / `uninstall` / `status` / `version` / `--service-run`; imports the EXISTING sensor, adds a real Windows Service, production-origin + tenant guards |
| Build definition | `agents/nivxforge-windows/build/build_windows_installer.ps1` | PyInstaller `--onefile`, PE-header check, credential scan, `SHA256SUMS.txt`, `build-info.json`; **refuses to run off Windows** |
| Windows CI | `.github/workflows/windows-sensor-installer.yml` | `runs-on: windows-latest`, `permissions: contents: read`, **zero secrets**, uploads EXE + manifest |
| Focused tests | `backend/tests/edr/test_windows_installer_v1.py` | 33 tests, all passing |
| Console truth | `backend/routers/edr_onboarding.py` | new `windows-x64-exe` package, artifact-gated |

**Service model** — `sc.exe create … start= auto obj= LocalSystem`,
`sc failure … reset= 86400 actions= restart/60000 ×3`, `sc description`, then `sc start`.
Hosted by `win32serviceutil.ServiceFramework`; `SvcDoRun` calls
`sensor.run(api, interval, once=True)` in a loop gated on the SCM stop event, so a stop is
honoured promptly. **No scheduled task** (test-enforced), and **no second sensor**: the test
suite fails if `wevtutil`, `collect()`, `_drain()`, `_heartbeat()` or the enrol URL are
reimplemented in the installer.

**Guards proven by test** — refuses `http://`, `localhost`, `127.0.0.1`, `::1`,
`preview.emergentagent.com`, `.local`, ports 8001/3000, and tenants
`""`/`default`/`test`/`test_database`/`unknown`/`none`; accepts only an explicit `ten_…`.
Requires elevation before any file is written. Credential dir locked with
`icacls /inheritance:r` to SYSTEM (`S-1-5-18`) + Administrators (`S-1-5-32-544`).
Uninstall keeps the identity/journal unless `--purge`.

**Honest limits.** The EXE has never been built or run — no PE exists, the service has never
been installed, started or uninstalled, and the frozen CLI has never executed. Those are
proven only by the CI job (which asserts the PE header, runs `version`, and asserts the
localhost guard refuses) and then by the first controlled install. Signing:
`UNSIGNED_INTERNAL_VALIDATION_BUILD` — **not** customer-production-ready.
