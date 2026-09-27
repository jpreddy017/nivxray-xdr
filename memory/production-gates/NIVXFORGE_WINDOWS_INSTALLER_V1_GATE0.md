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

---

# CI RUN 1 · FAILURE ROOT CAUSE + MINIMUM FIX

Run `36283667278`, job `108520219204`, head `d88a9035` (remote HEAD `d88a903`).
Step-level result read from the public Actions API (job **logs** require auth → `403`,
so the cause was derived from the code path, not guessed):

```
Set up job                     success
actions/checkout@v4            success
actions/setup-python@v5        success
Build installer                success   ← PyInstaller produced the EXE; the build
                                           script's own PE-header check, credential
                                           scan and manifest writing all passed
Verify artifact contract       FAILURE   ← exit code 1
actions/upload-artifact@v4     skipped
```

## Remote source question (A/B/C/D) → **A + D**

All five installer files are present on `feature/rc2-alignment` at HEAD `d88a9035` and are
**SHA-256 identical to local**:

```
PRESENT+MATCH  .github/workflows/windows-sensor-installer.yml
PRESENT+MATCH  agents/nivxforge-windows/nivxforge_setup.py
PRESENT+MATCH  agents/nivxforge-windows/build/build_windows_installer.ps1
PRESENT+MATCH  backend/tests/edr/test_windows_installer_v1.py
PRESENT+MATCH  backend/routers/edr_onboarding.py
```

Save-to-GitHub did **not** fail. The "1 file changed / `.emergent/emergent.yml`" screenshot is
a later **metadata-only** commit (`d88a903`, parent `8471748`); the installer files arrived in
the parent commit on the same branch. Nothing needed rewriting.

## ROOT CAUSE — my CI step leaked an exit code it had itself requested

`Build installer` **passed**, so the binary, the PE header, the credential scan and the
manifest were all fine. The defect was entirely inside my `Verify artifact contract` step:

1. The step deliberately invokes the installer with a bad backend to prove the
   production-origin guard is live in the binary: `& $exe install --backend http://localhost:8001 …`.
   **That invocation must exit non-zero** — that is the passing condition.
2. The remaining statements were PowerShell **cmdlets** (`Get-Content`), which do **not**
   reset `$LASTEXITCODE`.
3. GitHub's `pwsh` shell appends `if ((Test-Path -LiteralPath variable:\LASTEXITCODE)) { exit $LASTEXITCODE }`
   to every step script. So the leaked `1` from the intentional refusal became the step's exit
   code — the step failed **even though every assertion had passed**.

Classification: **CI CONTRACT DEFECT**, not a build defect, not a security defect, not a
sensor defect.

A second, latent non-determinism was fixed at the same time: `install()` called
`_assert_admin()` **before** `_assert_backend()`, so on a non-elevated host the refusal text
would have been the elevation message and the assertion would have failed for the wrong
reason.

## FIX (minimum, no verification weakened)

1. `.github/workflows/windows-sensor-installer.yml` — capture the guard's exit code
   (`$guardExit = $LASTEXITCODE`), **fail the build if it is 0** (a guard that permits
   localhost is now a hard failure — this *strengthens* the check), then clear
   `$global:LASTEXITCODE = 0` and end with an explicit `exit 0`. Added
   `$ErrorActionPreference = 'Stop'` and an exit-code check on the `version` probe.
2. `agents/nivxforge-windows/nivxforge_setup.py` — `install()` now validates `--backend`
   (pure, side-effect-free) **before** `_assert_admin()`. Nothing is written before elevation
   is proven; `INSTALL_DIR.mkdir` still comes after the admin check (test-enforced).

**Every security assertion is retained**: genuine PE (`MZ`), credential/secret shapes,
no preview origin, no localhost, production-origin guard, explicit `ten_…` tenant,
P0-PROD-2 enrolment authority, no duplicated sensor. Nothing was bypassed.

## Verification here

- `test_windows_installer_v1.py` → **35 passed** (2 new tests lock the exit-code contract and
  the guard ordering; 2 earlier failures were my own test slices — a comment naming
  `_assert_admin()` and a slice running past `exit 0` — and were corrected, not silenced).
- Live code-path simulation: `install('http://localhost:8001', …)` →
  `refusing to install: --backend must be https (got http)`, raised **before** the elevation
  check and before any write.
- Regression: **93 passed** across enrolment hardening, P0-A.2 and the Phase 0 bridge.
- Legacy Vercel `nivxray-xdr` root-deployment refusal: **untouched, still failing by design.**
