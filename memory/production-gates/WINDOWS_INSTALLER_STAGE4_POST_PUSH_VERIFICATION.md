# WINDOWS INSTALLER · STAGE-4 SCM FIX — POST-PUSH VERIFICATION (READ-ONLY)

Mode: **READ-ONLY**. No token minted, nothing installed, no deployment, no
production backend/DB/data write, no enrolment or credential change.
Evidence source: public GitHub REST API + `raw.githubusercontent.com`.

RESULT: **ALL FOUR ACCEPTANCE GATES GREEN (step-level, CI-attested)**
Caveat stated in §6: job LOG TEXT and the artifact BYTES are not readable
without repo-admin credentials, so the literal `sc qc` block and an
independently computed EXE SHA-256 are **NOT** in my hands. I will not
quote text I could not read.

## 1 · Commit actually built

```
WORKFLOW        NivXForge Windows Installer (V1)  (id 368031286)
RUN ID          36296416653   attempt 1   event push   branch feature/rc2-alignment
STATUS          completed / SUCCESS
STARTED         2026-09-27T05:10:18Z   FINISHED 05:11:30Z   (72 s)
RUNNER          windows-latest (GitHub Actions 1000000173)
HEAD SHA        3700d3f301e2002f9c687b6bac728c35420666bc
ARTIFACT        NivXForgeEDRSetup-windows-x64  (id 10924240416)
                17,932,393 bytes (zip)   expired: false   created 05:11:26Z
                bound to run 36296416653 / head_sha 3700d3f3 — the same green run
```

Artifact zip grew from 8,963,879 B (previous run 36284860051) to 17,932,393 B
— consistent with the one-file installer now carrying the onedir service host
as a payload.

## 2 · The 56a4d130 vs 3700d3f3 discrepancy — explained and proved

`56a4d130` is the local fix commit. `3700d3f3` is the platform's
"Save to Github" bookkeeping commit placed **on top of it**:

```
3700d3f3  "Auto-generated changes"   ← built by run 36296416653
   └─ diff: .emergent/emergent.yml only (created_at timestamp), 1 line
ccbdcc48  chat/summary commit
56a4d130  "Windows Stage 4: real SCM service entrypoint + onedir service host + CI lifecycle gate"
```

```
git merge-base --is-ancestor 56a4d130 3700d3f3   →  TRUE
git diff 56a4d130 3700d3f3 -- agents/nivxforge-windows .github/workflows backend/tests/edr
                                                  →  EMPTY (no drift)
```

Remote-vs-local SHA-256 of every file that defines the fix, fetched from
`raw.githubusercontent.com/.../3700d3f3/`:

```
MATCH fd00275231623c044980fb5c973f7434f270e0dc208d37ce6ea336459fc16c5f  agents/nivxforge-windows/nivxforge_setup.py
MATCH d316672fae5255bd05bc252546068349bea902591c2528ec91180b6fa5a3ed5b  agents/nivxforge-windows/build/build_windows_installer.ps1
MATCH a63030885e2c99505361d06347046dcd51d89dd0e69f06cd2e0d06d63c6cb682  .github/workflows/windows-sensor-installer.yml
MATCH 6e9b1fcd56edf78634cd8f4324d4aa564fe6c6627d277326ffa672f4c003b999  backend/tests/edr/test_windows_installer_scm_entrypoint.py
```

So the commit GitHub built contains the Stage-4 SCM runtime fix, byte for
byte, and nothing else in the installer scope changed between the two SHAs.

## 3 · Step-level gate results (run 36296416653)

```
 1 Set up job                                               success
 2 actions/checkout@v4                                      success
 3 actions/setup-python@v5                                   success
 4 Build installer                                           success
 5 Verify artifact contract                                  success   ← GATE 0
 6 Service host unpacks from the installer                   success   ← GATE 1
 7 SCM command line is recognised (not the installer CLI)    success   ← GATE 2
 8 Real Windows SCM lifecycle (artifact acceptance gate)     success   ← GATE 3
 9 Remove the CI service if the gate failed                  success   (if: always)
10 actions/upload-artifact@v4                                success   (if-no-files-found: error)
21 Complete job                                              success
```

## 4 · What each green step PROVES (every assertion throws on failure)

**GATE 0 · artifact contract** — genuine `MZ` PE; the frozen CLI answered
`version` with no separate Python; `ONEDIR_PAYLOAD` declared by the binary;
production-origin guard exited non-zero AND printed `refusing to install`
for `http://localhost:8001`; `build-info.json` + `SHA256SUMS.txt` printed.
The build script additionally scanned the whole PE for `nvx_`, `nvxenr_`,
`nvxses_`, `nvxcrd_`, `ten_<26hex>`, `EDR_AUTH_PEPPER`,
`preview.emergentagent.com` and deletes the EXE on any hit — no hit.

**GATE 1 · service host unpacks** — `NivXForgeEDRSetup.exe stage-host`
exited 0 and
`C:\Program Files\NivXForge\sensor\service\NivXForgeSensor.exe` existed
afterwards (step throws on either). The onedir payload therefore really is
inside the one-file installer and extracts.

**GATE 2 · exact SCM argv recognition** — the STAGED service image was run
with the literal SCM command line
`--service-run --backend https://nivxray.nivxforge.com --interval 30`.
The step fails if the output contains `invalid choice` or
`usage: NivXForgeEDRSetup`, and fails unless the output proves the control
dispatcher was reached (`StartServiceCtrlDispatcher` / error `1063`, the
expected refusal when a service image is run by hand). Green ⇒ the observed
laptop failure mode cannot occur in this artifact.

**GATE 3 · real Windows SCM lifecycle** — executed via the PRODUCTION code
path `nivxforge_setup._install_service(...)`, which itself raises unless:
`sc.exe create` rc=0 (binPath = quoted onedir `NivXForgeSensor.exe` +
`--service-run --backend … --interval 30`, `start= auto`, `obj= LocalSystem`,
DisplayName set), `sc.exe start` rc=0, and `sc.exe qc` output contains
**AUTO_START**. The step then polled `sc.exe query` until **RUNNING**
(throws after 90 s otherwise), printed `sc.exe qc`, issued `sc.exe stop`,
polled until **STOPPED** (throws otherwise), and `sc.exe delete`d the
service. So:

```
CREATE ✓ → START ✓ → RUNNING ✓ (polled) → STOP ✓ → STOPPED ✓ (polled) → DELETE ✓
```

The runner was deliberately **not** enrolled, so this also proves a failing
sensor cycle (`SystemExit: not enrolled`) is caught and retried instead of
stopping the service.

**Cleanup** — step 9 ran `if: always()` and succeeded: `sc.exe stop` +
`sc.exe delete NivXForgeSensor` on the ephemeral runner. Runner is destroyed
after the job regardless; nothing persists.

## 5 · No production surface touched

- Commit `56a4d130` touches only `agents/nivxforge-windows/**`,
  `.github/workflows/windows-sensor-installer.yml`, `backend/tests/edr/**`
  and `memory/**`. No backend route, model, migration or frontend source.
- The workflow declares `permissions: contents: read`, uses **no secret**,
  and performs no network call to the NivXForge backend (the CI service is
  unenrolled, so `sensor.run` exits before any request).
- No enrolment token minted or consumed; `tok_9cca5b436ad2400d` untouched;
  endpoint `ep_1989031c8c1d0085812f` identity and credential untouched; no
  DB read/write, no production data mutation, no response-authority change,
  no change to tenant isolation or authentication.

## 6 · What I could NOT verify (stated, not glossed)

```
GET /repos/jpreddy017/nivxray-xdr/actions/jobs/108555992477/logs   → 403 "Must have admin rights to Repository"
GET /repos/jpreddy017/nivxray-xdr/actions/artifacts/10924240416/zip → 401 "Requires authentication"
```

Consequences, precisely:

1. **EXE SHA-256: NOT INDEPENDENTLY OBTAINED.** It was computed inside the
   job and written to `SHA256SUMS.txt` + `build-info.json` (both printed in
   GATE 0 and uploaded), but I cannot read either. Get it by opening the
   run's "Verify artifact contract" log, or by downloading the artifact and
   reading `SHA256SUMS.txt`/`build-info.json` beside the EXE.
2. **`build-info.json` values: NOT READ.** Its schema at this commit is
   verified (identical build script hash): artifact, sha256, size_bytes,
   setup_version, sensor_version, architecture,
   `signing_status=UNSIGNED_INTERNAL_VALIDATION_BUILD`,
   `python_required_on_endpoint=false`, `startup=WINDOWS_SERVICE`,
   `service_name=NivXForgeSensor`, `service_host=ONEDIR_PAYLOAD`,
   `service_exe=service\NivXForgeSensor.exe`, `service_host_sha256`,
   `commit`, `built_at`, `built_on`.
3. **`sc qc` text: NOT QUOTED.** AUTO_START is proved by assertion (the
   production path throws without it); `LocalSystem` is proved only as far
   as `sc create obj= LocalSystem` returning rc=0 — the qc line was printed
   to the log I cannot read, and is not separately asserted.
4. **`service.log`: PRODUCTION NOT PROVEN.** GATE 3 prints it
   `if (Test-Path …)`, so a green step does not prove the file was created.
   Making its presence and its `RUNNING` line a hard assertion is a
   one-line change for the next build if you want that closed.

Two ways to close 1–4 without touching the laptop: paste the run log here,
or add a read-only GitHub PAT so I can pull logs and hash the artifact
myself.

## 7 · Position

GREEN on all four gates, on the commit proved to contain the fix.
Items in §6 are evidence-access gaps, not failures. Awaiting your PASS/HOLD.
No endpoint instructions issued.
