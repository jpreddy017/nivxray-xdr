# NivXForge · Windows enrolment secret is STDIN-ONLY

**Status:** implemented in the workspace; NEW WINDOWS ARTIFACT NOT YET BUILT.
**Owner directive:** `C0_5_STATUS = HOLD`,
`BLOCKER = ENROLLMENT_TOKEN_COMMAND_LINE_EXPOSURE`.
**Scope:** Windows installer + Windows sensor enrolment interface only.
No product semantics, no detection logic, no Sysmon or Defender change.
The frozen Gate-0 artifact for commit
`2cb841db10e4262bba89c115bfa8c3058f61fda4` is untouched.

---

## 1. The defect being removed

The installer accepted the one-time enrolment secret as an argv value:

```
NivXForgeEDRSetup.exe install --tenant <tenant> --token <secret>
```

Windows records process command lines in places **this product itself
collects**:

| Recorder | Consequence |
|---|---|
| Sysmon EID 1 `CommandLine` | the secret becomes acquired evidence, is written to the Local Evidence Journal, and is DELIVERED to the backend it authenticates against |
| Service `binPath` (SCM) | a secret would persist in the service configuration |
| PowerShell history / transcription | the secret survives the install on disk |
| argparse error text (`unrecognized arguments: --token <secret>`) | the secret is printed to stderr and into any captured log |

Single use shortens the secret's lifetime; it does not prevent the
recording. An EDR that publishes its own enrolment credential into its
own telemetry pipeline is not acceptable, so the interface was changed
rather than the operating procedure.

---

## 2. The new interface

```
<secret producer> | NivXForgeEDRSetup.exe install --tenant <tenant> --token-stdin
```

* `--token-stdin` is the ONLY accepted input for the enrolment secret.
* The plaintext `--token` flag is **REMOVED** from both
  `nivxforge_setup.py` (installer) and `nivxforge_sensor.py` (sensor
  `enrol`). There is no compatibility shim: leaving one would leave an
  unsafe production enrolment path, which the directive forbids.
* `--token`, `-token`, `--enrollment-token`, `--enrolment-token`, or ANY
  argv element that looks like an enrolment secret (`nvxenr_` prefix,
  bare or after `=`) causes an immediate refusal. The refusal never
  echoes the value.
* The refusal runs **before** argparse. `parse_known_args` would
  otherwise discard `--token <secret>` silently — the operator would
  believe the old interface still worked while the secret had already
  been recorded in this process's command line — and `parse_args` would
  print the value in its own error message.
* The secret is read from stdin, used once, and no reference is kept. It
  is never written to disk, never printed, and never placed on any
  command line the installer builds. The service `binPath` carries
  `--backend`, `--interval` and `--state-dir` only: a directory, never a
  credential.
* A FAILED enrolment is redacted. A backend validation error can echo the
  request body (a FastAPI 422 repeats the offending input), so the
  message replaces every occurrence of the secret with `[REDACTED]`, and
  the original exception is dropped (`raise ... from None`) so no chained
  traceback frame can carry the value either.
* After a successful enrolment the secret is not persisted:
  `identity.json` holds `tenant_id`, `endpoint_id`, `credential_id` and
  the endpoint-scoped `agent_credential` produced by the exchange, under
  the existing SYSTEM + Administrators ACL. That storage is unchanged.

### PowerShell (`Install-NivXForgeSensor.ps1`)

`-EnrollmentToken` is now a `SecureString`. The script starts the sensor
with `RedirectStandardInput`, writes the decrypted value to the child's
stdin, and frees the BSTR (`ZeroFreeBSTR`) immediately. The child's
command line contains `--token-stdin` only.

---

## 3. Files changed

| File | Change |
|---|---|
| `agents/nivxforge-windows/nivxforge_sensor.py` | `read_enrolment_secret()`, `refuse_secret_on_command_line()`, `redact()`, `SECRET_REDACTED`, `STDIN_ONLY_NOTICE`; `enrol()` asserts argv hygiene and redacts failures; `enrol --token` replaced by `--token-stdin` |
| `agents/nivxforge-windows/nivxforge_setup.py` | `install(..., token_stdin: bool, ...)`; `--token` removed from the parser; pre-parser refusal in `main()`; module contract documented |
| `agents/nivxforge-windows/Install-NivXForgeSensor.ps1` | `SecureString` parameter + `Invoke-Enrolment` stdin delivery |
| `backend/tests/edr/test_b5gap1_enrolment_secret_stdin.py` | NEW · the proofs in §4 |
| `backend/tests/edr/test_windows_installer_v1.py` | stdin-only CLI contract |
| `backend/tests/edr/test_windows_installer_scm_entrypoint.py` | install routing uses `--token-stdin` |
| `backend/tests/edr/test_windows_installer_service_stage4.py` | `install()` signature + refusal message |
| `docs/B5_GAP_1_CANARY_PLAN.md` | stage 5 and the C0.5 install block use the stdin invocation, plus the on-host EID 1 absence check |
| `.github/workflows/windows-sensor-installer.yml` | the artifact-contract step now probes the BINARY: the localhost origin probe no longer carries a token value, and a new probe requires the frozen binary to REFUSE `--token x` with `is REMOVED` |

---

## 4. What the tests prove (decidable on Linux)

1. the secret is absent from `argv` — asserted in-process AND on a LIVE
   child process through the kernel's own record, `/proc/<pid>/cmdline`,
   which is the Linux analogue of what Sysmon EID 1 reads;
2. the secret is absent from the service command line handed to `sc.exe`;
3. the secret is absent from stdout/stderr on success and on failure;
4. the secret is absent from every file in the state directory,
   including `identity.json`;
5. the secret is absent from the refusal messages and from argparse
   output (no value is ever echoed);
6. a rejected enrolment (422 echoing the request body) produces
   `[REDACTED]` and no `__cause__`/`__context__` chain;
7. enrolment still SUCCEEDS from stdin and creates the identity
   correctly;
8. the legacy plaintext flags are refused, and the Gate-0 evidence
   record is unchanged.

**Not claimed here:** that Sysmon EID 1 on a real Windows host records no
secret. A Linux pod cannot answer that.

---

## 5. Residual, declared

`agents/nivxforge-linux/nivxforge_sensor.py` still accepts `enrol --token
<secret>` and `scripts/nivxforge_sensor_supervise.py` passes it that way,
so the same exposure exists on Linux endpoints (`/proc/<pid>/cmdline`).
It is OUT OF SCOPE of this directive and is NOT fixed here. It is
recorded as an open item, not as a passing state.

---

## 6. Required on the canary, AFTER owner review of the new artifact

Run once, after the C0.5 install, on `KUSHU` only:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
} -MaxEvents 400 |
  Where-Object { $_.Message -match 'NivXForgeEDRSetup' } |
  ForEach-Object {
    $line = ([xml]$_.ToXml()).Event.EventData.Data |
              Where-Object { $_.Name -eq 'CommandLine' } |
              Select-Object -ExpandProperty '#text'
    [pscustomobject]@{
      TimeCreated       = $_.TimeCreated
      HasTokenStdinFlag = [bool]($line -match '--token-stdin')
      HasPlaintextFlag  = [bool]($line -match '--token(?!-stdin)')
      HasSecretShape    = [bool]($line -match 'nvxenr_')
    }
  } | Format-Table -AutoSize
```

PASS requires `HasTokenStdinFlag = True`, `HasPlaintextFlag = False`,
`HasSecretShape = False` for every installer process.

---

## 7. Still owed to the owner (cannot be produced from this workspace)

The agent workspace has no push rights and cannot dispatch GitHub
Actions, so these come from the owner's normal Windows workflow run:

* commit SHA,
* `windows-sensor-installer.yml` run ID,
* new `NivXForgeEDRSetup.exe` SHA256,
* signing status (the build is still
  `UNSIGNED_INTERNAL_VALIDATION_BUILD`; no signing was introduced by this
  change).

C0.5 remains **HOLD** until the new artifact is owner-reviewed and a new
artifact-hash gate has passed.
