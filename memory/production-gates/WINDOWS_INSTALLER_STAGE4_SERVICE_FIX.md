# WINDOWS INSTALLER V1 · STAGE 4 SERVICE-CREATION DEFECT — FIXED

Live-host result: **P0-PROD-2 enrolment succeeded on a real Windows machine.**
Endpoint `ep_1989031c8c1d0085812f`, tenant `ten_e759b7288598bd882e3dcac49d`,
credential present, sensor `0.2.0-windows`. Stage 4 then failed and registered no service.

No production mutation in this gate: no token minted, no endpoint touched, no DB change,
no deployment, response authority untouched.

## ROOT CAUSE

`sc.exe` uses `key= value` syntax where **the space after `=` is an argument separator, not
part of the value**: `start=` and `auto` must arrive as two distinct argv tokens.

`_sc()` invoked `subprocess.run(["sc.exe", ...])` with elements like `"start= auto"`. Any list
element containing a space is **quoted** by Windows argument building
(`subprocess.list2cmdline`), so `sc.exe` received one quoted token `"start= auto"`, could not
split key from value, and answered exactly:

```
ERROR: Invalid start= field
```

Reproduced deterministically in the test suite:

```
list2cmdline(["sc.exe","create","NivXForgeSensor","start= auto"])
  → sc.exe create NivXForgeSensor "start= auto"        ← the defect
```

The same latent bug applied to `binPath=`, `obj=`, `DisplayName=`, `reset=` and `actions=`,
so the failure was not specific to `start=`; it was the first field sc happened to reject.

Because `create` failed, `sc start` never ran and `Get-Service NivXForgeSensor` correctly
returned nothing. Enrolment had already completed, which is why the endpoint exists and the
token was consumed.

## THE FIX

`agents/nivxforge-windows/nivxforge_setup.py`

1. `_sc()` now takes a **raw command line string**. On Windows a string is handed to
   `CreateProcess` verbatim, which is the only way to control tokenisation exactly — including
   quoting a `binPath` value that itself contains spaces *and* its own arguments.
2. Added `_service_exists()` (`sc query`) and `_service_config()` (`sc qc`).
3. `_install_service()` now: replaces an existing service instead of blindly stopping/deleting;
   creates with the corrected syntax; sets description and the approved recovery policy;
   starts; then **verifies with `sc qc` that the SCM really recorded `AUTO_START`** and fails
   if not. A create failure is surfaced verbatim, never swallowed.

Exact command lines now issued (verified by executing the code path with a stubbed runner):

```
sc.exe query "NivXForgeSensor"
sc.exe stop "NivXForgeSensor"                      (only if it already exists)
sc.exe delete "NivXForgeSensor"                    (only if it already exists)
sc.exe create "NivXForgeSensor" binPath= "\"C:\Program Files\NivXForge\sensor\NivXForgeSensor.exe\" --service-run --backend https://nivxray.nivxforge.com --interval 30" start= auto obj= LocalSystem DisplayName= "NivXForge EDR Sensor"
sc.exe description "NivXForgeSensor" "Collects authorised Windows security telemetry ..."
sc.exe failure "NivXForgeSensor" reset= 86400 actions= restart/60000/restart/60000/restart/60000
sc.exe start "NivXForgeSensor"
sc.exe qc "NivXForgeSensor"                        ← AUTO_START asserted
```

Intended design confirmed unchanged: name `NivXForgeSensor`, startup **automatic**, account
**LocalSystem**, recovery **restart after 60 s ×3, counter resets daily**.

## RESUME SAFETY (the real lesson from the live host)

4. New `_validate_identity()` — fail-closed. A resume only skips enrolment when the local
   identity is genuinely complete (`tenant_id`, `endpoint_id`, `credential_id`,
   `agent_credential`). A truncated or corrupt `identity.json` is **refused** with an
   instruction to use `--re-enrol`, rather than being treated as "enrolled" — which would
   leave a computer looking installed while permanently unable to deliver evidence.
5. `install()` resume path: when a valid identity exists and `--re-enrol` is absent, the
   installer prints `RESUME: already enrolled`, **sends no enrolment request**, requires
   **no `--tenant` and no `--token`**, keeps the existing credential byte-for-byte, and
   proceeds straight to Stage 4.
6. `install()` now **stops a running service before replacing the binary** (a running service
   holds the EXE open, which would fail the copy).
7. `--re-enrol` still demands an explicit tenant and token — recovery convenience must not
   become a way to silently re-issue identity.

## TESTS

New: `backend/tests/edr/test_windows_installer_service_stage4.py` — **16 tests**

- reproduces `Invalid start= field` via real `list2cmdline` quoting
- raw command line keeps `start=` / `auto` as separate tokens
- full approved sc contract (auto start, LocalSystem, `--service-run`, quoted image path,
  recovery policy, `sc start`, `sc qc`)
- create failure surfaced; **created-but-not-AUTO_START rejected**
- existing service replaced, exactly one `create`
- **resume completes Stage 4 with no `--tenant`/`--token` and sends no second enrolment**
- resume preserves the credential byte-for-byte; never prints credential or credential_id
- running service stopped before the binary is replaced
- fail-closed on incomplete identity (3 variants) and corrupt JSON
- `--re-enrol` still demands tenant + token

```
test_windows_installer_service_stage4.py   16 passed
test_windows_installer_v1.py               35 passed
regression (P0-A.2 enrolment, P0-PROD-2 hardening, Phase 0 bridge,
            Gate 7 enforcement, P0-C findings)            181 passed total
```

Two pre-existing V1 assertions were updated because **my own refactor changed the strings they
matched** (`'"stop", SERVICE_NAME'` → `sc.exe stop`, and a `print(...token...)` regex that now
correctly forbids the token **value** while allowing the word in
`"no token required or consumed"`). Intent preserved, not relaxed: the credential/token value
still may not be printed or persisted.

## NEW ARTIFACT REQUIRED?

**YES.** The fix is in `nivxforge_setup.py`, which is frozen into the EXE, so the current
artifact (SHA-256 `41240f69…25b68`, commit `9f5ab8f5`) cannot install the service. A new
`windows-latest` build is required. The Windows CI workflow triggers on
`agents/nivxforge-windows/**`, so pushing is sufficient.

## SAFEST RECOVERY FOR `ep_1989031c8c1d0085812f`

The endpoint, its identity and its credential are **already correct** — only the service is
missing. **No new token, no re-enrolment, no endpoint deletion.**

1. Owner: Save to GitHub → the Windows workflow rebuilds → download the **new**
   `NivXForgeEDRSetup-windows-x64` and verify its SHA-256 against `SHA256SUMS.txt`.
2. On the same PC, elevated — note there is **no `--token` and no `--tenant`**:
   ```
   .\NivXForgeEDRSetup.exe install --backend https://nivxray.nivxforge.com
   ```
   Expect `RESUME: already enrolled — endpoint_id=ep_1989031c8c1d0085812f`, then Stage 4
   creating and starting the service.
3. Confirm locally:
   ```
   Get-Service NivXForgeSensor
   sc.exe qc NivXForgeSensor          # START_TYPE must read AUTO_START
   .\NivXForgeEDRSetup.exe status
   ```
4. Then I verify server-side (read-only) that telemetry arrives and the endpoint reaches
   **INVESTIGABLE**, not `RAW_ONLY_NOT_INVESTIGABLE`.

Do **not** pass `--re-enrol`: that would demand a fresh token and mint a second identity.
