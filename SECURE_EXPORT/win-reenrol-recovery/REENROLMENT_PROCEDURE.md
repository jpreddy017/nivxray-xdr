# After the artifact exists — the exact re-enrolment procedure

**This procedure is not yet executable.** It becomes valid only when steps 0a-0c
below have produced an artifact whose SHA256 you have matched. Nothing here
should be run against DESKTOP-A9HGFJJ before that.

## 0 · Preconditions the owner must satisfy

* **0a** Push `publish/win-reenrol-recovery` (commit
  `c845ff0bffdd6a68fc2839dc1c9c2e938db768b2`, tree `fe8becc2…`) and let
  **NivXForge Windows Installer (V1)** run on `windows-latest`.
* **0b** Confirm the run is green, including Gate 0 (frozen journal selftest),
  the artifact contract (build provenance, self-reported SHA256, unknown-flag
  refusal), the real SCM lifecycle gate and **Gate 4 · re-enrol against a
  RUNNING service**.
* **0c** Download `NivXForgeEDRSetup.exe` plus `build-info.json`, and record
  `artifact_sha256`, `build_commit` and `build_run_id`.

## 1 · Verify the artifact before it touches the endpoint

On the laptop, as Administrator, **read-only**:

```powershell
Get-FileHash .\NivXForgeEDRSetup.exe -Algorithm SHA256     # must equal build-info.json
.\NivXForgeEDRSetup.exe version
```

`version` must report `build_commit` = the pushed commit, `build_run_id` = the
CI run, `artifact_sha256` = the hash you just computed, and **no**
`UNOFFICIAL_BUILD`. A mismatch stops the procedure.

## 2 · Capture the state you must be able to return to

```powershell
sc.exe query NivXForgeSensor                       # expect RUNNING
.\NivXForgeEDRSetup.exe status                     # endpoint_id, tenant_id
Get-Item C:\ProgramData\NivXForge\sensor\identity.json,
         C:\ProgramData\NivXForge\sensor\outbox.jsonl,
         C:\ProgramData\NivXForge\sensor\outbox.offset |
  Select Name,Length,LastWriteTime
Copy-Item C:\ProgramData\NivXForge\sensor\identity.json `
          C:\ProgramData\NivXForge\sensor\identity.json.pre-reenrol
```

Record the endpoint_id. It must be `ep_1989031c8c1d0085812f` afterwards — a
different value means a second identity was created and the queue has been
split.

## 3 · Confirm the durable attribute, or do not proceed

```powershell
(Get-CimInstance Win32_Processor).ProcessorId
```

Must be **non-empty**. `endpoint_id` is minted from
`(tenant_id, "hw", processor_id)`; if WMI cannot read it, precedence falls to
the machine GUID and mints a **different** endpoint. Empty output stops the
procedure — this is the failure mode
`a_missing_processor_id_mints_a_DIFFERENT_endpoint` exists to name.

## 4 · Mint one token, console-side

Management → Computers → Enrolment tokens → mint **one** single-use token for
`Internal Validation`, with the shortest viable expiry. Do not email, paste
into chat, or store it. (Owner action — no token has been issued by this work.)

## 5 · Re-enrol — stdin only

```powershell
# the token NEVER appears on the command line; this build has no --token flag
Read-Host -AsSecureString |
  ConvertFrom-SecureString -AsPlainText |
  .\NivXForgeEDRSetup.exe install --re-enrol `
      --api https://nivxray.nivxforge.com `
      --tenant ten_e759b7288598bd882e3dcac49d `
      --token-stdin
```

Expected sequence, each line printed by the installer: build + artifact SHA256 →
`=== 1 . STAGE ===` with the service proved **STOPPED** and the image proved
released → `=== 2 . PROTECTED STATE ===` → `=== 3 . ENROLMENT ===` →
`=== 4 . WINDOWS SERVICE ===` → `=== 5 . IDENTITY ===`.

**If any step fails** the installer prints `=== ROLLBACK ===` and restores the
service to the state it held before the first mutation. A failure before step 3
consumes no token. `identity.json`, `outbox.jsonl` and `outbox.offset` are
untouched by every failure path — the state root is not the install directory.

## 6 · Verify recovery

```powershell
sc.exe query NivXForgeSensor                       # RUNNING
.\NivXForgeEDRSetup.exe status                     # SAME endpoint_id as step 2
Get-Item C:\ProgramData\NivXForge\sensor\outbox.jsonl,
         C:\ProgramData\NivXForge\sensor\outbox.offset |
  Select Name,Length                               # ~1.96 GB queue intact
```

Console-side: the endpoint shows **ENROLLED / ACTIVE**, `event_count` still
822,757 (it must not reset to zero), and the queue drains from `outbox.offset`
rather than restarting. CONNECTED is not INVESTIGABLE — wait for authenticated
telemetry before calling it recovered.

## 7 · If something went wrong

Do **not** re-run with a second token. Capture `sc.exe query NivXForgeSensor`,
the installer output, and the state-file listing, then stop. `identity.json.pre-reenrol`
from step 2 is the return path, and a stopped service can be restarted with
`sc.exe start NivXForgeSensor` without re-enrolling.
