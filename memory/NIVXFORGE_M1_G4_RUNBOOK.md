# NIVXFORGE M1 — G4 NATIVE WINDOWS ACCEPTANCE RUNBOOK

**Target: one genuinely working NivXForge Windows endpoint, enrolled into an
isolated lab tenant, emitting real telemetry visible in NivXRay.**

Approved source: commit `388bb3d637a076f36d78fc9d1e218c878b082b9b`, Windows
subtree `db21f422561f14fb4dcec91b70925f2b5291c500`, independently reviewed
snapshot `53a965ff6413de2d6a40858a4415080617323101`.

This document is an execution procedure, not a design. Every step names the
exact command, the observable that decides it, and where the evidence lands.
A step is **PASS** only with captured native evidence; a step never attempted
is **NOT RUN**, never PASS.

---

## 0 · Source identity — do this first, stop if it fails

The build must come from the reviewed bytes, and that must be *proved*, not
assumed.

```
# in the authoritative repository
git rev-parse 388bb3d6^{tree}                      # df8eb48b5719b01c936c8dec3442aeba7763a59f
git rev-parse 388bb3d6:agents/nivxforge-windows    # db21f422561f14fb4dcec91b70925f2b5291c500
git status --porcelain agents backend              # must be EMPTY

# in the independently reviewed snapshot
git clone NIVXFORGE_M1_G3_B3_AUTHZ_SNAPSHOT.bundle reviewed && cd reviewed
git rev-parse HEAD                                 # 53a965ff6413de2d6a40858a4415080617323101
git rev-parse HEAD:agents/nivxforge-windows        # db21f422... — MUST be identical
bash VERIFY.sh                                     # fsck, blobs, credential scan, 373 passed
```

Both subtree hashes must be `db21f422561f14fb4dcec91b70925f2b5291c500`. A
Git tree hash covers every file, name and mode in that directory, so equality
is proof that the source to be built is the source that was reviewed.

**STOP** if they differ, if the worktree is dirty, or if `VERIFY.sh` fails.
Do not build from an unproven tree.

> Status on the engineering pod: **VERIFIED.** Both subtrees are
> `db21f422…`; all 18 snapshot blobs are byte-identical to the candidate
> commit's blobs; `VERIFY.sh` passes with 373 portable tests.

---

## 1 · The VM

| Requirement | Value | Why |
|---|---|---|
| OS | Windows 11 (22H2+), x64, **freshly imaged** | `clean_host_report` refuses any prior service, scheduled task, worker process, install or state directory |
| Isolation | lab network only; no production asset, no domain join | boundary |
| Session | **elevated interactive administrator** | the installer context derives a filtered non-administrator probe token from the caller's own token |
| Never installed | no previous NivXForge sensor, no `NivXForgeSensor` scheduled task, no `C:\Program Files\NivXForge\EDR`, no `C:\ProgramData\NivXForge\state` | any of these is `HOST_NOT_CLEAN` |
| Snapshot | take a VM snapshot **before** step 5 | so the clean-install path can be re-run; M1 never adopts or repairs |
| Network | outbound HTTPS to the test backend, with a chain Windows already trusts | `certificate_policy` is `windows-default` and verification is never disabled |
| Defender | leave enabled; record any quarantine of the unsigned artifact | the build is `UNSIGNED_INTERNAL_VALIDATION_BUILD` |

Runtime dependencies on the endpoint: **none**. The frozen artifact carries
its own Python, pywin32 and sqlite3. `wevtutil` and `sc.exe` are in-box.
Sysmon is optional — the `Microsoft-Windows-Sysmon/Operational` channel is
*reported unavailable*, never faked. To exercise it, install Sysmon with
`agents/nivxforge-windows/sysmon/nivx-b5gap1-canary-sysmon.xml`.

---

## 2 · The build — Windows only

PyInstaller does not cross-compile: a Windows PE embedding a Python runtime
can only be produced on Windows. On a separate **build** host (or the same VM
before step 4, then removed):

```
python -m pip install pyinstaller==6.11.1 pywin32==308
cd agents\nivxforge-windows\build
.\build_windows_installer.ps1 -Commit 388bb3d637a076f36d78fc9d1e218c878b082b9b
```

The script already refuses to run off Windows, checks the nine required
source files, bakes build provenance into `nivxforge_build.py`, builds the
service host as **onedir** (a onefile service image causes Windows error
1053), carries it inside the **onefile** installer as an attested payload,
verifies the `MZ` header, scans the binary for credential shapes and a
preview origin, and emits `SHA256SUMS.txt` and `build-info.json`.

Record, as build provenance:

- `388bb3d6…`, the two subtree hashes, and the `git status` output from §0
- `dist\build-info.json` in full — it carries `sha256`, `size_bytes`,
  `setup_version`, `sensor_version`, `service_host_sha256`, `commit`
- `dist\SHA256SUMS.txt`
- the PyInstaller and pywin32 versions actually resolved, and `python -V`

The origin and the tenant are **not** baked in; they are supplied by the
protected configuration at runtime, which is why a lab origin never ends up
inside the artifact.

---

## 3 · The isolated test tenant

Use a **LAB** tenant with no endpoints and no events. On the current preview
backend that is:

| Field | Value |
|---|---|
| tenant_id | `ten_3f7f772b353a6bbbb0ac8bc564` (slug `g1-acceptance-clean`, kind `LAB`, state `ACTIVE`, products `XDR,EDR`) |
| endpoints today | 0 |
| raw events today | 0 |
| organization | `org_10b45e9746dd71655ecbb13287` (`g1-windows-proof-org`) |

No production tenant and no production credential is used. If a fresh tenant
is preferred, create one through the authenticated control plane — never by
editing the database:

```
POST /api/xdr/organizations   {"slug":"...","display_name":"...","kind":"VENDOR"}
POST /api/xdr/tenants         {"organization_id":"org_...","slug":"m1-g4-acceptance",
                               "display_name":"M1 G4 acceptance","kind":"LAB",
                               "products":["XDR","EDR"]}
```

**The enrolment token must be minted within 24 h of the install** (TTL is
capped at 86400 s) and is shown **once**:

```
POST /api/edr/enrollment/tokens        # authenticated, tenant-scoped
     {"label":"m1-g4-acceptance","ttl_seconds":3600}
```

The plaintext appears in that response and nowhere else — not in Mongo, not
in a log, not in any later `GET`. Carry it to the VM out of band and feed it
on **stdin only**: a token on a command line becomes Sysmon EID 1, the
service `binPath` and PowerShell history, all of which this product collects.

---

## 4 · Pre-provisioning on the VM

M1 never creates its own configuration root and refuses an absent
intermediate directory. From an elevated session:

```
.\agents\nivxforge-g4\New-M1LabConfig.ps1 `
    -Origin   'https://<test-backend>' `
    -TenantId 'ten_3f7f772b353a6bbbb0ac8bc564'
```

Creates, with owner Administrators and a protected SYSTEM+Administrators
DACL: `C:\ProgramData\NivXForge`, `…\NivXForge\m1`,
`…\m1\m1-config.json` (+ `.meta.json`), and `C:\Program Files\NivXForge`.
It refuses to continue if `C:\Program Files\NivXForge\EDR` or
`C:\ProgramData\NivXForge\state` already exist — those two must be **absent**
and are created by the installer.

Configuration contract (`load_config`): `origin` (https), `tenant_id`,
`state_dir`, `install_dir`, `service_exe`, `service_args`,
`certificate_policy = "windows-default"`, optional `interval`. The service
arguments must be exactly
`--m1-service-run --m1-config C:\ProgramData\NivXForge\m1\m1-config.json`,
and `service_exe` must be **inside** `install_dir` and a member of the
attested payload, or the install refuses
(`SERVICE_EXE_OUTSIDE_PAYLOAD` / `SERVICE_EXE_NOT_IN_MANIFEST`).

---

## 5 · The acceptance sequence

Run `Collect-M1Evidence.ps1 -Step <label>` after **every** step. Each
capture records SCM config and state, `sc sdshow`, filesystem and ancestry
ACLs, the registered and the running image hashes, the ownership record, the
local identity (never the credential), the outbox, and the System and
Application event-log entries, then hashes the lot.

### 5.1 Clean-host validation

```
.\Collect-M1Evidence.ps1 -Step 01-pre-install
```

Expect: no `NivXForgeSensor` service, no scheduled task of that name, no
`nivxforge` process, `install_dir` and `state_dir` absent, ancestry ACLs
admin-only. The installer re-verifies all of this itself and refuses with
`HOST_NOT_CLEAN` naming each failing probe.

### 5.2 Installer execution and protected filesystem configuration

```
$t = Read-Host 'enrolment token' -AsSecureString
[Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($t)) |
  .\NivXForgeEDRSetup.exe m1-install `
      --m1-config C:\ProgramData\NivXForge\m1\m1-config.json
```

Expect a JSON result with `"state": "ACTIVATION_VERIFIED"`, an
`install_id`, an `endpoint_id`, the service image digest and the host
report. The gated order inside is: clean-host → ownership record →
`install_dir`/`state_dir` created with protected DACLs and **read back** →
payload hash-verified member by member → payload copied → installed binary
digest verified → enrolment (single attempt) → service created **disabled**
→ descriptor applied and verified → demand-start → started → running image
verified → auto-start.

Capture `-Step 02-installed`. Evidence to read: `install_dir` and
`state_dir` SDDL must be `…D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`-shaped, and
`m1-ownership.json` must show `CREATE_CONFIRMED` for `install_dir`,
`state_dir`, `payload`, `enrollment` and `ACTIVATION_VERIFIED` for
`service`.

### 5.3 Native ACL, Authz and AccessCheck verification

This is the G3-B3 correction under real Windows. The installer already
performed it twice (installer context, then again after the start-type
change); the service performs it a third time under LocalSystem at every
start.

```
sc.exe sdshow NivXForgeSensor
```

Expect SYSTEM and Administrators with full access, Users (`BU`) with query
and read only, and a protected DACL. What must be confirmed natively:

- a real `AuthzInitializeContextFromSid` context is built for
  `S-1-5-11`, `S-1-5-4`, `S-1-1-0`, `S-1-5-32-545` under LocalSystem;
- `AuthzAccessCheck` returns `TRUE` with `Error[0] = ERROR_ACCESS_DENIED`
  and a zero granted mask for each dangerous right — **the verified denial
  that the portable tests can only simulate**;
- the installer-context `AccessCheck` path still denies the same rights
  from the filtered token;
- no probe reports "indeterminate" (that would be the old B3 blocker).

The observable proxy is simply that steps 5.2 and 5.4 complete: a single
indeterminate or granted probe refuses with `SERVICE_SD_UNSAFE`, and the
service refuses to start.

### 5.4 Disabled-first service creation and controlled startup

```
sc.exe qc NivXForgeSensor 4096
sc.exe query NivXForgeSensor
```

Expect `START_TYPE : 2 AUTO_START`, `SERVICE_START_NAME : LocalSystem`,
`STATE : 4 RUNNING`, and `BINARY_PATH_NAME` exactly
`"C:\Program Files\NivXForge\EDR\NivXForgeSensor.exe" --m1-service-run --m1-config C:\ProgramData\NivXForge\m1\m1-config.json`.

The transition through DISABLED → DEMAND_START → (started, image verified) →
AUTO_START is recorded in `m1-ownership.json`; the only place it is visible
afterwards is that record, which is why it is captured at step 02.

Confirm the running image: `running.image.sha256.txt` must equal
`service.exe.sha256.txt` and the `service_host_sha256` in `build-info.json`.

### 5.5 Genuine endpoint enrolment

```
# `status` reads the DEFAULT sensor state root, which is NOT the M1 one, so
# point it at the configured directory first or it will report nothing.
$env:NIVXFORGE_SENSOR_STATE = 'C:\ProgramData\NivXForge\state'
.\NivXForgeEDRSetup.exe status
```

Expect an `endpoint_id` and `credential_id`, no open
`enrollment_attempt.json` marker, and tenant binding proven by a successful
authenticated session. Backend side, in the lab tenant only:

```
GET /api/edr/endpoints            # the new endpoint, with this computer name
GET /api/edr/enrollment/tokens    # the token shows as USED, not reusable
```

If the marker is still `OPEN` while an identity exists, **do not re-install**:
run `m1-reconcile-enrollment --m1-config … --operator-confirmed` after
verifying backend-side that this endpoint has exactly one identity.

### 5.6 Telemetry ingestion and Device Trajectory visibility

Generate real activity on the VM (sign out and in, run a few processes, fail
a logon), wait two or three collection intervals (30 s each by default), then:

```
.\Collect-M1Evidence.ps1 -Step 06-telemetry
```

Expect the outbox to drain, heartbeats to arrive, and backend-side:

```
GET /api/edr/endpoints/{endpoint_id}
GET /api/edr/telemetry...           # raw events for this endpoint only
```

Then open **Device Trajectory** for that endpoint in NivXRay and confirm the
events are visible and attributed to the lab tenant and to no other. The
first cursor starts at record 0 of each channel, so collection begins
without any baseline command; `telemetry-baseline` is only for deliberately
re-basing to the current tails.

Record which channels were available: `Security`, `System`, and
`Microsoft-Windows-Sysmon/Operational` only if Sysmon was installed. An
unavailable channel must appear as *reported unavailable*, never as silence.

### 5.7 Reboot continuity and safe uninstall

```
Restart-Computer
# after boot, without logging in to anything:
.\Collect-M1Evidence.ps1 -Step 07-after-reboot
```

Expect the service to start automatically as LocalSystem, re-verify its
configuration under the service context, resume from its saved cursors, and
no duplicate identity. Then:

```
.\NivXForgeEDRSetup.exe m1-uninstall `
    --m1-config C:\ProgramData\NivXForge\m1\m1-config.json
.\Collect-M1Evidence.ps1 -Step 08-uninstalled
```

Expect `"service": "REMOVED"` (or `PENDING_DELETION` if a handle is still
open), **`state_dir` preserved**, identity, journal, cursors and queued
evidence intact, and the service absent from the SCM. M1 stops and deletes
only a resource its ownership record confirms it created, and it proves the
process exited — PID-reuse aware — before removing anything.

### 5.8 Refusal paths worth exercising once

| Attempt | Expected refusal |
|---|---|
| run `m1-install` a second time | `ALREADY_INSTALLED` |
| run `m1-install` from a non-elevated session | refuses — but **later**, at the first privileged operation (SCM or ACL readback), not at entry: M1 carries no explicit elevation gate. Record exactly where it stops |
| make `m1-config.json` writable by `Users`, then run | `CONFIG_ACL_UNSAFE` |
| point `service_exe` outside `install_dir` | `SERVICE_EXE_OUTSIDE_PAYLOAD` |
| create `C:\ProgramData\NivXForge\state` by hand first | `HOST_NOT_CLEAN` (`destination_present`) |
| run the loose `nivxforge_setup.py` instead of the frozen exe | refuses an unpinned installer |

---

## 6 · Status

| # | Acceptance step | Status | Evidence |
|---|---|---|---|
| 0 | Source identity vs reviewed snapshot | **PASS** | both subtrees `db21f422…`, 18/18 blobs, `VERIFY.sh` |
| 1 | Windows 11 VM provisioned and isolated | **NOT RUN** | no authorized VM |
| 2 | Frozen installer built on Windows | **NOT RUN** | PyInstaller cannot cross-compile; no Windows build host |
| 3 | Isolated lab tenant identified | **PASS** (prepared) | `ten_3f7f772b353a6bbbb0ac8bc564`, 0 endpoints, 0 events |
| 3b | Enrolment token minted | **NOT RUN** | must be minted ≤24 h before install, by an authenticated operator |
| 4 | Pre-provisioned config and roots | **NOT RUN** | script written, not executed |
| 5.1 | Clean-host validation | **NOT RUN** | — |
| 5.2 | Installer execution, protected filesystem | **NOT RUN** | — |
| 5.3 | Native ACL / Authz / AccessCheck | **NOT RUN** | — |
| 5.4 | Disabled-first creation, controlled start | **NOT RUN** | — |
| 5.5 | Genuine enrolment | **NOT RUN** | — |
| 5.6 | Telemetry + Device Trajectory | **NOT RUN** | — |
| 5.7 | Reboot continuity, safe uninstall | **NOT RUN** | — |

**G4 STATUS: NOT RUN.** Portable simulation is not native evidence. The 373
passing portable tests say the source logic is self-consistent; they say
nothing about real SCM, Authz, ACL, token, filesystem or telemetry
behaviour.

### Blockers

1. **No authorized Windows 11 host.** Both the build and every acceptance
   step need one. Nothing in steps 1–5 can be closed without it.
2. **No recorded operator credential for the test backend**, so the
   enrolment token cannot be minted from here. It must be minted by an
   authenticated operator, within 24 h of the install, and carried out of
   band.
3. **The artifact is unsigned** (`UNSIGNED_INTERNAL_VALIDATION_BUILD`).
   SmartScreen or Defender may block or quarantine it on a default image;
   record whatever happens rather than disabling protection silently.
4. **Sysmon is not installed by default**, so one of the three channels will
   report unavailable unless the canary config is deployed first.
5. **Credentials still pending rotation** in the wider repository (a bearer
   JWT in `.tok`, two `memory/` evidence JWTs, six live-suite admin
   passwords). Unrelated to this source, still outstanding.

### Stop conditions

Stop and escalate — do not improvise — on: a source identity mismatch; a
credential-scan refusal during the build; any `*_UNVERIFIED`, `*_UNSAFE`,
`*_UNKNOWN` or `indeterminate` refusal; an open enrolment attempt marker
alongside an existing identity; telemetry appearing under any tenant other
than the lab tenant; or the service starting as anything other than
LocalSystem.

### Boundaries held

No production endpoint, tenant or credential. No change to the approved
implementation: the three files here are NEW and live in `agents/nivxforge-g4/`,
deliberately OUTSIDE the reviewed subtree, so
`git rev-parse HEAD:agents/nivxforge-windows` still returns
`db21f422561f14fb4dcec91b70925f2b5291c500` on the preparation commit as well. No merge, no deployment,
no signing, no self-approval, no security HOLD removed. The enterprise
upgrade, transaction and recovery paths are not exercised by M1 and were not
modified.
