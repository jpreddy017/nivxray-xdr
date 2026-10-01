# TRACK A · FIRST REAL WINDOWS INSTALL — RUNBOOK (PREPARED, NOT EXECUTED)

Status: **READY — held at your instruction.** No token minted, no endpoint enrolled,
nothing installed, no production write. Use this only if you decide not to wait for the
Track B EXE.

## 1 · Package integrity (scanned now)

| File | SHA-256 (16) | Size | Credential / preview / localhost hits |
|---|---|---|---|
| `Install-NivXForgeSensor.ps1` | `98bbfdde7b8ceec2` | 7,313 B | **NONE** |
| `nivxforge_sensor.py` | `2c7fa46e9e46054d` | 21,496 B | **NONE** |
| `nivxforge_exclusions.py` | `da63bd1a7093fb1d` | 13,302 B | **NONE** |

Scanned for: `nvx_`/`nvxenr_`/`nvxses_`/`nvxcrd_` credential shapes, `ten_<26hex>`,
`EDR_AUTH_PEPPER`, `admin@nivxray.com`, JWT (`eyJ…`), `preview.emergentagent.com`,
`localhost`/`127.0.0.1`, `:8001`. **All clean** — the build is credential-free and carries no
preview or localhost origin. The backend applies the same scan before it will serve the
package (`edr_onboarding._SECRET_SHAPES`).

## 2 · Prerequisites on the validation PC

1. **Sysmon already installed and configured** (you confirmed this) — do not change its
   config during this gate.
2. **Python 3.11+** — a Track A-only prerequisite that Track B removes.
3. An **elevated PowerShell**.

## 3 · Get the package

Either download from the console (`Management → Computers → Add Computer → Windows`, package
`windows-x64`, which serves both files), or copy `agents/nivxforge-windows/` from the repo.
Both files must sit in the same folder.

## 4 · Install (one command, token supplied at install time)

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-NivXForgeSensor.ps1 `
  -BackendUrl 'https://nivxray.nivxforge.com' `
  -TenantId   'ten_e759b7288598bd882e3dcac49d' `
  -EnrollmentToken '<THE ONE OWNER-AUTHORISED TOKEN>'
```

The token is **never** committed, logged or stored — it is exchanged once for this computer's
own endpoint-scoped credential, which lands in
`C:\ProgramData\NivXForge\sensor\identity.json` under a SYSTEM+Administrators-only ACL.

## 5 · What must happen, in order

```
elevated check → stage to C:\Program Files\NivXForge\sensor
  → ACL-protected state dir → enrol (P0-PROD-2, single-use token)
  → endpoint_id minted by the platform from durable machine facts
  → scheduled task NivXForgeSensor (SYSTEM, ONSTART) started
  → heartbeat + policy fetch/ACK
  → wevtutil collection (Security, System, Sysmon/Operational)
  → durable journal (fsync BEFORE send)
  → POST /api/edr/agent/telemetry
  → Phase 0 canonical bridge → canonical evidence
  → deterministic detection → P0-C findings/evaluation → Device Trajectory
```

## 6 · Verification after install (I will run these read-only)

- `Computers` shows the host; **CONNECTED only after authenticated telemetry**, not at enrol.
- `investigability` must move to **`INVESTIGABLE`**; if it says
  `RAW_ONLY_NOT_INVESTIGABLE`, canonicalisation is failing and the console will say so.
- Trajectory must show the expected lanes: PROCESS (Sysmon 1 / Security 4688), NETWORK (3),
  FILE (11), REGISTRY (12/13), DNS (22), AUTHENTICATION (4624).
- Any disabled channel is reported **unavailable**, never as "nothing happened".

## 7 · Accepted Track A limitations (temporary, not permanent debt)

| Limitation | Removed by |
|---|---|
| Python 3.11+ required on the endpoint | Track B frozen EXE |
| ONSTART scheduled task, not a Windows Service | Track B `sc.exe` service + crash recovery |
| Unsigned | code-signing certificate (separate decision) |
| Outbox has no size cap | backlog item (disk-full risk on long outage) |

## 8 · Rollback

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-NivXForgeSensor.ps1 -Uninstall
```
Stops and removes the task and program files; **keeps** the identity and journal unless
`-Purge` is added, so evidence is never destroyed silently.
