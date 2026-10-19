# DEV RESET & FRESH TELEMETRY · exact execution steps (for approval)

Supersedes the recovery/preservation workflow: history, the 1.99 GB outbox
and the 1.72 M queue entries are **disposable test data**. Identity is still
preserved — not because the events matter, but because a deterministic
`endpoint_id` is the thing we are validating.

**Nothing here has been executed. Phases 1-2 are read-only; phase 4 is
irreversible.**

## PHASE 0 · decisions needed before anything runs

| # | Decision | Default in the script | Consequence |
|---|---|---|---|
| D1 | **Scope** — this computer only, or the whole tenant? | `SCOPE = "tenant"` | `"tenant"` also clears `ep_a67be48d5b4e01d4d9e8` (1,719,950 raw events — nearly all of the queue depth). If that is the preview/dev sensor, it disappears from the console until it re-enrols. `"endpoint"` leaves it untouched |
| D2 | **Keep EDR configuration?** (policies, groups, exclusions, boundary, deployments) | `KEEP_CONFIG = true` | Keeping avoids re-seeding and keeps `grp_default_windows` / `pol_default_detect_only` stable, so the fresh enrolment lands in a known group |
| D3 | **Keep enrolment/policy audit?** | `KEEP_AUDIT = true` | Append-only; it is the only record of what was enrolled before the reset |
| D4 | **XDR artefacts built on this telemetry** | script never writes them | `xdr_canonical_evidence` / `v2_shadow_observations` point at raw events via `raw_ref`. The dry run prints how many. Clearing raw events leaves those pointers unresolvable: XDR keeps working, but a case built on this telemetry will show evidence it cannot load. Clearing them too is a separate, deliberate step I have **not** scripted |
| D5 | **Snapshot taken?** | script refuses to run without one | The deletions cannot be undone from inside the app |

## PHASE 1 · identity and WMIC stability (read-only, on the laptop)

The sensor reads the processor id **only** through
`wmic cpu get ProcessorId /value` — there is no CIM fallback — and hashes it
before sending. Validate the exact chain the system uses:

```powershell
wmic cpu get ProcessorId /value                     # expect ProcessorId=BFEBFBFF000806C1
(Get-CimInstance Win32_Processor).ProcessorId       # cross-check only
```

Then step **A2 of `EXECUTION_CHECKLIST.md`** (two hashes, in order) must print

```
sensor sends : 166b4c9c1060a787586b119a      = sha256(ProcessorId)[:24]
endpoint_id  : ep_1989031c8c1d0085812f       = sha256(tenant ␟ hw ␟ that)[:20]
```

**Stability, not just presence:** run phase 1 **twice — once now and once
after a reboot**. WMIC is a removable Feature-on-Demand on current Windows 11,
so the failure that matters is "a servicing update removed it", and that
shows up at the next boot, not now. If `wmic` is ever absent the sensor falls
back to `machine_guid` and the platform mints a *different* endpoint.

**STOP** on: `wmic` not recognised, empty output, a changed ProcessorId, or
either hash not matching. Restore with
`DISM /Online /Add-Capability /CapabilityName:WMIC~~~~` and re-validate.

## PHASE 2 · backups (read-only, both sides)

1. **Atlas snapshot** of the serving cluster. Record the snapshot id — the
   script refuses to arm without it. This is the only rollback for phase 4.
2. Keep `C:\NivXForge-Recovery-Backup` as it is. Do not overwrite it.
3. Export the endpoint document for reference before it is deleted (console
   or `GET /api/edr/onboarding/computers/ep_1989031c8c1d0085812f`), so the
   "before" numbers survive the reset.

## PHASE 3 · local purge (laptop; destructive, local only)

```powershell
sc.exe stop NivXForgeSensor
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status      # record final state
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe uninstall --purge
Get-ChildItem C:\ProgramData\NivXForge\sensor -ErrorAction SilentlyContinue
```

`--purge` is **correct here and only here**: it removes the state directory,
including `identity.json`, `outbox.jsonl`, `outbox.offset` and the journal.
The last command must show the directory gone or empty. The backup from
phase 2 is untouched.

Do the local purge **before** the backend reset, so nothing in flight
re-creates a session or re-delivers a batch into the clean store.

## PHASE 4 · backend dev reset (irreversible)

```bash
mongosh "<MONGO_URL>" --file edr_dev_reset.mongosh.js        # DRY RUN first
```

The dry run prints, per collection, the in-scope count and the collection
total, plus the XDR reference counts, and exits without writing. **Review it
against D1-D4.** Then set `SNAPSHOT` to the phase-2 snapshot id and
`CONFIRM = "DELETE-EDR-DEV-DATA"` and re-run.

What it does and does not do:

* clears, tenant-scoped: `edr_raw_events`, `edr_processing_queue`,
  `edr_rejected_telemetry`, `edr_acquisition_gaps`,
  `edr_acquisition_integrity`, `edr_delivery_counters`, `edr_findings`,
  `edr_finding_evaluations`, `edr_compromise_events`,
  `edr_endpoint_address_observations`, `edr_response_commands`,
  `edr_policy_endpoint_state`, `edr_endpoint_exclusion_enforcement`,
  `edr_endpoints`, `edr_agent_credentials`, `edr_agent_sessions`,
  `edr_enrollment_tokens`
* keeps by default: all EDR configuration and audit (D2, D3)
* **never writes** any `xdr_*`, `v2_*`, `canonical`, `tenants` or `users`
  collection — those are only counted
* **no `dropDatabase`, no collection drops** — indexes and validators survive,
  so the fresh enrolment writes into the same shapes
* prints before/after counts and a verification pass that must read 0

Collection ownership was derived by reading the code (every collection in the
clear list is referenced only by `edr_plane/*`, `routers/edr_*`,
`services/edr/*` or `edr_trajectory/*`), not inferred from the `edr_` prefix.
`edr_raw_events` is the single exception — 18 files touch it, including
`routers/xdr_search.py`, `services/evidence_bridge.py`,
`services/incident_provenance.py` and `v2/ingestion/telemetry_bridge.py` —
which is why D4 exists.

## PHASE 5 · fresh enrolment

1. Mint **exactly one** enrolment token (console → Management → Enrolment).
2. On the laptop, elevated, in the directory holding the verified artifact
   (0.3.0-windows, `63d7d104`, Gate 4 PASS on run 39144147851):

```powershell
$t = Read-Host -AsSecureString "enrolment token"
[Runtime.InteropServices.Marshal]::PtrToStringBSTR(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($t)
) | .\NivXForgeEDRSetup.exe install `
      --backend https://nivxray.nivxforge.com `
      --tenant ten_e759b7288598bd882e3dcac49d `
      --token-stdin --interval 30
```

**No `--re-enrol`**: the state directory was purged in phase 3, so this is a
first install from the agent's point of view. The token still arrives only on
stdin.

**Expected:** the printed `endpoint_id` is **`ep_1989031c8c1d0085812f`** —
the same identity as before, because the mint is deterministic. A different
value means phase 1 was not re-validated; **STOP**.

## PHASE 6 · demonstrate live telemetry

The sensor collects three channels, in order, and **reports a missing channel
rather than faking it**: `Security`, `System`,
`Microsoft-Windows-Sysmon/Operational`.

1. Confirm what exists before generating anything:
```powershell
Get-WinEvent -ListLog Security,System,Microsoft-Windows-Sysmon/Operational |
  Format-Table LogName,RecordCount,IsEnabled
```
If the Sysmon channel is absent, install Sysmon with the shipped config
(`agents/nivxforge-windows/sysmon/nivx-b5gap1-canary-sysmon.xml`) or accept a
two-channel demonstration — the sensor will report the third as missing,
which is itself correct behaviour worth showing.

2. Generate activity that lands on those channels:
```powershell
whoami; cmd.exe /c ver; Get-Process | Select-Object -First 5   # process events
Restart-Service -Name Spooler -ErrorAction SilentlyContinue    # System
net use \\127.0.0.1\IPC$ /user:nivx-demo badpassword           # Security 4625
New-Item $env:TEMP\nivx-demo.txt -Force; Remove-Item $env:TEMP\nivx-demo.txt
```
Process-creation auditing (4688) and Sysmon 1/11 depend on local policy; the
failed logon (4625) and the service transition are the reliable two.

3. Watch it leave the machine (first cycle within `--interval 30` seconds):
```powershell
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status
```
`queue_depth` rises as events are journaled, then falls as batches are
acknowledged; `legacy_outbox_remaining` stays 0 (purged).

4. Watch it arrive, with your console session:

| Check | Expected |
|---|---|
| `GET /api/edr/enrollment/endpoints` | exactly **1** endpoint (or 2 if D1 was `"endpoint"`), `ep_1989031c8c1d0085812f` |
| `GET /api/edr/onboarding/computers/ep_1989031c8c1d0085812f` | ENROLLED / ACTIVE, `sensor_state` reporting, `event_count` rising **from 0**, `last_telemetry_at` and `last_heartbeat_at` within the last minute |
| EDR console → Computers → this computer | present, online, with events in the activity view |
| `GET /api/edr/enrollment/rejections` | **empty** — a rejection here means the credential or the batch shape is wrong, not that the demo failed |
| `edr_raw_events` (counts via the script's dry run, or Atlas) | rising, every document carrying `endpoint_ref = ep_1989031c8c1d0085812f` and **no other value** |
| `edr_processing_queue` | rising with raw events then draining — idempotent on `(tenant_id, raw_id)`, so a replay must not double-count |
| `edr_acquisition_gaps` | may contain LEADING/INTERIOR gap records: expected and correct after a purge, since the channel bookmarks restarted |

## ACCEPTANCE

All of: phase 1 passed twice (including after a reboot) · snapshot recorded ·
local state directory gone and recreated clean · dry run reviewed and the
armed run's verification reading 0 · `endpoint_id` unchanged ·
`event_count` rising from 0 · raw events attributed to exactly one
`endpoint_ref` · zero rejections · service Running · XDR console still loads
its own pages (cases, search, dashboards) after the reset.

## STOP / ROLLBACK

| id | Trigger | Action |
|---|---|---|
| S1 | Phase 1 fails at any point, including the post-reboot run | Do not reset, do not enrol. Restore WMIC first |
| S2 | Dry run shows XDR reference counts you are not willing to orphan | Stop at D4 and decide; nothing has been written |
| S3 | Armed run's verification does not read 0 | Stop. Do not enrol into a half-cleared store; restore the snapshot |
| S4 | Enrolment prints a different `endpoint_id` | Stop the service. The identity source changed between phase 1 and phase 5 — re-run phase 1 and report before any further enrolment |
| S5 | Rejections appear in phase 6 | Stop the service to end the loop; report the rejection codes. Do not mint another token |
| S6 | XDR pages break after the reset (not merely empty) | Restore the snapshot. Empty is expected; broken is a defect worth a fix, not a workaround |

Irreversibility: phase 3 and phase 4 cannot be undone from inside the
application. The phase-2 snapshot is the only rollback, and `--purge` is the
only command in this document that deletes local evidence.
