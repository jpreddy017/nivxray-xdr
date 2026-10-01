# FIRST REAL WINDOWS ENDPOINT ONBOARDING PROOF — runbook

**Status:** platform side is READY and rehearsed. Waiting on one real
Windows host. Nothing in this runbook mutates an existing endpoint.

**Customer to use:** `ten_f1a5479243e901cf159e230fa0` — *G1 Windows proof*
(ACTIVE · CUSTOMER · currently 0 computers, so every transition observed is
unambiguously this endpoint).

---

## What the rehearsal already proved (2026-06, SYNTHETIC, archived tenant)
`python3 /app/tools/edr_onboarding_proof.py rehearse` exercised every
server-side transition in a throwaway tenant and is green:

| # | Transition | Evidence |
|---|---|---|
| 1 | build offered from disk | `windows-x64` · sensor `0.1.0-windows` · both artifacts with SHA-256 · `credential_free=true` |
| 2 | bounded credential minted | single use · TTL enforced · tenant bound · enrolment purpose only |
| 3 | identity minted by the PLATFORM | `endpoint_id` + `credential_id` returned; installer carried neither |
| 4 | credential cannot be reused | second enrolment attempt → `401 ENROLLMENT_TOKEN_INVALID` |
| 5 | enrolment alone is not CONNECTED | `ENROLLED_NO_TELEMETRY` with its basis sentence |
| 6 | authenticated session | bearer session token issued |
| 7 | authenticated telemetry | `HTTP 200` · `stored=true` · canonicalised · observation created |
| 8 | CONNECTED read back | “authenticated telemetry received 0s ago, within the sensor's own declared cadence (90s)” |
| 9 | detection | `detections_24h=1`, `detections_total=1` |
| 10 | Command Intelligence | endpoint RESOLVED · 1 observed execution · `DETECTION_MATCHED` · decode `DECODE_NOT_RECORDED` (honest) |

**Two real defects were found and fixed by that rehearsal** — both would
have broken the single real attempt:
1. `EndpointRecord` (extra="forbid") rejected the placement fields written
   at enrolment (`group_id`, `policy_id`, `placement_basis`,
   `placement_at`), so **every placed endpoint got HTTP 500 on
   `/api/edr/agent/telemetry`** *after* its evidence was stored. The
   canonical bridge never ran.
2. Consequence of (1): Command Intelligence and Trajectory reported
   `ENDPOINT_NOT_RESOLVED` for a brand-new computer, because no canonical
   observation existed for the device directory to resolve.
   Regression test: `tests/test_edr_fleet_detection_counts.py::
   test_the_endpoint_record_accepts_the_placement_the_platform_writes`.

---

## Owner steps on the Windows host

1. In the EDR console pick customer **G1 Windows proof** in the header,
   then open **Management → Downloads** (`/edr/management/downloads`).
2. Download both artifacts: `Install-NivXForgeSensor.ps1` and
   `nivxforge_sensor.py`. Copy both into the same folder on the Windows
   host (for example `C:\NivXForge\`).
3. Open **Computers → Add device** (`/edr/computers/add`), choose the
   Windows x64 build, press **Generate enrolment token**. The plaintext is
   shown once, lives for 1 hour, is single use and authorises enrolment
   only.
4. Copy the generated command from step 4 of that screen and run it in an
   **elevated** PowerShell session from that folder. It looks like:

   ```
   powershell -ExecutionPolicy Bypass -File .\Install-NivXForgeSensor.ps1 `
     -BackendUrl <shown in the console> `
     -TenantId ten_f1a5479243e901cf159e230fa0 `
     -EnrollmentToken <minted value>
   ```

5. Leave the Add device screen open. It polls the fleet and shows the real
   transitions: enrolment recorded → authenticated telemetry → CONNECTED.
   **Installer success is not a PASS.** CONNECTED is only ever read back.

## Evidence capture (run this from the workspace while step 4 executes)

```
NVX_ADMIN_PASSWORD='<owner supplies>' \
python3 /app/tools/edr_onboarding_proof.py watch \
  --tenant ten_f1a5479243e901cf159e230fa0 --minutes 30
```

Read-only. It baselines the fleet, then prints the exact evidence for each
transition (endpoint id, hostname, OS, sensor version, enrolment and
credential state, telemetry timestamp, event count, detection counts,
device identity, observed/decoded/detected command counts) and finally the
console routes carrying that evidence.

## Then verify in the console
- `/edr/computers` — the computer, CONNECTED, with real detection counts
- `/edr/computers/{endpoint_id}` — Overview (three lifecycles + telemetry)
- `/edr/computers/{endpoint_id}/trajectory` — chronology from its evidence
- `/edr/computers/{endpoint_id}/commands` — observed command execution

## Boundaries honoured
- No deploy, no merge, no production change.
- No historical backlog drain, no unrelated durable-delivery work.
- No destructive endpoint action; no isolation, no kill, no quarantine.
- Nothing is reported as CONNECTED, observed or detected unless the
  platform recorded it.

## Known follow-up (owner-approved, AFTER this proof)
Device Trajectory takes ~18 s on the 204 k-observation endpoint and, being
a synchronous Mongo read, blocks the worker while it runs. Bounded P0
optimisation: server-side windowing/pagination, progressive viewport
retrieval, cached safe projections, details on demand.
