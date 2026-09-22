# G1 · Windows Event Log endpoint proof — IN PROGRESS (2026-06)

Owner scope: prove the EXISTING NivXForge EDR Windows Event Log acquisition
end-to-end on one real Windows endpoint into NivXRay XDR. No adapter
redesign. No G2-G9 work (no ETW, no WMI API, no Event Journal, no DSM
expansion, no Windows sensor expansion, no arbitrary-channel config).

## Pre-flight blockers found (code-level, before touching the host)

| # | Blocker | Decision |
|---|---|---|
| B1 | `main.py:79` (boot rehydrate) and `routes/connectors.py:173` (create) construct every connector as `cls(tenant_id=…, config=…, identity=rec.id)`. REST/webhook/syslog accept `identity`; `WindowsEventLogConnector` did not → `TypeError`, swallowed at boot, so the Windows connector silently never started. W2-1 was never wired through the service path. | **FIXED** (owner-approved) |
| B2 | `collector_id` defaulted to a random `collector-<uuid>`. It anchors the envelope identity the ingest boundary matches against its enrolled collector AND the bookmark scope `(tenant, collector_id, channel)`. Random per process ⇒ ingest `404 collector not found` and no acquisition resume. | **FIXED** — config `collector_id` → `NIVX_COLLECTOR_ID` → **fail closed**; never generated |
| B3 | Standalone collector: `framework/authz.py` returns `403 COLLECTOR_AUTH_UNAVAILABLE` for every HUMAN route (`POST /connectors`, `/start`, `/test`, `GET /connectors`); only `POST /webhooks/{secret_id}` is MACHINE. | **Accepted** — pre-seeded `connectors.json` + boot auto-start; authorization classifications NOT weakened |
| B4 | `routers/xdr_ingest.py::route_batch` — a refused declaration gets *"no raw row, no idempotency claim and no canonical evidence"*. `windows_system`, `windows_application`, `windows_task_scheduler`, `windows_wmi` … have no catalog key/alias, so an unparsed channel cannot be retained as raw forensic evidence server-side. | **Proven as a GAP inside G1**: ENDPOINT ACQUISITION = PASS, NIVXRAY XDR RAW FORENSIC RETENTION = GAP. No DSM/catalog work in G1 |

### B4 · architectural requirement recorded for a later gate
NivXRay XDR must eventually support **tenant-safe raw forensic retention of
legitimately declared and acquired telemetry even when no DSM / parser /
normalizer / detection capability exists**. Absence of a parser must not by
itself destroy otherwise authorized forensic evidence. This capability must
remain **fail-closed against arbitrary or unregistered sources** — it is not
permission to accept unrestricted telemetry.

## Code changed (minimum, deployment path only)
- `apps/nivxray-xdr-collector/framework/windows_eventlog.py` — accepts
  `identity`; authoritative `collector_id` with fail-closed resolution.
- `apps/nivxray-xdr-collector/tests/test_windows_eventlog_deployment_identity.py`
  (new, 6 tests): service construction contract, config-over-env precedence,
  env fallback, fail-closed when undeclared, no generated id, bookmark scope
  stable across a restart.
- Tests: 33 passed in the collector suite (6 new + 27 existing acquisition).
  **Linux tests prove the deployment contract, NOT the endpoint proof.**

## Delivered to the owner (STEP 1)
- `scripts/windows/g1/Get-NivXRayG1Preflight.ps1` — READ-ONLY pre-flight:
  host/edition/build/arch/hostname/domain, client-vs-server, PowerShell,
  elevation, python/pip/git/**pywin32 importability**, Sysmon
  installed-or-not (never installed by the script), and a 23-channel
  inventory with presence / enabled / log mode / size / record count /
  oldest record / last write / path plus a one-record **read probe**.
  Truth states: `NOT_PRESENT`, `PRESENT_NO_RECORDS`, `READ_DENIED`,
  `READ_OK` — none of which mean "no activity occurred".
- `scripts/windows/g1/README_G1_STEP1_PREFLIGHT.md` — GitHub-based delivery,
  the exact command, and what STEP 2 will contain.

## STOPPED — awaiting the owner's pre-flight JSON
STEP 2 (host-specific runbook + server-side onboarding + the proof itself) is
generated only after the JSON returns, so channel scope matches what the host
can actually read.
