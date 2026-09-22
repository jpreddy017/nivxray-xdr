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

## RE-REVIEW UNDER THE PRODUCTION-GRADE STANDARD (owner correction)

The first pass was NOT production-complete. Re-review found a third defect
inside B1's own contract and corrected all of it.

### B1 · CONNECTOR LIFECYCLE
- **ROOT CAUSE (1)** `WindowsEventLogConnector.__init__` rejected the
  `identity` argument the service passes to every connector → `TypeError`,
  swallowed at boot.
- **ROOT CAUSE (2 · found on re-review)** `CollectorRuntime.start()` had **no
  branch for this connector** and returned
  `unsupported_connector_kind:WindowsEventLogConnector`. Even with a working
  constructor the connector would never have been scheduled: no periodic
  read, no delivery, no bookmark advance. `stop()` likewise had no branch.
- **ROOT CAUSE (3)** boot rehydration swallowed every failure
  (`except Exception: continue`), so a connector that never came up was
  indistinguishable from a healthy one.
- **PRODUCTION CONTRACT** configuration validation → startup → construction →
  rehydration → auto-start → running (Read → Make Durable → Advance
  Acquisition) → controlled stop → restart → rehydration → resume, with
  every failure explicit and observable and every failure fail-closed.
- **IMPLEMENTATION** `framework/runtime.py`: `_start_windows_eventlog()`
  (profile validation, scheduling, durable-then-advance callback, error
  callback) + `deliver_windows()` (returns the channels the outbox actually
  holds) + a `stop()` branch reporting `DISCONNECTED` and any pending
  position. `framework/scheduler.py`: additive `on_error` and
  `always_callback` (the acquisition loop must run even when a read returns
  nothing; silence is not a health report). `main.py`: per-connector
  rehydration report (`records/constructed/started/not_started/failures`
  with stage + error), `logging.error` per failure, surfaced on `/health`.
  `routes/connectors.py`: a configuration the connector refuses is now
  `400 invalid_connector_configuration` and the unusable record is deleted,
  not persisted; delete releases the identity binding.
- **FAIL-CLOSED** a profile with no collectible channel never starts
  (`ok: False`, `Health.ERROR`, nothing scheduled); a channel that failed to
  read never advances its position; when the outbox does not accept the
  records the position stays put and the window is re-read.

### B2 · COLLECTOR IDENTITY (permanent contract, not a G1 convenience)
- **ROOT CAUSE** `collector_id` defaulted to a random `collector-<uuid>`.
- **PRODUCTION CONTRACT** authoritative source = connector configuration,
  explicit fallback `NIVX_COLLECTOR_ID`, validated, stable across process
  restart and host reboot (it is persisted configuration, not runtime
  state), one tenant per identity, no random fallback ever.
- **IMPLEMENTATION** `framework/collector_identity.py` (new): process-wide
  binding with `CollectorIdentityConflict` on cross-tenant reuse,
  whitespace/empty rejection, `release()` on connector delete.
  `framework/windows_eventlog.py` resolves config → env → **fail closed**,
  then binds.
- **SERVER ENROLMENT MATCH** enforced authoritatively at
  `backend/routers/xdr_ingest.py:818-835`: the batch's single
  `collector_id` must resolve to an enrolled collector, and the envelope
  tenant AND the `X-Tenant-Id` header must both equal that collector's
  tenant, else `404` / `TENANT_ISOLATION_VIOLATION`. Exercised for real in
  the endpoint proof.
- **BOOKMARK NAMESPACE** scope is `(tenant_id, collector_id, channel)`;
  stability across restart is now a test.

### TESTS
`tests/test_windows_eventlog_lifecycle.py` (new, 14): runtime start/stop,
`always_callback`, no-collectible-channel fail-closed, partly-invalid profile
starts and names the problem, advance-only-after-durable, no-advance-when-
durability-fails, empty-read may advance, failed-read never advances,
collect failure observable via health + `last_error`, cross-tenant identity
refused, same-tenant rebind, whitespace refused, rehydration failure reported
on `/health` while the healthy connector still starts, restart → rehydrate →
resume of the same bookmark scope.
`tests/test_windows_eventlog_deployment_identity.py` (6) ·
`tests/test_windows_eventlog_acquisition.py` (27) unchanged.
**Full collector suite: 154 passed.**

### RESIDUALS (stated, inside these contracts)
- Linux tests prove the deployment and durability contracts; **only the
  Windows host can prove real `EvtSubscribe` acquisition, reboot resume and
  log-clear behaviour.** That is the pending endpoint proof.
- Identity binding is per collector process. Two collector *processes* on
  different hosts sharing one enrolled `collector_id` remains a server-side
  enrolment concern (ingest accepts either, and their bookmark scopes would
  overlap). Not reachable from inside one process; recorded here rather than
  claimed closed.
- B3's pre-seeded-config lifecycle is the production NivXForge EDR
  acquisition lifecycle for an unattended endpoint (the same rehydrate →
  auto-start path the service uses everywhere). It is not a G1 workaround,
  and no authorization classification was weakened. The control plane for a
  standalone collector (operator-facing start/stop/status on the endpoint
  itself) remains absent by design and belongs to the Windows sensor gate.
- **B4 remains a required closure item**, not an accepted limitation.


## Code changed (production-grade, deployment path only)
- `framework/windows_eventlog.py` — accepts `identity`; authoritative
  `collector_id` (config → `NIVX_COLLECTOR_ID` → fail closed) bound to one
  tenant.
- `framework/collector_identity.py` (new) — the identity binding contract.
- `framework/runtime.py` — the Windows acquisition lifecycle
  (`_start_windows_eventlog`, `deliver_windows`, `stop` branch).
- `framework/scheduler.py` — additive `on_error` + `always_callback`.
- `main.py` — observable rehydration report on `/health`.
- `routes/connectors.py` — `400` on a refused configuration (record not
  persisted); identity released on delete.
- Tests: `test_windows_eventlog_lifecycle.py` (14 new) +
  `test_windows_eventlog_deployment_identity.py` (6 new) +
  `test_windows_eventlog_acquisition.py` (27) → **full suite 154 passed**.
  **Linux tests prove the deployment and durability contracts, NOT the
  endpoint proof.**

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
