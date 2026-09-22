# G1 · STEP 2 — NivXForge EDR Windows acquisition → NivXRay XDR ingestion

**Status:** S1–S5 **CLOSED IN CODE** (owner-approved 2026-06, pre-execution
gates). S6 decided: bounded 60-minute window. Acquisition NOT started; no
server-side G1 preparation performed; no proof tenant or credential exists.
**Input of record:** `nivxray-g1-preflight.json`, SHA-256
`210A3C1D705B1230D7B9601EF69AC0C4665E2A1C9215122C97390331D1819A37`,
produced on the real host under elevation.
**Code of record:** `jpreddy017/nivxray-xdr` @ `feature/rc2-alignment`,
G1 reviewed-code manifest 10/10 PASS remotely and on the endpoint.

---

## 1 · What the real host changed about the plan

| Pre-flight fact | Consequence for Step 2 |
| --- | --- |
| Windows 10 Pro 19045, CLIENT, WORKGROUP | `windows-validation` profile is correct. `windows-domain-controller` is not applicable; `Directory Service` / `DNSServer/Audit` stay truthfully `NOT_PRESENT`. |
| Elevated execution available | `Security` is readable. The acquisition process must ALSO run elevated, or `Security` silently degrades to `READ_DENIED`. |
| Sysmon 15.22 installed + running, ~80K retained records | **Do not install Sysmon.** But a fresh bookmark means `EvtSubscribeStartAtOldestRecord` → a first read that walks ~80K records. See **S6** (bounded window vs full backfill). |
| `py.exe` → 3.14.5; `python.exe` → Store alias; `pip` NOT PRESENT; `pywin32` NOT IMPORTABLE | The interpreter must be established deliberately. See **S5**. |
| 21/23 channels present, 16 readable, 0 read-denied | The three G1 channels (Sysmon / Security / PowerShell Operational) are all readable. No Windows configuration change is needed for G1. |
| ForwardedEvents, TaskScheduler/Operational, DNS-Client/Operational present but DISABLED | Left disabled. Reported `PRESENT_DISABLED`, never enabled to manufacture coverage. |

---

## 2 · Pre-execution gates S1–S6 · OWNER-APPROVED AND CLOSED

The findings below were raised as blockers and decided by the owner. S1–S5
are now closed in code; S6 is a scope decision applied at configuration
time. The original defect evidence is kept verbatim, because a closed gate
still has to say what it closed.

### CLOSURE SUMMARY

| Gate | Decision | Closed by |
| --- | --- | --- |
| S1 · sensor-clock conflation | FIX BEFORE ACQUISITION | `backend/services/ingest_provenance.py` — `declared_activity_clock()` + rewritten sensor derivation in `transport_stamps()`. 10 tests, `backend/tests/test_g1_s1_clock_independence.py` |
| S2 · protocol identity | FIX BEFORE ENROLMENT | `windows-eventlog` / `windows-evt-api` / IMPLEMENTED in `PROTOCOL_REGISTRY`, plus `SOURCE_KINDS["windows_eventlog_native"]` and catalog entry `cat_endpoint_windows_eventlog`. 12 tests, `backend/tests/test_g1_s2_windows_eventlog_protocol.py` |
| S3 · pywin32 pinned + fail closed | APPROVED, PIN IT | `apps/nivxray-xdr-collector/requirements-windows.txt` (`pywin32==312`) + `acquisition_capability()` + start-up refusal in `CollectorRuntime._start_windows_eventlog()` |
| S4 · Windows state root | APPROVED | `apps/nivxray-xdr-collector/framework/state_paths.py`; `WindowsBookmarkStore` no longer hard-codes the POSIX path |
| S5 · supported runtime, no silent fallback | APPROVED WITH CHANGE | `apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md`; the auto-install fallback is REMOVED from this runbook |
| S6 · first-acquisition scope | BOUNDED 60-MINUTE WINDOW | applied as a declared per-channel XPath filter, reported as `G1_VALIDATION_SCOPE_BOUND` |


### S1 · SENSOR CLOCK CONFLATION (blocks a required G1 proof)

`backend/services/ingest_provenance.py:88-101` derives the server's
`sensor_observed_at` from **`envelope.source_timestamp` only**:

```python
sensor = pick([(envelope.get("source_timestamp"),
                "collector:envelope.source_timestamp")], ...)
```

For the Windows adapter, `source_timestamp` is the **ACTIVITY** instant
(`apps/nivxray-xdr-collector/framework/windows_eventlog.py:545-558` —
`EventData.UtcTime`, else `System.TimeCreated`). The collector's true
sensor-observation instant is sent as `collection_timestamp` and, named
explicitly, as `canonical.sensor_observed_at` — **which the server
ignores**.

Consequence: if G1 runs as-is, `sensor_observed_at` in canonical evidence
would be a **copy of the activity clock**, and the required proof
"ACTIVITY_TIME / SENSOR_OBSERVED_AT / INGEST_TIME separation" would be
satisfied only in appearance. Two of the three clocks would be one clock
wearing two labels.

* **Recommended decision:** minimal server-side fix before acquisition —
  `transport_stamps()` prefers an explicitly declared sensor instant
  (`canonical.sensor_observed_at`) and must not claim `sensor_observed_at`
  from a value the envelope itself declares to be the activity clock
  (`canonical.activity_time_source` is already carried). `nivx_received_at`
  and `collector_received_at` are untouched.
* **Alternative:** run G1 as-is and report the conflation as a named,
  unwaived defect. Cheaper, but the clock-separation proof then FAILS by
  our own standard rather than passing.

### S2 · NO PROTOCOL IDENTITY FOR NATIVE WINDOWS EVENT LOG ACQUISITION

`backend/routers/xdr_collectors.py:123-176` is the closed protocol
registry, and `_validate_create()` refuses anything outside it. It has
**no `windows-eventlog` entry**. The nearest key is:

```python
"wef": {"implementation": "SCAFFOLD", "transport": "winrm",
        "canonical_schema": "canonical.host.process", ...}
```

WEF-over-WinRM is a **different acquisition architecture** from
`EvtSubscribe` on the endpoint. Enrolling the G1 endpoint today forces a
false declaration (`protocol: wef`, `implementation: SCAFFOLD`) into the
authoritative collector record, and the Integrations surface would then
describe the acquisition method incorrectly forever.

* **Recommended decision:** add one registry entry —
  `"windows-eventlog": {"implementation": "IMPLEMENTED", "transport":
  "windows-evt-api", "canonical_schema": "canonical.host.process"}` —
  before enrolment.
* **Alternative:** enrol as `wef` and accept a knowingly false protocol
  identity. Not recommended; it is the same class of defect as B2.

### S3 · `pywin32` IS NOT A DECLARED DEPENDENCY

`apps/nivxray-xdr-collector/requirements.txt` is `fastapi`, `uvicorn`,
`httpx`, `python-dotenv`. `NativeEvtReader.read()`
(`framework/windows_eventlog.py:317-355`) imports `win32evtlog` lazily and,
when the import fails, returns `read_ok: False` with
`"win32evtlog could not be bound"`. So a Windows host without pywin32 does
not crash — it produces a collector that **truthfully reads nothing**,
which is exactly what the pre-flight found (`pywin32: NOT IMPORTABLE`).

* **Recommended decision:** add `apps/nivxray-xdr-collector/requirements-windows.txt`
  (`-r requirements.txt` + `pywin32>=312`) so the Windows runtime is
  declared, not improvised. pywin32 build **312** is the first with cp314
  wheels; 3.14 free-threaded builds have no official wheel.
* **Alternative:** ad-hoc `pip install pywin32` in Step 2 with nothing in
  the repo recording it. Works once, reproduces never.

### S4 · `XDR_STATE_DIR` HAS NO VALID WINDOWS DEFAULT

`framework/windows_bookmarks.py:99-100` defaults to `/var/lib/nivxray`,
and `framework/store.py:63-68` treats an unset `XDR_STATE_DIR` as
"**no persistence at all**" (in-memory connectors, lost on restart). On
Windows the POSIX default resolves to `C:\var\lib\nivxray` on the current
drive — legal, but not a declared durable location.

* **Decision:** `XDR_STATE_DIR=C:\ProgramData\NivXForge\state`, set
  explicitly in the run environment. Both the durable outbox and the
  bookmark table live in `${XDR_STATE_DIR}\outbox.db` — one fsync domain,
  which is what makes "durable-before-bookmark-advance" provable.

### S5 · INTERPRETER: THE STORE ALIAS IS NOT AN INTERPRETER

`python.exe` on this host is the Microsoft Store **execution alias**. It is
not a usable interpreter, it has no `pip`, and it must never be the thing
that runs acquisition. `py.exe` resolves 3.14.5.

* **Decision (ordered, fail-closed):**
  1. `py -3.14 -m ensurepip --upgrade` → establishes `pip` for 3.14.5.
  2. `py -3.14 -m venv C:\nivx\.venv` → pins ONE interpreter for the
     lifetime of the proof; everything afterwards uses
     `C:\nivx\.venv\Scripts\python.exe` by absolute path. The alias can
     never be picked up by accident.
  3. `pip install -r requirements-windows.txt` (pinned `pywin32==312`).
  4. `python -c "import win32evtlog"` + a real `EvtSubscribe` bind probe on
     `System`. **If this probe fails, STOP and report.** Do not run
     acquisition against an interpreter that cannot bind the API.
  5. **No automatic interpreter fallback.** A dependency or bind failure is
     reported, not routed around by installing a different Python — that
     would silently change the runtime the proof is about. The supported
     runtime is declared in
     `apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md`, and changing it is a
     decision recorded there.

### S6 · FIRST-READ VOLUME: ~80K RETAINED SYSMON RECORDS

A fresh bookmark starts at `EvtSubscribeStartAtOldestRecord`
(`framework/windows_eventlog.py:335-336`), `max_events_per_read` defaults
to 500, and the scheduler interval defaults to 60s
(`framework/scheduler.py:24`). A full Sysmon backfill is therefore ~160
reads of 500 into the preview backend.

* **DECIDED — bounded 60-minute window for the first correctness proof.**
  A Windows-side XPath filter of the last 60 minutes per channel, declared
  in the connector configuration and reported in the proof metadata as
  **`G1_VALIDATION_SCOPE_BOUND`**. It must not be presented as telemetry
  loss, as a successful historical backfill, or as complete channel
  coverage. Windows applies the filter server-side, so nothing is read and
  discarded.
* Historical / backfill volume testing (the ~80K retained Sysmon records)
  remains a **separate later test**: it measures a different property and
  would mix volume behaviour into an acquisition-correctness proof.

---

## 3 · Server-side preparation (NivXRay XDR, preview)

Target: `https://greeting-app-5782.preview.emergentagent.com` — verified
reachable from outside the container (`GET /api/health` → 200) and
fail-closed on ingest (`POST /api/xdr/ingest/telemetry` unauthenticated →
403). `NIVX_TENANT_REGISTRY_ENFORCE=true`, so tenancy must exist before
anything else.

Executed by me, in this order, once S1/S2 are decided:

1. **Organisation + tenant** — `POST /api/xdr/organizations`
   (`slug: g1-windows-proof-org`, `kind: VENDOR`), then
   `POST /api/xdr/tenants` (`slug: g1-windows-proof`, `products: ["XDR","EDR"]`).
   No existing tenant is reused: G1's tenant-isolation proof needs a tenant
   whose entire content was created by G1.
2. **Second tenant** — `g1-windows-isolation` — exists only to receive the
   cross-tenant refusal proof. Nothing ever delivers to it successfully.
3. **Collector enrolment** — `POST /api/xdr/collectors`:
   ```json
   { "name": "g1-windows-endpoint",
     "protocol": "windows-eventlog",          // S2 closed
     "authorized_sources": ["microsoft-sysmon",
                            "windows-security-evd",
                            "windows-powershell-evd"],
     "auth_kind": "none", "tls": true }
   ```
   The response `id` (`col_…`) is THE `collector_id`. It becomes
   `NIVX_COLLECTOR_ID` on the endpoint and one third of the bookmark scope.
   Verified vocabulary: the adapter declares `sysmon` / `windows_security` /
   `windows_powershell`, which `services/source_routing.py:110-124` resolves
   to exactly these three catalog keys — one declared source → one DSM, no
   widening.
4. **Ingest credential** — `POST /api/xdr/api-keys` with
   `scopes: ["collectors.enroll"]` and nothing else, `confirm_tenant_id`
   restated. The plaintext is shown once, goes straight into the endpoint's
   environment, and is **never** written to chat, a log, a report or the
   repo (`memory/test_credentials.md` records only its `prefix`).
5. **Isolation credential** — one key in `g1-windows-isolation`, used only
   to prove that key + a foreign `X-Tenant-Id` / foreign `collector_id` is
   refused.
6. **Baseline snapshot** — record, before any Windows delivery:
   `xdr_collectors` counters (`events_received/parsed/normalized`, `state`),
   `xdr_canonical_events` count for the tenant, `xdr_ingest_routing_blocks`
   count. A proof needs a before, not only an after.

---

## 4 · Endpoint preparation (Windows host)

Read-only with respect to Windows configuration: no Sysmon install, no
channel enabling, no registry write, no service install, no audit-policy
change. The only things created are a venv, a state directory and a
connector record.

1. `cd C:\nivx` · fetch + hard-reset to `origin/feature/rc2-alignment` ·
   re-verify the 10-file SHA-256 manifest · **STOP on any mismatch**.
2. Establish the interpreter per **S5** (ensurepip → venv → deps → bind
   probe). Record `python -V`, `pywin32` build, and the `EvtSubscribe`
   probe result into the run report.
3. `New-Item C:\ProgramData\NivXForge\state` (per **S4**), ACL to
   Administrators + SYSTEM only.
4. Environment for the acquisition process (elevated console; nothing
   persisted to the registry, nothing global):
   | Var | Value |
   | --- | --- |
   | `NIVX_INGEST_URL` | `https://greeting-app-5782.preview.emergentagent.com/api/xdr/ingest/telemetry` |
   | `NIVX_INGEST_TOKEN` | the minted key (sent as `X-XDR-API-Key`; **not** a bearer token — `framework/delivery.py:91-103`) |
   | `NIVX_INGEST_AUTH_MODE` | `api_key` |
   | `NIVX_TENANT_ID` | `g1-windows-proof` |
   | `NIVX_COLLECTOR_ID` | the `col_…` id from §3.3 |
   | `XDR_STATE_DIR` | `C:\ProgramData\NivXForge\state` |
   | `XDR_AUTO_START_CONNECTORS` | `1` |
5. **Seed the connector record.** The standalone control plane **fails
   closed by design** — `framework/authz.py:27-40` refuses every
   non-webhook route with `COLLECTOR_AUTH_UNAVAILABLE`, because a
   standalone collector has no identity, RBAC or tenant authority to
   authenticate against. So the connector is NOT created over HTTP. It is
   written to `${XDR_STATE_DIR}\connectors.json` in the exact
   `ConnectorRecord` shape (`framework/store.py:27-37`) and the service's
   lifespan rehydrates and auto-starts it (`main.py:88-139`):
   ```json
   { "connectors": [ {
     "id": "windows-eventlog-g1proof01",
     "tenant_id": "g1-windows-proof",
     "source_type": "windows-eventlog",
     "label": "G1 Windows endpoint",
     "config": { "profile_id": "windows-validation",
                 "collector_id": "col_…",
                 "interval_seconds": 60,
                 "max_events_per_read": 500,
                 "scope_bound": "G1_VALIDATION_SCOPE_BOUND",
                 "filters": {
                   "Microsoft-Windows-Sysmon/Operational":
                     "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]",
                   "Security":
                     "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]",
                   "Microsoft-Windows-PowerShell/Operational":
                     "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]"
                 }
               },
     "created_at": "…", "updated_at": "…", "enabled": true } ] }
   ```
6. Start elevated: `C:\nivx\.venv\Scripts\python.exe -m uvicorn main:app
   --host 127.0.0.1 --port 8080` from `C:\nivx\apps\nivxray-xdr-collector`.
   Bound to loopback only — the control plane is fail-closed and has no
   business being reachable.
7. **Observability without the control plane.** `GET /health` is
   unguarded (`main.py:205-228`) and already reports `rehydration`,
   `ingest`, `outbox` and `worker`. Everything else is read directly from
   `${XDR_STATE_DIR}\outbox.db` (`envelopes` table, `windows_channel_state`
   table) with `sqlite3`. No guarded route is called, nothing is
   loosened to make the proof convenient.

---

## 5 · Proof matrix — every G1 requirement, and what evidences it

| # | Required proof | Evidence, and where it comes from |
| --- | --- | --- |
| 1 | Real `EvtSubscribe` acquisition | `NativeEvtReader` bound (not `UnsupportedPlatformReader`); `/health` shows the connector started; `windows_channel_state.reads/events_read > 0` for all three channels |
| 2 | Raw XML preservation | `envelopes.payload.raw.xml` byte-compared against `wevtutil qe <channel> /q:"*[System[EventRecordID=N]]" /f:xml` for a named record on each channel |
| 3 | Sysmon acquisition | ≥1 canonical event, `declared_source=sysmon → microsoft-sysmon`, `selected_dsm_id=microsoft-sysmon` |
| 4 | Security acquisition | ≥1 canonical event via `windows-security-evd`; proves elevation held |
| 5 | PowerShell acquisition | ≥1 canonical event via `windows-powershell-evd` (`detection_coverage: NOT AVAILABLE` stated, not hidden) |
| 6 | Stable collector identity | `NIVX_COLLECTOR_ID` == enrolled `col_…`; unchanged across both restarts; `bind()` refuses a second tenant (`collector_identity.py:44-52`) |
| 7 | Durable-before-bookmark-advance | For one read: `envelopes` rows exist **before** `windows_channel_state.bookmark_xml` changes; `runtime.deliver_windows()` returns the durable channel set and only those advance (`runtime.py:70-95,118-128`) |
| 8 | Collector restart / resume | Stop uvicorn, generate new events, restart → `resume_for()` returns `RESUME_FROM_BOOKMARK`, and the new events arrive with **no** re-delivery of old ones |
| 9 | Host reboot / resume | Full Windows reboot, restart the process → same as #8 across a kernel boundary; `last_boot` in the report proves the reboot happened |
| 10 | Mid-delivery interruption / recovery | Kill the process while rows are `DELIVERING` → on boot they are reset to `QUEUED` (`outbox.py:186-190`) and drain; bookmark did NOT advance past them |
| 11 | Duplicate / loss accounting | Re-deliver a known `source_event_id` → server receipt reports `DUPLICATE`, no second raw/canonical/detection chain; loss is separately accounted by `log_cleared` + record-id gaps, never as zero |
| 12 | Three-clock separation | Per event: `activity_occurred_at` (XML `UtcTime`/`TimeCreated`), `sensor_observed_at` (collector read instant, declared in `canonical.sensor_observed_at`), `nivx_received_at` (server receipt) — three DISTINCT values. **S1 closed: the activity clock can no longer populate the sensor boundary.** |
| 13 | Raw → canonical provenance | `provenance.ingest.identity.raw_ref` on the canonical event resolves to the stored raw row, and that raw row's XML is the one from #2 |
| 14 | Tenant isolation | Same key + `X-Tenant-Id: g1-windows-isolation` → 403 `TENANT_ISOLATION_VIOLATION`; foreign `collector_id` → 404 that does not disclose existence (`xdr_ingest.py:788-834`) |
| 15 | Server collector-enrolment match | Envelope `collector_id` matched to `xdr_collectors.id` **and** its `tenant_id`; unenrolled id → 404, no evidence created |
| 16 | Canonical evidence identity | `canonical_evidence_id` present on every accepted event and resolvable through the P1 Evidence Namespace Bridge |
| 17 | Per-channel truth states | Collection / Parsing / Normalization / Detection / Forensic-availability stated separately per channel from `CHANNELS` + `ANALYSIS_SUPPORTED` + measured counts. `PARTIAL` and `NOT AVAILABLE` are printed as-is |
| 18 | Event Explorer / evidence verification | The three channels' events are retrievable in the tenant-scoped UI by `canonical_evidence_id`, `origin_computer` and channel, verified by Playwright DOM script (no screenshots) |

---

## 6 · B4 gap capture (observe, do not fix)

B4 stays **mandatory and unwaived**. Step 2 records it as measured
behaviour, exactly as ordered, with no code change:

* A 4th channel (`System`, declared `windows_system`) is acquired in a
  **separate** connector and delivered. `windows_system` is absent from
  `SOURCE_CATALOG` and `SOURCE_ALIASES`, so the batch is refused
  `UNSUPPORTED_SOURCE`, is written to `xdr_ingest_routing_blocks`, and
  produces **no raw row and no canonical evidence**.
* That is the defect in one line: telemetry that was AUTHORIZED, DECLARED
  and ACQUIRED is **discarded because no DSM understands it**. Parsing
  capability is deciding retention. Raw forensic evidence must survive the
  absence of comprehension.
* Step 2 will record this as a **FAIL / GAP**, never as a PASS, with the
  block rows as evidence. B4 is not changed to make the acquisition proof
  green; it closes later as its own bounded engineering gate, after the
  native acquisition path is proven.

---

## 7 · Out of scope for Step 2 (explicit)

G2, ETW, native WMI API telemetry, Endpoint Event Journal, DSM expansion,
Windows sensor expansion, Dense Timeline, Sensor Clock Mapping beyond the
minimal S1 correction, Control Center, Hunting and Event Explorer
modernization, Vercel (tracked separately; it does not touch the G1
ingestion path), and the L3 `llm_decoder` shutdown hang.

No Windows feature is installed or enabled to manufacture coverage. No
channel that is truthfully `NOT_PRESENT` or `PRESENT_DISABLED` is made to
look collected.
