# DEV RESET & FRESH TELEMETRY · approved direction · awaiting execution authority

Supersedes the recovery/preservation workflow: history, the Windows outbox and
the processing-queue backlog are **disposable test data**. Identity is still
preserved — not because the events matter, but because a deterministic
`endpoint_id` is the thing being validated.

**Nothing in this document has been executed.** Phases 1, 2 and 2a are
read-only; phases 3 and 4 are irreversible.

## PHASE 0 · decisions — APPROVED 2026-10-19

| # | Decision | Approved value | Script setting |
|---|---|---|---|
| D1 | Scope | **Tenant-wide** cleanup of obsolete development EDR telemetry and enrolment data | filters are `tenant_id = ten_e759…cac49d`, every collection |
| D2 | EDR configuration, groups, policies, tenant settings | **RETAIN** | `KEEP_CONFIG = true` |
| D3 | Enrolment and policy audit | **RETAIN** | `KEEP_AUDIT = true` |
| D4 | XDR artefacts built on this telemetry | **No broken references.** Retire the dependent *obsolete development* evidence in the same pass; preserve unrelated XDR | `CASCADE_XDR = true` + the MIXED guard below |
| D5 | Snapshot | **Real Atlas snapshot id recorded first** | `SNAPSHOT` must be non-empty or the script refuses |

Priority stated by the owner: eliminate unnecessary test-data storage and
processing cost first, then fresh Windows enrolment and live ingestion.

### D4 · how "dependent" is decided

The join is the one the code itself persists (`services/evidence_bridge.py`
owner contract). It is deterministic — no name, hash, timestamp or proximity
matching anywhere:

```
edr_raw_events.raw_id
  → xdr_canonical_evidence      provenance.source_kind = "sensor"
                                provenance.trust_state = "AUTHENTICATED"
                                provenance.collector_id       ∈ EDR endpoints
                                additional_fields.endpoint_id ∈ EDR endpoints
                                provenance.trace_id = the originating raw_id
  → v2_shadow_observations      origin = "collector-live"
                                collector_id / connector_id   ∈ EDR endpoints
                                event.raw.raw_evidence_ref.collection
                                                        = "edr_raw_events"
  → workspace_cases             endpoint_campaign.endpoint_id ∈ EDR endpoints
                                xdr_pipeline.source_provenance.collector_id
  → dependents                  <collection>.incident_id ∈ those incident ids
```

**Correction to the earlier note on `raw_ref`.** The EDR bridge stamps
`raw_ref = {raw_id, collection}` on the canonical dict
(`edr_plane/canonical_bridge.py:560`), but the row actually persisted by
`detection_content/xdr_pipeline.py:421` is re-derived from the sensor payload
and carries **no** `raw_ref` pointer — verified against real sensor rows:
`raw_ref.raw_id` exists on **0** documents, while 344,566 rows carry
`provenance.source_kind = "sensor"` + `trust_state = "AUTHENTICATED"`. The
authenticated-sensor provenance above is therefore the authoritative join; a
`raw_ref`-based scope would have deleted nothing and left every reference
dangling. This is why the scope is measured before it is executed.

**The MIXED guard.** An incident that cites *any* canonical evidence which is
not from an EDR endpoint of this tenant is classified `MIXED` and is **never
deleted** — it is listed by id for a human decision. Only incidents whose every
cited evidence row is EDR-derived (or already absent) are retired. Unrelated
incidents are not even considered.

## FINAL DELETION SCOPE · production counts, 2026-10-19

Source: read-only count inventory against the serving database
`greeting-app-5782-test_database`, run
`4067c54d-e252-4243-a214-27a9f17715bc`
(`/app/deployer-agent-docs/RCA_4067c54d-e252-4243-a214-27a9f17715bc.MD`).
`count` / `find` / `distinct` only — no write, no deploy.

### Endpoints in scope (D1 is tenant-wide, so BOTH go)

| endpoint | host | state | event_count |
|---|---|---|---|
| `ep_1989031c8c1d0085812f` | DESKTOP-A9HGFJJ | REVOKED | 157,226 |
| `ep_a67be48d5b4e01d4d9e8` | KUSHU | **ENROLLED** | 34,488 |

**KUSHU is still enrolled.** Tenant-wide means it is deleted too and
disappears from the console until it re-enrols. If that is not intended, say
so and the scope narrows to `endpoint` before anything runs.

### To delete

| collection | documents |
|---|---|
| `edr_raw_events` | 1,877,149 *(less pinned, see below)* |
| `edr_processing_queue` | 1,718,750 |
| `edr_finding_evaluations` | 301,539 |
| `edr_rejected_telemetry` | 25,750 |
| `edr_acquisition_gaps` | 2,786 |
| `edr_endpoint_address_observations` | 29 |
| `edr_delivery_counters` | 6 |
| `edr_acquisition_integrity` | 3 |
| `edr_policy_endpoint_state` | 2 |
| `edr_endpoints` | 2 |
| `edr_agent_credentials` | 2 |
| `edr_findings`, `edr_response_commands`, `edr_endpoint_exclusion_enforcement`, `edr_agent_sessions`, `edr_enrollment_tokens` | 0 |
| **EDR subtotal** | **3,926,018** |
| `xdr_canonical_evidence` (D4, EDR-derived) | 149,161 |
| `v2_shadow_observations` (D4, EDR-derived) | 149,174 |
| **TOTAL** | **≈ 4,224,353** |

Absent collections: `edr_compromise_events`, `edr_isolation_policy`,
`edr_tenant_boundary`, `edr_connector_deployments`.

### To retain

`edr_policies` 1 · `edr_groups` 1 · `edr_policy_versions` 1 ·
`edr_enrollment_audit` 14 · `edr_policy_audit` 4,426 · `edr_saved_views` 0
(D2/D3), plus:

* **5** `xdr_canonical_evidence` rows the EDR selectors do not claim
  (149,166 tenant − 149,161 EDR-attributed) — the tenant's own non-EDR evidence
* **4** `v2_shadow_observations` not matched by the EDR reference selectors
* **9** `v2_shadow_observations` belonging to **other tenants** (149,187 total −
  149,178 tenant) — out of scope by the tenant filter, never touched
* all **48** `workspace_cases` documents

### The D4 cascade is empty — and that is a finding, not an assumption

`workspace_cases` holds **0** `xdr_incident` documents for this tenant
(E1 = 0), so there are no EDR-derived incidents, no MIXED cases, no UNKNOWN
cases and **no dependents to delete**. The eight dependent collections are
untouched. The classification machinery stays armed anyway, because it is what
proves the cascade is empty rather than merely assumed — and because the same
script will be correct once incidents do exist.

### The three D4 safety checks, as implemented

1. **Tenant-scoped dependents.** A dependent is deleted only when it carries
   *this* tenant's id or no tenant stamp at all. One carrying another tenant's
   id **aborts the armed run** (S2).
2. **UNKNOWN evidence.** An incident citing a canonical event that does not
   resolve is **preserved**, never deleted. Absent is not "mine to delete".
3. **MIXED preservation, with entanglement propagation.** An incident citing
   any non-EDR evidence is preserved. And if a dependent cites *both* a
   deletable and a preserved incident, preserving that dependent would leave a
   live reference to a deleted incident — so the deletable incident is
   **promoted to preserved** instead, repeated to a fixpoint. The rehearsal
   caught exactly this: before propagation the verification reported 1 dangling
   dependent; after it, 0.

Plus **evidence pinning**, the other direction of the same rule: canonical
events cited by preserved incidents, and every raw event still referenced by a
surviving row (`provenance.trace_id`,
`event.raw.raw_evidence_ref.raw_id`), are pinned out of all sweeps. This is why
`edr_raw_events` is "1,877,149 less pinned" — the exact pin count prints in the
dry run.

## PREREQUISITE VERIFICATION · second read-only pass, 2026-10-20

### Exact deletion counts after evidence pinning

`KEEP_RAW` resolves to **0 existing rows**, so the raw sweep is the full
**1,877,149**. The five surviving `xdr_canonical_evidence` rows cite trace ids
shaped `live_3eee147edfa74fa5`, `live_5b8470579b8145c4`,
`live_6267f80b081d4ae2`, `live_bfded2f28d7247d7`, `live_fd512680a4ed4117`.

**Those are not EDR raw ids and never were.** `live_<16hex>` is minted by
`routers/xdr_ingest.py:564` — the direct XDR ingest API — whereas
`edr_raw_events.raw_id` is `raw_<24hex>` (`edr_plane/raw_events.py:143`). So
these five rows belong to the XDR ingest path, not to the sensor, and deleting
EDR telemetry cannot orphan them. The inventory flagged them as "already
dangling"; that reading is wrong, and no repair is required. They are
preserved, and they are *why* the evidence selector is provenance-based rather
than tenant-wide.

The four unmatched `v2_shadow_observations` carry no `raw_id` at all, so they
contribute nothing to the pin set and are likewise preserved.

| final scope | documents |
|---|---|
| EDR telemetry + identity | **3,926,018** |
| `xdr_canonical_evidence` (D4) | 149,161 |
| `v2_shadow_observations` (D4) | 149,174 |
| **TOTAL** | **4,224,353** |

### Zero unintended XDR dependencies

* `xdr_detection_matches` — **does not exist** in this database
* `xdr_spread_sightings` — **does not exist**
* `xdr_correlation_matches` — exists, **globally empty** (0 of 0)
* `xdr_ingest_dedupe` — exists, **globally empty** (0 of 0)

The evidence-keyed stage is therefore a no-op here. It stays in the script
because those collections exist in other environments and will exist here once
detection content runs — and because a no-op that *proves* it is a no-op is
worth more than an assumption.

### Tenant isolation

* **0** unstamped documents across all 16 EDR collections — a tenant-scoped
  delete leaves nothing behind
* `edr_raw_events` with a different tenant: **0**; `edr_endpoints` distinct
  `tenant_id`: exactly one value
* `workspace_cases`: 0 incidents, 0 documents of *any* `doc_type` for this
  tenant, and **0** incidents about these endpoints under any other tenant —
  so MIXED, UNKNOWN and the whole dependent cascade are empty **by
  measurement**
* **Correction to the inventory's summary:** two EDR collections are *not*
  single-tenant. `edr_rejected_telemetry` holds 25,992 overall against 25,750
  for this tenant, and `edr_finding_evaluations` 301,549 against 301,539 —
  so **242 + 10 = 252 documents belong to another tenant and are preserved by
  the tenant filter.** That is the filter doing its job, and it is the reason
  no sweep here is written as a bare collection wipe.

### Execution note · 1.8M rows

There is no `raw_id`-prefixed index (`events_keyset` is
`{ingest_time, raw_id, tenant_id}`), so a bare `raw_id` filter collection-scans.
Because `KEEP_RAW` is empty, the script uses the plain tenant filter and the
tenant index. Sweeps above 200,000 documents run in committed 50,000-row
chunks with progress printed, so a multi-million-row delete cannot hit a client
timeout and a re-run simply resumes. Rehearsed on a scratch collection: 450
rows cleared in three chunks, 0 remaining.

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
so the failure that matters is "a servicing update removed it", and that shows
up at the next boot, not now. If `wmic` is ever absent the sensor falls back to
`machine_guid` and the platform mints a *different* endpoint.

**STOP** on: `wmic` not recognised, empty output, a changed ProcessorId, or
either hash not matching. Restore with
`DISM /Online /Add-Capability /CapabilityName:WMIC~~~~` and re-validate.

## PHASE 2 · backups (read-only, both sides)

1. **Atlas snapshot** of the serving cluster — Atlas console → cluster →
   Backup. Record the snapshot id and timestamp; the script refuses to arm
   without the id. This is the only rollback for phase 4.
2. Keep `C:\NivXForge-Recovery-Backup` as it is. Do not overwrite it.
3. Export the endpoint document before it is deleted (console or
   `GET /api/edr/onboarding/computers/ep_1989031c8c1d0085812f`), so the
   "before" numbers survive the reset.

## PHASE 2a · the impact report (read-only) — RUN THIS FIRST

```bash
mongosh "<MONGO_URL>" --file edr_d4_impact_report.mongosh.js
```

`edr_d4_impact_report.mongosh.js` contains **no** delete, update, insert, drop
or createIndex verb — only `countDocuments`, projected `find` and `collStats`.
It prints, for the production database:

* every EDR endpoint in the tenant with its raw-event count and counter
* per-collection delete candidates, and the retained config/audit counts
* the D4 blast radius: EDR-derived `xdr_canonical_evidence` and
  `v2_shadow_observations`, incidents split **EDR-ONLY / MIXED / unrelated**
* **discovered** dependents — it probes every `xdr_*` / `v2_*` collection for
  references to the EDR-ONLY incident ids, so the cleanup list comes from the
  data rather than from an assumption about naming
* remaining-after-cleanup totals, and data+index bytes per collection

Its section-4 output is what fills `DEPENDENTS` in the reset script. In a
rehearsal against a copy of this schema the discovered set was
`xdr_investigation_activity`, `xdr_investigations`,
`xdr_investigation_findings`, `xdr_iue_understanding`,
`xdr_framework_mappings`, `xdr_response_timeline`,
`xdr_intelligence_overlays`, `xdr_intelligence_overlay_audit` — the production
run must confirm or extend that list before phase 4.

## PHASE 3 · local purge (laptop; destructive, local only)

```powershell
sc.exe stop NivXForgeSensor
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe status      # record final state
C:\"Program Files"\NivXForge\NivXForgeEDRSetup.exe uninstall --purge
Get-ChildItem C:\ProgramData\NivXForge\sensor -ErrorAction SilentlyContinue
```

`--purge` is **correct here and only here**: it removes the state directory,
including `identity.json`, `outbox.jsonl`, `outbox.offset` and the journal.
The last command must show the directory gone or empty. The phase-2 backup is
untouched.

Do the local purge **before** the backend reset, so nothing in flight
re-creates a session or re-delivers a batch into the clean store.

## PHASE 4 · backend dev reset (irreversible)

```bash
mongosh "<MONGO_URL>" --file edr_dev_reset.mongosh.js        # DRY RUN first
```

The dry run prints the full plan and exits without writing. Review it against
D1-D4, then set `SNAPSHOT` to the phase-2 snapshot id and
`CONFIRM = "DELETE-EDR-DEV-DATA"` and re-run.

Deletion order is **leaf → root**, so an interrupted run leaves a smaller
consistent graph and never a dangling reference:

1. dependents of the EDR-ONLY incidents (`DEPENDENTS`, by `incident_id`)
2. the EDR-ONLY incidents themselves (`workspace_cases`)
3. evidence-keyed artefacts — `xdr_detection_matches` (`source:"sensor"`),
   `xdr_spread_sightings` (`collector_id ∈ EP`) and `xdr_correlation_matches`
   (`trace_id` matching a raw id), each excluding anything pinned. These key
   on the evidence rather than on an incident, so an incident-only cascade
   would have stranded them.
4. `v2_shadow_observations` — EDR-derived only
5. `xdr_canonical_evidence` — EDR-derived only
6. EDR telemetry: `edr_raw_events` (minus pinned raw ids),
   `edr_processing_queue`, `edr_rejected_telemetry`, `edr_acquisition_gaps`,
   `edr_acquisition_integrity`, `edr_delivery_counters`, `edr_findings`,
   `edr_finding_evaluations`, `edr_compromise_events`,
   `edr_endpoint_address_observations`, `edr_response_commands`,
   `edr_policy_endpoint_state`, `edr_endpoint_exclusion_enforcement`
7. EDR identity: `edr_endpoints`, `edr_agent_credentials`,
   `edr_agent_sessions`, `edr_enrollment_tokens`

Guarantees:

* **no `dropDatabase`, no collection drops** — indexes and validators survive,
  so the fresh enrolment writes into the same shapes
* every filter is tenant-scoped; other tenants are untouched
* MIXED incidents are listed, never written
* the script **refuses to run** if `KEEP_CONFIG` or `KEEP_AUDIT` is false —
  D2/D3 said retain, so a stray edit cannot quietly widen the scope
* verification pass: EDR collections and EDR-derived XDR rows must read 0,
  dangling dependents must read 0, retained config/audit must read non-zero

Rehearsed end-to-end on a scratch copy of this schema: planned 4,350,
deleted 4,350, verification 0 across every in-scope collection, 0 dangling
dependents, config/audit retained, the seeded MIXED incident and the unrelated
incident both still present.

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

**Expected:** the printed `endpoint_id` is **`ep_1989031c8c1d0085812f`** — the
same identity as before, because the mint is deterministic. A different value
means phase 1 was not re-validated; **STOP**.

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
two-channel demonstration — the sensor will report the third as missing, which
is itself correct behaviour worth showing.

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
| `GET /api/edr/enrollment/endpoints` | exactly **1** endpoint, `ep_1989031c8c1d0085812f` |
| `GET /api/edr/onboarding/computers/ep_1989031c8c1d0085812f` | ENROLLED / ACTIVE, `sensor_state` reporting, `event_count` rising **from 0**, `last_telemetry_at` and `last_heartbeat_at` within the last minute |
| EDR console → Computers → this computer | present, online, with events in the activity view |
| `GET /api/edr/enrollment/rejections` | **empty** — a rejection means the credential or the batch shape is wrong, not that the demo failed |
| `edr_raw_events` | rising, every document carrying `endpoint_ref = ep_1989031c8c1d0085812f` and **no other value** |
| `edr_processing_queue` | rising with raw events then draining — idempotent on `(tenant_id, raw_id)`, so a replay must not double-count |
| `edr_acquisition_gaps` | may contain LEADING/INTERIOR gap records: expected and correct after a purge, since the channel bookmarks restarted |
| XDR console (cases, search, dashboards) | still loads; EDR-derived cases are gone, unrelated and MIXED cases intact |

## ACCEPTANCE

All of: phase 1 passed twice (including after a reboot) · snapshot id
recorded · impact report reviewed and `DEPENDENTS` confirmed against it ·
local state directory gone and recreated clean · armed run's verification
reading 0 with **0 dangling dependents** and non-zero retained config/audit ·
`endpoint_id` unchanged · `event_count` rising from 0 · raw events attributed
to exactly one `endpoint_ref` · zero rejections · service Running · XDR console
still loads its own pages after the reset.

## STOP / ROLLBACK

| id | Trigger | Action |
|---|---|---|
| S1 | Phase 1 fails at any point, including the post-reboot run | Do not reset, do not enrol. Restore WMIC first |
| S2 | The impact report shows MIXED incidents, or dependents in collections not in `DEPENDENTS` | Stop. Extend the list or exclude the incident deliberately; nothing has been written |
| S3 | Armed run's verification does not read 0, or dangling dependents are non-zero | Stop. Do not enrol into a half-cleared store; restore the snapshot |
| S4 | Enrolment prints a different `endpoint_id` | Stop the service. The identity source changed between phase 1 and phase 5 — re-run phase 1 and report before any further enrolment |
| S5 | Rejections appear in phase 6 | Stop the service to end the loop; report the rejection codes. Do not mint another token |
| S6 | XDR pages break after the reset (not merely empty) | Restore the snapshot. Empty is expected; broken is a defect worth a fix, not a workaround |

Irreversibility: phases 3 and 4 cannot be undone from inside the application.
The phase-2 snapshot is the only rollback, and `--purge` is the only command in
this document that deletes local evidence.

## WHAT COULD NOT BE OBTAINED FROM HERE

* **Production counts — now OBTAINED.** The first attempt failed because the
  deployment tooling cannot execute arbitrary scripts. Re-expressed as plain
  `count` / `find` / `distinct` calls, it returned the full inventory, recorded
  above and in
  `/app/deployer-agent-docs/RCA_4067c54d-e252-4243-a214-27a9f17715bc.MD`.
  Remaining gap: **`collStats` / `dbStats` are not exposed to that tooling**,
  so byte sizes are unavailable from here — document counts stand in for them.
  The dry run prints the byte figures when it is run with database access.
* **The snapshot id (D5).** No tool here can see Atlas backup state and an id
  must never be inferred. Take the snapshot in the Atlas console and paste the
  real id into `SNAPSHOT`; the script refuses to arm without it.
