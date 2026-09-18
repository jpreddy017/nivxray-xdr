# W1 EVIDENCE PACKAGE — first genuine Windows Sysmon transmission

Host `DESKTOP-A9HGFJJ` · collector `col_2c20bb28ac744be48f67` ·
tenant `ten_e759b7288598bd882e3dcac49d` ("Internal Validation") ·
production `nivxray.nivxforge.com`.

Read-only. No code, configuration, deployment, credential, tenant data or
telemetry was changed. Nothing was replayed. No new events were requested.

---

## 0 · WHAT I COULD AND COULD NOT READ — STATED BEFORE ANY VERDICT

**I have no production credential and did not ask for one.** Verified in this
session:

```
GET https://nivxray.nivxforge.com/api/health                     200
GET https://nivxray.nivxforge.com/api/xdr/tenants                403 ACCESS_DENIED (unauthenticated)
GET https://nivxray.nivxforge.com/api/xdr/collectors             403
GET https://nivxray.nivxforge.com/api/xdr/ingest/routing/...     403 / Not authenticated
```
`NIVXPW` is unset in this workspace; `backend/.env` holds `MONGO_URL=mongodb://localhost:27017`
and `DB_NAME=test_database` — the **preview** store, not production. So there is
no authenticated production read and no production DB query available to me.

Therefore every verdict below rests on exactly three evidence classes, each
labelled per criterion:

| class | what it is | authority |
|---|---|---|
| **R** | the `TelemetryReceipt` your forwarder logged | **produced by the production ingest route itself** — backend-authoritative, merely transported through your console |
| **C** | the deployed code contract | `git diff 9ae7bdac..HEAD` over `xdr_ingest.py`, `ingest_idempotency.py`, `xdr_collectors.py`, `xdr_ingest_routing.py`, `sysmon_dsm.py`, `source_routing.py` = **empty**, so this workspace's code is byte-identical to what production runs |
| **P** | a preview-only execution of that identical module | proves behaviour, not production row state |

A criterion is marked **PASS** only where R+C together make the outcome
impossible to fake. Where the five actual stored rows are required, it is
marked **NOT PROVEN** — not PASS.

### Receipt under examination (your paste, verbatim)
```
sent=5 accepted=5 duplicates=0 resumed=0 routing_blocked=0
reasoned=5 refused_recorded=0 collector_state=CONNECTED
```

### DryRun vs live — your observation confirmed
`NivXRay-SysmonForwarder.ps1` reads the bookmark only when `-DryRun` is absent
(`:320`) and the DryRun branch (`:326`) returns **before** any
`Set-Bookmark` (`:396`).
So the dry run genuinely moved nothing and `1696775–1696779` are **not** the
transmitted set. The runbook's W1-E clause "…and match the dry run exactly" is
**void** and is not used anywhere below. The live window beginning `1696988` is
the only identity authority.

---

## 1 · PASS / FAIL PER CRITERION

### W1-A · ingestion truth — **PASS** (R + C)
* `accepted` is incremented **only** inside the `fresh` loop and **only** when
  `e.parser_ok and e.normalized_ok` (`xdr_ingest.py:867-870`). `accepted=5`
  with `duplicates=0 resumed=0 routing_blocked=0` means all five envelopes
  were `FRESH` claims — nothing was a retry, nothing resumed, nothing refused.
* Each `FRESH` envelope's raw row is inserted into `xdr_canonical_events`
  before reasoning (`:913-917`), and `events_received` is incremented by
  `len(fresh)` in a single atomic `$inc` (`:940-948`) which also sets
  `last_event_at`.
* `refused_recorded=0` is the forwarder's own count of receipt outcomes whose
  status is outside `{REASONED, DUPLICATE, RESUME_FROM_RAW, STITCHED_INTO}`
  (`NivXRay-SysmonForwarder.ps1:369-381`) — no envelope came back unaccounted.
* Five raw rows, five counted events, one real host. **PASS.**

Strengthener (non-secret, already in your hand): the receipt's
`collector_state_reason` string embeds the freshly written counters verbatim —
`"telemetry received/parsed/normalized: 5/5/5"` (`:979-985`). Paste that one
line and W1-A is closed on the collector row too.

### W1-B · Sysmon DSM / canonical normalization — **PASS** (R + C)
* `routing_blocked=0` means `source_routing.route()` returned `ACCEPTED` for
  every envelope. `ACCEPTED` is only reachable when the envelope **declares**
  a source, the declaration **resolves in the catalog**, it is **in the
  collector's allowlist**, and the payload is **content-compatible with that
  DSM** — otherwise the delivery is refused as `DECLARATION_REQUIRED` /
  `UNSUPPORTED_SOURCE` / `SOURCE_NOT_AUTHORIZED` / `SOURCE_FORMAT_MISMATCH`
  with no raw row, no canonical evidence and no counter movement
  (`xdr_ingest.py:640-688`).
* The forwarder declares `microsoft-sysmon` (`forwarder.json.SourceLabel` →
  `envelope.declared_source`), so the selected DSM is `SysmonDSM.id =
  "microsoft-sysmon"`, whose `supports()` requires `provider` containing
  `"Sysmon"` and `event_id ∈ {1,3,11,12,13,14,22}`
  (`sysmon_dsm.py:484-501`). Non-Sysmon content could not have satisfied it.
* `accepted=5` additionally requires `parser_ok` **and** `normalized_ok` on all
  five; any failure would have surfaced as `parse_errors` / `normalize_errors`
  and lowered `accepted`.
* `reasoned=5` means all five produced `status=REASONED` through the existing
  canonical-evidence → detection → IUE/ICE/VEEE chain. **PASS.**

### W1-C · field-level provenance — **NOT PROVEN** (C only)
The provenance *contract* is unambiguous and fail-closed:
* raw row carries `tenant_id`, `collector_id`, `source`, `source_event_id`,
  `collection_method`, `parser_version`, `event_type`, `source_timestamp`,
  `nivx_received_at`, plus the D11 honesty fields `received_at_source` and
  `received_at_substituted` (`xdr_ingest.py:880-912`);
* canonical evidence carries `provenance.routing` (`routing_result`,
  `routing_authority = AUTHENTICATED_COLLECTOR_DECLARATION`,
  `declared_source`, `declared_source_resolved`,
  `collector_authorized_sources`, `selected_dsm_id`, `content_compatible`),
  `provenance.ingest` (`collector_id` + `collector_id_source`,
  `payload_shape`, `raw_envelope_ref`) and
  `provenance.timestamps.nivx_received_at`
  (`xdr_ingest_routing.py:131-181`).

But I have **not observed the five rows**. A contract is not evidence. This
criterion stays NOT PROVEN until one read-only query is run — see §3 query B.
It is the smallest remaining gap and it costs one GET.

### W1-D · authoritative tenant attribution — **PASS** (R + C, + P for the refusal)
* The ingest route does **not** trust the header. It loads the collector by
  the authenticated principal and takes `owner_ten = coll_doc["tenant_id"]`;
  a header that disagrees is refused `403 TENANT_ISOLATION_VIOLATION`
  (`xdr_ingest.py:724`, `:731`, `:753`, `:760`). Acceptance therefore *proves* the header tenant
  equalled the collector's own tenant — the one you configured,
  `ten_e759b7288598bd882e3dcac49d`.
* Every raw row, every counter `$inc` and every routing-block row is written
  under that resolved tenant, never the header value (`:796-948`).
* Tenancy is registry-only and enforced: an unregistered tenant id is refused
  `403 TENANT_NOT_FOUND — "tenancy is established only by POST /api/xdr/tenants;
  collector creation, API-key creation, endpoint enrolment, telemetry and
  incident creation never create a tenant"`. I observed exactly that refusal
  shape live against this identical code in preview during this session. **PASS.**

### W1-E · exact `source_event_id` identity + deduplication — **NOT PROVEN** (split)

**E1 · the exact five ids — NOT PROVEN, and not obtainable from any production
read-only API.** This is the significant finding of this package:
`xdr_ingest_routing._accepted_row()` deliberately returns
`"source_event_id": None` with
`source_event_id_basis = "NOT_CARRIED_INTO_CANONICAL_EVIDENCE — the collector's
own event id is not persisted on the evidence row; the evidence ref and trace
id identify this delivery"` (`xdr_ingest_routing.py:165-171`). The ids **are**
persisted, in `xdr_canonical_events.source_event_id` and
`xdr_ingest_dedupe.source_event_id`, but **no HTTP endpoint reads either
collection** (`grep` over `backend/routers`: `xdr_canonical_events` appears
only inside `xdr_ingest.py`; `xdr_ingest_dedupe` appears in no router at all).
So on the accepted path, production can prove *which five deliveries* by
`trace_id` / `evidence_ref`, but cannot hand back the collector's own id
strings. Two non-secret, no-send ways to close E1 are in §3 (query A2 and the
local Sysmon read) — neither requires a replay and neither touches production.

**E2 · the deduplication / idempotency contract — contract PASS, production
instance NOT PROVEN.** `duplicates=0` means production has never yet been
asked to dedupe anything, so no stored production record *demonstrates* it.
What I could prove without production access: I executed the byte-identical
deployed module against Sysmon-shaped identities
`DESKTOP-A9HGFJJ|1696988…1696992` in the preview store
(`scripts/w1e_dedupe_contract_probe.py`) — **34/34 checks PASS**:

```
first delivery of each of the five        FRESH            (5/5)
five distinct delivery keys              5
replay of each of the five               DUPLICATE        (5/5)
  duplicate_count after one replay       1                (5/5)
  delivery_count after one replay        2                (5/5)
  original trace_id reported back        exact match      (5/5)
a NEW record id                          FRESH  (not suppressed)
same id + different payload              FRESH  (no payload-only suppression)
same delivery in another tenant          FRESH  (tenants independent)
unique index on the delivery key         present
RESULT: CONTRACT PROVEN (preview, deployed code)
```
Identity is `sha256(tenant | collector | source | source_event_id |
sha256(raw))` (`ingest_idempotency.py:139-158`), claimed atomically against a
unique index, and a terminal claim answers `DUPLICATE` without creating a
second raw row, canonical event, detection or incident
(`xdr_ingest.py:806-854`).

I also confirmed the replay would be *recognisable*: `ConvertTo-RawEvent`
derives `raw` **only** from the Sysmon event XML, and the envelope carries no
`collection_timestamp` and no `received_at`
(`NivXRay-SysmonForwarder.ps1:150-193`), so a re-send of the same record
produces a byte-identical digest and therefore the identical dedupe key.

**Verdict for W1-E: NOT PROVEN.** Per your ordering I checked stored evidence
first; the stored records that would settle E2 (`xdr_ingest_dedupe` claims in
`COMPLETED`) are not exposed by any read-only surface. The safe same-five
replay procedure is in §4 — **I have not executed it and will not without your
explicit instruction.**

### W1-F · collector-state truth — **PASS** (R + C)
* `CONNECTED` is absent from the admin transition table and is explicitly
  refused to the admin API with `CONNECTED_REQUIRES_TELEMETRY`
  (`xdr_collectors.py:169-179`, `:258-264`). The comment is enforced, not
  aspirational.
* The only writer of `CONNECTED` is the ingest route, which recomputes state
  from the counters it just wrote in the same request and stamps
  `state_evidence {received, parsed, normalized, errors, by, at}`
  (`xdr_ingest.py:951-1003`).
* The receipt returned `collector_state=CONNECTED`, which is that post-write
  computation ⇒ `received>0 ∧ parsed>0 ∧ normalized>0` with error ratio ≤10%.
  The transition cannot have been asserted by a human or by the UI. **PASS.**

Strengthener: `GET /api/xdr/audit-log?action=COLLECTOR_STATE_CHANGED` will show
`before {state: ADOPTED} → after {state: CONNECTED}` with an **api-key**
principal and the counter evidence attached (`xdr_ingest.py:1004-1017`).

---

## 2 · SUMMARY TABLE

| # | criterion | verdict | basis | what is missing |
|---|---|---|---|---|
| W1-A | ingestion truth | **PASS** | receipt + route contract | nothing (optional: `collector_state_reason` line) |
| W1-B | Sysmon DSM / canonical normalization | **PASS** | receipt + fail-closed routing + `SysmonDSM.supports()` | nothing (optional: `selected_dsm_id` on the rows) |
| W1-C | field-level provenance | **NOT PROVEN** | contract only | one read-only GET — query B |
| W1-D | authoritative tenant attribution | **PASS** | tenant resolved from the authenticated collector, header mismatch = 403 | nothing |
| W1-E | `source_event_id` identity + dedup | **NOT PROVEN** | E1 not exposed by any read API · E2 contract proven 34/34 on identical code, never exercised in production | E1: the five id strings (no send needed) · E2: your decision on the §4 replay |
| W1-F | collector-state truth | **PASS** | `CONNECTED` unreachable from the admin API; only ingest writes it | nothing (optional: audit row) |

**W1 IS NOT CLOSED.** Four of six criteria are closed on authoritative
evidence. Two remain, and neither needs a new five-event send.

---

## 3 · THE READ-ONLY QUERIES THAT CLOSE W1-C AND W1-E1

Owner-executed, in your own authenticated session — no credential comes from
this workspace and none is requested. `$H2` = your bearer + `X-Tenant-Id`.
All four are GETs.

```powershell
$col = 'col_2c20bb28ac744be48f67'

# A · collector row (closes the W1-A strengthener and the W1-F audit)
(Invoke-RestMethod -Headers $H2 -Uri "$Api/api/xdr/collectors/$col").data |
  Select-Object id,tenant_id,state,state_reason,events_received,events_parsed,
                events_normalized,events_error,events_duplicate,
                events_routing_blocked,last_event_at | Format-List

# A2 · state evidence + the audit trail that proves ingest set CONNECTED
(Invoke-RestMethod -Headers $H2 -Uri `
  "$Api/api/xdr/audit-log?action=COLLECTOR_STATE_CHANGED&resource_kind=collector&limit=10"
) | ConvertTo-Json -Depth 6

# B · W1-C · the five accepted deliveries, field level
(Invoke-RestMethod -Headers $H2 -Uri `
  "$Api/api/xdr/ingest/routing/deliveries?collector_id=$col&result=ACCEPTED&limit=50").rows |
  Select-Object at,at_basis,tenant_id,collector_id,collector_id_basis,
                routing_result,routing_authority,declared_source,
                declared_source_resolved,selected_dsm_id,content_compatible,
                authorization_relationship,collection_method,payload_shape,
                trace_id,evidence_ref | Format-Table -AutoSize

# C · W1-D negative control (must refuse, must leak no row)
$HX = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = 'ten_not_registered_0000' }
try { Invoke-RestMethod -Headers $HX -Uri `
        "$Api/api/xdr/ingest/routing/deliveries?collector_id=$col" }
catch { $_.ErrorDetails.Message }      # expect TENANT_NOT_FOUND
```

**PASS for W1-C requires, on exactly 5 rows:** `routing_result=ACCEPTED`,
`routing_authority=AUTHENTICATED_COLLECTOR_DECLARATION`,
`declared_source=declared_source_resolved=microsoft-sysmon`,
`selected_dsm_id=microsoft-sysmon`, `content_compatible=true`,
`authorization_relationship=DECLARED_SOURCE_IN_COLLECTOR_ALLOWLIST`,
`tenant_id=ten_e759b7288598bd882e3dcac49d`, `collector_id=col_2c20…`, a
non-null `trace_id` and a non-null `evidence_ref`.

### W1-E1 · the five id strings, with no send and no bookmark movement
Purely local, purely read. The forwarder selects records **forward** from the
bookmark, ascending, `BatchSize=5`, and advances the bookmark to the **last**
record of the chunk (`:396`), so the five transmitted records are the five with
the highest ids at or below the current bookmark:

```powershell
$bm = Get-Content 'C:\ProgramData\NivXRay\state\sysmon-bookmark.json' -Raw |
      ConvertFrom-Json
$L5 = [int64]$bm.LastRecordId
$L5                                     # expect the 5th of the live five

$five = @()
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop |
  ForEach-Object {
    if ($_.RecordId -le $L5 -and $five.Count -lt 5) { $five += $_ }
  }
$five | Sort-Object RecordId |
  Select-Object @{n='source_event_id';e={'{0}|{1}' -f $_.MachineName,$_.RecordId}},
                Id, ProviderName, TimeCreated | Format-Table -AutoSize
```
Expect five rows, ids ascending from `DESKTOP-A9HGFJJ|1696988`, `ProviderName`
containing `Sysmon`, `Id ∈ {1,3,11,12,13,14,22}`. Reading the event log does
not move the bookmark, does not read the key and sends nothing.

---

## 4 · IF — AND ONLY IF — YOU CHOOSE TO CLOSE W1-E2 BEHAVIOURALLY

**Not executed by me.** This replays the **same five already-ingested
events**; it never advances the bookmark past its current value and never
sends a new event. Run §3 and the E1 block first, so you know the five ids
before touching the bookmark.

Why it is safe, from the code: a recognised duplicate creates **no** raw row,
**no** canonical event, **no** detection and **no** incident — it only
increments `events_duplicate` on the collector, `delivery_count` /
`duplicate_count` on the existing claim, and `duplicate_delivery_count` on any
incident the original produced (`xdr_ingest.py:806-864`). The locked
`events_received` counter is explicitly not touched by a retry (`:936-948`), so
the `CONNECTED` gate cannot be inflated.

```powershell
$bmPath = 'C:\ProgramData\NivXRay\state\sysmon-bookmark.json'
$saved  = Get-Content $bmPath -Raw          # KEEP THIS. It is the rollback.
$saved

$firstId = ($five | Sort-Object RecordId | Select-Object -First 1).RecordId
@{ LastRecordId = ([int64]$firstId - 1)
   UpdatedUtc   = (Get-Date).ToUniversalTime().ToString('o') } |
  ConvertTo-Json | Set-Content -Encoding UTF8 $bmPath

Set-Location C:\NivX\forwarder
.\NivXRay-SysmonForwarder.ps1 -MaxEvents 5     # exactly one chunk of 5

[IO.File]::WriteAllText($bmPath, $saved)       # restore verbatim
Get-Content $bmPath -Raw
```

Rules: rewind by **exactly** those five (`firstId - 1`), never further; use
`-MaxEvents 5`; run it **once**; restore `$saved` immediately afterwards even
if the run errors.

**PASS for W1-E2 requires** the second receipt to read
`sent=5 accepted=0 duplicates=5 resumed=0 routing_blocked=0 refused_recorded=0`,
and the §3 query A afterwards to show `events_received` **still 5** with
`events_duplicate = 5`. Any other shape — especially `accepted>0` — is a FAIL
and must stop the run.

---

## 5 · SIDE FINDING (no action taken, reported for the record)

`backend/tests/test_p0_ingest_idempotency.py` and
`backend/tests/test_p0_dedupe_hardening.py`: **7 passed, 25 errors** in this
workspace. Every error is the same fixture failure — the module fixtures
`POST /api/xdr/collectors` for an ad-hoc tenant id that was never registered,
so the now-enforced tenant registry answers `403 TENANT_NOT_FOUND`. This is
**test drift behind tenant-registry enforcement, not an ingest defect**: the
pure-contract tests pass, and my independent probe of the same module scored
34/34. Worth a P1 fixture fix (register the tenant first) so the dedupe
regression gate is armed again. No code was changed in this session.
