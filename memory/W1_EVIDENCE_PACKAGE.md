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

### W1-C · field-level provenance — **PASS** (owner-executed query B, 2026-06)
Query B returned **exactly 5** ACCEPTED rows for `col_2c20bb28ac744be48f67`,
every one satisfying the full PASS bar: authoritative tenant correct, collector
correct, `routing_result=ACCEPTED`,
`routing_authority=AUTHENTICATED_COLLECTOR_DECLARATION`,
`declared_source = declared_source_resolved = selected_dsm_id =
microsoft-sysmon`, `content_compatible=True`,
`authorization_relationship=DECLARED_SOURCE_IN_COLLECTOR_ALLOWLIST`,
`at_basis=provenance.timestamps.nivx_received_at` with a non-null ingest
timestamp, unique non-null `trace_id`, non-null canonical `evidence_ref`.
The contract below is therefore no longer contract-only — it is observed on the
five real rows.

#### the contract that those rows satisfy (retained for the record)
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

Query B (§3) observed all five rows carrying exactly these fields, so the
contract is now evidenced, not assumed.

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
| W1-C | field-level provenance | **PASS** | owner-executed query B — 5/5 ACCEPTED rows meet the full bar | nothing |
| W1-D | authoritative tenant attribution | **PASS** | tenant resolved from the authenticated collector, header mismatch = 403 | nothing |
| W1-E | `source_event_id` identity + dedup | **NOT PROVEN** | E1 not exposed by any read API · E2 contract proven 34/34 on identical code, never exercised in production | E1: the five id strings (no send needed) · E2: your decision on the §4 replay |
| W1-F | collector-state truth | **PASS** | `CONNECTED` unreachable from the admin API; only ingest writes it | nothing (optional: audit row) |

**W1 IS NOT CLOSED — 5/6 PASS.** A · B · C · D · F closed on authoritative
evidence. **W1-E alone remains**, and it does not need a new five-event send.

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

#### 3.1 · CORRECTION (2026-06) — the block above is WITHDRAWN, use §3.2

Owner-executed result: `$L5` returned **1696992** (bookmark confirmed), then
`Get-WinEvent` threw
`EventLogException: The description string for parameter reference (%1) could
not be found`. Root cause: the block passes **`-ErrorAction Stop`** while
enumerating the *whole* channel, so the first record whose provider metadata
cannot be rendered terminates the entire pipeline. A `-FilterHashtable` +
`Where-Object` fallback also scanned the (very large) channel without
returning and was correctly interrupted. Two defects in one block: unbounded
enumeration, and dependence on description rendering.

#### 3.2 · W1-E1 · targeted, render-free, XPath-bounded (authoritative)

`EventLogQuery` + `EventLogReader` with `ReverseDirection`, reading **only**
`ToXml()`. The event-log service applies the XPath predicate, so the channel is
never enumerated; `ToXml()` returns the raw record and never renders a
description, so the `%1` fault cannot occur. It also derives
`source_event_id` from `System.Computer` + `System.EventRecordID` — exactly
how `ConvertTo-RawEvent` built the value that was transmitted.

```powershell
$L5 = 1696992
$q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
       'Microsoft-Windows-Sysmon/Operational',
       [System.Diagnostics.Eventing.Reader.PathType]::LogName,
       "*[System[EventRecordID<=$L5]]")
$q.ReverseDirection = $true
$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
$out = @()
try {
  while ($out.Count -lt 5 -and ($null -ne ($ev = $reader.ReadEvent()))) {
    $x = [xml]$ev.ToXml()
    $out += [pscustomobject]@{
      source_event_id = '{0}|{1}' -f $x.Event.System.Computer,
                                     $x.Event.System.EventRecordID
      sysmon_event_id = [int]$x.Event.System.EventID
      provider        = $x.Event.System.Provider.Name
      time_created    = $x.Event.System.TimeCreated.SystemTime
      record_id       = [int64]$x.Event.System.EventRecordID
    }
    $ev.Dispose()
  }
} finally { $reader.Dispose() }
$out | Sort-Object record_id | Format-Table -AutoSize
```

PASS bar: exactly 5 rows; `record_id` ascending and ending at 1696992;
`source_event_id` of the form `DESKTOP-A9HGFJJ|<record_id>`; `provider`
containing `Sysmon`; `sysmon_event_id ∈ {1,3,11,12,13,14,22}`.

#### 3.3 · CORRECTION 2 (2026-06) — §3.2 WITHDRAWN, two defects

Owner-executed result: §3.2 returned **zero rows, no error** — `ReadEvent()`
answered `$null` on the first call, so the structured query matched nothing.
Two separate defects, one of which is a **correctness** defect that would have
produced the WRONG five even if it had returned rows:

1. **Wrong identity predicate (correctness).** `Get-PendingEvents` does not
   select "the records after the bookmark" — it selects
   `*[System[EventRecordID > $AfterRecordId and (EventID=1 or EventID=3 or
   EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=22)]]`
   (`NivXRay-SysmonForwarder.ps1:204-206`). The transmitted five are therefore
   the five highest **supported-EventID** records at or below 1696992, not the
   five highest records of any kind. §3 and §3.2 both omitted the EventID
   predicate and are wrong on that point.
2. **Query form.** The forwarder's own proven form is `Get-WinEvent -LogName
   -FilterXPath` with **whitespace around the relational operator**
   (`EventRecordID > n`). §3.2 emitted `EventRecordID<=1696992` with no
   spaces into an `EventLogQuery`; the event-log XPath parser matched nothing
   and, via `EventLogReader`, failed silently rather than throwing.

#### 3.4 · W1-E1 · authoritative (mirrors the forwarder's own query) + diagnostics

Same channel, same relational form, same EventID predicate as the code that
selected the five. Bounded by `-MaxEvents 5`, newest-first, so the service
returns the five highest matching records ≤ 1696992 and nothing else. Fields
are read from `ToXml()`, so no description is ever rendered. If zero rows come
back it prints the query, the count, the channel's newest/oldest record ids and
the underlying error instead of returning silently.

```powershell
$L5  = 1696992
$ch  = 'Microsoft-Windows-Sysmon/Operational'
$ids = ((1,3,11,12,13,14,22) | ForEach-Object { "EventID=$_" }) -join ' or '
$xpath = "*[System[EventRecordID <= $L5 and ($ids)]]"
"channel : $ch"
"xpath   : $xpath"

$evts = @()
try   { $evts = @(Get-WinEvent -LogName $ch -FilterXPath $xpath -MaxEvents 5 -ErrorAction Stop) }
catch { "QUERY ERROR : $($_.Exception.GetType().FullName): $($_.Exception.Message)" }
"records returned : $($evts.Count)"

if ($evts.Count -gt 0) {
  $evts | ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      source_event_id = '{0}|{1}' -f $x.Event.System.Computer,
                                     $x.Event.System.EventRecordID
      sysmon_event_id = [int]$x.Event.System.EventID
      provider        = $x.Event.System.Provider.Name
      time_created    = $x.Event.System.TimeCreated.SystemTime
      record_id       = [int64]$x.Event.System.EventRecordID
    }
  } | Sort-Object record_id | Format-Table -AutoSize
} else {
  "--- diagnostics (read-only) ---"
  try { "newest RecordId in channel : $((Get-WinEvent -LogName $ch -MaxEvents 1 -ErrorAction Stop).RecordId)" }
  catch { "newest probe error : $($_.Exception.Message)" }
  try { "oldest RecordId available  : $((Get-WinEvent -LogName $ch -Oldest -MaxEvents 1 -ErrorAction Stop).RecordId)" }
  catch { "oldest probe error : $($_.Exception.Message)" }
  try { $li = Get-WinEvent -ListLog $ch -ErrorAction Stop
        "log mode / records / maxMB : $($li.LogMode) / $($li.RecordCount) / $([math]::Round($li.MaximumSizeInBytes/1MB,1))" }
  catch { "listlog error : $($_.Exception.Message)" }
  try { "exact-id probe rows        : $(@(Get-WinEvent -LogName $ch -FilterXPath "*[System[EventRecordID = $L5]]" -MaxEvents 1 -ErrorAction Stop).Count)" }
  catch { "exact-id probe error : $($_.Exception.Message)" }
  try { "no-EventID-filter probe    : $(@(Get-WinEvent -LogName $ch -FilterXPath "*[System[EventRecordID <= $L5]]" -MaxEvents 1 -ErrorAction Stop).Count)" }
  catch { "no-EventID probe error : $($_.Exception.Message)" }
}

"--- forwarder log corroboration (local file read) ---"
Select-String -Path 'C:\ProgramData\NivXRay\logs\forwarder.log' `
              -Pattern 'pending records after bookmark' |
  Select-Object -Last 3 -ExpandProperty Line
```

PASS bar: exactly 5 rows; `record_id` ascending, ending at **1696992**;
`source_event_id` = `DESKTOP-A9HGFJJ|<record_id>`; `provider` contains
`Sysmon`; `sysmon_event_id ∈ {1,3,11,12,13,14,22}`.

Diagnostic readings that would explain a second zero: `oldest RecordId
available > 1696992` means the channel has rolled and the five are no longer
on the endpoint (identity must then come from the receipt JSON, not the log);
`no-EventID-filter probe = 1` while the full query returns 0 would isolate the
EventID predicate; a non-empty `QUERY ERROR` names the parser fault outright.

---

## 4 · W1-E2 · SAME-FIVE ENDPOINT REPLAY — **WITHDRAWN 2026-09-18, UNEXECUTABLE**

The §4 procedure below assumed the five records were still in the local Sysmon
channel. They are not. Owner-executed §3.4 diagnostics:

```
records returned           : 0
newest RecordId in channel : 1827133
oldest RecordId available  : 1751184
log mode / records / maxMB : Circular / 75950 / 64
```
Transmission was `2026-09-18T10:01:42Z`; at `~11:36Z` the channel had advanced
to 1827133 — **130,141 records in ~95 minutes** against a 75,950-record
circular capacity. `1696988–1696992` are below the oldest surviving record
1751184 and were overwritten. This is expected behaviour of a 64 MB circular
channel on a busy host; it says nothing about the transmission, which W1-A…D
and F already proved.

Consequences:
* rewinding the bookmark can no longer re-read those five records, so the
  procedure below **cannot be run** and must not be attempted. Rewinding now
  would forward *different*, newer events — i.e. new telemetry, not a replay.
* the only remaining behavioural route is to replay the **stored** envelopes:
  production still holds each `raw` payload in `xdr_canonical_events`, and the
  dedupe identity is `sha256(raw)` with no transport fields, so re-posting a
  stored raw reproduces the identical key. That requires §3.5 first.
* **retention clock:** `complete()` arms `retention_at = now + 14 days`
  (`ingest_idempotency.py:267-292`). Elapsed at time of writing: ~95 minutes.
  So the five claims are live, but any behavioural proof must happen inside
  that 14-day window — after it, the TTL purges the claims and a replay would
  be counted as **new** telemetry (`events_received` 5 → 10), which would
  damage the W1-A evidence. This is now the real deadline on W1-E2.

### 3.5 · W1-E1 · THE FIVE IDENTITIES ARE PERSISTED IN PRODUCTION — DB READ REQUIRED

Not recoverable from the receipt: the forwarder logs only the aggregate line
(`Write-ForwarderLog`), and `Write-RefusedRows` writes **only** non-accounted
outcomes — `refused_recorded=0`, so nothing was written
(`NivXRay-SysmonForwarder.ps1:296-304`). `$receipt` was function-scoped inside
`Invoke-ForwardCycle` and is gone from the session.

But production **did** persist them, twice:

| collection | field | written by |
|---|---|---|
| `xdr_ingest_dedupe` | `source_event_id` (+ `key`, `status`, `delivery_count`, `duplicate_count`, `trace_id`, `canonical_event_id`, `retention_at`) | `event_identity()` / `claim()` / `complete()` |
| `xdr_live_reasoning_audit` | `outcomes[].source_event_id` — the full `ReasoningOutcome` set, i.e. the receipt itself | `xdr_ingest.py:597-605` |
| `xdr_canonical_events` | `source_event_id` + the `raw` payload | `xdr_ingest.py:880-917` |

**No HTTP endpoint reads any of the three.** Verified: `xdr_canonical_events`
appears only inside `xdr_ingest.py`; `xdr_ingest_dedupe` and
`xdr_live_reasoning_audit` appear in no router at all. So W1-E1 is closable
only by an owner-executed **read-only query against the production database**
(no new telemetry, no replay, no code change), or by adding a read-only admin
endpoint (a code change, which is out of scope until authorised).

Owner-executed, production DB, `find` only — no insert/update/delete/drop.
Use the production store, never `test_database`.

```javascript
// E1-a · PRIMARY — closes W1-E1 identity and, on stored-record evidence, W1-E2
db.xdr_ingest_dedupe.find(
  { tenant_id: "ten_e759b7288598bd882e3dcac49d",
    collector_id: "col_2c20bb28ac744be48f67" },
  { _id: 0, source_event_id: 1, key: 1, source: 1, status: 1, stage: 1,
    outcome: 1, delivery_count: 1, duplicate_count: 1, payload_digest: 1,
    trace_id: 1, canonical_event_id: 1, observation_id: 1, incident_id: 1,
    raw_row_id: 1, first_seen_at: 1, completed_at: 1, retention_at: 1 }
).sort({ first_seen_at: 1 })

// E1-b · CORROBORATION — the persisted receipt
db.xdr_live_reasoning_audit.find(
  { tenant_id: "ten_e759b7288598bd882e3dcac49d" },
  { _id: 0, at: 1, envelopes: 1, reasoned: 1, observations_created: 1,
    incidents_promoted: 1, "outcomes.source_event_id": 1,
    "outcomes.trace_id": 1, "outcomes.status": 1,
    "outcomes.selected_dsm_id": 1, "outcomes.routing_result": 1,
    "outcomes.dedupe_key": 1 }
).sort({ at: -1 }).limit(1)

// E1-c · OPTIONAL — the five raw rows (also the source material for a
// stored-envelope replay, if W1-E2 is to be closed behaviourally)
db.xdr_canonical_events.find(
  { tenant_id: "ten_e759b7288598bd882e3dcac49d",
    collector_id: "col_2c20bb28ac744be48f67" },
  { _id: 1, source_event_id: 1, source: 1, collection_method: 1,
    parser_ok: 1, normalized_ok: 1, nivx_received_at: 1,
    received_at_source: 1, received_at_substituted: 1, ingested_at: 1 }
).sort({ ingested_at: 1 })
```

**PASS bar · W1-E1** (from E1-a): exactly **5** documents; five distinct
`key`s; `source_event_id` of the form `DESKTOP-A9HGFJJ|<record_id>` ascending
and **ending at 1696992**; `source = microsoft-sysmon`; every `trace_id`
matching one of the five trace ids already returned by the W1-C query.
E1-b must independently show `envelopes: 5`, `reasoned: 5` and the same five
ids with `status: REASONED`.

**PASS bar · W1-E2 on stored-record evidence** (same query): all five
`status = COMPLETED`, `delivery_count = 1`, `duplicate_count = 0`,
`canonical_event_id` non-null, `retention_at` ≈ transmission + 14 days, and a
unique index on `key` (`db.xdr_ingest_dedupe.getIndexes()` → `uniq_event_key`,
`unique: true`). With the contract probe already at 34/34 on the identical
module, that fixes every input to the dedupe decision and makes
`DUPLICATE` the only reachable outcome for a replay. The one thing it still
does not contain is an *observed* duplicate — that needs the replay.

## 4 · (superseded — retained for the record)

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
