# W1 GO — FIVE GENUINE SYSMON EVENTS · OWNER-EXECUTED RUNBOOK
# Host DESKTOP-A9HGFJJ · tenant "Internal Validation" · production
# nivxray.nivxforge.com

The agent cannot execute any of this, for two unchanged reasons:
1. `POST /api/xdr/collectors` and `POST /api/xdr/api-keys` need a bearer JWT
   from the PRODUCTION user store. This workspace holds no production
   credential and will not ask you to paste one.
2. `create_key` returns the plaintext in the HTTP response body
   (`routers/xdr_api_keys.py:186-191`). An agent-executed mint would put
   one-time secret material into the transcript.
3. The five events must come from the real Sysmon channel on your laptop.
   Nothing the agent could send would be genuine.

So: Windows PowerShell 5.1, on DESKTOP-A9HGFJJ, as Administrator. The
plaintext key never leaves that machine. Report back only the non-secret
fields listed at the end.

---

## DELTA vs `W1_PHASE3_1_COLLECTOR_ENROLMENT_RUNBOOK.md` (read this first)

That runbook predates tenant-registry enforcement and Collector Auth P0. Two
statements in it are now WRONG:

| old runbook said | now |
|---|---|
| "control-plane tenant resolution … defaults to `default` if omitted" | there is NO default. Omitting `X-Tenant-Id` returns **403 `TENANT_REQUIRED`**; an unregistered value returns `TENANT_NOT_FOUND` |
| tenant discovered via `/api/xdr/rbac/session-context` | use **`GET /api/xdr/tenants`** (authenticated, needs no tenant header) — the registry is the authority |

Unchanged and verified against the deployed code: the forwarder posts to
`POST /api/xdr/ingest/telemetry`, gated by `require_permission("collectors.enroll")`
(`xdr_ingest.py:691-693`), authenticating with `X-XDR-API-Key` plus
`X-Tenant-Id`. Collector Auth P0 hardened `/api/xdr/collector/*` (the landed
collector control plane) — a different surface. **The forwarder path is
untouched by it.**

---

## STEP 0 · SESSION (password never echoed, never in history)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Api  = 'https://nivxray.nivxforge.com'
$email = Read-Host 'admin email'
$sec   = Read-Host 'admin password' -AsSecureString
$bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try {
  $pw  = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  $tok = (Invoke-RestMethod -Method Post -Uri "$Api/api/auth/login" `
            -ContentType 'application/json' `
            -Body (@{ email=$email; password=$pw } | ConvertTo-Json)).access_token
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  Remove-Variable pw, sec, bstr -ErrorAction SilentlyContinue
}
"token length : $($tok.Length)   (value not displayed)"
```
Login limiter: 5 failures / 300 s → 900 s lockout. Type carefully.

## STEP 0b · RESOLVE THE TENANT FROM THE REGISTRY (never guess, never type an id)

```powershell
$H = @{ Authorization = "Bearer $tok" }
$reg = (Invoke-RestMethod -Uri "$Api/api/xdr/tenants" -Headers $H).data
$reg.enforcing
$reg.tenants | Select-Object id,display_name,state,products | Format-Table

$T  = ($reg.tenants | Where-Object { $_.state -eq 'ACTIVE' }).id
$H2 = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = $T }
"resolved tenant : $T"
```
Expect `enforcing = True`, exactly one ACTIVE tenant, display name
`Internal Validation`. If more than one is ACTIVE, **STOP** and report — do not
pick one.

```powershell
(Invoke-RestMethod -Uri "$Api/api/xdr/collectors" -Headers $H2).data.count          # expect 0
(Invoke-RestMethod -Uri "$Api/api/xdr/collectors/sources/catalog" -Headers $H2).data.sources.'microsoft-sysmon'
```

## STEP 1 · ENROL EXACTLY ONE COLLECTOR

```powershell
$body = @{
  name               = 'DESKTOP-A9HGFJJ Sysmon'
  protocol           = 'rest'
  tls                = $true
  auth_kind          = 'bearer'
  description        = 'W1 acceptance - genuine Windows host, Sysmon EventLog pull'
  authorized_sources = @('microsoft-sysmon')
  tags               = @('w1','windows','sysmon')
} | ConvertTo-Json
$col = (Invoke-RestMethod -Method Post -Uri "$Api/api/xdr/collectors" `
          -Headers $H2 -ContentType 'application/json' -Body $body).data
$col | Select-Object id,tenant_id,protocol,implementation,transport,tls,state,
        state_reason,authorized_sources,events_received,last_event_at | Format-List
```
Expected: `state = ADOPTED`, `state_reason = created`, `events_received = 0`,
`last_event_at = null`, `tenant_id = $T`. `CONNECTED` is refused to the admin
API by design (`CONNECTED_REQUIRES_TELEMETRY`) — only the ingest path may set
it, which is what makes step 4 meaningful. Record `col_…` (not secret).

## STEP 2 · ONE MINIMUM-SCOPE, SHORT-LIVED INGEST CREDENTIAL

The forwarder calls exactly one endpoint, gated by one permission, so the scope
is one entry. Nothing else.

```powershell
$exp = (Get-Date).ToUniversalTime().AddHours(72).ToString('yyyy-MM-ddTHH:mm:ssZ')
$kb = @{
  name              = 'w1-desktop-a9hgfjj-sysmon'
  confirm_tenant_id = $T
  description       = 'W1 acceptance ingest key - Sysmon forwarder on DESKTOP-A9HGFJJ'
  scopes            = @('collectors.enroll')
  expires_at        = $exp
} | ConvertTo-Json
$k = (Invoke-RestMethod -Method Post -Uri "$Api/api/xdr/api-keys" `
        -Headers $H2 -ContentType 'application/json' -Body $kb).data

New-Item -ItemType Directory -Force 'C:\ProgramData\NivXRay\config' | Out-Null
[IO.File]::WriteAllText('C:\ProgramData\NivXRay\config\ingest.key',
                        $k.plaintext, [Text.UTF8Encoding]::new($false))
$k | Select-Object id,name,tenant_id,prefix,scopes,expires_at,enabled | Format-List
$k = $null; Remove-Variable k -ErrorAction SilentlyContinue; [GC]::Collect()
```
**Never** print `$k.plaintext`, never paste it anywhere. Only the SHA-256 hash
is stored server-side. Safe to report: `id`, `prefix`, `scopes`, `expires_at`,
`enabled`.

## STEP 3 · WINDOWS CONFIGURATION + KEY ACL

```powershell
$cfg = @{ ApiBaseUrl='https://nivxray.nivxforge.com'; TenantId=$T;
          CollectorId=$col.id; SourceLabel='microsoft-sysmon'; BatchSize=5 } |
       ConvertTo-Json
[IO.File]::WriteAllText('C:\ProgramData\NivXRay\config\forwarder.json', $cfg,
                        [Text.ASCIIEncoding]::new())

$kp = 'C:\ProgramData\NivXRay\config\ingest.key'
icacls $kp /inheritance:r
icacls $kp /grant:r "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
icacls $kp /remove:g "Everyone" "BUILTIN\Users" "NT AUTHORITY\Authenticated Users"
(Get-Acl $kp).Access | Select-Object IdentityReference,FileSystemRights | Format-Table
```
The forwarder REFUSES to read the key if `Everyone`, `BUILTIN\Users` or
`Authenticated Users` hold any ACE. Expected final ACL: SYSTEM and
BUILTIN\Administrators only.

## STEP 4 · DRY RUN FIRST — NO NETWORK, NO BOOKMARK MOVEMENT

```powershell
Set-Location C:\NivX\forwarder
.\NivXRay-SysmonForwarder.ps1 -DryRun -MaxEvents 5
```
Confirms parsing, the `microsoft-sysmon` declaration, supported event ids
(1, 3, 11, 12, 13, 14, 22) and the `source_event_id` shape
`<Computer>|<EventRecordID>`. Sends nothing. **Record the five
`source_event_id` values** — they are the identities the whole proof follows.

## STEP 5 · THE FIVE-EVENT TRANSMISSION (`-MaxEvents 5` is the cap that makes it five)

```powershell
.\NivXRay-SysmonForwarder.ps1 -MaxEvents 5
```
`-MaxEvents 5` truncates the pending set, `BatchSize=5` makes it one request,
and the bookmark advances only over those five. No `-Loop`. No bulk backlog.
No Sysmon configuration change. No detection tuning.

**Capture the receipt line from the log**
(`C:\ProgramData\NivXRay\logs\`):
```
sent=5 accepted=? duplicates=? resumed=? routing_blocked=? reasoned=? refused_recorded=? collector_state=?
```

## STEP 6 · EVIDENCE PACKAGE (read-only GETs)

```powershell
# 6a · collector must now be CONNECTED, by the ingest path only
(Invoke-RestMethod -Uri "$Api/api/xdr/collectors/$($col.id)" -Headers $H2).data |
  Select-Object id,tenant_id,state,state_reason,events_received,last_event_at,
                duplicate_delivery_count | Format-List

# 6b · routing + provenance per event
$d = (Invoke-RestMethod -Headers $H2 -Uri `
      "$Api/api/xdr/ingest/routing/deliveries?collector_id=$($col.id)&limit=25").rows
$d | Select-Object at,source_event_id,declared_source,routing_result,
                   selected_dsm_id,routing_authority,reason_code,tenant_id |
     Format-Table -AutoSize
$d.Count

# 6c · routing summary for this tenant
(Invoke-RestMethod -Headers $H2 -Uri "$Api/api/xdr/ingest/routing/summary") |
  ConvertTo-Json -Depth 6

# 6d · canonical evidence reachable by host identity
(Invoke-RestMethod -Headers $H2 -Uri "$Api/api/xdr/search?q=DESKTOP-A9HGFJJ") |
  ConvertTo-Json -Depth 5
```

## STEP 7 · TENANT-ATTRIBUTION FAIL-CLOSED CHECK (read-only)

```powershell
$H3 = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = 'ten_not_registered_0000' }
try { Invoke-RestMethod -Headers $H3 -Uri `
        "$Api/api/xdr/ingest/routing/deliveries?collector_id=$($col.id)" }
catch { $_.ErrorDetails.Message }      # expect TENANT_NOT_FOUND, never these rows
```

## STEP 8 · EXACTLY-ONCE PROOF (re-deliver the SAME five)

The bookmark advanced, so a normal re-run sends nothing. Rewind it by five
records — a local state file on your laptop, no platform mutation — and
re-deliver:

```powershell
$bm  = 'C:\ProgramData\NivXRay\state\sysmon-bookmark.json'
$cur = Get-Content $bm -Raw
$cur                                     # note LastRecordId before changing it
# the five record ids came from the STEP 4 dry run; rewind to the one BEFORE the first
@{ LastRecordId = <record_id immediately before the first of the five>
   UpdatedUtc   = (Get-Date).ToUniversalTime().ToString('o') } |
  ConvertTo-Json | Set-Content -Encoding UTF8 $bm

Set-Location C:\NivX\forwarder
.\NivXRay-SysmonForwarder.ps1 -MaxEvents 5

[IO.File]::WriteAllText($bm, $cur)       # restore the original bookmark
Get-Content $bm -Raw
```
Expected receipt: `accepted=0 duplicates=5`, and re-running **6a** must show
`events_received` **still 5** with `duplicate_delivery_count = 5`. Identity is
`source_event_id`; a retry is recorded honestly rather than double-counted.

---

## W1 ACCEPTANCE — PASS/FAIL PER CRITERION

| # | criterion | PASS requires |
|---|---|---|
| **W1-A** | ingestion | receipt `sent=5 accepted=5 refused_recorded=0`; 6a `events_received = 5`, `last_event_at` set |
| **W1-B** | canonical normalization | every delivery row `routing_result = ACCEPTED` with `selected_dsm_id` = the Sysmon DSM; receipt `reasoned = 5`, `routing_blocked = 0` |
| **W1-C** | provenance | 5 rows under `collector_id = col_…`, each carrying `declared_source = microsoft-sysmon`, a `routing_authority`, and an `ingest_time`; source stated as `…provenance.routing` |
| **W1-D** | tenant attribution | every row `tenant_id = <the ACTIVE tenant>`; collector `tenant_id` identical; STEP 7 refuses with `TENANT_NOT_FOUND` and leaks no row |
| **W1-E** | identity + dedup | the 5 `source_event_id` values are `DESKTOP-A9HGFJJ|<record_id>` and match the dry run exactly; re-delivery gives `accepted=0 duplicates=5`, `events_received` stays 5, `duplicate_delivery_count = 5` |
| **W1-F** | collector state truth | 6a `state = CONNECTED` with a `state_reason` naming telemetry — proving the ingest path set it, since the admin API refuses `CONNECTED` |

**Report back (non-secret only):** collector fields from STEP 1 and 6a · key
`id`/`prefix`/`scopes`/`expires_at`/`enabled` · the `icacls` result · the five
`source_event_id` values · both receipt lines · the STEP 6b table · STEP 7
refusal · STEP 6c summary. **Never** the key plaintext, the JWT, or any raw
event body you are not comfortable sharing.

If any criterion fails, STOP and paste the output — no retry loops, no Sysmon
config changes, no bulk sends. W1 is not closed until the evidence proves each
of A–F.
