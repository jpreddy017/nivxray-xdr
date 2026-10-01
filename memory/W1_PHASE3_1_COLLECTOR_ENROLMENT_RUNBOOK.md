# W1 PHASE 3.1 — WINDOWS COLLECTOR ENROLMENT · OWNER-SIDE RUNBOOK
# STOPPED BEFORE CREDENTIAL CREATION (by the owner's own security rule)

Target backend: `https://nivxray.nivxforge.com` (aligned build `8e473e4`)
Host: DESKTOP-A9HGFJJ · declared source: `microsoft-sysmon`
Nothing created by the agent. No collector, no key, no forwarder.json, no
ingest.key, no telemetry, no bookmark movement.

## WHY THE AGENT CANNOT EXECUTE 3.1A / 3.1B

1. `POST /api/xdr/collectors` and `POST /api/xdr/api-keys` are RBAC-gated
   (`collectors.create`, `api_keys.create`) and require a bearer JWT from the
   PRODUCTION user store. This workspace holds no production credential
   (verified: production login rejects the workspace values with 401; the
   production admin password is deliberately not recorded here). Obtaining it
   would require pasting a secret into the chat — forbidden.
2. Even with authority, `create_key` returns the plaintext in the HTTP
   response body (`routers/xdr_api_keys.py:186-191`). Any agent-executed call
   would place one-time secret material into tool output and the transcript —
   a direct violation of the Phase 3.1 security rule.

Therefore: owner-side execution, on DESKTOP-A9HGFJJ, in Windows PowerShell 5.1.
The plaintext key never leaves that machine.

## STEP 0 — SESSION (password never typed in clear, never in history)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Api = 'https://nivxray.nivxforge.com'
$email = Read-Host 'admin email'
$sec   = Read-Host 'admin password' -AsSecureString
$pw    = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
           [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$tok = (Invoke-RestMethod -Method Post -Uri "$Api/api/auth/login" `
         -ContentType 'application/json' `
         -Body (@{ email=$email; password=$pw } | ConvertTo-Json)).access_token
$pw  = $null
$H = @{ Authorization = "Bearer $tok" }
```

## STEP 0b — DISCOVER THE AUTHORITATIVE TENANT (do not guess)

```powershell
(Invoke-RestMethod -Uri "$Api/api/xdr/rbac/session-context" -Headers $H).data |
  ConvertTo-Json -Depth 5
```
Read `tenant_scope.tenant_ids` / `active_customer.value`. That value is
`$Tenant` below. Control-plane tenant resolution reads the `X-Tenant-Id`
header (`xdr_collectors.py:79-86`, `xdr_api_keys.py:54-61`) and defaults to
`default` if omitted — so ALWAYS send it explicitly.

```powershell
$Tenant = '<value from above>'
$H2 = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = $Tenant }
(Invoke-RestMethod -Uri "$Api/api/xdr/collectors" -Headers $H2).data.count
(Invoke-RestMethod -Uri "$Api/api/xdr/collectors/sources/catalog" -Headers $H2).data.sources.'microsoft-sysmon'
```
Expect: current collector count (0 expected) and a `microsoft-sysmon` catalog
entry naming exactly one DSM.

## STEP 3.1A — ENROL EXACTLY ONE COLLECTOR

```powershell
$body = @{
  name               = 'DESKTOP-A9HGFJJ Sysmon'
  protocol           = 'rest'
  tls                = $true
  auth_kind          = 'bearer'
  description        = 'W1 acceptance - genuine Windows 10 host, Sysmon EventLog pull'
  authorized_sources = @('microsoft-sysmon')
  tags               = @('w1','windows','sysmon')
} | ConvertTo-Json
$col = (Invoke-RestMethod -Method Post -Uri "$Api/api/xdr/collectors" `
         -Headers $H2 -ContentType 'application/json' -Body $body).data
$col | Select-Object id,tenant_id,protocol,implementation,transport,tls,state,
       state_reason,authorized_sources,events_received | Format-List
```
Contract guarantees (`xdr_collectors.py:352-407`):
- `state = ADOPTED`, `state_reason = created`; `CONNECTED` is refused to the
  admin API (`CONNECTED_REQUIRES_TELEMETRY`, line 248) — only the ingest path
  may set it.
- all telemetry counters start at 0 / `last_event_at = null`.
- `authorized_sources` is validated at configuration time; a misspelling fails
  with `UNSUPPORTED_SOURCE` instead of silently authorizing nothing.
- `protocol=rest` is `IMPLEMENTED`, transport `https`.
- `tenant_id` is taken from `X-Tenant-Id` and is the binding.
Record `id` (`col_...`). It is NOT secret.

## STEP 3.1B — ONE SCOPED, SHORT-LIVED INGEST CREDENTIAL

Minimum scope established by the existing contract: the ingest endpoint is
gated by `collectors.enroll` only (`xdr_ingest.py`). The forwarder calls no
other endpoint, so `scopes = @('collectors.enroll')` — nothing else.

```powershell
$exp = (Get-Date).ToUniversalTime().AddHours(72).ToString('yyyy-MM-ddTHH:mm:ssZ')
$kb = @{
  name              = 'w1-desktop-a9hgfjj-sysmon'
  confirm_tenant_id = $Tenant
  description       = 'W1 acceptance ingest key - Sysmon forwarder on DESKTOP-A9HGFJJ'
  scopes            = @('collectors.enroll')
  expires_at        = $exp
} | ConvertTo-Json
$k = (Invoke-RestMethod -Method Post -Uri "$Api/api/xdr/api-keys" `
       -Headers $H2 -ContentType 'application/json' -Body $kb).data

# plaintext goes STRAIGHT to the ACL'd file - never echoed, never in a variable dump
New-Item -ItemType Directory -Force 'C:\ProgramData\NivXRay\config' | Out-Null
[IO.File]::WriteAllText('C:\ProgramData\NivXRay\config\ingest.key',
                        $k.plaintext, [Text.UTF8Encoding]::new($false))
$k | Select-Object id,name,tenant_id,prefix,scopes,expires_at,enabled | Format-List
$k = $null; Remove-Variable k -ErrorAction SilentlyContinue
[GC]::Collect()
```
`confirm_tenant_id` must equal the resolved tenant or the mint is refused
(`TENANT_CONFIRMATION_MISMATCH`). If the tenant owns no control-plane object
yet the mint is refused with `UNKNOWN_TENANT` — re-send with
`allow_new_tenant = $true` ONLY if that tenant is genuinely new. Only the
SHA-256 hash is stored server-side; the plaintext is shown once and never
again. Safe to report back: `id`, `prefix` (12 chars), `scopes`,
`expires_at`. NEVER the plaintext.

## STEP 3.1C — WINDOWS CONFIGURATION

`C:\ProgramData\NivXRay\config\forwarder.json` (ASCII, no BOM):
```json
{
  "ApiBaseUrl":  "https://nivxray.nivxforge.com",
  "TenantId":    "<authoritative tenant id>",
  "CollectorId": "col_<from 3.1A>",
  "SourceLabel": "microsoft-sysmon",
  "BatchSize":   5
}
```
```powershell
$cfg = @{ ApiBaseUrl='https://nivxray.nivxforge.com'; TenantId=$Tenant;
          CollectorId=$col.id; SourceLabel='microsoft-sysmon'; BatchSize=5 } |
       ConvertTo-Json
[IO.File]::WriteAllText('C:\ProgramData\NivXRay\config\forwarder.json', $cfg,
                        [Text.ASCIIEncoding]::new())
```
Contract notes: the four required fields are `ApiBaseUrl`, `TenantId`,
`CollectorId`, `SourceLabel` (line 101); `ApiBaseUrl` must match `^https://`
(line 106); `BatchSize` defaults to 200 when absent (line 110) — hence the
explicit 5. `declared_source` is a script constant `microsoft-sysmon`
(line 67) and is NOT configurable; `SourceLabel` only fills the informational
`source` field, set equal to the declaration for consistency.

## STEP 3.1C(ii) — KEY ACL (required by the forwarder)

The forwarder REFUSES to read the key if `Everyone`, `BUILTIN\Users` or
`Authenticated Users` hold any ACE (lines 117-127). It reads the file raw and
`.Trim()`s it, so a trailing newline is tolerated; an empty file is refused.

```powershell
$kp = 'C:\ProgramData\NivXRay\config\ingest.key'
icacls $kp /inheritance:r
icacls $kp /grant:r "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
icacls $kp /remove:g "Everyone" "BUILTIN\Users" "NT AUTHORITY\Authenticated Users"
icacls $kp
(Get-Acl $kp).Access | Select-Object IdentityReference,FileSystemRights | Format-Table
```
Expected final ACL: SYSTEM and BUILTIN\Administrators only.

## STEP 3.1D — STOP. NO TRANSMISSION.

Do NOT run the forwarder without `-DryRun`. Do NOT send the ~5,000-event
backlog. The bookmark must not move. The collector must stay `ADOPTED`.
Windows is not collected/live. `_COLLECTED_PRODUCTS` stays `{"linux"}`.

## PHASE 3.1 ACCEPTANCE — report back (non-secret only)

1. collector `id`, `tenant_id`, `protocol`, `tls`, `state`, `state_reason`,
   `authorized_sources`, `events_received`
2. key `id`, `prefix`, `scopes`, `expires_at`, `enabled`
3. `icacls` output for `ingest.key`
4. `forwarder.json` contents with `TenantId`/`CollectorId` shown (non-secret)

Phase 3.2 (separate approval) = ONE bounded authenticated transmission,
BatchSize 5, then trace the exact `source_event_id` values
(`<Computer>|<record_id>`) through routing -> raw evidence -> Sysmon DSM ->
canonical evidence + provenance, and the receipt counters.

B3 (machine-path audit attribution from authenticated identity rather than
`X-Principal-*` headers) remains separately tracked.
