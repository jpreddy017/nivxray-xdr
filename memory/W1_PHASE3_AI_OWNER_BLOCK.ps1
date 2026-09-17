# A-I PRODUCTION ENFORCEMENT ACCEPTANCE - owner-side, PowerShell 5.1
# Requires $tok already present in this session. $tok is NEVER printed.
# Read-only, except two deliberately-rejected negatives (D, G). G is gated
# behind a hard abort if enforcement is not confirmed ON in gate A.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = 'Stop'

if (-not $tok) { Write-Host 'ABORT: $tok is not set in this session.'; return }

$A  = 'https://nivxray.nivxforge.com'
$T  = 'ten_e759b7288598bd882e3dcac49d'
$O  = 'org_55f6dc202dbf8995369db989ad'
$H  = @{ Authorization = "Bearer $tok" }
$HT = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = $T }

function Show-Fail($label, $err) {
  $code = $null
  try { $code = $err.Exception.Response.StatusCode.value__ } catch {}
  $body = $null
  try { $body = $err.ErrorDetails.Message } catch {}
  if (-not $body) { $body = $err.Exception.Message }
  "{0} :: HTTP {1} :: {2}" -f $label, $code, ($body -replace '\s+',' ')
}

Write-Host "=== A-I ENFORCEMENT ACCEPTANCE  publish 100 / build 8833215 ==="
Write-Host ("UTC: " + (Get-Date).ToUniversalTime().ToString('s') + "Z")

# ---------------------------------------------------------------- A  registry
Write-Host "`n--- A  REGISTRY AUTHORITY (GET, read-only) ---"
$enforcing = $null
try {
  $r = (Invoke-RestMethod -Method Get -Uri "$A/api/xdr/tenants" -Headers $H).data
  $enforcing = $r.enforcing
  "A enforcing    : $($r.enforcing)      (expect True)"
  "A tenant_count : $($r.count)          (expect 1)"
  "A tenant_ids   : $((@($r.tenants) | ForEach-Object { $_.id }) -join ',')"
} catch { Write-Host (Show-Fail 'A FAILED' $_) }

# ---------------------------------------------------------------- B  tenant
Write-Host "`n--- B  AUTHORITATIVE TENANT (GET, read-only) ---"
try {
  $t = (Invoke-RestMethod -Method Get -Uri "$A/api/xdr/tenants/$T" -Headers $H).data
  "B id           : $($t.id)              (expect $T)"
  "B state        : $($t.state)           (expect ACTIVE)"
  "B organization : $($t.organization_id)  (expect $O)"
  "B kind         : $($t.kind)"
  "B products     : $($t.products -join ',')   (expect XDR,EDR)"
} catch { Write-Host (Show-Fail 'B FAILED' $_) }

# ---------------------------------------------------------------- C  scoped
Write-Host "`n--- C  VALID EXPLICIT SCOPE (GET, read-only) ---"
try { "C collectors   : $((Invoke-RestMethod -Method Get -Uri "$A/api/xdr/collectors" -Headers $HT).data.count)   (expect 0)" }
catch { Write-Host (Show-Fail 'C collectors FAILED' $_) }
try { "C api_keys     : $((Invoke-RestMethod -Method Get -Uri "$A/api/xdr/api-keys" -Headers $HT).data.count)     (expect 0)" }
catch { Write-Host (Show-Fail 'C api-keys FAILED' $_) }
try {
  $cat = (Invoke-RestMethod -Method Get -Uri "$A/api/xdr/collectors/sources/catalog" -Headers $HT).data
  $ms  = $cat.sources.'microsoft-sysmon'
  "C sysmon_present: $([bool]$ms)          (expect True)"
  "C source_count  : $(@($cat.sources.PSObject.Properties).Count)"
} catch { Write-Host (Show-Fail 'C catalog FAILED' $_) }

# ---------------------------------------------------------------- D  unknown
Write-Host "`n--- D  UNKNOWN TENANT MUST FAIL CLOSED (GET, creates nothing) ---"
try {
  $x = Invoke-RestMethod -Method Get -Uri "$A/api/xdr/collectors" `
        -Headers @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = 'ten_does_not_exist' }
  "D UNEXPECTED 200 - FAILURE: $($x | ConvertTo-Json -Compress -Depth 4)"
} catch { Write-Host (Show-Fail 'D refused (expect 403 TENANT_NOT_FOUND)' $_) }

# ---------------------------------------------------------------- E  B7
Write-Host "`n--- E  MISSING SCOPE -> TENANT_REQUIRED (GET) ---"
try {
  $x = Invoke-RestMethod -Method Get -Uri "$A/api/xdr/collectors" -Headers $H
  "E UNEXPECTED 200 - FAILURE: $($x | ConvertTo-Json -Compress -Depth 4)"
} catch { Write-Host (Show-Fail 'E refused (expect 403 TENANT_REQUIRED)' $_) }

# ---------------------------------------------------------------- F  B6
Write-Host "`n--- F  B6 SECURITY STATE HONOURS AUTHORITY (GET) ---"
try {
  $ss = Invoke-RestMethod -Method Get -Uri "$A/api/v2/security-state/streaming/status?tenant_id=$T" -Headers $H
  "F authoritative_tenant_ok : $($ss.tenant_id)   (expect $T)"
} catch { Write-Host (Show-Fail 'F authoritative FAILED' $_) }
try {
  $x = Invoke-RestMethod -Method Get -Uri "$A/api/v2/security-state/streaming/status?tenant_id=default" -Headers $H
  "F UNEXPECTED 200 for 'default' - FAILURE: $($x | ConvertTo-Json -Compress -Depth 4)"
} catch { Write-Host (Show-Fail "F 'default' refused (expect TENANT_NOT_FOUND)" $_) }

# ---------------------------------------------------------------- G  B4
Write-Host "`n--- G  B4 NO IMPLICIT TENANCY (POST, must be refused) ---"
if ($enforcing -ne $true) {
  Write-Host "G SKIPPED - gate A did not confirm enforcing=True. Refusing to issue a POST that could create an object. STOP and report."
} else {
  try {
    $x = Invoke-RestMethod -Method Post -Uri "$A/api/xdr/collectors" `
          -Headers @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = 'ten_typo_not_registered' } `
          -ContentType 'application/json' `
          -Body '{"name":"b4-probe","protocol":"rest","authorized_sources":["microsoft-sysmon"]}'
    "G UNEXPECTED SUCCESS - FAILURE, AN OBJECT MAY EXIST: $($x | ConvertTo-Json -Compress -Depth 5)"
  } catch { Write-Host (Show-Fail 'G refused (expect 403 TENANT_NOT_FOUND)' $_) }

  try { "G tenant_count_after : $((Invoke-RestMethod -Method Get -Uri "$A/api/xdr/tenants" -Headers $H).data.count)   (expect 1)" }
  catch { Write-Host (Show-Fail 'G recount FAILED' $_) }
  try { "G collectors_after   : $((Invoke-RestMethod -Method Get -Uri "$A/api/xdr/collectors" -Headers $HT).data.count)   (expect 0)" }
  catch { Write-Host (Show-Fail 'G collector recount FAILED' $_) }
}

# ---------------------------------------------------------------- H  B5 EDR
Write-Host "`n--- H  B5 EDR PLANE CONSUMES SAME AUTHORITY (GET) ---"
try {
  $e = Invoke-RestMethod -Method Get -Uri "$A/api/edr/enrollment/endpoints" -Headers $HT
  "H scoped_ok      : True   endpoints=$(@($e.endpoints).Count)   (expect 0)"
} catch { Write-Host (Show-Fail 'H scoped FAILED' $_) }
try {
  $x = Invoke-RestMethod -Method Get -Uri "$A/api/edr/enrollment/endpoints" -Headers $H
  "H UNEXPECTED 200 without tenant - FAILURE: $($x | ConvertTo-Json -Compress -Depth 4)"
} catch { Write-Host (Show-Fail 'H unscoped refused (expect TENANT_REQUIRED)' $_) }

# ---------------------------------------------------------------- I  B3
Write-Host "`n--- I  B3 ACTOR AUTHENTICITY / HEADER SPOOF (GET) ---"
try {
  $au = Invoke-RestMethod -Method Get -Uri "$A/api/xdr/audit-log?limit=10&tenant=$T" `
         -Headers @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = $T; 'X-Principal-Id' = 'attacker@evil.test' }
  $rows = @($au.data.entries)
  "I entries       : $($rows.Count)"
  $rows | Select-Object action, principal_id, principal_kind | Format-Table -AutoSize | Out-String | Write-Host
  $spoof = @($rows | Where-Object { $_.principal_id -eq 'attacker@evil.test' })
  "I spoofed_rows  : $($spoof.Count)   (expect 0)"
} catch { Write-Host (Show-Fail 'I FAILED' $_) }

Write-Host "`n=== END A-I. HARD STOP. Return this output (no secrets present). ==="
