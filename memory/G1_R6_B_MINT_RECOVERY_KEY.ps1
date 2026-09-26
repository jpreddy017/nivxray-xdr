# =====================================================================
# G1-R6-B . MINT EXACTLY ONE TEMPORARY RECOVERY INGEST CREDENTIAL
# Run this on YOUR host (normal PowerShell is enough - no elevation, no
# collector state is touched). The one-time plaintext is printed on YOUR
# console only; it is never sent to Emergent, never written to disk and
# never logged.
#
# WHAT IT DOES
#   1. logs in as the NivXRay XDR PREVIEW administrator
#   2. creates ONE api key: tenant ten_f1a5479243e901cf159e230fa0,
#      scope collectors.enroll ONLY, expires in 24h
#   3. self-checks the returned secret against ^nvx_[0-9a-f]{48}$
#   4. re-reads the key SERVER-SIDE and prints only non-secret metadata
#      (id / prefix / scopes / enabled / revoked_at / expires_at) - that
#      block is safe to paste back to Emergent
#
# WHAT IT NEVER DOES
#   no rotate . no revoke . no change to the expired historical key
#   no extra scopes . no auth-policy change . no tenant change
#   no delivery . no canary . no acquisition . no collector state
# =====================================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$BaseUrl  = 'https://greeting-app-5782.preview.emergentagent.com'
$TenantId = 'ten_f1a5479243e901cf159e230fa0'
$Scope    = 'collectors.enroll'
$TtlHours = 24

function Get-PlainFromSecure([System.Security.SecureString]$sec) {
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

try {
  Write-Host "`n=== 1 . AUTHORITY ===" -ForegroundColor Cyan
  Write-Host ("   Backend   : " + $BaseUrl)
  Write-Host ("   Tenant    : " + $TenantId)
  Write-Host ("   Scope     : " + $Scope + "   (exactly one)")
  Write-Host ("   TTL       : " + $TtlHours + "h")
  Write-Host  "   Operation : CREATE one temporary G1-R6-B recovery credential"

  $adminEmail  = Read-Host '  NivXRay XDR PREVIEW Admin Email'
  $adminSecret = Read-Host '  NivXRay XDR PREVIEW Admin Password (not echoed, not stored)' -AsSecureString
  $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
    -ContentType 'application/json' -TimeoutSec 30 `
    -Body (@{ email = $adminEmail
              password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
  Remove-Variable adminSecret -ErrorAction SilentlyContinue
  [GC]::Collect()
  $hdr = @{ Authorization = 'Bearer ' + $login.access_token
            'X-Tenant-Id' = $TenantId }
  Remove-Variable login -ErrorAction SilentlyContinue
  Write-Host '  authenticated (token held in memory only)' -ForegroundColor Green

  Write-Host "`n=== 2 . CREATE ONE CREDENTIAL ===" -ForegroundColor Cyan
  $stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $expires = (Get-Date).ToUniversalTime().AddHours($TtlHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
  $body = @{ name              = 'G1-R6-B-recovery-' + $stamp
             description       = 'Temporary collector ingest credential for the G1-R6-B bounded recovery of the exact 28. Single purpose, 24h TTL.'
             confirm_tenant_id = $TenantId
             scopes            = @($Scope)
             expires_at        = $expires } | ConvertTo-Json
  $created = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/xdr/api-keys" `
               -Headers $hdr -ContentType 'application/json' -TimeoutSec 30 -Body $body
  $keyId = $created.data.id

  Write-Host "`n=== 3 . LOCAL FORMAT SELF-CHECK ===" -ForegroundColor Cyan
  $plain = $created.data.plaintext
  $ok = (($plain -cmatch '^nvx_[0-9a-f]{48}$') -and ($plain.Length -eq 52))
  Write-Host ('  matches ^nvx_[0-9a-f]{48}$ : ' + $ok) -ForegroundColor $(
    if ($ok) { 'Green' } else { 'Red' })
  if (-not $ok) { throw 'the server returned an unexpected key format - do not use it; report this.' }

  Write-Host "`n=== 4 . ONE-TIME SECRET (YOUR CONSOLE ONLY) ===" -ForegroundColor Yellow
  Write-Host '  This is the ONLY time the full value is shown. Copy it into a' -ForegroundColor Yellow
  Write-Host '  secret manager now. Do NOT paste it into Emergent or any chat.' -ForegroundColor Yellow
  Write-Host ''
  Write-Host ('  ' + $plain) -ForegroundColor White
  Write-Host ''
  Write-Host '  When the Phase B wrapper asks for the Collector Ingest API Key,' -ForegroundColor Yellow
  Write-Host '  paste ALL 52 characters above - not the 12-character prefix.' -ForegroundColor Yellow
  Remove-Variable plain -ErrorAction SilentlyContinue
  $created = $null
  [GC]::Collect()

  Write-Host "`n=== 5 . SERVER-SIDE VERIFICATION (non-secret metadata) ===" -ForegroundColor Cyan
  $doc = (Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/xdr/api-keys/$keyId" `
            -Headers $hdr -TimeoutSec 30).data
  $meta = [ordered]@{
    id         = $doc.id
    tenant_id  = $doc.tenant_id
    name       = $doc.name
    prefix     = $doc.prefix
    scopes     = ($doc.scopes -join ',')
    enabled    = $doc.enabled
    revoked_at = $doc.revoked_at
    expires_at = $doc.expires_at
    created_at = $doc.created_at
  }
  foreach ($k in $meta.Keys) { Write-Host ('  ' + $k.PadRight(11) + ': ' + $meta[$k]) }
  $verdict = ($doc.enabled -eq $true -and
              $null -eq $doc.revoked_at -and
              $doc.tenant_id -eq $TenantId -and
              ($doc.scopes -join ',') -eq $Scope -and
              ([datetime]$doc.expires_at).ToUniversalTime() -gt (Get-Date).ToUniversalTime())
  Write-Host ("`n  usable now (enabled, unrevoked, unexpired, correct tenant, exact scope): " +
              $verdict) -ForegroundColor $(if ($verdict) { 'Green' } else { 'Red' })
  Write-Host '  Paste ONLY the metadata block above back to Emergent.' -ForegroundColor Cyan
  if (-not $verdict) { throw 'the new credential is not usable as issued - report the metadata above.' }
  Write-Host "`nREADY: mint complete. Next step is the single canary, nothing else." -ForegroundColor Green
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
  if ($_.Exception.Response) {
    Write-Host ('  HTTP ' + [int]$_.Exception.Response.StatusCode) -ForegroundColor Red
  }
  Write-Host '  No credential was rotated or revoked. Nothing was delivered.' -ForegroundColor Yellow
}
finally {
  Remove-Variable hdr, doc, created, plain, body, adminSecret -ErrorAction SilentlyContinue
  [GC]::Collect()
}
