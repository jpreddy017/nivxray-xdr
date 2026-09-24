# =====================================================================
# G1-R5 . BOUNDED DELIVERY DRAIN . FIRST 500 ROWS
# ELEVATED PowerShell (Run as Administrator).
#
# R4 is CLOSED/FROZEN. This block does NOT touch R4 recovery.
# This is the DELIVERY phase, bounded to an exact 500-row ceiling, run
# through a delivery-ONLY driver that has no acquisition surface at all.
#
# WHAT IT DOES
#   0. refreshes the checkout and refuses a stale tool
#   1. writer guard: no collector / delivery worker may hold the outbox
#   2. fresh SHA-256 verified pre-run backup (earlier backups preserved)
#   3. ingest credential: reuses the token in this window, else mints ONE
#      scoped 12h key; authentication + tenant binding probed (expect 400)
#   4. DRY RUN: population + candidate identities, nothing sent
#   5. EXECUTE (only when $Execute = $true): exactly <= 500 rows attempted
#   6. SERVER RECONCILIATION: every attempted identity is reconciled against
#      the authoritative plane (canonical / B4 retained raw / refusal /
#      still-open), because HTTP 2xx is NOT canonical ingestion
#   7. FINAL RECONCILIATION json + PASS / FAIL
#
# WHAT IT DOES NOT DO
#   * does NOT start acquisition: the Windows Event Log connector is never
#     constructed, EvtSubscribe is never called, no channel is read
#   * does NOT advance or write a bookmark / checkpoint
#   * does NOT start the uvicorn collector service or its continuous worker
#   * does NOT modify, replay or reinterpret R4 recovery
#   * does NOT deploy, merge or push
#   * does NOT wait out a health-gate cooldown or attempt a HALF_OPEN probe:
#     an OPEN gate is a HARD STOP with evidence
#
# EXPECTED (endpoint)
#   delivering   50 -> 0 at startup      (R3.1 restart recovery, MEASURED)
#   queued  122393 -> 122443 at startup  (+50 from that recovery)
#   attempted <= 500 . delivered/retrying/dead accounted per row
#   total   125452 unchanged . bookmarks byte-identical
#
# EXPECTED (server)
#   every attempted identity lands in exactly one bucket:
#     DELIVERED_CANONICAL . DELIVERED_RETAINED_RAW .
#     RETRYABLE_STILL_QUEUED . TERMINAL_ACCOUNTED . UNEXPLAINED
#   PASS requires UNEXPLAINED = 0
#
# OUTPUT (C:\nivx\g1-proof\r5\)
#   r5-drain-pre-snapshot.json . r5-drain-identities.json
#   r5-drain-run.json . r5-drain-post-snapshot.json
#   r5-server-reconciliation.json . r5-final-reconciliation.json
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R5DeliveryDrain {

# ---- configuration --------------------------------------------------
$StateDir    = 'C:\ProgramData\NivXForge\state'
$Work        = 'C:\nivx'
$Repo        = "$Work\nivxray-xdr-collector"     # adjust if the checkout differs
$VenvPy      = "$Work\.venv\Scripts\python.exe"
$ProofDir    = "$Work\g1-proof\r5"
$BackupDir   = "$Work\g1-proof\backup"
$Tool        = "$Repo\scripts\g1_r5_delivery_drain.py"

$BaseUrl     = 'https://greeting-app-5782.preview.emergentagent.com'
#   ^ the SAME authoritative plane the G1 acquisition delivered to (the
#     collector enrolment, tenant binding and API keys live there). Do not
#     point a drain at a different plane: the rows would be refused and the
#     reconciliation would have nothing to reconcile against.
$TenantId    = $env:NIVX_TENANT_ID               # must already be the G1 tenant
$CollectorId = $env:NIVX_COLLECTOR_ID            # must be the ENROLLED collector

# ---- ceilings (owner-approved first drain) --------------------------
$MaxRows     = 500
$BatchSize   = 50
$MaxTicks    = 40
$MaxSeconds  = 600

# ---- THE ONLY SWITCH ------------------------------------------------
#   $false = dry run only (nothing is sent, nothing is mutated)
#   $true  = attempt at most $MaxRows deliveries
$Execute     = $false

$mintedKeyId = $null

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  if ([string]::IsNullOrWhiteSpace($TenantId)) {
    throw 'NIVX_TENANT_ID is not set in this window. The batch tenant is derived from it; nothing was attempted.'
  }
  if ([string]::IsNullOrWhiteSpace($CollectorId)) {
    throw 'NIVX_COLLECTOR_ID is not set in this window. The DELIVERY IDENTITY depends on it, so a drain under the "collector-local" fallback is refused. Set it to the SAME enrolled collector the acquisition ran under.'
  }

  # ---- 0 . repo -----------------------------------------------------
  Write-Host "`n=== 0 . REPO UPDATE ===" -ForegroundColor Cyan
  if (Test-Path "$Repo\.git") {
    try {
      git -C $Repo fetch origin --prune 2>&1 | Out-Null
      git -C $Repo checkout feature/rc2-alignment 2>&1 | Out-Null
      git -C $Repo pull --ff-only origin feature/rc2-alignment 2>&1 | Out-Null
      Write-Host ("  checkout HEAD: " + (git -C $Repo rev-parse HEAD).Trim())
    } catch {
      Write-Host ("  git update skipped: " + $_.Exception.Message) -ForegroundColor Yellow
    }
  }
  if (-not (Test-Path $Tool)) { throw "tool not found at $Tool" }
  $helpText = (& $VenvPy $Tool --help) -join ' '
  foreach ($opt in @('max-rows', 'max-ticks', 'max-seconds',
                     'expect-collector-id', 'execute')) {
    if ($helpText -notmatch $opt) {
      throw "the checkout is stale: the tool has no --$opt option. Nothing was attempted."
    }
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db)) { throw "outbox database not found at $db" }
  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

  # ---- 1 . writer guard ---------------------------------------------
  Write-Host "`n=== 1 . WRITER GUARD (no collector may hold the outbox) ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*'   -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object {
      Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. Stop it first. Nothing was attempted.'
  }
  try {
    $probe = [System.IO.File]::Open($db, 'Open', 'ReadWrite', 'None')
    $probe.Close(); $probe.Dispose()
    Write-Host "  no process holds the outbox" -ForegroundColor Green
  } catch {
    throw ('the outbox is locked by another process. Nothing was attempted. ' +
           'Detail: ' + $_.Exception.Message)
  }

  # ---- 2 . pre-run backup -------------------------------------------
  Write-Host "`n=== 2 . PRE-RUN BACKUP ===" -ForegroundColor Cyan
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $pre   = Join-Path $BackupDir ("outbox.pre-r5drain.$stamp.db")
  foreach ($suf in @('', '-wal', '-shm')) {
    if (Test-Path "$db$suf") {
      Copy-Item "$db$suf" ("$pre" + $suf) -Force
      $a = (Get-FileHash "$db$suf"     -Algorithm SHA256).Hash
      $b = (Get-FileHash ("$pre"+$suf) -Algorithm SHA256).Hash
      if ($a -ne $b) { throw "backup hash mismatch for $db$suf" }
      Write-Host ("  outbox.db" + $suf + "  sha256=" + $a.Substring(0,16) + "...")
    }
  }
  Write-Host "  pre-run backup verified (earlier backups preserved)" -ForegroundColor Green

  # ---- 3 . ingest credential + auth probe ---------------------------
  Write-Host "`n=== 3 . INGEST CREDENTIAL + AUTH / TENANT BINDING ===" -ForegroundColor Cyan
  try { Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 30 | Out-Null }
  catch { throw "NivXRay XDR is not reachable at $BaseUrl : $($_.Exception.Message)" }
  Write-Host "  reachable ($BaseUrl)" -ForegroundColor Green

  function Get-PlainFromSecure([System.Security.SecureString]$sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }

  if (-not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)) {
    Write-Host '  reusing the ingest token already present in this window (not re-displayed)'
  } else {
    Write-Host '  no in-process token found - minting exactly ONE temporary key'
    $adminEmail  = Read-Host '  NivXRay admin e-mail'
    $adminSecret = Read-Host '  NivXRay admin password (not echoed, not stored)' -AsSecureString
    $expires = (Get-Date).ToUniversalTime().AddHours(12).ToString('o')
    try {
      $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
        -ContentType 'application/json' -TimeoutSec 30 `
        -Body (@{ email = $adminEmail
                  password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
      $mint = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/xdr/api-keys" `
        -Headers @{ Authorization = "Bearer $($login.access_token)"
                    'X-Tenant-Id' = $TenantId } `
        -ContentType 'application/json' -TimeoutSec 30 `
        -Body (@{ name = "g1-r5-drain-$([int](Get-Date -UFormat %s))"
                  confirm_tenant_id = $TenantId
                  description = 'G1-R5 bounded delivery drain - 12h - collectors.enroll only'
                  scopes = @('collectors.enroll')
                  expires_at = $expires } | ConvertTo-Json)
    } catch {
      Remove-Variable login, mint, adminSecret -ErrorAction SilentlyContinue
      [GC]::Collect()
      throw "key minting failed: $($_.Exception.Message). Nothing was attempted."
    }
    $env:NIVX_INGEST_TOKEN = $mint.data.plaintext
    $mintedKeyId = $mint.data.id
    Write-Host ("  minted key id : " + $mintedKeyId)
    Write-Host ("  prefix        : " + $mint.data.prefix)
    Write-Host  '  scopes        : collectors.enroll  (no control-plane authority)'
    Remove-Variable login, mint, adminSecret, adminEmail -ErrorAction SilentlyContinue
    [GC]::Collect()
  }

  $authStatus = $null
  try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/api/xdr/ingest/telemetry" `
      -Headers @{ 'X-XDR-API-Key' = $env:NIVX_INGEST_TOKEN
                  'X-Tenant-Id'   = $TenantId } `
      -ContentType 'application/json' -Body '{"envelopes":[]}' `
      -TimeoutSec 30 -UseBasicParsing | Out-Null
  } catch { $authStatus = [int]$_.Exception.Response.StatusCode }
  Write-Host ("  auth probe : HTTP $authStatus  (400 = authenticated, tenant resolved, empty batch refused; creates no evidence)")
  if ($authStatus -eq 401 -or $authStatus -eq 403) {
    throw "ingest authentication / tenant binding REFUSED (HTTP $authStatus). Nothing was attempted."
  }
  if ($authStatus -ne 400) {
    throw "unexpected auth-probe result (HTTP $authStatus); delivery is not attempted until the boundary answers as contracted."
  }
  Write-Host '  authenticated; tenant binding accepted; no evidence created by the probe' -ForegroundColor Green

  # ---- 3b . reconciliation capability must exist BEFORE delivering ---
  # PASS requires server-side accounting for every attempted row. A delivery
  # that cannot be reconciled afterwards is exactly the blind spot this phase
  # exists to close, so the drain refuses to start without the read-only
  # reconciliation surface.
  $reconStatus = $null
  try {
    Invoke-WebRequest -Method Post `
      -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
      -ContentType 'application/json' `
      -Body '{"identities":[{"source_event_id":"preflight","endpoint_outcome":"queued"}]}' `
      -TimeoutSec 30 -UseBasicParsing | Out-Null
  } catch { $reconStatus = [int]$_.Exception.Response.StatusCode }
  Write-Host ("  reconcile probe : HTTP $reconStatus  (401/403 = present and fail-closed)")
  if ($reconStatus -eq 404) {
    throw 'POST /api/xdr/ingest/routing/reconcile is NOT available on this plane. The drain refuses to deliver rows it cannot reconcile. Publish the R5 reconciliation surface first; nothing was attempted.'
  }
  if ($reconStatus -ne 401 -and $reconStatus -ne 403) {
    throw "unexpected reconcile-probe result (HTTP $reconStatus); nothing was attempted."
  }
  Write-Host '  reconciliation surface present and fail-closed' -ForegroundColor Green

  # ---- driver environment (DELIVERY ONLY) ---------------------------
  $env:NIVX_INGEST_URL       = "$BaseUrl/api/xdr/ingest/telemetry"
  $env:NIVX_INGEST_AUTH_MODE = 'api_key'
  $env:XDR_STATE_DIR         = $StateDir
  # Belt and braces: even though the driver never constructs a connector,
  # these make an accidental service start non-acquiring too.
  $env:XDR_AUTO_START_CONNECTORS = '0'

  Push-Location $Repo

  # ---- 4 . DRY RUN --------------------------------------------------
  Write-Host "`n=== 4 . DRY RUN (nothing is sent) ===" -ForegroundColor Cyan
  $dryDir = Join-Path $ProofDir 'dry'
  & $VenvPy $Tool --state-dir $StateDir --evidence-dir $dryDir `
      --max-rows $MaxRows --batch-size $BatchSize `
      --max-ticks $MaxTicks --max-seconds $MaxSeconds `
      --expect-collector-id $CollectorId
  $dryRun = Get-Content (Join-Path $dryDir 'r5-drain-run.json') -Raw | ConvertFrom-Json
  Write-Host ("  queued=" + $dryRun.post_snapshot.status_histogram.queued +
              "  delivering=" + $dryRun.post_snapshot.status_histogram.delivering +
              "  delivered=" + $dryRun.post_snapshot.status_histogram.delivered +
              "  retrying=" + $dryRun.post_snapshot.status_histogram.retrying +
              "  dead_letter=" + $dryRun.post_snapshot.status_histogram.dead_letter +
              "  total=" + $dryRun.post_snapshot.total)
  $rec = $dryRun.invariants.restart_recovery_accounted
  Write-Host ("  restart recovery: delivering " + $rec.delivering_before + " -> " +
              $rec.delivering_after + "  reset_to_queued=" + $rec.delivering_reset_to_queued +
              "  queued_delta=" + $rec.queued_delta + "  consistent=" + $rec.consistent)
  Write-Host ("  acquisition tables unchanged: " + $dryRun.invariants.no_acquisition.unchanged)
  Write-Host ("  gate: " + $dryRun.gate.state)
  if (-not $rec.consistent) {
    throw 'restart recovery accounting is INCONSISTENT. HARD STOP before any delivery.'
  }
  if (-not $dryRun.invariants.no_acquisition.unchanged) {
    throw 'an acquisition table changed during a read-only dry run. HARD STOP.'
  }
  if ($dryRun.gate.state -eq 'OPEN') {
    throw 'the durable delivery health gate is already OPEN. HARD STOP: return for owner decision.'
  }

  if (-not $Execute) {
    Write-Host "`n=== DRY RUN COMPLETE . NOTHING WAS SENT ===" -ForegroundColor Yellow
    Write-Host "  To attempt the bounded 500-row drain, set `$Execute = `$true and re-run." -ForegroundColor Yellow
    Pop-Location
    return
  }

  # ---- 5 . EXECUTE (bounded) ----------------------------------------
  Write-Host "`n=== 5 . EXECUTE . BOUNDED DELIVERY (max $MaxRows rows) ===" -ForegroundColor Cyan
  & $VenvPy $Tool --state-dir $StateDir --evidence-dir $ProofDir `
      --max-rows $MaxRows --batch-size $BatchSize `
      --max-ticks $MaxTicks --max-seconds $MaxSeconds `
      --expect-collector-id $CollectorId --execute
  $driverExit = $LASTEXITCODE
  $run = Get-Content (Join-Path $ProofDir 'r5-drain-run.json') -Raw | ConvertFrom-Json

  Write-Host ("  stop_reason = " + $run.stop_reason)
  Write-Host ("  attempted   = " + $run.attempted +
              "  delivered=" + $run.worker_totals.delivered +
              "  retrying="  + $run.worker_totals.retrying +
              "  dead="      + $run.worker_totals.dead +
              "  released="  + $run.worker_totals.released_unattempted)
  Write-Host ("  gate        = " + $run.gate.state + "  opened=" + $run.gate_opened)
  Write-Host ("  endpoint pass = " + $run.pass)

  if ($run.gate_opened) {
    Write-Host "`n*** HEALTH GATE OPENED . HARD STOP ***" -ForegroundColor Red
    Write-Host '  The durable gate state, the per-tick accounting and every attempted' -ForegroundColor Red
    Write-Host '  identity are preserved in r5-drain-run.json. No cooldown was waited' -ForegroundColor Red
    Write-Host '  out and no HALF_OPEN probe was attempted. Return for owner decision.' -ForegroundColor Red
  }

  # ---- 6 . SERVER RECONCILIATION ------------------------------------
  Write-Host "`n=== 6 . SERVER-SIDE RECONCILIATION (read-only) ===" -ForegroundColor Cyan
  $identities = (Get-Content (Join-Path $ProofDir 'r5-drain-identities.json') -Raw |
                  ConvertFrom-Json).identities
  Write-Host ("  attempted identities to reconcile: " + $identities.Count)

  $reconEmail  = Read-Host '  NivXRay admin e-mail (read-only reconciliation)'
  $reconSecret = Read-Host '  NivXRay admin password (not echoed, not stored)' -AsSecureString
  $reconLogin = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
    -ContentType 'application/json' -TimeoutSec 30 `
    -Body (@{ email = $reconEmail
              password = (Get-PlainFromSecure $reconSecret) } | ConvertTo-Json)
  $jwt = $reconLogin.access_token
  Remove-Variable reconLogin, reconSecret, reconEmail -ErrorAction SilentlyContinue
  [GC]::Collect()

  $allRows = @()
  $buckets = @{ DELIVERED_CANONICAL = 0; DELIVERED_RETAINED_RAW = 0
                RETRYABLE_STILL_QUEUED = 0; TERMINAL_ACCOUNTED = 0
                UNEXPLAINED = 0 }
  for ($i = 0; $i -lt $identities.Count; $i += 500) {
    $slice = $identities[$i..([Math]::Min($i + 499, $identities.Count - 1))]
    $payload = @{ identities = @($slice | ForEach-Object {
      @{ ref              = $_.ref
         delivery_key     = $_.delivery_key
         source_event_id  = $_.source_event_id
         collector_id     = $_.collector_id
         connector_id     = $_.connector_id
         payload_digest   = $_.payload_digest
         endpoint_outcome = $_.endpoint_outcome } }) }
    $resp = Invoke-RestMethod -Method Post `
      -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
      -Headers @{ Authorization = "Bearer $jwt" } `
      -ContentType 'application/json' -TimeoutSec 120 `
      -Body ($payload | ConvertTo-Json -Depth 6)
    $allRows += $resp.rows
    foreach ($k in @($buckets.Keys)) {
      $buckets[$k] = $buckets[$k] + [int]$resp.buckets.$k
    }
    Write-Host ("  chunk " + ($i/500 + 1) + ": attempted=" + $resp.attempted +
                " unexplained=" + $resp.unexplained)
  }
  Remove-Variable jwt -ErrorAction SilentlyContinue
  [GC]::Collect()

  $serverTotal = 0
  foreach ($k in $buckets.Keys) { $serverTotal += $buckets[$k] }
  $serverPass  = ($buckets['UNEXPLAINED'] -eq 0) -and ($serverTotal -eq $identities.Count)
  $crossTenant = @($allRows | Where-Object {
      $_.claim -ne $null -and $_.claim.status -ne $null -and
      $_.bucket -eq 'UNEXPLAINED' -and $_.matched_by -ne 'NONE' }).Count

  [pscustomobject]@{
    at                = (Get-Date).ToUniversalTime().ToString('o')
    attempted         = $identities.Count
    buckets           = $buckets
    server_pass       = $serverPass
    rows              = $allRows
  } | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-server-reconciliation.json') -Encoding UTF8

  Write-Host ("  DELIVERED_CANONICAL    = " + $buckets['DELIVERED_CANONICAL'])
  Write-Host ("  DELIVERED_RETAINED_RAW = " + $buckets['DELIVERED_RETAINED_RAW'])
  Write-Host ("  TERMINAL_ACCOUNTED     = " + $buckets['TERMINAL_ACCOUNTED'])
  Write-Host ("  RETRYABLE_STILL_QUEUED = " + $buckets['RETRYABLE_STILL_QUEUED'])
  Write-Host ("  UNEXPLAINED            = " + $buckets['UNEXPLAINED']) -ForegroundColor (
      $(if ($buckets['UNEXPLAINED'] -eq 0) { 'Green' } else { 'Red' }))

  # ---- 7 . FINAL RECONCILIATION -------------------------------------
  Write-Host "`n=== 7 . FINAL RECONCILIATION ===" -ForegroundColor Cyan
  $inv = $run.invariants
  $final = [pscustomobject]@{
    at                          = (Get-Date).ToUniversalTime().ToString('o')
    phase                       = 'G1-R5 bounded delivery drain (first 500)'
    driver_exit_code            = $driverExit
    stop_reason                 = $run.stop_reason
    attempted                   = $run.attempted
    ceiling_respected           = $inv.row_ceiling_respected.holds
    worker_totals               = $run.worker_totals
    endpoint_outcomes           = $run.endpoint_outcomes
    restart_recovery            = $inv.restart_recovery_accounted
    total_rows_unchanged        = $inv.total_rows_unchanged.holds
    acquisition_unchanged       = $inv.no_acquisition.unchanged
    windows_connector_unloaded  = $inv.windows_connector_never_imported.holds
    gate_state                  = $run.gate.state
    gate_opened                 = $run.gate_opened
    endpoint_pass               = $run.pass
    server_buckets              = $buckets
    server_unexplained          = $buckets['UNEXPLAINED']
    server_pass                 = $serverPass
    suspicious_cross_tenant_rows = $crossTenant
    pre_histogram               = $run.pre_snapshot.status_histogram
    post_histogram              = $run.post_snapshot.status_histogram
  }
  $pass = ($final.endpoint_pass -eq $true) -and ($final.server_pass -eq $true) -and
          ($final.gate_opened -eq $false) -and ($final.acquisition_unchanged -eq $true) -and
          ($final.total_rows_unchanged -eq $true) -and
          ($final.restart_recovery.consistent -eq $true) -and
          ($final.ceiling_respected -eq $true) -and
          ($final.server_unexplained -eq 0)
  $final | Add-Member -NotePropertyName overall_pass -NotePropertyValue $pass
  $final | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-final-reconciliation.json') -Encoding UTF8
  $final | ConvertTo-Json -Depth 6 | Write-Host

  if ($pass) {
    Write-Host "`n=== R5 FIRST 500-ROW DRAIN: PASS ===" -ForegroundColor Green
    Write-Host '  Every attempted delivery is accounted on BOTH sides. Zero unexplained loss.' -ForegroundColor Green
  } else {
    Write-Host "`n=== R5 FIRST 500-ROW DRAIN: FAIL / HALTED ===" -ForegroundColor Red
    Write-Host '  Do NOT widen the drain. Send r5-final-reconciliation.json back for review.' -ForegroundColor Red
  }
  Pop-Location
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
  try { Pop-Location -ErrorAction SilentlyContinue } catch { }
}
finally {
  if ($mintedKeyId) {
    Write-Host ("`nNOTE: temporary ingest key " + $mintedKeyId +
                " remains valid for 12h. Revoke it when the phase closes.") -ForegroundColor Yellow
  }
}
}

Invoke-G1R5DeliveryDrain
