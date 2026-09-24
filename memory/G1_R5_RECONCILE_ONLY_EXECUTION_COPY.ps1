# =====================================================================
# G1-R5 . RECONCILE-ONLY . ACCOUNT THE 450 ALREADY-TOUCHED ROWS
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# THIS BLOCK DELIVERS NOTHING. It does not construct the Outbox, so it does
# not even perform R3.1 restart recovery: the 50 rows currently in
# `delivering` are LEFT EXACTLY AS THEY ARE and are reconciled in place.
#
# It only:
#   1. takes an independent read-only snapshot of the endpoint outbox
#   2. reads the identities the drain already recorded
#   3. POSTs them to the read-only reconciliation surface (now bulk-indexed:
#      450 identities answer in ~0.4 s end-to-end, previously 35 s / HTTP 504)
#   4. writes the accounting evidence and a PASS/FAIL verdict
#
# DOES NOT: deliver, redeliver, requeue, reset, replay R4, start acquisition,
# read an Event Log, touch a bookmark, or write to outbox.db in any way.
#
# OUTPUT (C:\nivx\g1-proof\r5\)
#   r5-reconcile-only-endpoint-snapshot.json
#   r5-server-reconciliation.json
#   r5-retained-raw-outcomes.json
#   r5-terminal-outcomes.json
#   r5-450-accounting.json
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R5ReconcileOnly {

$StateDir  = 'C:\ProgramData\NivXForge\state'
$Work      = 'C:\nivx'
$VenvPy    = "$Work\.venv\Scripts\python.exe"
$ProofDir  = "$Work\g1-proof\r5"
$BaseUrl   = 'https://greeting-app-5782.preview.emergentagent.com'
$IdFile    = Join-Path $ProofDir 'r5-drain-identities.json'
$ChunkSize = 450    # one request; the surface accepts up to 500

try {
  if (-not (Test-Path $VenvPy))   { throw "venv python not found at $VenvPy" }
  if (-not (Test-Path $IdFile))   { throw "identities file not found: $IdFile" }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db))       { throw "outbox database not found at $db" }
  New-Item -ItemType Directory -Force -Path $ProofDir | Out-Null

  # ---- 1 . independent read-only endpoint snapshot -------------------
  Write-Host "`n=== 1 . ENDPOINT SNAPSHOT (read-only, mode=ro) ===" -ForegroundColor Cyan
  $snap = @'
import hashlib, json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
con.row_factory = sqlite3.Row
out = {"counts_by_status": {r[0]: r[1] for r in con.execute(
    "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}}
out["total"] = con.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]
tables = {r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
if "windows_channel_state" in tables:
    h, rows = hashlib.sha256(), 0
    for r in con.execute("SELECT * FROM windows_channel_state ORDER BY rowid"):
        rows += 1
        h.update(("|".join("" if v is None else str(v)
                           for v in tuple(r))).encode("utf-8"))
    out["bookmarks"] = {"rows": rows, "sha256": h.hexdigest()}
else:
    out["bookmarks"] = {"rows": None, "sha256": None}
if "delivery_health_gate" in tables:
    r = con.execute("SELECT * FROM delivery_health_gate").fetchone()
    out["delivery_health_gate"] = None if r is None else {
        k: r[k] for k in r.keys()}
print(json.dumps(out, indent=2))
'@
  $sFile = Join-Path $env:TEMP ("nivx_r5_snap_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $sFile -Value $snap -Encoding UTF8
  $endpoint = (& $VenvPy $sFile $db) -join "`n" | ConvertFrom-Json
  $endpoint | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-reconcile-only-endpoint-snapshot.json') -Encoding UTF8
  Write-Host ("  queued="      + $endpoint.counts_by_status.queued +
              "  delivering="  + $endpoint.counts_by_status.delivering +
              "  delivered="   + $endpoint.counts_by_status.delivered +
              "  retrying="    + $endpoint.counts_by_status.retrying +
              "  dead_letter=" + $endpoint.counts_by_status.dead_letter +
              "  total="       + $endpoint.total)
  Write-Host ("  bookmarks sha256=" + $endpoint.bookmarks.sha256)
  if ($endpoint.delivery_health_gate) {
    Write-Host ("  durable gate: " + $endpoint.delivery_health_gate.state +
                "  consecutive_failures=" + $endpoint.delivery_health_gate.consecutive_failures)
  }

  # ---- 2 . identities ------------------------------------------------
  Write-Host "`n=== 2 . IDENTITIES RECORDED BY THE DRAIN ===" -ForegroundColor Cyan
  $identities = @((Get-Content $IdFile -Raw | ConvertFrom-Json).identities)
  Write-Host ("  identities: " + $identities.Count)
  $byOutcome = @{}
  foreach ($i in $identities) {
    $k = [string]$i.endpoint_outcome
    if ($byOutcome.ContainsKey($k)) { $byOutcome[$k] = $byOutcome[$k] + 1 }
    else { $byOutcome[$k] = 1 }
  }
  ($byOutcome.GetEnumerator() | Sort-Object Name) | ForEach-Object {
    Write-Host ("    endpoint_outcome " + $_.Key + " = " + $_.Value) }
  if ($identities.Count -eq 0) { throw 'no identities recorded; nothing to reconcile.' }

  # ---- 3 . reconciliation (read-only) --------------------------------
  Write-Host "`n=== 3 . SERVER RECONCILIATION (identity-level, read-only) ===" -ForegroundColor Cyan
  function Get-PlainFromSecure([System.Security.SecureString]$sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }
  Write-Host '  NOTE: an e-mail that is not a known user returns 401 in ~2 ms;'
  Write-Host '        a known e-mail with a wrong password returns 401 in ~220 ms.'
  Write-Host '        Five failures in 5 minutes for the same (e-mail, IP) then'
  Write-Host '        returns 429 with Retry-After - so type carefully.'
  $adminEmail  = Read-Host '  NivXRay admin e-mail'
  $adminSecret = Read-Host '  NivXRay admin password (not echoed, not stored)' -AsSecureString
  try {
    $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
      -ContentType 'application/json' -TimeoutSec 30 `
      -Body (@{ email = $adminEmail
                password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
  } catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    Remove-Variable adminSecret -ErrorAction SilentlyContinue; [GC]::Collect()
    if ($code -eq 429) { throw 'login rate-limited (HTTP 429). Wait for Retry-After, then re-run. Nothing was changed.' }
    throw "login failed (HTTP $code). Nothing was changed."
  }
  $jwt = $login.access_token
  Remove-Variable login, adminSecret, adminEmail -ErrorAction SilentlyContinue
  [GC]::Collect()
  Write-Host '  authenticated' -ForegroundColor Green

  $allRows = @()
  $buckets = [ordered]@{ DELIVERED_CANONICAL = 0; DELIVERED_RETAINED_RAW = 0
                         RETRYABLE_STILL_QUEUED = 0; TERMINAL_ACCOUNTED = 0
                         UNEXPLAINED = 0 }
  for ($i = 0; $i -lt $identities.Count; $i += $ChunkSize) {
    $slice = $identities[$i..([Math]::Min($i + $ChunkSize - 1, $identities.Count - 1))]
    $payload = @{ identities = @($slice | ForEach-Object {
      @{ ref              = $_.ref
         delivery_key     = $_.delivery_key
         source_event_id  = $_.source_event_id
         collector_id     = $_.collector_id
         connector_id     = $_.connector_id
         payload_digest   = $_.payload_digest
         endpoint_outcome = $_.endpoint_outcome } }) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $resp = Invoke-RestMethod -Method Post `
      -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
      -Headers @{ Authorization = "Bearer $jwt" } `
      -ContentType 'application/json' -TimeoutSec 120 `
      -Body ($payload | ConvertTo-Json -Depth 6)
    $sw.Stop()
    $allRows += $resp.rows
    foreach ($k in @($buckets.Keys)) { $buckets[$k] = $buckets[$k] + [int]$resp.buckets.$k }
    Write-Host ("  chunk " + [int]($i/$ChunkSize + 1) + ": n=" + $slice.Count +
                "  unexplained=" + $resp.unexplained +
                "  equation=" + $resp.accounting_identity.holds +
                "  " + $sw.ElapsedMilliseconds + " ms")
  }
  Remove-Variable jwt -ErrorAction SilentlyContinue; [GC]::Collect()

  [pscustomobject]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    attempted = $identities.Count; buckets = $buckets; rows = $allRows
  } | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-server-reconciliation.json') -Encoding UTF8

  $retainedRows = @($allRows | Where-Object { $_.bucket -eq 'DELIVERED_RETAINED_RAW' })
  $retainedByReason = @{}
  foreach ($r in $retainedRows) {
    $k = $r.retained_raw_reason; if (-not $k) { $k = 'UNSPECIFIED' }
    if ($retainedByReason.ContainsKey($k)) { $retainedByReason[$k] = $retainedByReason[$k] + 1 }
    else { $retainedByReason[$k] = 1 }
  }
  [pscustomobject]@{
    count = $retainedRows.Count; by_reason = $retainedByReason
    note = 'RAW RETAINED is NOT canonical evidence and NOT evaluated'
    rows = @($retainedRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         retained_raw_id = $_.retained_raw_id; reason = $_.retained_raw_reason } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-retained-raw-outcomes.json') -Encoding UTF8

  $terminalRows = @($allRows | Where-Object { $_.bucket -eq 'TERMINAL_ACCOUNTED' })
  [pscustomobject]@{
    count = $terminalRows.Count
    rows = @($terminalRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         disposition = $_.disposition
         mismatch_reason = $_.routing_block.mismatch_reason
         claim_status = $_.claim.status; review_reason = $_.claim.review_reason } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-terminal-outcomes.json') -Encoding UTF8

  # ---- 4 . verdict ---------------------------------------------------
  Write-Host "`n=== 4 . ACCOUNTING OF THE ALREADY-TOUCHED POPULATION ===" -ForegroundColor Cyan
  $total = 0; foreach ($k in $buckets.Keys) { $total += $buckets[$k] }
  Write-Host ("  DELIVERED_CANONICAL    = " + $buckets['DELIVERED_CANONICAL'])
  Write-Host ("  DELIVERED_RETAINED_RAW = " + $buckets['DELIVERED_RETAINED_RAW'])
  Write-Host ("  TERMINAL_ACCOUNTED     = " + $buckets['TERMINAL_ACCOUNTED'])
  Write-Host ("  RETRYABLE_STILL_QUEUED = " + $buckets['RETRYABLE_STILL_QUEUED'])
  if ($buckets['UNEXPLAINED'] -eq 0) {
    Write-Host  "  UNEXPLAINED            = 0" -ForegroundColor Green
  } else {
    Write-Host ("  UNEXPLAINED            = " + $buckets['UNEXPLAINED']) -ForegroundColor Red
  }

  # Rows the endpoint left claimed-but-unresolved (status `delivering`) are
  # the interesting ones: the server may well have accounted them already.
  $inflight = @($allRows | Where-Object { $_.endpoint_outcome -eq 'delivering' })
  $inflightAccounted = @($inflight | Where-Object { $_.bucket -ne 'UNEXPLAINED' }).Count
  Write-Host ("  endpoint 'delivering' rows reconciled = " + $inflight.Count +
              "  of which server-accounted = " + $inflightAccounted)

  $pass = ($buckets['UNEXPLAINED'] -eq 0) -and ($total -eq $identities.Count)
  $final = [pscustomobject]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    phase = 'G1-R5 read-only accounting of the 450 already-touched rows'
    delivered_nothing = $true
    outbox_written = $false
    identities = $identities.Count
    endpoint_outcomes = $byOutcome
    buckets = $buckets
    accounting_equation = 'identities = canonical + retained_raw + retryable/still-queued + terminal + unexplained'
    accounting_equation_holds = ($total -eq $identities.Count)
    unexplained = $buckets['UNEXPLAINED']
    inflight_rows = $inflight.Count
    inflight_server_accounted = $inflightAccounted
    endpoint_snapshot = $endpoint
    overall_pass = $pass
  }
  $final | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-450-accounting.json') -Encoding UTF8
  $final | ConvertTo-Json -Depth 6 | Write-Host

  if ($pass) {
    Write-Host "`n=== 450-ROW ACCOUNTING: PASS . ZERO UNEXPLAINED LOSS ===" -ForegroundColor Green
  } else {
    Write-Host "`n=== 450-ROW ACCOUNTING: FAIL . DO NOT RESUME THE DRAIN ===" -ForegroundColor Red
  }
  Write-Host "`nSTOP. Nothing was delivered and the outbox was not written to." -ForegroundColor Yellow
  Write-Host 'Send r5-450-accounting.json back before any further delivery.' -ForegroundColor Yellow
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
}
}

Invoke-G1R5ReconcileOnly
