# =====================================================================
# G1-R5 EVIDENCE RECOVERY . RECONCILE THE EXACT 50 IN-FLIGHT IDENTITIES
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# WHY THIS EXISTS
#   The successful 450-row reconciliation proved, in AGGREGATE, 422 canonical
#   + 28 retryable. Its per-row record (r5-server-reconciliation.json) was
#   never persisted. R6 Phase A cannot repair individual rows from aggregate
#   counts - it must know WHICH 22 of the 50 locally-`delivering` rows the
#   server already holds as canonical. This block recreates exactly that
#   missing per-row authority and nothing else.
#
# WHAT IT DOES
#   1. read-only pre-snapshot of outbox.db (SHA-256, histogram, bookmarks)
#   2. loads the EXACT 50 recorded in-flight refs; refuses any other count
#   3. asserts the local `delivering` set is EXACTLY those same 50 refs
#   4. asserts the frozen pre-state histogram and total
#   5. issues ONE read-only reconciliation request for those 50 identities
#   6. verifies 22 DELIVERED_CANONICAL + 28 RETRYABLE_STILL_QUEUED,
#      0 retained raw, 0 terminal, 0 unexplained, and a strict 1:1 ref
#      correspondence (no missing, no foreign, no duplicate refs)
#   7. read-only post-snapshot: file bytes, histogram, total, bookmarks and
#      the delivering set must all be identical
#   8. writes the authoritative per-row evidence file ONLY on full PASS
#
# WHAT IT NEVER DOES
#   no SQLite write . no Outbox construction . no DeliveryWorker . no ingest
#   client . no delivery / redelivery / requeue / retry . no acquisition .
#   no EvtSubscribe . no bookmark write . no backlog processing .
#   NO NEGATIVE CONTROL (an auxiliary request destroyed this evidence once) .
#   no R6 Phase A . no Phase B . no widening beyond the exact 50
#
# FAILURE SEMANTICS (owner decision)
#   pre-request failure (count != 50, delivering-set mismatch, histogram
#   drift, auth failure, unreachable surface) -> HARD STOP, nothing written.
#   assertion failure AFTER a response was received -> the complete raw
#   response is persisted as
#     r5-inflight-50-server-reconciliation.json.FAILED-UNTRUSTED.json
#   banner-marked "NOT AUTHORITY FOR R6", then HARD STOP. The authoritative
#   file is never created unless every assertion holds.
#
# OUTPUT (C:\nivx\g1-proof\r5\)
#   r5-inflight-50-server-reconciliation.json          (PASS only)
#   r5-inflight-50-server-reconciliation.json.FAILED-UNTRUSTED.json  (FAIL)
#
# The password and the JWT are never echoed and never written to any file.
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R5Inflight50Reconcile {

# ---- configuration ---------------------------------------------------
$StateDir = 'C:\ProgramData\NivXForge\state'
$Work     = 'C:\nivx'
$Repo     = "$Work\nivxray-xdr-collector"
$VenvPy   = "$Work\.venv\Scripts\python.exe"
$Tool     = "$Repo\scripts\g1_r5_inflight50_reconcile.py"
$ProofDir = "$Work\g1-proof\r5"
$IdFile   = "$ProofDir\interruption-reconciliation-corrected\r5-inflight-identities-20260924T063436Z.json"
$OutFile  = "$ProofDir\r5-inflight-50-server-reconciliation.json"
$BaseUrl  = 'https://greeting-app-5782.preview.emergentagent.com'

# Hard expectations from the frozen endpoint evidence.
$ExpectCount     = 50
$ExpectCanonical = 22
$ExpectRetryable = 28
$ExpectTotalRows = 125452
$ExpectHistogram = 'delivered=3284,delivering=50,queued=121993,retrying=125,dead_letter=0'

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. Nothing was attempted.'
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  if (-not (Test-Path $db))     { throw "outbox database not found at $db" }
  if (-not (Test-Path $Tool))   { throw "tool not found at $Tool (publish the branch and pull)" }
  if (-not (Test-Path $IdFile)) { throw "in-flight identities file not found at $IdFile . Nothing was attempted." }
  if (Test-Path $OutFile) {
    throw ("$OutFile already exists. This recovery refuses to overwrite " +
           'existing authoritative evidence. Move it aside deliberately if ' +
           'you intend to regenerate it. Nothing was attempted.')
  }
  if ([string]::IsNullOrWhiteSpace($env:NIVX_COLLECTOR_ID)) {
    throw 'NIVX_COLLECTOR_ID is not set in this window. The delivery identity the server answers about is derived from it. Nothing was attempted.'
  }
  New-Item -ItemType Directory -Force -Path $ProofDir | Out-Null

  # ---- 0 . writer guard ----------------------------------------------
  Write-Host "`n=== 0 . WRITER GUARD + LINEAGE ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*' -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object { Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. Stop it first so the snapshots are stable. Nothing was attempted.'
  }
  Write-Host ("  tool sha256: " + (Get-FileHash $Tool -Algorithm SHA256).Hash)
  $help = (& $VenvPy $Tool --help) -join ' '
  foreach ($opt in @('identities', 'out', 'expect-count', 'expect-canonical',
                     'expect-retryable', 'expect-histogram')) {
    if ($help -notmatch $opt) { throw "the tool has no --$opt option; the checkout is stale. Nothing was attempted." }
  }
  Write-Host '  no writer running; tool verified' -ForegroundColor Green

  # ---- 1 . the EXACT 50 refs (local pre-check) ------------------------
  Write-Host "`n=== 1 . SUPPLIED IN-FLIGHT POPULATION ===" -ForegroundColor Cyan
  $idDoc = Get-Content $IdFile -Raw | ConvertFrom-Json
  $idRows = $null
  foreach ($k in @('identities', 'rows', 'refs', 'ids')) {
    if ($null -ne $idDoc.$k) { $idRows = @($idDoc.$k); break }
  }
  if ($null -eq $idRows) { $idRows = @($idDoc) }
  Write-Host ("  identities in file: " + $idRows.Count + "   (expected " + $ExpectCount + ")")
  if ($idRows.Count -ne $ExpectCount) {
    throw ("the supplied population holds " + $idRows.Count + ' entries, expected exactly ' +
           $ExpectCount + '. This recovery neither widens nor narrows it. Nothing was attempted.')
  }
  Write-Host ("  identities file sha256: " + (Get-FileHash $IdFile -Algorithm SHA256).Hash)
  Write-Host ("  outbox.db sha256 (pre):  " + (Get-FileHash $db -Algorithm SHA256).Hash)

  # ---- 2 . authenticate ----------------------------------------------
  Write-Host "`n=== 2 . AUTHENTICATE (read-only reconciliation) ===" -ForegroundColor Cyan
  function Get-PlainFromSecure([System.Security.SecureString]$sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }
  Write-Host '  NOTE: five failed logins in 5 minutes for the same (e-mail, IP)'
  Write-Host '  returns HTTP 429 with Retry-After. Type carefully.'
  $adminEmail  = Read-Host '  NivXRay admin e-mail'
  $adminSecret = Read-Host '  NivXRay admin password (not echoed, not stored)' -AsSecureString
  try {
    $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
      -ContentType 'application/json' -TimeoutSec 30 `
      -Body (@{ email    = $adminEmail
                password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
  } catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    Remove-Variable adminSecret -ErrorAction SilentlyContinue; [GC]::Collect()
    if ($code -eq 429) { throw 'login rate-limited (HTTP 429). Wait for Retry-After and re-run. Nothing was read or changed.' }
    throw "login failed (HTTP $code). Nothing was read or changed."
  }
  # The token is handed to the tool via the environment of THIS window only:
  # never on a command line, never in any evidence file.
  $env:NIVX_RECONCILE_TOKEN = $login.access_token
  Remove-Variable login, adminSecret, adminEmail -ErrorAction SilentlyContinue
  [GC]::Collect()
  Write-Host '  authenticated (token held in memory only)' -ForegroundColor Green

  # ---- 3 . ONE bounded read-only reconciliation ----------------------
  Write-Host "`n=== 3 . RECONCILE THE EXACT $ExpectCount (one request, read-only) ===" -ForegroundColor Cyan
  Write-Host '  the tool opens outbox.db strictly mode=ro, recomputes each'
  Write-Host '  delivery identity locally, issues exactly one request, and'
  Write-Host '  writes the authoritative file only if every assertion holds.'
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $raw = & $VenvPy $Tool `
            --state-dir        $StateDir `
            --identities       $IdFile `
            --out              $OutFile `
            --base-url         $BaseUrl `
            --expect-count     $ExpectCount `
            --expect-canonical $ExpectCanonical `
            --expect-retryable $ExpectRetryable `
            --expect-total     $ExpectTotalRows `
            --expect-histogram $ExpectHistogram
  $exit = $LASTEXITCODE
  $sw.Stop()
  Remove-Item Env:\NIVX_RECONCILE_TOKEN -ErrorAction SilentlyContinue
  [GC]::Collect()
  ($raw -join "`n") | Write-Host
  Write-Host ("`n  tool exit code: " + $exit + "   runtime: " + $sw.ElapsedMilliseconds + " ms")

  # ---- 4 . independent non-mutation re-check -------------------------
  Write-Host "`n=== 4 . INDEPENDENT NON-MUTATION RE-CHECK ===" -ForegroundColor Cyan
  Write-Host ("  outbox.db sha256 (post): " + (Get-FileHash $db -Algorithm SHA256).Hash)
  $hist = @'
import json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
print(json.dumps({
    "counts_by_status": {r[0]: r[1] for r in con.execute(
        "SELECT status, COUNT(*) FROM envelopes GROUP BY status")},
    "total": con.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]}))
'@
  $hFile = Join-Path $env:TEMP ("nivx_r5_hist_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $hFile -Value $hist -Encoding UTF8
  $after = (& $VenvPy $hFile $db) -join "`n" | ConvertFrom-Json
  Write-Host ("  delivered="   + $after.counts_by_status.delivered +
              "  delivering=" + $after.counts_by_status.delivering +
              "  queued="     + $after.counts_by_status.queued +
              "  retrying="   + $after.counts_by_status.retrying +
              "  dead_letter="+ $after.counts_by_status.dead_letter +
              "  total="      + $after.total)
  Remove-Item $hFile -ErrorAction SilentlyContinue

  # ---- 5 . verdict ----------------------------------------------------
  Write-Host "`n=== 5 . VERDICT ===" -ForegroundColor Cyan
  $failedFile = "$OutFile.FAILED-UNTRUSTED.json"
  if ($exit -eq 0 -and (Test-Path $OutFile)) {
    Write-Host "  EXACT-50 EVIDENCE RECOVERY: PASS" -ForegroundColor Green
    Write-Host ("  per-row authority written: " + $OutFile) -ForegroundColor Green
    Write-Host '  This file is now the authority R6 Phase A consumes.' -ForegroundColor Green
  } else {
    Write-Host "  EXACT-50 EVIDENCE RECOVERY: FAIL" -ForegroundColor Red
    if (Test-Path $failedFile) {
      Write-Host ("  raw response persisted as UNTRUSTED forensic evidence: " +
                  $failedFile) -ForegroundColor Yellow
      Write-Host '  It is banner-marked NOT AUTHORITY FOR R6 and must not be' -ForegroundColor Yellow
      Write-Host '  used by Phase A.' -ForegroundColor Yellow
    } else {
      Write-Host '  the run stopped BEFORE any reconciliation response was' -ForegroundColor Yellow
      Write-Host '  received; no evidence file was created.' -ForegroundColor Yellow
    }
    if (Test-Path $OutFile) {
      Write-Host '  *** UNEXPECTED: the authoritative file exists despite a' -ForegroundColor Red
      Write-Host '      non-zero exit. Do NOT use it. Report this. ***' -ForegroundColor Red
    }
  }

  Write-Host "`nSTOP. Nothing was delivered, requeued or recovered, and" -ForegroundColor Yellow
  Write-Host 'outbox.db was not written to. The 50 rows are still delivering.' -ForegroundColor Yellow
  Write-Host 'R6 Phase A was NOT executed and Phase B was NOT built.' -ForegroundColor Yellow
  Write-Host 'Send back the console output and the written JSON file.' -ForegroundColor Yellow
}
catch {
  Remove-Item Env:\NIVX_RECONCILE_TOKEN -ErrorAction SilentlyContinue
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
}
}

Invoke-G1R5Inflight50Reconcile
