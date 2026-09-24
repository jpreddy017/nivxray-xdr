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
#   5. BACKEND READINESS PREFLIGHT, before any credential is requested:
#      /api/auth/login with an invalid shape must answer 422, and
#      /api/xdr/ingest/routing/reconcile unauthenticated must answer 403.
#      Anything else hard-stops BEFORE the password prompt.
#   6. issues ONE read-only reconciliation request for those 50 identities
#   7. verifies 22 DELIVERED_CANONICAL + 28 RETRYABLE_STILL_QUEUED,
#      0 retained raw, 0 terminal, 0 unexplained, and a strict 1:1 ref
#      correspondence (no missing, no foreign, no duplicate refs)
#   8. read-only post-snapshot: file bytes, histogram, total, bookmarks and
#      the delivering set must all be identical
#   9. writes the authoritative per-row evidence file ONLY on full PASS
#
# WHAT IT NEVER DOES
#   no SQLite write . no Outbox construction . no DeliveryWorker . no ingest
#   client . no delivery / redelivery / requeue / retry . no acquisition .
#   no EvtSubscribe . no bookmark write . no backlog processing .
#   NO NEGATIVE CONTROL (an auxiliary request destroyed this evidence once) .
#   no R6 Phase A . no Phase B . no widening beyond the exact 50
#
# FAILURE SEMANTICS (owner decision)
#   EVERY failure path returns a NON-ZERO process exit code. Exit 0 requires
#   both a clean python exit AND the authoritative file existing. (The
#   previous copy printed HARD STOP and still returned 0.)
#   readiness preflight failure (login != 422 or unauthenticated reconcile
#   != 403) -> HARD STOP BEFORE THE CREDENTIAL PROMPT, printing
#   "BACKEND NOT READY/BOUND - DO NOT RETYPE PASSWORD. NO RECONCILIATION
#   ATTEMPTED." Never retried automatically.
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
# The repository is a monorepo: the collector lives UNDER apps\. The earlier
# execution copy omitted that segment and hard-stopped with "tool not found",
# so the python tool never ran.
$Repo     = "$Work\apps\nivxray-xdr-collector"
$VenvPy   = "$Work\.venv\Scripts\python.exe"
$Tool     = "$Repo\scripts\g1_r5_inflight50_reconcile.py"
$ProofDir = "$Work\g1-proof\r5"
# Verified BOM-free identities. A UTF-8 BOM corrupts the first JSON byte, so
# the no-BOM copy is authoritative for this run.
$IdFile   = "$ProofDir\interruption-reconciliation-corrected\r5-inflight-identities-20260924T063436Z.utf8-nobom.json"
$OutFile  = "$ProofDir\r5-inflight-50-server-reconciliation.json"
$BaseUrl  = 'https://greeting-app-5782.preview.emergentagent.com'

# Hard expectations from the frozen endpoint evidence.
$ExpectCount     = 50
$ExpectCanonical = 22
$ExpectRetryable = 28
$ExpectTotalRows = 125452
$ExpectHistogram = 'delivered=3284,delivering=50,queued=121993,retrying=125,dead_letter=0'

# Lineage: the exact tool this block was written for. Re-pinned after the
# edge-1010 correction (an explicit non-`Python-urllib` User-Agent on the one
# reconciliation request). A mismatch means the pull did not land that
# correction, or the checkout is stale.
$ExpectToolSha = 'D624C632808B4E1D6F5ECD559D3C176EF8AF82B749CC4B43851CB3D67A3A3C0A'

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. Nothing was attempted.'
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  if (-not (Test-Path $db))     { throw "outbox database not found at $db" }
  if (-not (Test-Path $Tool))   {
    throw ("tool not found at $Tool . The collector lives UNDER apps\ in the " +
           "monorepo; confirm $Repo exists after the pull. Nothing was attempted.")
  }
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
  $toolSha = (Get-FileHash $Tool -Algorithm SHA256).Hash
  Write-Host ("  pinned python tool sha256: " + $toolSha)
  # Provenance of THIS orchestration block, printed for the record only. It is
  # NOT a substitute for, and never recalculates, the pinned python lineage
  # assertion below: the reconciliation authority lives in the .py.
  $selfSha = [BitConverter]::ToString(
      [Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes(
          ${function:Invoke-G1R5Inflight50Reconcile}.ToString()))).Replace('-','')
  Write-Host ("  this PS block (orchestration) sha256: " + $selfSha)
  if ($toolSha -ne $ExpectToolSha) {
    throw ('tool sha256 is ' + $toolSha + ', expected ' + $ExpectToolSha +
           '. The checkout does not hold the edge-1010 correction. Pull ' +
           'feature/rc2-alignment again. ' +
           'Nothing was attempted.')
  }
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
  # ---- 2 . BACKEND READINESS PREFLIGHT (no credentials) --------------
  # A recycled preview pod serves edge errors for every /api/* path while the
  # static frontend still answers 200. That window produced the earlier
  # HTTP 404 from /api/auth/login and cost a credential attempt. These two
  # probes prove, WITHOUT any credential, that both routes are bound and that
  # reconcile is still protected. They are route/readiness probes only: the
  # login probe sends a deliberately invalid shape so it can never
  # authenticate, and the reconcile probe sends no Authorization header so it
  # can never read anything.
  Write-Host "`n=== 2 . BACKEND READINESS PREFLIGHT (no credentials) ===" -ForegroundColor Cyan
  function Probe-Status([string]$uri, [string]$body) {
    try {
      $r = Invoke-WebRequest -Method Post -Uri $uri -ContentType 'application/json' `
             -Body $body -TimeoutSec 20 -UseBasicParsing
      return [int]$r.StatusCode
    } catch {
      if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
      return -1
    }
  }
  # (a) login route bound and validating: an empty JSON object cannot satisfy
  #     the LoginIn model, so a live route MUST answer 422.
  $probeLogin = Probe-Status "$BaseUrl/api/auth/login" '{}'
  Write-Host ("  POST /api/auth/login  (invalid shape, no credentials) -> HTTP " +
              $probeLogin + "   (require 422)")
  # (b) reconcile route bound AND still requiring authenticated admin
  #     authority: unauthenticated MUST be refused with 403.
  $probeRecon = Probe-Status "$BaseUrl/api/xdr/ingest/routing/reconcile" '{"identities":[]}'
  Write-Host ("  POST /api/xdr/ingest/routing/reconcile (unauthenticated) -> HTTP " +
              $probeRecon + "   (require 403)")
  if ($probeLogin -ne 422 -or $probeRecon -ne 403) {
    Write-Host ''
    Write-Host '  BACKEND NOT READY/BOUND - DO NOT RETYPE PASSWORD. NO RECONCILIATION ATTEMPTED.' -ForegroundColor Red
    Write-Host ''
    if ($probeRecon -eq 200) {
      Write-Host '  *** The reconcile route answered 200 WITHOUT authentication.' -ForegroundColor Red
      Write-Host '      That is an authorization regression, not a readiness' -ForegroundColor Red
      Write-Host '      problem. Report it before anything else. ***' -ForegroundColor Red
    }
    throw ('backend readiness preflight failed (login=' + $probeLogin +
           ', reconcile=' + $probeRecon + '; required 422 / 403). No credential ' +
           'was requested, no reconciliation was attempted, nothing was written. ' +
           'This is NOT retried automatically: wait, then re-run this block ' +
           'deliberately.')
  }
  # (c) THE PROBE THAT MATTERS: issue the same unauthenticated request from
  #     the SAME python client, with the SAME User-Agent the tool sends. The
  #     earlier failure was exactly this asymmetry - PowerShell's signature
  #     was accepted while the python client's default `Python-urllib/*`
  #     signature was banned at the edge (error code: 1010), which only became
  #     visible AFTER the password had been typed. A 403 here must come from
  #     FastAPI, not from the edge.
  $pyProbe = @'
import json, sys, urllib.error, urllib.request
base, ua = sys.argv[1], sys.argv[2]
req = urllib.request.Request(
    base.rstrip("/") + "/api/xdr/ingest/routing/reconcile",
    data=b'{"identities":[]}', method="POST",
    headers={"Content-Type": "application/json", "Accept": "application/json",
             "User-Agent": ua})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        code, body = r.status, r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as ex:
    code, body = ex.code, ex.read().decode("utf-8", "replace")
except Exception as ex:
    code, body = -1, str(ex)
print(json.dumps({"status": code, "edge_banned": "error code: 1010" in body,
                  "body": body[:200]}))
'@
  $pFile = Join-Path $env:TEMP ("nivx_r5_pyprobe_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $pFile -Value $pyProbe -Encoding UTF8
  $toolUa = (& $VenvPy -c "import importlib.util,sys;s=importlib.util.spec_from_file_location('t',r'$Tool');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.USER_AGENT)") -join ''
  Write-Host ("  python client User-Agent: " + $toolUa)
  $pyRes = (& $VenvPy $pFile $BaseUrl $toolUa) -join "`n" | ConvertFrom-Json
  Remove-Item $pFile -ErrorAction SilentlyContinue
  Write-Host ("  python client, unauthenticated reconcile -> HTTP " + $pyRes.status +
              "   edge_banned=" + $pyRes.edge_banned + "   (require 403 / False)")
  if ($pyRes.edge_banned -or [int]$pyRes.status -ne 403) {
    Write-Host ''
    if ($pyRes.edge_banned) {
      Write-Host '  EDGE BAN ON THE PYTHON CLIENT (error code: 1010) - DO NOT RETYPE' -ForegroundColor Red
      Write-Host '  PASSWORD. NO RECONCILIATION ATTEMPTED. The request never reaches' -ForegroundColor Red
      Write-Host '  the backend, so this is not an authorization or token problem.' -ForegroundColor Red
    } else {
      Write-Host '  BACKEND NOT READY/BOUND - DO NOT RETYPE PASSWORD. NO RECONCILIATION ATTEMPTED.' -ForegroundColor Red
    }
    throw ('the python client itself was refused before authentication (HTTP ' +
           $pyRes.status + ', edge_banned=' + $pyRes.edge_banned + '): ' +
           $pyRes.body + ' . No credential was requested and nothing was ' +
           'written. Report this rather than retrying.')
  }
  Write-Host '  the python client signature is accepted by the edge; 403 is FastAPI' -ForegroundColor Green
  Write-Host '  both routes bound on the same backend; reconcile still protected' -ForegroundColor Green

  Write-Host "`n=== 3 . AUTHENTICATE (read-only reconciliation) ===" -ForegroundColor Cyan
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
  Write-Host "`n=== 4 . RECONCILE THE EXACT $ExpectCount (one request, read-only) ===" -ForegroundColor Cyan
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
  Write-Host "`n=== 5 . INDEPENDENT NON-MUTATION RE-CHECK ===" -ForegroundColor Cyan
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
  Write-Host "`n=== 6 . VERDICT ===" -ForegroundColor Cyan
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

  # A PASS is the ONLY path that yields 0. A failed python run, a missing
  # authority file, or anything else yields non-zero.
  if ($exit -eq 0 -and (Test-Path $OutFile)) { return 0 } else { return 1 }
}
catch {
  Remove-Item Env:\NIVX_RECONCILE_TOKEN -ErrorAction SilentlyContinue
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
  # Every HARD STOP must be observable to the parent process. The previous
  # execution copy printed HARD STOP and still exited 0, which made a failed
  # prerequisite look like a successful run.
  return 1
}
}

$NivxExit = Invoke-G1R5Inflight50Reconcile
if ($null -eq $NivxExit) { $NivxExit = 1 }
Write-Host ("`nPROCESS EXIT CODE: " + $NivxExit) -ForegroundColor $(
  if ($NivxExit -eq 0) { 'Green' } else { 'Red' })
$global:LASTEXITCODE = $NivxExit
# When saved and run as a .ps1, surface the code to the parent process. When
# pasted interactively, `exit` would close the window and destroy the console
# evidence, so the code is only printed and left in $LASTEXITCODE.
if ($PSCommandPath) { exit $NivxExit }

