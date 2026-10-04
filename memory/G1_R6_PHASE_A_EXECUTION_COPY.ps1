# =====================================================================
# G1-R6 PHASE A . LOCAL ACCOUNTING REPAIR OF THE EXACT 22 CANONICAL ROWS
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# WHY THIS EXISTS
#   The exact-50 recovery produced per-row authority: of the 50 rows the
#   interrupted worker left in `delivering`, 22 are DELIVERED_CANONICAL
#   server-side and 28 are RETRYABLE_STILL_QUEUED. The endpoint's accounting
#   for those 22 is stale - the delivery is not. This block repairs ONLY that
#   local bookkeeping: delivering -> delivered.
#
# WHAT IT DOES
#   1. writer guard + tool lineage (pinned SHA-256)
#   2. validates the authority file: pass=true, 50 rows, exactly 22 canonical
#      and 28 retryable, and that it is NOT the FAILED-UNTRUSTED sibling
#   3. reports whether `envelopes.recovery_json` exists (the audit column the
#      repair marker is written into)
#   4. DRY RUN: plans the 22, proves the database bytes, histogram, bookmarks
#      and the 28 retryable rows are untouched
#   5. only when $Apply = $true: backs up outbox.db, then applies the 22
#      transitions in ONE SQLite transaction after every precondition passes
#
# WHAT IT NEVER DOES
#   no network I/O of any kind . no reconciliation request . no ingest client .
#   no Outbox construction . no DeliveryWorker . no delivery / redelivery /
#   requeue / retry . no acquisition . no EvtSubscribe . no bookmark write .
#   no change to the 28 retryable rows, their status, attempts,
#   next_attempt_at or last_error . no Phase B . no backlog processing
#
#   There is no credential prompt and no authentication in this phase,
#   because there is no network destination. (Operational convention: when a
#   script DOES need a credential it must name the authority explicitly, e.g.
#   "NivXRay XDR PREVIEW Admin Password".)
#
# EXPECTED PRE-STATE      EXPECTED POST-STATE (only after $Apply = $true)
#   delivered    3284       delivered    3306   (+22)
#   delivering     50       delivering     28   (-22)
#   queued     121993       queued     121993
#   retrying      125       retrying      125
#   dead_letter     0       dead_letter     0
#   total      125452       total      125452
#   bookmarks unchanged in BOTH modes.
#
# FAILURE SEMANTICS
#   EVERY failure path returns a NON-ZERO process exit code. Exit 0 requires
#   the tool to report pass=true. Any refused row, any count mismatch, any
#   identity mismatch and any violated invariant rolls the whole transaction
#   back - the repair is all-or-nothing.
#
# OUTPUT (C:\ProgramData\NivXForge\state\g1_r6_evidence\)
#   r6-phaseA-dryrun.json   (always)
#   r6-phaseA-apply.json    (only when $Apply = $true)
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ============ THE ONLY SWITCH IN THIS BLOCK ==========================
# Leave $false to plan and prove without touching anything. Set $true ONLY
# after reading r6-phaseA-dryrun.json and confirming: planned 22, refused 0,
# retryable_untouched 28, every invariant true.
$Apply = $false
# =====================================================================

function Invoke-G1R6PhaseA {

# ---- configuration ---------------------------------------------------
$StateDir = 'C:\ProgramData\NivXForge\state'
$Work     = 'C:\nivx'
# The collector lives UNDER apps\ in the monorepo.
$Repo     = "$Work\apps\nivxray-xdr-collector"
$VenvPy   = "$Work\.venv\Scripts\python.exe"
$Tool     = "$Repo\scripts\g1_r6_local_accounting_repair.py"
$ProofDir = "$Work\g1-proof\r5"
$Authority = "$ProofDir\r5-inflight-50-server-reconciliation.json"
$EvidenceDir = "$StateDir\g1_r6_evidence"

$ExpectCanonical = 22
$ExpectRetryable = 28
$ExpectTotalRows = 125452

# Lineage of the repair tool this block was written for.
$ExpectToolSha = 'C92FA282CEB1A6F7F9EAAD30FAA43471071498BE6D8DE4EB7E4D9CB1A47A2B64'

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. Nothing was attempted.'
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $VenvPy))    { throw "venv python not found at $VenvPy" }
  if (-not (Test-Path $db))        { throw "outbox database not found at $db" }
  if (-not (Test-Path $Tool))      {
    throw ("tool not found at $Tool . The collector lives UNDER apps\ in the " +
           "monorepo; confirm $Repo exists after the pull. Nothing was attempted.")
  }
  if (-not (Test-Path $Authority)) {
    throw ("the exact-50 authority file was not found at $Authority . Phase A " +
           'consumes per-row server proof and refuses to infer it. Nothing ' +
           'was attempted.')
  }
  if ([string]::IsNullOrWhiteSpace($env:NIVX_COLLECTOR_ID)) {
    throw 'NIVX_COLLECTOR_ID is not set in this window. The delivery identity that binds each server proof to a local row is derived from it. Nothing was attempted.'
  }

  $bar = '=' * 60
  Write-Host ''
  Write-Host "  $bar" -ForegroundColor Cyan
  Write-Host '   NivXRay XDR - G1-R6 Phase A Local Accounting Repair' -ForegroundColor Cyan
  Write-Host "  $bar" -ForegroundColor Cyan
  Write-Host  '   Product      : NivXRay XDR / NivXForge EDR Collector'
  Write-Host  '   Scope        : LOCAL SQLite BOOKKEEPING ONLY'
  Write-Host ("   Endpoint DB  : " + $db)
  Write-Host ("   Authority    : " + (Split-Path $Authority -Leaf))
  Write-Host  '   Network      : NONE - no destination, no credential required'
  Write-Host ("   Mode         : " + $(if ($Apply) { 'APPLY (mutating, transactional)' }
                                       else { 'DRY RUN (read-only)' })) `
             -ForegroundColor $(if ($Apply) { 'Red' } else { 'Yellow' })
  Write-Host  '   Operation    : delivering -> delivered for exactly 22 rows'
  Write-Host "  $bar" -ForegroundColor Cyan

  # ---- 0 . writer guard + lineage ------------------------------------
  Write-Host "`n=== 0 . WRITER GUARD + LINEAGE ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*' -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object { Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. Stop it first: it would race the repair and could requeue the 28. Nothing was attempted.'
  }
  $toolSha = (Get-FileHash $Tool -Algorithm SHA256).Hash
  Write-Host ("  pinned repair tool sha256: " + $toolSha)
  if ($toolSha -ne $ExpectToolSha) {
    throw ('tool sha256 is ' + $toolSha + ', expected ' + $ExpectToolSha +
           '. The checkout is not the reviewed Phase A tool. Pull ' +
           'feature/rc2-alignment again. Nothing was attempted.')
  }
  Write-Host ("  authority sha256:          " + (Get-FileHash $Authority -Algorithm SHA256).Hash)
  Write-Host ("  outbox.db sha256 (pre):    " + (Get-FileHash $db -Algorithm SHA256).Hash)
  Write-Host '  no writer running; tool lineage verified' -ForegroundColor Green

  # ---- 1 . validate the authority file -------------------------------
  Write-Host "`n=== 1 . AUTHORITY FILE ===" -ForegroundColor Cyan
  $auth = Get-Content $Authority -Raw | ConvertFrom-Json
  if ($auth.PSObject.Properties.Name -contains 'VERDICT') {
    throw ('this file is the FAILED/UNTRUSTED forensic sibling, not authority ' +
           'for R6: ' + $auth.VERDICT + ' . Nothing was attempted.')
  }
  if ($auth.pass -ne $true) { throw 'the authority file does not carry pass=true. Nothing was attempted.' }
  $rowCount  = @($auth.rows).Count
  $canonical = @($auth.rows | Where-Object { $_.bucket -eq 'DELIVERED_CANONICAL' }).Count
  $retryable = @($auth.rows | Where-Object { $_.bucket -eq 'RETRYABLE_STILL_QUEUED' }).Count
  Write-Host ("  rows=" + $rowCount + "  canonical=" + $canonical +
              "  retryable=" + $retryable +
              "   (require 50 / $ExpectCanonical / $ExpectRetryable)")
  if ($rowCount -ne ($ExpectCanonical + $ExpectRetryable) -or
      $canonical -ne $ExpectCanonical -or $retryable -ne $ExpectRetryable) {
    throw 'the authority file does not carry exactly 22 canonical + 28 retryable rows. Nothing was attempted.'
  }
  $noEvidence = @($auth.rows | Where-Object {
      $_.bucket -eq 'DELIVERED_CANONICAL' -and
      ([string]::IsNullOrWhiteSpace($_.evidence_ref) -or
       [string]::IsNullOrWhiteSpace($_.claim.canonical_event_id)) }).Count
  Write-Host ("  canonical rows lacking evidence_ref/canonical_event_id: " + $noEvidence + "   (require 0)")
  if ($noEvidence -ne 0) {
    throw 'some canonical rows carry no resolvable server evidence. Nothing was attempted.'
  }
  Write-Host '  authority file is the per-row PASS record' -ForegroundColor Green

  # ---- 2 . audit column -----------------------------------------------
  Write-Host "`n=== 2 . AUDIT COLUMN (recovery_json) ===" -ForegroundColor Cyan
  $colProbe = @'
import json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
cols = [c[1] for c in con.execute("PRAGMA table_info(envelopes)")]
print(json.dumps({"has_recovery_json": "recovery_json" in cols,
                  "columns": cols}))
'@
  $cFile = Join-Path $env:TEMP ("nivx_r6_cols_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $cFile -Value $colProbe -Encoding UTF8
  $cols = (& $VenvPy $cFile $db) -join "`n" | ConvertFrom-Json
  Remove-Item $cFile -ErrorAction SilentlyContinue
  Write-Host ("  envelopes.recovery_json present: " + $cols.has_recovery_json)
  if (-not $cols.has_recovery_json) {
    Write-Host '  the repair marker has nowhere to be written. APPLY would' -ForegroundColor Yellow
    Write-Host '  hard-stop unless the column is added (additive, as R4 did).' -ForegroundColor Yellow
    Write-Host '  Report this instead of improvising: the owner decides whether' -ForegroundColor Yellow
    Write-Host '  --allow-schema-add is authorised.' -ForegroundColor Yellow
    if ($Apply) {
      throw ('APPLY refused: envelopes has no recovery_json column, so the ' +
             'repair could not be recorded on the row itself. Nothing was ' +
             'changed. Re-authorise with --allow-schema-add if you want the ' +
             'additive column.')
    }
  }

  # ---- 3 . DRY RUN ----------------------------------------------------
  Write-Host "`n=== 3 . DRY RUN (read-only plan + proof) ===" -ForegroundColor Cyan
  $dry = & $VenvPy $Tool `
            --state-dir        $StateDir `
            --proof            $Authority `
            --evidence-dir     $EvidenceDir `
            --expect-canonical $ExpectCanonical `
            --expect-retryable $ExpectRetryable `
            --expect-total     $ExpectTotalRows
  $dryExit = $LASTEXITCODE
  ($dry -join "`n") | Write-Host
  Write-Host ("`n  dry-run exit code: " + $dryExit)
  if ($dryExit -ne 0) {
    throw ('the dry run did not pass (exit ' + $dryExit + '). Nothing was ' +
           'changed. Do not set $Apply until this is green.')
  }
  Write-Host ("  outbox.db sha256 (post dry run): " + (Get-FileHash $db -Algorithm SHA256).Hash) -ForegroundColor Green

  if (-not $Apply) {
    Write-Host "`n=== 4 . STOP (DRY RUN ONLY) ===" -ForegroundColor Cyan
    Write-Host '  Nothing was changed. outbox.db is byte-identical and the 50' -ForegroundColor Yellow
    Write-Host '  rows are all still `delivering`.' -ForegroundColor Yellow
    Write-Host ("  Review " + (Join-Path $EvidenceDir 'r6-phaseA-dryrun.json')) -ForegroundColor Yellow
    Write-Host '  Confirm: planned 22, refused 0, retryable_untouched 28, every' -ForegroundColor Yellow
    Write-Host '  invariant true. Then set $Apply = $true and re-run.' -ForegroundColor Yellow
    Write-Host '  Phase B (the 28) was NOT built and NOT executed.' -ForegroundColor Yellow
    return 0
  }

  # ---- 4 . BACKUP, then APPLY -----------------------------------------
  Write-Host "`n=== 4 . BACKUP BEFORE THE ONLY MUTATING STEP ===" -ForegroundColor Cyan
  $stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $backup = Join-Path $ProofDir ("outbox-pre-r6a-" + $stamp + ".db")
  Copy-Item $db $backup
  foreach ($side in @("$db-wal", "$db-shm")) {
    if (Test-Path $side) { Copy-Item $side ($backup + [IO.Path]::GetExtension($side)) }
  }
  Write-Host ("  backup: " + $backup)
  Write-Host ("  backup sha256: " + (Get-FileHash $backup -Algorithm SHA256).Hash)

  Write-Host "`n=== 5 . APPLY (one transaction, 22 rows) ===" -ForegroundColor Cyan
  $app = & $VenvPy $Tool `
            --state-dir        $StateDir `
            --proof            $Authority `
            --evidence-dir     $EvidenceDir `
            --expect-canonical $ExpectCanonical `
            --expect-retryable $ExpectRetryable `
            --expect-total     $ExpectTotalRows `
            --apply
  $appExit = $LASTEXITCODE
  ($app -join "`n") | Write-Host
  Write-Host ("`n  apply exit code: " + $appExit)

  # ---- 6 . independent post-state re-check ----------------------------
  Write-Host "`n=== 6 . INDEPENDENT POST-STATE RE-CHECK ===" -ForegroundColor Cyan
  $hist = @'
import json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
print(json.dumps({
    "counts_by_status": {r[0]: r[1] for r in con.execute(
        "SELECT status, COUNT(*) FROM envelopes GROUP BY status")},
    "total": con.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0],
    "repaired_marker_rows": con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json LIKE '%G1-R6-A%'"
        ).fetchone()[0]}))
'@
  $hFile = Join-Path $env:TEMP ("nivx_r6_hist_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $hFile -Value $hist -Encoding UTF8
  $after = (& $VenvPy $hFile $db) -join "`n" | ConvertFrom-Json
  Remove-Item $hFile -ErrorAction SilentlyContinue
  $c = $after.counts_by_status
  Write-Host ("  delivered="   + $c.delivered + "  delivering=" + $c.delivering +
              "  queued="      + $c.queued    + "  retrying="   + $c.retrying +
              "  dead_letter=" + $c.dead_letter + "  total="     + $after.total)
  Write-Host ("  rows carrying the G1-R6-A repair marker: " + $after.repaired_marker_rows)
  $ok = ($appExit -eq 0 -and [int]$c.delivered -eq 3306 -and
         [int]$c.delivering -eq 28 -and [int]$c.queued -eq 121993 -and
         [int]$c.retrying -eq 125 -and [int]$after.total -eq $ExpectTotalRows -and
         [int]$after.repaired_marker_rows -eq $ExpectCanonical)
  Write-Host ("  contracted post-state reached: " + $ok) -ForegroundColor $(
    if ($ok) { 'Green' } else { 'Red' })

  Write-Host "`n=== 7 . VERDICT ===" -ForegroundColor Cyan
  if ($ok) {
    Write-Host '  R6 PHASE A: PASS - 22 rows repaired as local accounting only.' -ForegroundColor Green
    Write-Host '  The 28 retryable rows are UNTOUCHED and still `delivering`.' -ForegroundColor Green
    Write-Host '  Phase B was NOT built and NOT executed.' -ForegroundColor Green
    return 0
  }
  Write-Host '  R6 PHASE A: FAIL - report before any further action.' -ForegroundColor Red
  Write-Host ("  restore from: " + $backup) -ForegroundColor Yellow
  return 1
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
  return 1
}
}

$NivxExit = Invoke-G1R6PhaseA
if ($null -eq $NivxExit) { $NivxExit = 1 }
Write-Host ("`nPROCESS EXIT CODE: " + $NivxExit) -ForegroundColor $(
  if ($NivxExit -eq 0) { 'Green' } else { 'Red' })
$global:LASTEXITCODE = $NivxExit
if ($PSCommandPath) { exit $NivxExit }
