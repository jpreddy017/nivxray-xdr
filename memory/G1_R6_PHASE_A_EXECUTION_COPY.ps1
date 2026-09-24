# =====================================================================
# G1-R6 PHASE A . LOCAL ACCOUNTING REPAIR OF THE 22 PROVEN ROWS
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# WHAT THIS IS
#   R5 proved, at identity level, that of the 50 rows the interrupted worker
#   left in `delivering`:
#       22 are DELIVERED_CANONICAL server-side  -> local accounting is stale
#       28 are RETRYABLE_STILL_QUEUED           -> genuinely not delivered
#   This block repairs ONLY those 22, and only locally: delivering -> delivered.
#
# WHAT IT DOES NOT DO
#   NO network delivery . NO redelivery . NO retry . NO requeue .
#   NO touch of the 28 retryable rows . NO touch of the 400 proven rows .
#   NO acquisition . NO Event Log read . NO bookmark write . NO Outbox
#   construction (so R3.1 restart recovery never runs and cannot requeue the
#   28 as a side effect) . NO backlog widening . NO deploy .
#
# AUTHORITY FOR EVERY MUTATION
#   each repaired row must appear in r5-server-reconciliation.json as
#   bucket=DELIVERED_CANONICAL with a resolvable evidence_ref and a
#   canonical_event_id, AND its locally recomputed delivery identity must
#   equal the identity the server answered about. Any mismatch refuses the
#   ENTIRE repair - the update is one transaction.
#
# STAGES
#   0  locate the R5 proof, verify counts (22 / 28) and tool lineage
#   1  writer guard + SHA-256 verified backup
#   2  independent read-only pre-evidence
#   3  DRY RUN (opens the database read-only; writes nothing)
#   4  APPLY (only when $Apply = $true) - one transaction, 22 rows
#   5  independent post-evidence + exact pre/post accounting
#   6  optional post-repair reconciliation of the SAME 22 identities
#   7  verdict, then STOP
#
# OUTPUT (C:\nivx\g1-proof\r6\)
#   r6-pre-endpoint-evidence.json      r6-phaseA-dryrun.json
#   r6-phaseA-apply.json               r6-post-endpoint-evidence.json
#   r6-phaseA-verdict.json
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R6PhaseA {

# ---- configuration ---------------------------------------------------
$StateDir    = 'C:\ProgramData\NivXForge\state'
$Work        = 'C:\nivx'
$Repo        = "$Work\nivxray-xdr-collector"
$VenvPy      = "$Work\.venv\Scripts\python.exe"
$R5Proof     = "$Work\g1-proof\r5\r5-server-reconciliation.json"
$ProofDir    = "$Work\g1-proof\r6"
$BackupDir   = "$Work\g1-proof\backup"
$Tool        = "$Repo\scripts\g1_r6_local_accounting_repair.py"
$BaseUrl     = 'https://greeting-app-5782.preview.emergentagent.com'

$ExpectCanonical = 22
$ExpectRetryable = 28
$ExpectTotalRows = 125452

# ---- THE ONLY SWITCH -------------------------------------------------
#   $false = dry run only (database opened read-only, nothing written)
#   $true  = apply the 22-row local status repair, transactionally
$Apply       = $false

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. Nothing was attempted.'
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $VenvPy))  { throw "venv python not found at $VenvPy" }
  if (-not (Test-Path $db))      { throw "outbox database not found at $db" }
  if (-not (Test-Path $R5Proof)) {
    throw ("R5 proof not found at $R5Proof . That file is written at stage 4 " +
           'of the reconcile-only run, BEFORE the optional control, so it ' +
           'should exist even though the script terminated later. Nothing was attempted.')
  }
  if (-not (Test-Path $Tool))    { throw "tool not found at $Tool (publish the branch and pull)" }
  if ([string]::IsNullOrWhiteSpace($env:NIVX_COLLECTOR_ID)) {
    throw 'NIVX_COLLECTOR_ID is not set in this window. The delivery identity that binds the server proof to a local row is derived from it. Nothing was attempted.'
  }
  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

  # ---- 0 . proof + lineage -------------------------------------------
  Write-Host "`n=== 0 . R5 PROOF + TOOL LINEAGE ===" -ForegroundColor Cyan
  $proof = Get-Content $R5Proof -Raw | ConvertFrom-Json
  $prows = @($proof.rows)
  $inflight  = @($prows | Where-Object { $_.endpoint_outcome -eq 'delivering' })
  $canonical = @($inflight | Where-Object { $_.bucket -eq 'DELIVERED_CANONICAL' })
  $retryable = @($inflight | Where-Object { $_.bucket -eq 'RETRYABLE_STILL_QUEUED' })
  Write-Host ("  proof rows: " + $prows.Count +
              "  in-flight: " + $inflight.Count +
              "  canonical: " + $canonical.Count +
              "  retryable: " + $retryable.Count)
  if ($canonical.Count -ne $ExpectCanonical -or $retryable.Count -ne $ExpectRetryable) {
    throw ("the proof splits in-flight rows as " + $canonical.Count + '/' +
           $retryable.Count + ', expected ' + $ExpectCanonical + '/' +
           $ExpectRetryable + '. Nothing was attempted.')
  }
  Write-Host ("  tool sha256: " + (Get-FileHash $Tool -Algorithm SHA256).Hash)
  $help = (& $VenvPy $Tool --help) -join ' '
  foreach ($opt in @('proof', 'expect-canonical', 'expect-retryable', 'apply')) {
    if ($help -notmatch $opt) { throw "the tool has no --$opt option; the checkout is stale." }
  }
  Write-Host '  proof and tool verified' -ForegroundColor Green

  # ---- 1 . writer guard + backup -------------------------------------
  Write-Host "`n=== 1 . WRITER GUARD + VERIFIED BACKUP ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*' -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object { Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. Stop it first. Nothing was attempted.'
  }
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $bak = Join-Path $BackupDir ("outbox.pre-r6a.$stamp.db")
  foreach ($suf in @('', '-wal', '-shm')) {
    if (Test-Path "$db$suf") {
      Copy-Item "$db$suf" ("$bak" + $suf) -Force
      $a = (Get-FileHash "$db$suf" -Algorithm SHA256).Hash
      $b = (Get-FileHash ("$bak"+$suf) -Algorithm SHA256).Hash
      if ($a -ne $b) { throw "backup hash mismatch for $db$suf" }
    }
  }
  Write-Host ("  backup verified: " + $bak) -ForegroundColor Green

  # ---- independent read-only evidence helper -------------------------
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
  $sFile = Join-Path $env:TEMP ("nivx_r6_snap_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $sFile -Value $snap -Encoding UTF8
  function Snapshot { return (& $VenvPy $sFile $db) -join "`n" | ConvertFrom-Json }

  # ---- 2 . pre-evidence ----------------------------------------------
  Write-Host "`n=== 2 . PRE-REPAIR EVIDENCE (read-only) ===" -ForegroundColor Cyan
  $pre = Snapshot
  $pre | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r6-pre-endpoint-evidence.json') -Encoding UTF8
  Write-Host ("  queued="      + $pre.counts_by_status.queued +
              "  delivering="  + $pre.counts_by_status.delivering +
              "  delivered="   + $pre.counts_by_status.delivered +
              "  retrying="    + $pre.counts_by_status.retrying +
              "  dead_letter=" + $pre.counts_by_status.dead_letter +
              "  total="       + $pre.total)
  if ($pre.total -ne $ExpectTotalRows) {
    throw ("total rows is " + $pre.total + ", expected " + $ExpectTotalRows + '. HARD STOP.')
  }
  if ([int]$pre.counts_by_status.delivering -ne ($ExpectCanonical + $ExpectRetryable)) {
    throw ("delivering is " + $pre.counts_by_status.delivering + ", expected " +
           ($ExpectCanonical + $ExpectRetryable) + '. HARD STOP.')
  }
  Write-Host '  frozen endpoint state confirmed' -ForegroundColor Green

  # ---- 3 . DRY RUN ---------------------------------------------------
  Write-Host "`n=== 3 . DRY RUN (database opened read-only) ===" -ForegroundColor Cyan
  & $VenvPy $Tool --state-dir $StateDir --proof $R5Proof `
      --evidence-dir $ProofDir --expect-canonical $ExpectCanonical `
      --expect-retryable $ExpectRetryable
  if ($LASTEXITCODE -ne 0) { throw "dry run did not pass (exit $LASTEXITCODE). Nothing was changed." }
  $dry = Get-Content (Join-Path $ProofDir 'r6-phaseA-dryrun.json') -Raw | ConvertFrom-Json
  Write-Host ("  planned=" + $dry.planned.Count + "  refused=" + $dry.refused.Count +
              "  retryable_untouched=" + $dry.retryable_untouched.Count)
  if ($dry.planned.Count -ne $ExpectCanonical) {
    throw ('the dry run planned ' + $dry.planned.Count + ' rows, expected ' +
           $ExpectCanonical + '. Nothing was changed.')
  }

  if (-not $Apply) {
    Write-Host "`n=== DRY RUN COMPLETE . NOTHING WAS CHANGED ===" -ForegroundColor Yellow
    Write-Host "  Review r6-phaseA-dryrun.json, then set `$Apply = `$true and re-run." -ForegroundColor Yellow
    return
  }

  # ---- 4 . APPLY -----------------------------------------------------
  Write-Host "`n=== 4 . APPLY . 22-ROW LOCAL ACCOUNTING REPAIR ===" -ForegroundColor Cyan
  & $VenvPy $Tool --state-dir $StateDir --proof $R5Proof `
      --evidence-dir $ProofDir --expect-canonical $ExpectCanonical `
      --expect-retryable $ExpectRetryable --apply
  $applyExit = $LASTEXITCODE
  $applied = Get-Content (Join-Path $ProofDir 'r6-phaseA-apply.json') -Raw | ConvertFrom-Json
  Write-Host ("  repaired rows: " + $applied.repair.updated.Count +
              "  repair_id: " + $applied.repair.repair_id)
  Write-Host ("  delivered delta = " + $applied.invariants.delivered_delta_exact.actual +
              "  delivering delta = " + $applied.invariants.delivering_delta_exact.actual)

  # ---- 5 . post-evidence ---------------------------------------------
  Write-Host "`n=== 5 . POST-REPAIR EVIDENCE (independent, read-only) ===" -ForegroundColor Cyan
  $post = Snapshot
  $post | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r6-post-endpoint-evidence.json') -Encoding UTF8
  Write-Host ("  queued="      + $post.counts_by_status.queued +
              "  delivering="  + $post.counts_by_status.delivering +
              "  delivered="   + $post.counts_by_status.delivered +
              "  retrying="    + $post.counts_by_status.retrying +
              "  dead_letter=" + $post.counts_by_status.dead_letter +
              "  total="       + $post.total)
  $deliveredDelta   = [int]$post.counts_by_status.delivered   - [int]$pre.counts_by_status.delivered
  $deliveringDelta  = [int]$post.counts_by_status.delivering  - [int]$pre.counts_by_status.delivering
  $queuedSame       = ([int]$post.counts_by_status.queued      -eq [int]$pre.counts_by_status.queued)
  $retryingSame     = ([int]$post.counts_by_status.retrying    -eq [int]$pre.counts_by_status.retrying)
  $deadSame         = ([int]$post.counts_by_status.dead_letter -eq [int]$pre.counts_by_status.dead_letter)
  $totalSame        = (($pre.total -eq $post.total) -and ($post.total -eq $ExpectTotalRows))
  $bookmarksSame    = ($pre.bookmarks.sha256 -eq $post.bookmarks.sha256)
  $retryableHeld    = ([int]$post.counts_by_status.delivering -eq $ExpectRetryable)
  Write-Host ("  delivered +" + $deliveredDelta + " (expected +" + $ExpectCanonical + ")")
  Write-Host ("  delivering " + $deliveringDelta + " (expected -" + $ExpectCanonical + ")")
  Write-Host ("  queued/retrying/dead unchanged = " + ($queuedSame -and $retryingSame -and $deadSame))
  Write-Host ("  total rows unchanged = " + $totalSame + "   bookmarks unchanged = " + $bookmarksSame)
  Write-Host ("  the 28 retryable rows still delivering = " + $retryableHeld)

  # ---- 6 . post-repair reconciliation of the SAME 22 -----------------
  Write-Host "`n=== 6 . POST-REPAIR RECONCILIATION (read-only, optional) ===" -ForegroundColor Cyan
  $reconOk = $null
  $reconStatus = $null
  try {
    function Get-PlainFromSecure([System.Security.SecureString]$sec) {
      $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
      try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
      finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
    $adminEmail  = Read-Host '  NivXRay admin e-mail (blank to skip)'
    if (-not [string]::IsNullOrWhiteSpace($adminEmail)) {
      $adminSecret = Read-Host '  NivXRay admin password (not echoed)' -AsSecureString
      $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
        -ContentType 'application/json' -TimeoutSec 30 `
        -Body (@{ email = $adminEmail
                  password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
      $jwt = $login.access_token
      Remove-Variable login, adminSecret, adminEmail -ErrorAction SilentlyContinue
      [GC]::Collect()
      $body = @{ identities = @($canonical | ForEach-Object {
        @{ ref = $_.ref; delivery_key = $_.delivery_key
           source_event_id = $_.source_event_id
           collector_id = $_.collector_id
           endpoint_outcome = 'delivered' } }) }
      $re = Invoke-RestMethod -Method Post `
        -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
        -Headers @{ Authorization = "Bearer $jwt" } `
        -ContentType 'application/json' -TimeoutSec 120 `
        -Body ($body | ConvertTo-Json -Depth 6)
      Remove-Variable jwt -ErrorAction SilentlyContinue; [GC]::Collect()
      $re | ConvertTo-Json -Depth 8 |
          Set-Content (Join-Path $ProofDir 'r6-post-repair-reconciliation.json') -Encoding UTF8
      Write-Host ("  canonical=" + $re.buckets.DELIVERED_CANONICAL +
                  "  unexplained=" + $re.unexplained + "  pass=" + $re.'pass')
      $reconOk = (([int]$re.buckets.DELIVERED_CANONICAL -eq $ExpectCanonical) -and
                  ([int]$re.unexplained -eq 0))
    } else {
      Write-Host '  skipped by operator' -ForegroundColor Yellow
    }
  } catch {
    if ($_.Exception.Response) { $reconStatus = [int]$_.Exception.Response.StatusCode }
    Write-Host ("  post-repair reconciliation could not run (HTTP " + $reconStatus +
                "); recorded as inconclusive. The local repair above is unaffected.") -ForegroundColor Yellow
  }

  # ---- 7 . verdict ---------------------------------------------------
  Write-Host "`n=== 7 . VERDICT ===" -ForegroundColor Cyan
  $pass = ($applyExit -eq 0) -and
          ($applied.repair.updated.Count -eq $ExpectCanonical) -and
          ($applied.refused.Count -eq 0) -and
          ($deliveredDelta -eq $ExpectCanonical) -and
          ($deliveringDelta -eq (-1 * $ExpectCanonical)) -and
          $queuedSame -and $retryingSame -and $deadSame -and
          $totalSame -and $bookmarksSame -and $retryableHeld -and
          ($reconOk -ne $false)
  $verdict = [pscustomobject]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    phase = 'G1-R6 Phase A . local accounting repair of the 22 proven rows'
    network_delivery_performed = $false
    rows_redelivered = 0
    repaired = $applied.repair.updated.Count
    repair_id = $applied.repair.repair_id
    refused = $applied.refused.Count
    retryable_untouched = $ExpectRetryable
    pre_histogram = $pre.counts_by_status
    post_histogram = $post.counts_by_status
    delivered_delta = $deliveredDelta
    delivering_delta = $deliveringDelta
    queued_unchanged = $queuedSame
    retrying_unchanged = $retryingSame
    dead_letter_unchanged = $deadSame
    total_rows = $post.total
    total_rows_unchanged = $totalSame
    bookmarks_unchanged = $bookmarksSame
    bookmark_sha256 = $post.bookmarks.sha256
    delivery_health_gate = $post.delivery_health_gate
    post_repair_reconciliation_ok = $reconOk
    post_repair_reconciliation_http = $reconStatus
    backup = $bak
    overall_pass = $pass
    next_decision = 'the 28 RETRYABLE_STILL_QUEUED rows remain in `delivering` and are untouched; Phase B is a separate owner authorisation'
  }
  $verdict | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r6-phaseA-verdict.json') -Encoding UTF8
  $verdict | ConvertTo-Json -Depth 6 | Write-Host

  if ($pass) {
    Write-Host "`n=== PHASE A: PASS . 22 ROWS CORRECTED, 0 REDELIVERED ===" -ForegroundColor Green
  } else {
    Write-Host "`n=== PHASE A: FAIL . REVIEW BEFORE ANY FURTHER ACTION ===" -ForegroundColor Red
  }
  Write-Host "`nSTOP. The 28 retryable rows were not touched and nothing was" -ForegroundColor Yellow
  Write-Host 'delivered. Send r6-phaseA-verdict.json back before Phase B.' -ForegroundColor Yellow
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
}
}

Invoke-G1R6PhaseA
