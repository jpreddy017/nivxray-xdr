# =====================================================================
# G1-R4 . FIRST CONTROLLED RECOVERY BATCH . EXACTLY 500 ROWS
# ELEVATED PowerShell (Run as Administrator).
#
# THIS IS THE FIRST INTENTIONAL MUTATION OF THE 14,868 PRESERVED ROWS.
#
# WHAT IT DOES
#   0. refreshes the checkout and refuses a stale tool
#   1. writer guard: refuses while any process holds the outbox
#   2. fresh SHA-256 verified pre-batch backup (earlier backups preserved)
#   3. independent PRE-batch snapshot (counts + bookmark hash)
#   4. read-only dry run: aborts unless target == 14,868 and non-target == 0
#   5. EXECUTE one batch: --expect-count 14868 --batch-size 500
#      --max-batches 1   ->  requeue 500 rows, nothing else
#   6. independent POST-batch verification against the exact expected
#      numbers, computed WITHOUT trusting the tool's own report
#   7. prints PASS/FAIL and writes the rollback command for this exact
#      recovery id
#
# WHAT IT DOES NOT DO
#   * does NOT start the collector, the delivery worker or acquisition
#   * does NOT deliver, acknowledge or mark anything delivered
#   * does NOT read or write bookmarks / checkpoints
#   * does NOT touch the other 14,368 rows, or any non-target dead letter
#   * does NOT deploy, merge or push
#
# EXPECTED TRANSITION
#   dead_letter  14868 -> 14368
#   queued      107525 -> 108025
#   delivered     2884 -> 2884
#   delivering      50 -> 50
#   retrying       125 -> 125
#   total       125452 -> 125452
#
# OUTPUT
#   C:\nivx\g1-proof\r4-batch1-dryrun.json
#   C:\nivx\g1-proof\r4-batch1.json
#   C:\nivx\g1-proof\r4-batch1-verify.json
#   C:\nivx\g1-proof\r4-batch1-rollback.txt
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R4FirstBatch {

$StateDir  = 'C:\ProgramData\NivXForge\state'
$Work      = 'C:\nivx'
$Repo      = "$Work\nivxray-xdr-collector"     # adjust if the checkout differs
$VenvPy    = "$Work\.venv\Scripts\python.exe"
$ProofDir  = "$Work\g1-proof"
$BackupDir = "$ProofDir\backup"
$Tool      = "$Repo\scripts\g1_r4_recover_dead_letters.py"
$Expect    = 14868
$Batch     = 500

# the exact expectations for this batch
$ExpDead = 14368; $ExpQueued = 108025; $ExpDelivered = 2884
$ExpDelivering = 50; $ExpRetrying = 125; $ExpTotal = 125452

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }

  # ---- 0 . refresh the checkout ------------------------------------
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
  foreach ($opt in @('max-batches', 'init-health-gate', 'json-out')) {
    if ($helpText -notmatch $opt) {
      throw ("the checkout is stale: the tool has no --$opt option. Pull the " +
             "published branch and re-run. Nothing was changed.")
    }
  }
  Write-Host "  tool present and current" -ForegroundColor Green

  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db)) { throw "outbox database not found at $db" }

  # ---- 1 . writer guard -------------------------------------------
  Write-Host "`n=== 1 . WRITER GUARD (collector must stay stopped) ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*'   -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object {
      Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw ('a collector process is running. Stop it first ' +
           '(Stop-Process -Id <pid> -Force). Nothing was changed.')
  }
  try {
    $probe = [System.IO.File]::Open($db, 'Open', 'ReadWrite', 'None')
    $probe.Close(); $probe.Dispose()
    Write-Host "  no process holds the outbox" -ForegroundColor Green
  } catch {
    throw ('the outbox is locked by another process. Nothing was changed. ' +
           'Detail: ' + $_.Exception.Message)
  }

  # ---- 2 . fresh verified pre-batch backup ------------------------
  Write-Host "`n=== 2 . PRE-BATCH BACKUP ===" -ForegroundColor Cyan
  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $pre   = Join-Path $BackupDir ("outbox.pre-r4batch1.$stamp.db")
  foreach ($suf in @('', '-wal', '-shm')) {
    if (Test-Path "$db$suf") {
      Copy-Item "$db$suf" ("$pre" + $suf) -Force
      $a = (Get-FileHash "$db$suf"     -Algorithm SHA256).Hash
      $b = (Get-FileHash ("$pre"+$suf) -Algorithm SHA256).Hash
      if ($a -ne $b) { throw "backup hash mismatch for $db$suf" }
      Write-Host ("  outbox.db" + $suf + " -> " + (Split-Path $pre -Leaf) + $suf +
                  "  sha256=" + $a.Substring(0,16) + "...")
    }
  }
  Write-Host "  pre-batch backup verified (earlier backups preserved)" -ForegroundColor Green

  # ---- the independent verifier (read-only, does not use the tool) --
  $verifier = @'
import hashlib, json, os, sqlite3, sys

db, rid = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
con.row_factory = sqlite3.Row
out = {"db": db, "recovery_id": rid}
out["counts_by_status"] = {r[0]: r[1] for r in con.execute(
    "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
out["total"] = con.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]
out["target_remaining"] = con.execute(
    "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
    "  AND last_error LIKE 'HTTP 404%'").fetchone()[0]
out["non_target_dead_letter"] = con.execute(
    "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
    "  AND (last_error IS NULL OR last_error NOT LIKE 'HTTP 404%')"
    ).fetchone()[0]
h = hashlib.sha256()
rows = 0
for r in con.execute("SELECT * FROM windows_channel_state ORDER BY rowid"):
    rows += 1
    h.update(("|".join("" if v is None else str(v)
                       for v in tuple(r))).encode("utf-8"))
out["bookmarks"] = {"rows": rows, "sha256": h.hexdigest()}
cols = {c["name"] for c in con.execute("PRAGMA table_info(envelopes)")}
out["recovery_column_present"] = "recovery_json" in cols
if rid and out["recovery_column_present"]:
    out["rows_with_recovery_id"] = con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE "
        "json_extract(recovery_json,'$.recovery_id')=?", (rid,)).fetchone()[0]
    out["recovered_not_queued"] = con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE "
        "json_extract(recovery_json,'$.recovery_id')=? AND status<>'queued'",
        (rid,)).fetchone()[0]
    out["recovered_with_attempts"] = con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE "
        "json_extract(recovery_json,'$.recovery_id')=? AND attempts<>0",
        (rid,)).fetchone()[0]
    out["recovered_delivered"] = con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE "
        "json_extract(recovery_json,'$.recovery_id')=? AND status='delivered'",
        (rid,)).fetchone()[0]
    sample = con.execute(
        "SELECT recovery_json FROM envelopes WHERE "
        "json_extract(recovery_json,'$.recovery_id')=? LIMIT 1",
        (rid,)).fetchone()
    out["provenance_sample"] = json.loads(sample[0]) if sample else None
print(json.dumps(out, indent=2))
'@
  $vFile = Join-Path $env:TEMP ("nivx_verify_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $vFile -Value $verifier -Encoding UTF8

  # ---- 3 . independent PRE-batch snapshot -------------------------
  Write-Host "`n=== 3 . PRE-BATCH SNAPSHOT (independent, read-only) ===" -ForegroundColor Cyan
  $pre1 = (& $VenvPy $vFile $db) -join "`n" | ConvertFrom-Json
  Write-Host ("  dead_letter=" + $pre1.counts_by_status.dead_letter +
              "  queued=" + $pre1.counts_by_status.queued +
              "  delivered=" + $pre1.counts_by_status.delivered +
              "  delivering=" + $pre1.counts_by_status.delivering +
              "  retrying=" + $pre1.counts_by_status.retrying +
              "  total=" + $pre1.total)
  Write-Host ("  target=" + $pre1.target_remaining +
              "  non_target=" + $pre1.non_target_dead_letter +
              "  bookmarks_sha256=" + $pre1.bookmarks.sha256.Substring(0,16) + "...")
  if ($pre1.target_remaining -ne $Expect) {
    throw ("pre-batch target is " + $pre1.target_remaining + ", not $Expect. " +
           "Nothing was changed.")
  }
  if ($pre1.non_target_dead_letter -ne 0) {
    throw ("pre-batch non-target dead letters = " + $pre1.non_target_dead_letter +
           ". Nothing was changed.")
  }

  # ---- 4 . read-only dry run on a copy ---------------------------
  Write-Host "`n=== 4 . DRY RUN (read-only, on a copy) ===" -ForegroundColor Cyan
  $tmp = Join-Path $env:TEMP ("nivx_r4b1_" + [guid]::NewGuid().ToString('N').Substring(0,8))
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  foreach ($suf in @('', '-wal', '-shm')) {
    if (Test-Path "$db$suf") { Copy-Item "$db$suf" (Join-Path $tmp ("outbox.db"+$suf)) -Force }
  }
  & $VenvPy $Tool --db (Join-Path $tmp 'outbox.db') --expect-count $Expect `
      --json-out "$ProofDir\r4-batch1-dryrun.json" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw ("the dry run did not confirm the population (exit $LASTEXITCODE). " +
           "Read r4-batch1-dryrun.json. Nothing was changed.")
  }
  $dry = Get-Content "$ProofDir\r4-batch1-dryrun.json" -Raw | ConvertFrom-Json
  if (-not $dry.health_gate_prerequisite.satisfied) {
    throw 'the health-gate prerequisite is not satisfied. Nothing was changed.'
  }
  Write-Host ("  target=" + $dry.population.target_count +
              "  prerequisite=" + $dry.health_gate_prerequisite.effective_state +
              "  would_write=" + $dry.would_write) -ForegroundColor Green

  # ---- 5 . EXECUTE exactly one batch of 500 ----------------------
  Write-Host "`n=== 5 . EXECUTE ONE BATCH OF $Batch (requeue only) ===" -ForegroundColor Yellow
  & $VenvPy $Tool --db $db --execute --expect-count $Expect `
      --batch-size $Batch --max-batches 1 --backup $pre `
      --json-out "$ProofDir\r4-batch1.json" | Out-Null
  $execRc = $LASTEXITCODE
  $exec = Get-Content "$ProofDir\r4-batch1.json" -Raw | ConvertFrom-Json
  $rid  = $exec.recovery_id
  Write-Host ("  result=" + $exec.result + "  recovery_id=" + $rid +
              "  requeued=" + $exec.requeued + "  batches=" + $exec.batches)

  # ---- 6 . independent POST-batch verification -------------------
  Write-Host "`n=== 6 . POST-BATCH VERIFICATION (independent, read-only) ===" -ForegroundColor Cyan
  (& $VenvPy $vFile $db $rid) -join "`n" |
      Out-File -FilePath "$ProofDir\r4-batch1-verify.json" -Encoding UTF8
  $post = Get-Content "$ProofDir\r4-batch1-verify.json" -Raw | ConvertFrom-Json
  Write-Host ("  dead_letter=" + $post.counts_by_status.dead_letter +
              "  queued=" + $post.counts_by_status.queued +
              "  delivered=" + $post.counts_by_status.delivered +
              "  delivering=" + $post.counts_by_status.delivering +
              "  retrying=" + $post.counts_by_status.retrying +
              "  total=" + $post.total)

  # ---- 7 . PASS / FAIL -------------------------------------------
  Write-Host "`n=== 7 . PASS / FAIL ===" -ForegroundColor Cyan
  $checks = [ordered]@{
    'execute exit 0'                     = ($execRc -eq 0)
    'tool result ACCEPTED'               = ($exec.result -eq 'ACCEPTED')
    'requeued exactly 500'               = ($exec.requeued -eq $Batch)
    'exactly one batch'                  = ($exec.batches -eq 1)
    "dead_letter -> $ExpDead"            = ($post.counts_by_status.dead_letter -eq $ExpDead)
    "queued -> $ExpQueued"               = ($post.counts_by_status.queued -eq $ExpQueued)
    "delivered stays $ExpDelivered"      = ($post.counts_by_status.delivered -eq $ExpDelivered)
    "delivering stays $ExpDelivering"    = ($post.counts_by_status.delivering -eq $ExpDelivering)
    "retrying stays $ExpRetrying"        = ($post.counts_by_status.retrying -eq $ExpRetrying)
    "total stays $ExpTotal"              = ($post.total -eq $ExpTotal)
    '500 rows carry this recovery id'    = ($post.rows_with_recovery_id -eq $Batch)
    'all recovered rows are queued'      = ($post.recovered_not_queued -eq 0)
    'all recovered attempts reset to 0'  = ($post.recovered_with_attempts -eq 0)
    'no recovered row marked delivered'  = ($post.recovered_delivered -eq 0)
    'original disposition preserved'     = ($post.provenance_sample.original_status -eq 'dead_letter')
    'original error preserved'           = ($post.provenance_sample.original_last_error -ne $null)
    'bookmarks unchanged'                = ($post.bookmarks.sha256 -eq $pre1.bookmarks.sha256)
    'bookmark row count unchanged'       = ($post.bookmarks.rows -eq $pre1.bookmarks.rows)
    'remaining target 14,368'            = ($post.target_remaining -eq $ExpDead)
    'non-target dead letters still 0'    = ($post.non_target_dead_letter -eq 0)
    'no delivery performed by the tool'  = ($exec.no_delivery_performed -eq $true)
  }
  $fail = 0
  foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host ("  PASS  " + $k) -ForegroundColor Green }
    else             { Write-Host ("  FAIL  " + $k) -ForegroundColor Red; $fail++ }
  }

  $rollback = ("cd $Repo && $VenvPy scripts\g1_r4_recover_dead_letters.py " +
               "--db `"$db`" --rollback --recovery-id $rid")
  $rollback | Set-Content "$ProofDir\r4-batch1-rollback.txt" -Encoding UTF8

  if ($fail -eq 0) {
    Write-Host "`nG1_R4_BATCH_1 = PASS" -ForegroundColor Green
  } else {
    Write-Host "`nG1_R4_BATCH_1 = FAIL ($fail checks)" -ForegroundColor Red
  }
  Write-Host "`nROLLBACK for this batch (recovery id $rid):" -ForegroundColor Yellow
  Write-Host ("  " + $rollback)
  Write-Host ("  or restore " + (Split-Path $pre -Leaf) + "* over the live files")
  Write-Host "`nSTOP. The remaining 14,368 rows are NOT recovered." -ForegroundColor Yellow
  Write-Host "The collector, delivery worker and acquisition were NOT started." -ForegroundColor Yellow
  Write-Host "`n  $ProofDir\r4-batch1.json"
  Write-Host "  $ProofDir\r4-batch1-verify.json"
  Write-Host "  $ProofDir\r4-batch1-rollback.txt"
}
catch {
  Write-Host "`nFAILED: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'If the execute step had already started, read r4-batch1.json and' -ForegroundColor Yellow
  Write-Host 'use r4-batch1-rollback.txt; otherwise nothing was changed.'       -ForegroundColor Yellow
}
finally {
  if ($tmp   -and (Test-Path $tmp))   { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
  if ($vFile -and (Test-Path $vFile)) { Remove-Item $vFile -Force -ErrorAction SilentlyContinue }
}
}

Invoke-G1R4FirstBatch
