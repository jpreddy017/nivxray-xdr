# =====================================================================
# G1-R4 . REMAINING RECOVERY . 14,368 ROWS IN CONTROLLED BATCHES
# ELEVATED PowerShell (Run as Administrator).
#
# One tool invocation PER BATCH, so every batch has its own recovery id,
# its own accounting and its own rollback. Every invocation must state the
# CURRENT remaining target, so a drift of even one row refuses that batch
# instead of widening the selection.
#
# WHAT IT DOES
#   0. refreshes the checkout and refuses a stale tool
#   1. writer guard: collector / delivery worker must stay stopped
#   2. fresh SHA-256 verified pre-run backup (earlier backups preserved)
#   3. independent pre-run snapshot; aborts unless target == 14,368 and
#      non-target == 0
#   4. loop: requeue in batches of $BatchSize, verifying INDEPENDENTLY after
#      each batch and STOPPING immediately on any invariant failure
#   5. final reconciliation JSON + all recovery ids + rollback instructions
#
# WHAT IT DOES NOT DO
#   * does NOT start the collector, delivery worker or acquisition
#   * does NOT deliver, acknowledge or mark anything delivered
#   * does NOT read or write bookmarks / checkpoints
#   * does NOT touch non-target dead letters
#   * does NOT deploy, merge or push
#
# EXPECTED FINAL STATE
#   dead_letter  14368 -> 0
#   queued      108025 -> 122393
#   delivered     2884 unchanged
#   delivering      50 unchanged
#   retrying       125 unchanged
#   total       125452 unchanged
#   rows carrying a recovery id -> 14868 (500 from batch 1 + 14368 here)
#
# OUTPUT
#   C:\nivx\g1-proof\r4-remaining-batch-<n>.json         (per batch)
#   C:\nivx\g1-proof\r4-remaining-verify-<n>.json        (per batch)
#   C:\nivx\g1-proof\r4-final-reconciliation.json
#   C:\nivx\g1-proof\r4-rollback-all.txt
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R4Remaining {

$StateDir  = 'C:\ProgramData\NivXForge\state'
$Work      = 'C:\nivx'
$Repo      = "$Work\nivxray-xdr-collector"     # adjust if the checkout differs
$VenvPy    = "$Work\.venv\Scripts\python.exe"
$ProofDir  = "$Work\g1-proof"
$BackupDir = "$ProofDir\backup"
$Tool      = "$Repo\scripts\g1_r4_recover_dead_letters.py"

$BatchSize      = 2000          # 2,000 per batch -> 7 x 2,000 + 1 x 368
$ExpectRemaining= 14368         # what batch 1 left behind
$PriorRecoveryId= 'r4_f3304b612fc04b99'   # the proven first batch

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }

  # ---- 0 . repo ---------------------------------------------------
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
  foreach ($opt in @('max-batches', 'json-out')) {
    if ($helpText -notmatch $opt) {
      throw "the checkout is stale: the tool has no --$opt option. Nothing was changed."
    }
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db)) { throw "outbox database not found at $db" }

  # ---- 1 . writer guard ------------------------------------------
  Write-Host "`n=== 1 . WRITER GUARD (collector must stay stopped) ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*'   -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object {
      Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. Stop it first. Nothing was changed.'
  }
  try {
    $probe = [System.IO.File]::Open($db, 'Open', 'ReadWrite', 'None')
    $probe.Close(); $probe.Dispose()
    Write-Host "  no process holds the outbox" -ForegroundColor Green
  } catch {
    throw ('the outbox is locked by another process. Nothing was changed. ' +
           'Detail: ' + $_.Exception.Message)
  }

  # ---- 2 . pre-run backup ----------------------------------------
  Write-Host "`n=== 2 . PRE-RUN BACKUP ===" -ForegroundColor Cyan
  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $pre   = Join-Path $BackupDir ("outbox.pre-r4remaining.$stamp.db")
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

  # ---- the independent verifier ----------------------------------
  $verifier = @'
import hashlib, json, sqlite3, sys

db, rid = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
con.row_factory = sqlite3.Row
one = lambda q, p=(): con.execute(q, p).fetchone()[0]
out = {"db": db, "recovery_id": rid}
out["counts_by_status"] = {r[0]: r[1] for r in con.execute(
    "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
out["total"] = one("SELECT COUNT(*) FROM envelopes")
out["target_remaining"] = one(
    "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
    "  AND last_error LIKE 'HTTP 404%'")
out["non_target_dead_letter"] = one(
    "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
    "  AND (last_error IS NULL OR last_error NOT LIKE 'HTTP 404%')")
h, rows = hashlib.sha256(), 0
for r in con.execute("SELECT * FROM windows_channel_state ORDER BY rowid"):
    rows += 1
    h.update(("|".join("" if v is None else str(v)
                       for v in tuple(r))).encode("utf-8"))
out["bookmarks"] = {"rows": rows, "sha256": h.hexdigest()}
cols = {c["name"] for c in con.execute("PRAGMA table_info(envelopes)")}
out["recovery_column_present"] = "recovery_json" in cols
if out["recovery_column_present"]:
    out["rows_with_any_recovery_id"] = one(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json IS NOT NULL")
    out["recovered_not_queued_any"] = one(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json IS NOT NULL "
        "  AND status<>'queued'")
    out["recovered_with_attempts_any"] = one(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json IS NOT NULL "
        "  AND attempts<>0")
    out["distinct_recovery_ids"] = one(
        "SELECT COUNT(DISTINCT json_extract(recovery_json,'$.recovery_id')) "
        "  FROM envelopes WHERE recovery_json IS NOT NULL")
    out["recovery_ids"] = [r[0] for r in con.execute(
        "SELECT DISTINCT json_extract(recovery_json,'$.recovery_id') "
        "  FROM envelopes WHERE recovery_json IS NOT NULL ORDER BY 1")]
    if rid:
        out["rows_with_recovery_id"] = one(
            "SELECT COUNT(*) FROM envelopes WHERE "
            "json_extract(recovery_json,'$.recovery_id')=?", (rid,))
        out["this_batch_not_queued"] = one(
            "SELECT COUNT(*) FROM envelopes WHERE "
            "json_extract(recovery_json,'$.recovery_id')=? "
            "  AND status<>'queued'", (rid,))
        out["this_batch_with_attempts"] = one(
            "SELECT COUNT(*) FROM envelopes WHERE "
            "json_extract(recovery_json,'$.recovery_id')=? AND attempts<>0",
            (rid,))
print(json.dumps(out, indent=2))
'@
  $vFile = Join-Path $env:TEMP ("nivx_verify_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $vFile -Value $verifier -Encoding UTF8
  function Verify([string]$database, [string]$rid) {
    if ($rid) { return (& $VenvPy $vFile $database $rid) -join "`n" | ConvertFrom-Json }
    return (& $VenvPy $vFile $database) -join "`n" | ConvertFrom-Json
  }

  # ---- 3 . pre-run snapshot --------------------------------------
  Write-Host "`n=== 3 . PRE-RUN SNAPSHOT (independent, read-only) ===" -ForegroundColor Cyan
  $pre1 = Verify $db $null
  Write-Host ("  dead_letter=" + $pre1.counts_by_status.dead_letter +
              "  queued=" + $pre1.counts_by_status.queued +
              "  delivered=" + $pre1.counts_by_status.delivered +
              "  delivering=" + $pre1.counts_by_status.delivering +
              "  retrying=" + $pre1.counts_by_status.retrying +
              "  total=" + $pre1.total)
  Write-Host ("  target=" + $pre1.target_remaining +
              "  non_target=" + $pre1.non_target_dead_letter +
              "  already_recovered=" + $pre1.rows_with_any_recovery_id)
  if ($pre1.target_remaining -ne $ExpectRemaining) {
    throw ("pre-run target is " + $pre1.target_remaining + ", not $ExpectRemaining. " +
           "Nothing was changed.")
  }
  if ($pre1.non_target_dead_letter -ne 0) {
    throw 'pre-run non-target dead letters are not 0. Nothing was changed.'
  }

  $expFinalQueued = $pre1.counts_by_status.queued + $pre1.target_remaining
  $expFinalTagged = $pre1.rows_with_any_recovery_id + $pre1.target_remaining
  $expTotal       = $pre1.total

  # ---- 4 . batched recovery --------------------------------------
  Write-Host "`n=== 4 . RECOVERY IN BATCHES OF $BatchSize (requeue only) ===" -ForegroundColor Yellow
  $remaining = $pre1.target_remaining
  $ledger = New-Object System.Collections.ArrayList
  $n = 0
  $abort = $null
  while ($remaining -gt 0) {
    $n++
    $size = [Math]::Min($BatchSize, $remaining)
    $expDead   = $remaining - $size + $pre1.non_target_dead_letter
    $expQueued = $pre1.counts_by_status.queued + ($pre1.target_remaining - $remaining) + $size

    & $VenvPy $Tool --db $db --execute --expect-count $remaining `
        --batch-size $size --max-batches 1 --backup $pre `
        --json-out "$ProofDir\r4-remaining-batch-$n.json" | Out-Null
    $rc   = $LASTEXITCODE
    $exec = Get-Content "$ProofDir\r4-remaining-batch-$n.json" -Raw | ConvertFrom-Json
    $rid  = $exec.recovery_id
    $post = Verify $db $rid
    (Get-Content "$ProofDir\r4-remaining-batch-$n.json" -Raw) | Out-Null
    $post | ConvertTo-Json -Depth 8 |
      Set-Content "$ProofDir\r4-remaining-verify-$n.json" -Encoding UTF8

    $bad = New-Object System.Collections.ArrayList
    if ($rc -ne 0)                                   { [void]$bad.Add("exit $rc") }
    if ($exec.result -ne 'ACCEPTED')                 { [void]$bad.Add("result " + $exec.result) }
    if ($exec.requeued -ne $size)                    { [void]$bad.Add("requeued " + $exec.requeued) }
    if ($exec.batches -ne 1)                         { [void]$bad.Add("batches " + $exec.batches) }
    if ($post.rows_with_recovery_id -ne $size)       { [void]$bad.Add("rid rows " + $post.rows_with_recovery_id) }
    if ($post.this_batch_not_queued -ne 0)           { [void]$bad.Add("not queued " + $post.this_batch_not_queued) }
    if ($post.this_batch_with_attempts -ne 0)        { [void]$bad.Add("attempts " + $post.this_batch_with_attempts) }
    if (([int]$post.counts_by_status.dead_letter) -ne $expDead)   { [void]$bad.Add("dead_letter " + [int]$post.counts_by_status.dead_letter) }
    if (([int]$post.counts_by_status.queued) -ne $expQueued)      { [void]$bad.Add("queued " + [int]$post.counts_by_status.queued) }
    if ($post.counts_by_status.delivered  -ne $pre1.counts_by_status.delivered)  { [void]$bad.Add('delivered moved') }
    if ($post.counts_by_status.delivering -ne $pre1.counts_by_status.delivering) { [void]$bad.Add('delivering moved') }
    if ($post.counts_by_status.retrying   -ne $pre1.counts_by_status.retrying)   { [void]$bad.Add('retrying moved') }
    if ($post.total -ne $expTotal)                   { [void]$bad.Add("total " + $post.total) }
    if ($post.bookmarks.sha256 -ne $pre1.bookmarks.sha256) { [void]$bad.Add('bookmarks changed') }
    if ($post.non_target_dead_letter -ne 0)          { [void]$bad.Add('non-target touched') }

    [void]$ledger.Add([ordered]@{
      batch = $n; recovery_id = $rid; requeued = $exec.requeued
      dead_letter_after = [int]$post.counts_by_status.dead_letter
      queued_after = $post.counts_by_status.queued
      total_after = $post.total
      target_remaining_after = $post.target_remaining
      bookmarks_sha256 = $post.bookmarks.sha256
      ok = ($bad.Count -eq 0); problems = @($bad)
    })

    if ($bad.Count -eq 0) {
      Write-Host ("  PASS  batch $n  " + $rid + "  requeued=" + $exec.requeued +
                  "  dead_letter=" + [int]$post.counts_by_status.dead_letter +
                  "  remaining=" + $post.target_remaining) -ForegroundColor Green
    } else {
      Write-Host ("  FAIL  batch $n  " + ($bad -join '; ')) -ForegroundColor Red
      $abort = "batch $n failed: " + ($bad -join '; ')
      break
    }
    $remaining = $post.target_remaining
  }

  # ---- 5 . final reconciliation ----------------------------------
  Write-Host "`n=== 5 . FINAL RECONCILIATION ===" -ForegroundColor Cyan
  $final = Verify $db $null
  $resultText = 'FAIL'
  $allIds = @($PriorRecoveryId) + ($ledger | ForEach-Object { $_.recovery_id })
  $checks = [ordered]@{
    'no abort during the run'            = ($abort -eq $null)
    'target remaining 0'                 = ($final.target_remaining -eq 0)
    'dead_letter 0'                      = (([int]$final.counts_by_status.dead_letter) -eq 0)
    "queued -> $expFinalQueued"          = ($final.counts_by_status.queued -eq $expFinalQueued)
    'delivered unchanged'                = ($final.counts_by_status.delivered  -eq $pre1.counts_by_status.delivered)
    'delivering unchanged'               = ($final.counts_by_status.delivering -eq $pre1.counts_by_status.delivering)
    'retrying unchanged'                 = ($final.counts_by_status.retrying   -eq $pre1.counts_by_status.retrying)
    "total stays $expTotal"              = ($final.total -eq $expTotal)
    "recovered rows -> $expFinalTagged"  = ($final.rows_with_any_recovery_id -eq $expFinalTagged)
    'all recovered rows queued'          = ($final.recovered_not_queued_any -eq 0)
    'all recovered attempts 0'           = ($final.recovered_with_attempts_any -eq 0)
    'non-target dead letters still 0'    = ($final.non_target_dead_letter -eq 0)
    'bookmarks unchanged'                = ($final.bookmarks.sha256 -eq $pre1.bookmarks.sha256)
    'recovery ids accounted'             = ($final.distinct_recovery_ids -eq $allIds.Count)
  }
  $fail = 0
  foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host ("  PASS  " + $k) -ForegroundColor Green }
    else             { Write-Host ("  FAIL  " + $k) -ForegroundColor Red; $fail++ }
  }

  if ($fail -eq 0) { $resultText = 'PASS' }
  $recon = [ordered]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    batch_size = $BatchSize
    prior_recovery_id = $PriorRecoveryId
    pre_run = $pre1
    per_batch = @($ledger)
    final = $final
    expected = [ordered]@{ queued = $expFinalQueued; total = $expTotal
                           recovered_rows = $expFinalTagged
                           target_remaining = 0 }
    recovery_ids_from_db = $final.recovery_ids
    checks = $checks
    aborted = $abort
    result = $resultText
    note = ('requeue only. Nothing was delivered, acknowledged or marked ' +
            'delivered; no bookmark or checkpoint was read or written; the ' +
            'collector, delivery worker and acquisition were never started.')
  }
  $recon | ConvertTo-Json -Depth 10 |
    Set-Content "$ProofDir\r4-final-reconciliation.json" -Encoding UTF8

  # ---- 6 . rollback instructions ---------------------------------
  $lines = @('# G1-R4 rollback. Each recovery id is independent and may be',
             '# rolled back on its own, in any order. Collector must be stopped.',
             "# Full restore of last resort: copy $((Split-Path $pre -Leaf))* over the live files.")
  foreach ($id in $allIds) {
    $lines += ("$VenvPy $Repo\scripts\g1_r4_recover_dead_letters.py --db `"$db`" --rollback --recovery-id $id")
  }
  $lines | Set-Content "$ProofDir\r4-rollback-all.txt" -Encoding UTF8

  Write-Host ("`n  recovery ids in the database: " + $final.distinct_recovery_ids)
  if ($fail -eq 0) {
    Write-Host "`nG1_R4_REMAINING = PASS  (14,868 of 14,868 requeued)" -ForegroundColor Green
  } else {
    Write-Host "`nG1_R4_REMAINING = FAIL ($fail checks)" -ForegroundColor Red
    if ($abort) { Write-Host ("  aborted: " + $abort) -ForegroundColor Red }
  }
  Write-Host "`nSTOP. Delivery and acquisition were NOT started." -ForegroundColor Yellow
  Write-Host "The recovered rows sit in QUEUED until you deliberately start the collector." -ForegroundColor Yellow
  Write-Host "`n  $ProofDir\r4-final-reconciliation.json"
  Write-Host "  $ProofDir\r4-rollback-all.txt"
  Write-Host "  $ProofDir\r4-remaining-batch-*.json / r4-remaining-verify-*.json"
}
catch {
  Write-Host "`nFAILED: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'Batches already completed are listed in r4-remaining-batch-*.json' -ForegroundColor Yellow
  Write-Host 'and are individually reversible via r4-rollback-all.txt if written.' -ForegroundColor Yellow
}
finally {
  if ($vFile -and (Test-Path $vFile)) { Remove-Item $vFile -Force -ErrorAction SilentlyContinue }
}
}

Invoke-G1R4Remaining
