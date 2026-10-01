# =====================================================================
# G1-R3.1 . HEALTH-GATE PREREQUISITE for R4 . BOUNDED, SCHEMA-ONLY
# ELEVATED PowerShell (Run as Administrator).
#
# WHY
#   The preserved G1 outbox predates R3.1, so it has no
#   delivery_health_gate table. Absence is NOT an outage - R3.1's contract
#   is that a gate with no persisted state has observed nothing, and CLOSED
#   is the truthful first-boot default. This block makes the DURABILITY
#   present (so an outage during the recovery drain is remembered across a
#   restart) as a controlled, backed-up, proven step instead of letting the
#   collector create it implicitly on its next start.
#
# WHAT IT DOES
#   1. writer guard: refuses while any process holds the outbox
#   2. verifies (or takes) a SHA-256 verified backup
#   3. runs the PUBLISHED tool with --init-health-gate:
#        CREATE TABLE IF NOT EXISTS delivery_health_gate (...)   <- DDL only
#      inside one transaction, and proves before/after that every envelope
#      row, status, attempt count, error, bookmark and checkpoint is
#      byte-identical
#   4. re-runs the read-only R4 dry run to confirm the population is still
#      exactly 14,868 and the prerequisite now reports durability PRESENT
#
# WHAT IT DOES NOT DO
#   * writes NO gate row - CLOSED is not fabricated, it is the truthful
#     default for a gate that has observed nothing
#   * no requeue of the 14,868 rows, no status change, no delete
#   * no acquisition, no bookmark or checkpoint change, no replay
#   * nothing delivered, acknowledged or marked delivered
#   * no server call, no credential use, no canonical/dedupe change
#   * does NOT execute R4 recovery
#
# OUTPUT
#   C:\nivx\g1-proof\r31-gate-init.json
#   C:\nivx\g1-proof\r4-dryrun-after-gate-init.json
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R31GateInit {

$StateDir  = 'C:\ProgramData\NivXForge\state'
$Work      = 'C:\nivx'
$Repo      = "$Work\nivxray-xdr-collector"     # adjust if the checkout differs
$VenvPy    = "$Work\.venv\Scripts\python.exe"
$ProofDir  = "$Work\g1-proof"
$BackupDir = "$ProofDir\backup"
$Tool      = "$Repo\scripts\g1_r4_recover_dead_letters.py"
$Expect    = 14868

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }

  # ---- 0 . refresh the checkout (use the PUBLISHED tool) -----------
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
  if (-not (Test-Path $Tool)) {
    throw ("tool not found at $Tool - pull feature/rc2-alignment, or set `$Repo " +
           "to the real checkout. The tool must contain --init-health-gate.")
  }
  $helpText = (& $VenvPy $Tool --help) -join ' '
  if ($helpText -notmatch 'init-health-gate') {
    throw ('the checkout is stale: the tool has no --init-health-gate option. ' +
           'Pull the published branch and re-run. Nothing was changed.')
  }
  Write-Host "  tool present and supports --init-health-gate" -ForegroundColor Green

  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db)) { throw "outbox database not found at $db" }

  # ---- 1 . writer guard -------------------------------------------
  Write-Host "`n=== 1 . WRITER GUARD ===" -ForegroundColor Cyan
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
    Write-Host "  no process holds the outbox (exclusive-open probe passed)" -ForegroundColor Green
  } catch {
    throw ('the outbox is locked by another process. Nothing was changed. ' +
           'Detail: ' + $_.Exception.Message)
  }

  # ---- 2 . backup ------------------------------------------------
  Write-Host "`n=== 2 . BACKUP ===" -ForegroundColor Cyan
  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
  $backup = Join-Path $BackupDir 'outbox.db'
  $stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $pre    = Join-Path $BackupDir ("outbox.pre-gate-init.$stamp.db")
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
  if (-not (Test-Path $backup)) { Copy-Item $pre $backup -Force }
  Write-Host "  fresh pre-change backup verified; the earlier R4 backup is preserved" -ForegroundColor Green

  # ---- 3 . initialize the gate table (DDL only) -------------------
  Write-Host "`n=== 3 . GATE INIT (schema only, no rows) ===" -ForegroundColor Cyan
  & $VenvPy $Tool --db $db --init-health-gate --backup $pre `
      --json-out "$ProofDir\r31-gate-init.json"
  $initRc = $LASTEXITCODE
  $init = Get-Content "$ProofDir\r31-gate-init.json" -Raw | ConvertFrom-Json
  if ($init.result -eq 'ALREADY_PRESENT') {
    Write-Host "  gate table already present - no change was made" -ForegroundColor Green
  } else {
    Write-Host ("  rows_written: " + $init.rows_written)
    $init.proof.PSObject.Properties | ForEach-Object {
      $col = if ($_.Value) { 'Green' } else { 'Red' }
      Write-Host ("    " + $_.Name + " = " + $_.Value) -ForegroundColor $col }
  }

  # ---- 4 . re-prove the R4 population (read-only) -----------------
  Write-Host "`n=== 4 . R4 DRY RUN AFTER INIT (read-only) ===" -ForegroundColor Cyan
  $tmp = Join-Path $env:TEMP ("nivx_r31_" + [guid]::NewGuid().ToString('N').Substring(0,8))
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  foreach ($suf in @('', '-wal', '-shm')) {
    if (Test-Path "$db$suf") { Copy-Item "$db$suf" (Join-Path $tmp ("outbox.db"+$suf)) -Force }
  }
  & $VenvPy $Tool --db (Join-Path $tmp 'outbox.db') --expect-count $Expect `
      --json-out "$ProofDir\r4-dryrun-after-gate-init.json"
  $dryRc = $LASTEXITCODE
  $dry = Get-Content "$ProofDir\r4-dryrun-after-gate-init.json" -Raw | ConvertFrom-Json

  # ---- PASS / FAIL -----------------------------------------------
  Write-Host "`n=== PASS / FAIL ===" -ForegroundColor Cyan
  $checks = [ordered]@{
    'gate init accepted'          = ($initRc -eq 0)
    'no gate row written'         = ($init.result -eq 'ALREADY_PRESENT' -or $init.proof.no_gate_row_written)
    'envelope rows unchanged'     = ($init.result -eq 'ALREADY_PRESENT' -or $init.proof.envelope_state_unchanged)
    'status counts unchanged'     = ($init.result -eq 'ALREADY_PRESENT' -or $init.proof.counts_unchanged)
    'bookmarks unchanged'         = ($init.result -eq 'ALREADY_PRESENT' -or $init.proof.bookmarks_unchanged)
    'only the gate table is new'  = ($init.result -eq 'ALREADY_PRESENT' -or $init.proof.only_new_table_is_the_gate)
    'gate table now present'      = ($dry.schema.delivery_health_gate_table_present -eq $true)
    'gate durability PRESENT'     = ($dry.health_gate_prerequisite.durability -eq 'PRESENT')
    'prerequisite satisfied'      = ($dry.health_gate_prerequisite.satisfied -eq $true)
    'target still 14,868'         = ($dry.population.target_count -eq $Expect)
    'non-target dead letters 0'   = ($dry.population.non_target_dead_letter_count -eq 0)
    'dry run wrote nothing'       = ($dry.would_write -eq $false)
  }
  $fail = 0
  foreach ($k in $checks.Keys) {
    if ($checks[$k]) { Write-Host ("  PASS  " + $k) -ForegroundColor Green }
    else             { Write-Host ("  FAIL  " + $k) -ForegroundColor Red; $fail++ }
  }
  if ($fail -eq 0) {
    Write-Host "`nG1_R31_GATE_PREREQUISITE = PASS" -ForegroundColor Green
    Write-Host "R4 recovery is still NOT executed and remains owner-gated." -ForegroundColor Yellow
  } else {
    Write-Host "`nG1_R31_GATE_PREREQUISITE = FAIL ($fail checks)" -ForegroundColor Red
    Write-Host ("Restore from " + $pre + " if anything looks wrong.") -ForegroundColor Yellow
  }
  Write-Host "`n  $ProofDir\r31-gate-init.json"
  Write-Host "  $ProofDir\r4-dryrun-after-gate-init.json"
}
catch {
  Write-Host "`nFAILED: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'No recovery was executed.' -ForegroundColor Yellow
}
finally {
  if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
}

Invoke-G1R31GateInit
