# =====================================================================
# G1-R4 . PREPARATION GATE . READ-ONLY (no requeue, no mutation)
# ELEVATED PowerShell (Run as Administrator).
#
# WHAT THIS DOES
#   1. refuses to run while a collector process holds the outbox
#   2. takes a VERIFIED BACKUP of the live outbox (copy + SHA256) - reading
#      the originals only, so the preserved population is untouched
#   3. runs the R4 recovery tool in DRY-RUN mode against a separate
#      read-only COPY, proving the exact target population
#   4. runs the SECURITY EVENTID SWEEP against the same copy, so the 24
#      historically refused Security records can finally be characterised
#
# WHAT THIS DOES NOT DO
#   * no requeue, no status change, no schema change, no delete
#   * no collector start, no acquisition, no server call, no credential use
#   * no event payload is printed - metadata and counts only
#
# OUTPUT
#   C:\nivx\g1-proof\r4-dryrun.json
#   C:\nivx\g1-proof\security-eventid-sweep.json
#   C:\nivx\g1-proof\backup\outbox.db (+ -wal, -shm) + backup-manifest.json
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R4Preparation {

$StateDir = 'C:\ProgramData\NivXForge\state'
$Work     = 'C:\nivx'
$Repo     = "$Work\nivxray-xdr-collector"      # adjust if the checkout differs
$VenvPy   = "$Work\.venv\Scripts\python.exe"
$ProofDir = "$Work\g1-proof"
$BackupDir= "$ProofDir\backup"
$Tool     = "$Repo\scripts\g1_r4_recover_dead_letters.py"

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  # ---- 0 . refresh the checkout (the dry run must use the PUBLISHED tool)
  Write-Host "`n=== 0 . REPO UPDATE ===" -ForegroundColor Cyan
  if (Test-Path "$Repo\.git") {
    try {
      git -C $Repo fetch origin --prune 2>&1 | Out-Null
      git -C $Repo checkout feature/rc2-alignment 2>&1 | Out-Null
      git -C $Repo pull --ff-only origin feature/rc2-alignment 2>&1 | Out-Null
      $head = (git -C $Repo rev-parse HEAD).Trim()
      Write-Host ("  checkout HEAD: " + $head)
      Write-Host  "  expected lineage: ed32ccc6 <- dc4909ac <- 5bd1dc94"
    } catch {
      Write-Host ("  git update skipped: " + $_.Exception.Message) -ForegroundColor Yellow
    }
  } else {
    Write-Host "  no git checkout at $Repo - using the files as they are" -ForegroundColor Yellow
  }
  if (-not (Test-Path $Tool)) {
    throw ("recovery tool not found at $Tool . The checkout is stale or the path is wrong: " +
           "pull feature/rc2-alignment (remote HEAD ed32ccc6) or set `$Repo to the real checkout.")
  }
  Write-Host ("  tool present: " + $Tool) -ForegroundColor Green

  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db))     { throw "outbox database not found at $db" }

  # ---- 1 . no writer may hold the database -------------------------
  Write-Host "`n=== 1 . WRITER GUARD ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*'   -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object {
      Write-Host ("  running collector pid " + $_.ProcessId + " : " + $_.CommandLine) -ForegroundColor Red }
    throw ('a collector process is still running. This preparation refuses to copy the ' +
           'outbox under an active writer. Stop it first (Stop-Process -Id <pid> -Force), ' +
           'then re-run. Nothing was read or changed.')
  }
  try {
    $probe = [System.IO.File]::Open($db, 'Open', 'Read', 'None')
    $probe.Close(); $probe.Dispose()
    Write-Host "  no process holds the outbox (exclusive-open probe passed)" -ForegroundColor Green
  } catch {
    throw ('the outbox is locked by another process, so a copy could be torn. ' +
           'Nothing was read or changed. Detail: ' + $_.Exception.Message)
  }

  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

  # ---- 2 . verified backup (reads the originals, writes a copy) -----
  Write-Host "`n=== 2 . BACKUP (non-mutating copy + SHA256) ===" -ForegroundColor Cyan
  $manifest = @{ taken_at = (Get-Date).ToUniversalTime().ToString('o'); files = @() }
  foreach ($suf in @('', '-wal', '-shm')) {
    $src = "$db$suf"
    if (Test-Path $src) {
      $dst = Join-Path $BackupDir ("outbox.db" + $suf)
      Copy-Item $src $dst -Force
      $srcHash = (Get-FileHash $src -Algorithm SHA256).Hash
      $dstHash = (Get-FileHash $dst -Algorithm SHA256).Hash
      if ($srcHash -ne $dstHash) { throw "backup hash mismatch for $src" }
      $manifest.files += @{ file = ("outbox.db" + $suf)
                            bytes = (Get-Item $src).Length
                            sha256 = $srcHash }
      Write-Host ("  backed up outbox.db" + $suf + "  " + (Get-Item $src).Length +
                  " bytes  sha256=" + $srcHash.Substring(0,16) + "...")
    }
  }
  $manifest | ConvertTo-Json -Depth 6 |
    Set-Content (Join-Path $BackupDir 'backup-manifest.json') -Encoding UTF8
  Write-Host "  backup verified byte-for-byte (originals read only)" -ForegroundColor Green

  # ---- 3 . analysis copy (all queries run against THIS) ------------
  $tmp = Join-Path $env:TEMP ("nivx_r4_" + [guid]::NewGuid().ToString('N').Substring(0,8))
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  foreach ($suf in @('', '-wal', '-shm')) {
    $src = "$db$suf"
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp ("outbox.db" + $suf)) -Force }
  }
  $copy = Join-Path $tmp 'outbox.db'
  Write-Host "`n=== 3 . R4 DRY RUN (read-only, against the copy) ===" -ForegroundColor Cyan
  Write-Host "  copy: $copy" -ForegroundColor DarkGray

  & $VenvPy $Tool --db $copy --expect-count 14868 |
      Tee-Object -FilePath "$ProofDir\r4-dryrun.json"
  $dryRc = $LASTEXITCODE
  if ($dryRc -eq 0) {
    Write-Host "  DRY RUN: target population == 14,868 (as expected)" -ForegroundColor Green
  } elseif ($dryRc -eq 2) {
    Write-Host ("  DRY RUN: target population does NOT equal 14,868 - read " +
                "r4-dryrun.json before anything else. Recovery must not run " +
                "until the predicate and the evidence agree.") -ForegroundColor Yellow
  } else {
    Write-Host "  DRY RUN exited $dryRc" -ForegroundColor Yellow
  }

  # ---- 4 . SECURITY EVENTID SWEEP (read-only, metadata only) -------
  Write-Host "`n=== 4 . SECURITY EVENTID SWEEP (read-only) ===" -ForegroundColor Cyan
  $py = @'
import json, os, re, sqlite3, sys

db = os.path.join(sys.argv[1], "outbox.db")
con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
con.row_factory = sqlite3.Row
out = {"analyzed_copy": db,
       "note": ("read-only copy of the endpoint outbox; originals unmodified. "
                "Metadata only - no event payload is emitted."),
       "why": ("the 24 Security records refused server-side as "
               "SOURCE_FORMAT_MISMATCH could not be explained because the "
               "server discarded the payload (B4 fixes that for the future). "
               "The endpoint outbox still holds the delivered envelopes, so "
               "the EventIDs are recoverable HERE, read-only.")}

EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
REC = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
PRV = re.compile(r"<Provider Name='([^']+)'")
CHN = re.compile(r"<Channel>([^<]+)</Channel>")

rows = con.execute(
    "SELECT source_event_id, status, last_error, raw_json, created_at "
    "  FROM envelopes WHERE source_event_id LIKE '%|Security|%'").fetchall()
out["security_rows_total"] = len(rows)

by_eid, by_status, records = {}, {}, []
for r in rows:
    raw = r["raw_json"] or ""
    eid = EID.search(raw)
    rec = REC.search(raw)
    eid = eid.group(1) if eid else None
    recid = rec.group(1) if rec else None
    key = eid or "<no EventID extracted>"
    by_eid[key] = by_eid.get(key, 0) + 1
    by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    records.append({
        "source_event_id": r["source_event_id"],
        "event_record_id": recid,
        "event_id": eid,
        "provider": (PRV.search(raw).group(1) if PRV.search(raw) else None),
        "channel": (CHN.search(raw).group(1) if CHN.search(raw) else None),
        "outbox_status": r["status"],
        "last_error": (r["last_error"] or "")[:120] or None,
        "created_at": r["created_at"],
        "raw_bytes": len(raw),
    })

records.sort(key=lambda x: int(x["event_record_id"] or 0))
out["security_eventid_histogram"] = dict(
    sorted(by_eid.items(), key=lambda kv: -kv[1]))
out["security_status_histogram"] = by_status

# The server ACCEPTED 239165-239168 and refused 239169-239192.
lo, hi = 239169, 239192
window = [x for x in records
          if x["event_record_id"] and lo <= int(x["event_record_id"]) <= hi]
out["refused_window"] = {"first_event_record_id": lo,
                         "last_event_record_id": hi,
                         "expected_rows": hi - lo + 1,
                         "rows_found": len(window),
                         "eventid_histogram": {},
                         "rows": window}
for x in window:
    k = x["event_id"] or "<no EventID extracted>"
    out["refused_window"]["eventid_histogram"][k] = \
        out["refused_window"]["eventid_histogram"].get(k, 0) + 1

accepted = [x for x in records
            if x["event_record_id"] and 239165 <= int(x["event_record_id"]) <= 239168]
out["accepted_control_window"] = {"rows": accepted,
                                  "note": ("these four were ACCEPTED and "
                                           "canonicalized server-side - the "
                                           "control that proves the channel, "
                                           "decoder and DSM all work")}
out["all_security_rows"] = records[:400]
print(json.dumps(out, indent=2))
'@
  $pyFile = Join-Path $tmp 'security_sweep.py'
  Set-Content -Path $pyFile -Value $py -Encoding UTF8
  & $VenvPy $pyFile $tmp | Tee-Object -FilePath "$ProofDir\security-eventid-sweep.json" | Out-Null
  $sweep = Get-Content "$ProofDir\security-eventid-sweep.json" -Raw | ConvertFrom-Json
  Write-Host ("  Security rows in outbox: " + $sweep.security_rows_total)
  Write-Host  "  refused window 239169-239192 EventID histogram:"
  $sweep.refused_window.eventid_histogram.PSObject.Properties |
    ForEach-Object { Write-Host ("    EventID " + $_.Name + " : " + $_.Value + " rows") }

  Write-Host "`n=== DONE (nothing was requeued, nothing was modified) ===" -ForegroundColor Green
  Write-Host "  $ProofDir\r4-dryrun.json"
  Write-Host "  $ProofDir\security-eventid-sweep.json"
  Write-Host "  $BackupDir\backup-manifest.json"
  Write-Host "`nSend both JSON files back. R4 execution stays BLOCKED until the" -ForegroundColor Yellow
  Write-Host "dry-run count and the predicate are confirmed by the owner."      -ForegroundColor Yellow
}
catch {
  Write-Host "`nFAILED: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'Nothing was requeued and nothing was modified.' -ForegroundColor Yellow
}
finally {
  if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
}

Invoke-G1R4Preparation
