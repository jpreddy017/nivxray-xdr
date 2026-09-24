# =====================================================================
# G1-R5 . RECONCILE-ONLY . ACCOUNT THE 450 ALREADY-TOUCHED ROWS
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# THIS BLOCK DELIVERS NOTHING AND WRITES NOTHING.
#
# It never constructs the Outbox, so it does not even perform R3.1 restart
# recovery: the 50 rows currently in `delivering` are LEFT EXACTLY AS THEY
# ARE and are reconciled in place. Recovering them is a SEPARATE owner
# decision that this block deliberately does not make, even if reconciliation
# proves they landed.
#
# WHAT IT DOES
#   1. SHA-256 + read-only snapshot of outbox.db  (pre)
#   2. loads the EXACT 450 recorded identities; refuses any other count
#   3. reconciles them against the corrected read-only surface
#   4. recomputes the accounting equation INDEPENDENTLY from the per-row
#      dispositions - the server's own totals are cross-checked, not trusted
#   5. reports the 400 locally-delivered and the 50 locally-delivering rows
#      SEPARATELY, with a per-row server disposition for all 50
#   6. runs a 1-identity match-strictness control (a deliberately corrupted
#      identity MUST come back NOT_FOUND)
#   7. SHA-256 + read-only snapshot of outbox.db  (post) and proves the file,
#      the histogram, the total and the bookmarks are all unchanged
#
# WHAT IT NEVER DOES
#   no delivery . no redelivery . no requeue . no reset of the 50 delivering
#   rows . no write to outbox.db . no backup restore . no R4 replay .
#   no acquisition . no EvtSubscribe . no Event Log read . no bookmark write .
#   no collector/uvicorn start . no widening beyond the exact 450 . no deploy
#
# OUTPUT (C:\nivx\g1-proof\r5\)
#   r5-reconcile-only-pre-snapshot.json
#   r5-reconcile-only-post-snapshot.json
#   r5-server-reconciliation.json
#   r5-delivered-400-disposition.json
#   r5-inflight-50-disposition.json
#   r5-retained-raw-outcomes.json
#   r5-terminal-outcomes.json
#   r5-450-accounting.json
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R5ReconcileOnly {

# ---- configuration ---------------------------------------------------
$StateDir           = 'C:\ProgramData\NivXForge\state'
$Work               = 'C:\nivx'
$VenvPy             = "$Work\.venv\Scripts\python.exe"
$ProofDir           = "$Work\g1-proof\r5"
$BaseUrl            = 'https://greeting-app-5782.preview.emergentagent.com'
$IdFile             = Join-Path $ProofDir 'r5-drain-identities.json'

# OPTIONAL FALLBACK. Leave empty to use the identities file only.
# If the drain's identities file is missing or is not exactly 450 entries,
# set this to the UTC instant the drain started (ISO-8601, e.g.
# '2026-06-24T06:20:00+00:00'). The touched population is then reconstructed
# READ-ONLY from outbox.db as the rows whose status is delivered/delivering
# and whose updated_at is at or after that instant - and the run still
# refuses to proceed unless that yields exactly 450 rows.
$RunStartUtc        = ''

# Hard expectations from the frozen endpoint evidence.
$ExpectedIdentities = 450
$ExpectedTotalRows  = 125452
$ExpectedDelivering = 50

try {
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  if (-not (Test-Path $db))     { throw "outbox database not found at $db" }
  if ((-not (Test-Path $IdFile)) -and [string]::IsNullOrWhiteSpace($RunStartUtc)) {
    throw ("identities file not found: $IdFile . Either restore it from the " +
           'drain evidence, or set $RunStartUtc to reconstruct the touched ' +
           'population read-only from outbox.db.')
  }
  New-Item -ItemType Directory -Force -Path $ProofDir | Out-Null

  # ---- read-only snapshot helper (mode=ro; cannot write) -------------
  $snap = @'
import hashlib, json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
con.row_factory = sqlite3.Row
out = {"counts_by_status": {r[0]: r[1] for r in con.execute(
    "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}}
out["total"] = con.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]
tables = {r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
acq = {}
for t in ("windows_channel_state", "acquisition_batch", "acquisition_window",
          "acquisition_terminal_record"):
    if t not in tables:
        acq[t] = {"state": "ABSENT", "rows": None, "sha256": None}
        continue
    h, rows = hashlib.sha256(), 0
    for r in con.execute("SELECT * FROM %s ORDER BY rowid" % t):
        rows += 1
        h.update(("|".join("" if v is None else str(v)
                           for v in tuple(r))).encode("utf-8"))
    acq[t] = {"state": "PRESENT", "rows": rows, "sha256": h.hexdigest()}
out["acquisition_tables"] = acq
out["bookmarks"] = acq["windows_channel_state"]
gate = None
if "delivery_health_gate" in tables:
    r = con.execute("SELECT * FROM delivery_health_gate").fetchone()
    if r is not None:
        gate = {k: r[k] for k in r.keys()}
out["delivery_health_gate"] = gate
print(json.dumps(out, indent=2))
'@
  $sFile = Join-Path $env:TEMP ("nivx_r5_snap_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $sFile -Value $snap -Encoding UTF8
  function Snapshot([string]$database) {
    return (& $VenvPy $sFile $database) -join "`n" | ConvertFrom-Json
  }
  function FileHashes([string]$database) {
    $h = [ordered]@{}
    foreach ($suf in @('', '-wal', '-shm')) {
      if (Test-Path "$database$suf") {
        $h["outbox.db$suf"] = (Get-FileHash "$database$suf" -Algorithm SHA256).Hash
      } else { $h["outbox.db$suf"] = 'ABSENT' }
    }
    return $h
  }

  # ---- 1 . PRE snapshot ---------------------------------------------
  Write-Host "`n=== 1 . ENDPOINT PRE-SNAPSHOT (read-only) ===" -ForegroundColor Cyan
  $preHashes = FileHashes $db
  $pre = Snapshot $db
  $pre | Add-Member -NotePropertyName file_sha256 -NotePropertyValue $preHashes
  $pre | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-reconcile-only-pre-snapshot.json') -Encoding UTF8
  Write-Host ("  queued="      + $pre.counts_by_status.queued +
              "  delivering="  + $pre.counts_by_status.delivering +
              "  delivered="   + $pre.counts_by_status.delivered +
              "  retrying="    + $pre.counts_by_status.retrying +
              "  dead_letter=" + $pre.counts_by_status.dead_letter +
              "  total="       + $pre.total)
  Write-Host ("  bookmarks sha256=" + $pre.bookmarks.sha256 + "  rows=" + $pre.bookmarks.rows)
  Write-Host ("  outbox.db sha256=" + $preHashes['outbox.db'])
  if ($pre.delivery_health_gate) {
    Write-Host ("  durable gate: " + $pre.delivery_health_gate.state +
                "  consecutive_failures=" + $pre.delivery_health_gate.consecutive_failures)
  }
  if ($pre.total -ne $ExpectedTotalRows) {
    throw ("total rows is " + $pre.total + ", expected " + $ExpectedTotalRows +
           '. The endpoint is not in the frozen state this proof was written for. Nothing was read further.')
  }
  if ([int]$pre.counts_by_status.delivering -ne $ExpectedDelivering) {
    throw ("delivering is " + $pre.counts_by_status.delivering + ", expected " +
           $ExpectedDelivering + '. HARD STOP.')
  }
  Write-Host '  frozen endpoint state confirmed' -ForegroundColor Green

  # ---- 2 . the EXACT 450 identities ----------------------------------
  Write-Host "`n=== 2 . IDENTITIES (exactly $ExpectedIdentities, no widening) ===" -ForegroundColor Cyan
  $identities = @()
  $identitySource = 'drain identities file'
  if (Test-Path $IdFile) {
    $identities = @((Get-Content $IdFile -Raw | ConvertFrom-Json).identities)
    Write-Host ("  identities in file: " + $identities.Count)
  }
  if ($identities.Count -ne $ExpectedIdentities -and
      -not [string]::IsNullOrWhiteSpace($RunStartUtc)) {
    Write-Host ("  falling back to a read-only reconstruction from outbox.db since " +
                $RunStartUtc) -ForegroundColor Yellow
    # Same delivery identity the driver and the ingest boundary both derive:
    # sha256(tenant | collector | source | source_event_id | sha256(raw)).
    $recon = @'
import hashlib, json, sqlite3, sys
db, since, collector = sys.argv[1], sys.argv[2], sys.argv[3]
con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
con.row_factory = sqlite3.Row
rows = con.execute(
    "SELECT * FROM envelopes "
    " WHERE status IN ('delivered','delivering') AND updated_at >= ? "
    " ORDER BY updated_at ASC, id ASC", (since,)).fetchall()
out = []
for r in rows:
    raw = json.loads(r["raw_json"] or "{}")
    digest = hashlib.sha256(json.dumps(
        raw, sort_keys=True, default=str, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    sei = r["source_event_id"] or "__no_source_event_id__"
    key = hashlib.sha256("\x1f".join([
        str(r["tenant_id"] or ""), collector, str(r["source"] or ""),
        str(sei), digest]).encode("utf-8")).hexdigest()
    out.append({"ref": r["id"], "tenant_id": r["tenant_id"],
                "connector_id": r["connector_id"], "collector_id": collector,
                "source": r["source"], "source_event_id": r["source_event_id"],
                "payload_digest": digest, "delivery_key": key,
                "endpoint_outcome": r["status"], "updated_at": r["updated_at"]})
print(json.dumps({"count": len(out), "identities": out}))
'@
    $rFile = Join-Path $env:TEMP ("nivx_r5_recon_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
    Set-Content -Path $rFile -Value $recon -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($env:NIVX_COLLECTOR_ID)) {
      throw 'NIVX_COLLECTOR_ID is not set in this window; the delivery identity cannot be reconstructed. Nothing was reconciled.'
    }
    $rebuilt = (& $VenvPy $rFile $db $RunStartUtc $env:NIVX_COLLECTOR_ID) -join "`n" | ConvertFrom-Json
    $identities = @($rebuilt.identities)
    $identitySource = "read-only reconstruction from outbox.db since $RunStartUtc"
    Write-Host ("  reconstructed identities: " + $identities.Count)
    $identities | ConvertTo-Json -Depth 6 |
        Set-Content (Join-Path $ProofDir 'r5-reconstructed-450-identities.json') -Encoding UTF8
  }
  if ($identities.Count -ne $ExpectedIdentities) {
    throw ("the touched population resolved to " + $identities.Count +
           ' entries, expected exactly ' + $ExpectedIdentities +
           '. This proof accounts the already-touched population ONLY; it will not widen or narrow it. Nothing was reconciled.')
  }
  Write-Host ("  identity source: " + $identitySource) -ForegroundColor Green
  $dupes = @($identities | Group-Object -Property delivery_key |
             Where-Object { $_.Count -gt 1 }).Count
  Write-Host ("  duplicate delivery keys: " + $dupes)
  $byOutcome = @{}
  foreach ($i in $identities) {
    $k = [string]$i.endpoint_outcome
    if ($byOutcome.ContainsKey($k)) { $byOutcome[$k] = $byOutcome[$k] + 1 }
    else { $byOutcome[$k] = 1 }
  }
  ($byOutcome.GetEnumerator() | Sort-Object Name) | ForEach-Object {
    Write-Host ("    endpoint_outcome " + $_.Key + " = " + $_.Value) }

  # ---- 3 . authenticate ----------------------------------------------
  Write-Host "`n=== 3 . AUTHENTICATE (read-only reconciliation) ===" -ForegroundColor Cyan
  function Get-PlainFromSecure([System.Security.SecureString]$sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }
  Write-Host '  NOTE on the earlier 401s: an e-mail that is not a known user'
  Write-Host '  returns 401 in ~2 ms; a known e-mail with a wrong password'
  Write-Host '  returns 401 in ~220 ms. Five failures in 5 minutes for the same'
  Write-Host '  (e-mail, IP) then returns 429 with Retry-After. Type carefully.'
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
    if ($code -eq 429) { throw 'login rate-limited (HTTP 429). Wait for Retry-After and re-run. Nothing was read or changed.' }
    throw "login failed (HTTP $code). Nothing was read or changed."
  }
  $jwt = $login.access_token
  Remove-Variable login, adminSecret, adminEmail -ErrorAction SilentlyContinue
  [GC]::Collect()
  Write-Host '  authenticated' -ForegroundColor Green

  # ---- 4 . reconcile the 450 (one bounded request) -------------------
  Write-Host "`n=== 4 . RECONCILE THE $ExpectedIdentities (identity-level, read-only) ===" -ForegroundColor Cyan
  $payload = @{ identities = @($identities | ForEach-Object {
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
  $runtimeMs = $sw.ElapsedMilliseconds
  $rows = @($resp.rows)
  Write-Host ("  runtime: " + $runtimeMs + " ms   (previously 35,439 ms -> HTTP 504)")
  Write-Host ("  tenant scope: " + $resp.tenant_scope.basis)
  Write-Host ("  rows returned: " + $rows.Count)
  $resp | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-server-reconciliation.json') -Encoding UTF8
  if ($rows.Count -ne $ExpectedIdentities) {
    throw ("the surface returned " + $rows.Count + ' rows for ' + $ExpectedIdentities +
           ' identities. HARD STOP: the population is not accounted one-to-one.')
  }

  # ---- 5 . INDEPENDENT accounting (recomputed from the rows) ---------
  Write-Host "`n=== 5 . INDEPENDENT ACCOUNTING (recomputed locally) ===" -ForegroundColor Cyan
  $local = [ordered]@{ DELIVERED_CANONICAL = 0; DELIVERED_RETAINED_RAW = 0
                       RETRYABLE_STILL_QUEUED = 0; TERMINAL_ACCOUNTED = 0
                       UNEXPLAINED = 0 }
  $unknownBucket = 0
  foreach ($r in $rows) {
    $b = [string]$r.bucket
    if ($local.Contains($b)) { $local[$b] = $local[$b] + 1 } else { $unknownBucket++ }
  }
  $localTotal = 0; foreach ($k in $local.Keys) { $localTotal += $local[$k] }
  Write-Host ("  DELIVERED_CANONICAL    = " + $local['DELIVERED_CANONICAL'])
  Write-Host ("  DELIVERED_RETAINED_RAW = " + $local['DELIVERED_RETAINED_RAW'])
  Write-Host ("  RETRYABLE_STILL_QUEUED = " + $local['RETRYABLE_STILL_QUEUED'])
  Write-Host ("  TERMINAL_ACCOUNTED     = " + $local['TERMINAL_ACCOUNTED'])
  if ($local['UNEXPLAINED'] -eq 0) {
    Write-Host  "  UNEXPLAINED            = 0" -ForegroundColor Green
  } else {
    Write-Host ("  UNEXPLAINED            = " + $local['UNEXPLAINED']) -ForegroundColor Red
  }
  $serverTotal = 0
  foreach ($k in $local.Keys) { $serverTotal += [int]$resp.buckets.$k }
  $bucketsAgree = $true
  foreach ($k in $local.Keys) {
    if ($local[$k] -ne [int]$resp.buckets.$k) { $bucketsAgree = $false }
  }
  Write-Host ("  server totals match local recount: " + $bucketsAgree)
  Write-Host ("  equation (" + $localTotal + " = " + $ExpectedIdentities + "): " +
              ($localTotal -eq $ExpectedIdentities))
  if ($unknownBucket -gt 0) { Write-Host ("  *** " + $unknownBucket + ' rows had an unrecognised bucket ***') -ForegroundColor Red }

  # ---- 6 . the 400 delivered vs the 50 delivering, SEPARATELY --------
  Write-Host "`n=== 6 . LOCAL 'delivered' VS LOCAL 'delivering', SEPARATELY ===" -ForegroundColor Cyan
  function Summarise($subset) {
    $b = [ordered]@{ DELIVERED_CANONICAL = 0; DELIVERED_RETAINED_RAW = 0
                     RETRYABLE_STILL_QUEUED = 0; TERMINAL_ACCOUNTED = 0
                     UNEXPLAINED = 0 }
    foreach ($r in $subset) {
      $k = [string]$r.bucket
      if ($b.Contains($k)) { $b[$k] = $b[$k] + 1 }
    }
    return $b
  }
  $deliveredRows = @($rows | Where-Object { $_.endpoint_outcome -eq 'delivered' })
  $inflightRows  = @($rows | Where-Object { $_.endpoint_outcome -eq 'delivering' })
  $otherRows     = @($rows | Where-Object { $_.endpoint_outcome -ne 'delivered' -and
                                            $_.endpoint_outcome -ne 'delivering' })
  $deliveredBuckets = Summarise $deliveredRows
  $inflightBuckets  = Summarise $inflightRows

  Write-Host ("  local 'delivered' rows  : " + $deliveredRows.Count)
  foreach ($k in $deliveredBuckets.Keys) {
    if ($deliveredBuckets[$k] -gt 0) { Write-Host ("      " + $k + " = " + $deliveredBuckets[$k]) } }
  Write-Host ("  local 'delivering' rows : " + $inflightRows.Count)
  foreach ($k in $inflightBuckets.Keys) {
    if ($inflightBuckets[$k] -gt 0) { Write-Host ("      " + $k + " = " + $inflightBuckets[$k]) } }
  if ($otherRows.Count -gt 0) {
    Write-Host ("  other local outcomes    : " + $otherRows.Count) -ForegroundColor Yellow }

  # Does the authoritative plane already hold each of the 50?
  $inflightLanded = @($inflightRows | Where-Object {
      $_.claim -ne $null -or $_.retained_raw_id -ne $null -or $_.routing_block -ne $null }).Count
  $inflightUnknown = @($inflightRows | Where-Object {
      $_.disposition -eq 'NOT_FOUND' }).Count
  Write-Host ("  of the local 'delivering' rows: server holds a record for " +
              $inflightLanded + ", holds NO record for " + $inflightUnknown)

  [pscustomobject]@{
    count = $deliveredRows.Count
    buckets = $deliveredBuckets
    rows = @($deliveredRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         disposition = $_.disposition; bucket = $_.bucket
         matched_by = $_.matched_by; evidence_ref = $_.evidence_ref
         claim_status = $_.claim.status
         canonical_event_id = $_.claim.canonical_event_id
         delivery_count = $_.claim.delivery_count
         duplicate_count = $_.claim.duplicate_count } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-delivered-400-disposition.json') -Encoding UTF8

  [pscustomobject]@{
    count = $inflightRows.Count
    buckets = $inflightBuckets
    server_holds_a_record = $inflightLanded
    server_holds_no_record = $inflightUnknown
    decision_note = 'EVIDENCE ONLY. No recovery, requeue, reset or redelivery was performed for these rows, whatever their disposition. That remains a separate owner decision.'
    rows = @($inflightRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         disposition = $_.disposition; bucket = $_.bucket
         matched_by = $_.matched_by; evidence_ref = $_.evidence_ref
         claim_status = $_.claim.status
         claim_stage = $_.claim.stage
         canonical_event_id = $_.claim.canonical_event_id
         raw_row_present = $_.claim.raw_row_present
         delivery_count = $_.claim.delivery_count
         duplicate_count = $_.claim.duplicate_count
         retained_raw_id = $_.retained_raw_id
         routing_mismatch_reason = $_.routing_block.mismatch_reason } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-inflight-50-disposition.json') -Encoding UTF8

  # ---- 7 . B4 retained raw + terminal, separately -------------------
  $retainedRows = @($rows | Where-Object { $_.bucket -eq 'DELIVERED_RETAINED_RAW' })
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

  $terminalRows = @($rows | Where-Object { $_.bucket -eq 'TERMINAL_ACCOUNTED' })
  [pscustomobject]@{
    count = $terminalRows.Count
    rows = @($terminalRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         disposition = $_.disposition
         mismatch_reason = $_.routing_block.mismatch_reason
         routing_result = $_.routing_block.routing_result
         retained_raw_id = $_.routing_block.retained_raw_id
         claim_status = $_.claim.status; review_reason = $_.claim.review_reason } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-terminal-outcomes.json') -Encoding UTF8

  # ---- 8 . match-strictness control (1 identity, separate request) ---
  # Proves the surface is not matching loosely: a corrupted identity from the
  # SAME tenant must come back NOT_FOUND. This control is NOT part of the 450
  # population and is never counted in the accounting.
  Write-Host "`n=== 8 . MATCH-STRICTNESS CONTROL (not part of the 450) ===" -ForegroundColor Cyan
  $sample = $identities[0]
  $badKey = ($sample.delivery_key.Substring(0, 63) +
             $(if ($sample.delivery_key.Substring(63,1) -eq 'a') { 'b' } else { 'a' }))
  $ctlBody = @{ identities = @(@{
      ref = 'control-corrupted-identity'
      delivery_key = $badKey
      source_event_id = ($sample.source_event_id + '|CONTROL-NOT-REAL')
      collector_id = $sample.collector_id
      endpoint_outcome = 'queued' }) }
  $ctl = Invoke-RestMethod -Method Post `
    -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
    -Headers @{ Authorization = "Bearer $jwt" } `
    -ContentType 'application/json' -TimeoutSec 60 `
    -Body ($ctlBody | ConvertTo-Json -Depth 6)
  $controlDisposition = $ctl.rows[0].disposition
  $controlOk = ($controlDisposition -eq 'NOT_FOUND')
  Write-Host ("  corrupted identity disposition = " + $controlDisposition +
              "  (expected NOT_FOUND)  ok=" + $controlOk)
  Remove-Variable jwt -ErrorAction SilentlyContinue; [GC]::Collect()

  # ---- 9 . POST snapshot . prove nothing was written -----------------
  Write-Host "`n=== 9 . ENDPOINT POST-SNAPSHOT . NON-MUTATION PROOF ===" -ForegroundColor Cyan
  $postHashes = FileHashes $db
  $post = Snapshot $db
  $post | Add-Member -NotePropertyName file_sha256 -NotePropertyValue $postHashes
  $post | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-reconcile-only-post-snapshot.json') -Encoding UTF8
  $fileUnchanged = ($preHashes['outbox.db'] -eq $postHashes['outbox.db'])
  # -wal / -shm are volatile SQLite side files: merely OPENING a WAL database
  # (even strictly mode=ro) can normalise the shared-memory index without any
  # change to the database itself. They are reported, never part of PASS.
  $sideFilesChanged = @()
  foreach ($k in @('outbox.db-wal', 'outbox.db-shm')) {
    if ($preHashes[$k] -ne $postHashes[$k]) { $sideFilesChanged += $k }
  }
  $histogramUnchanged = (
    ([int]$pre.counts_by_status.queued      -eq [int]$post.counts_by_status.queued) -and
    ([int]$pre.counts_by_status.delivering  -eq [int]$post.counts_by_status.delivering) -and
    ([int]$pre.counts_by_status.delivered   -eq [int]$post.counts_by_status.delivered) -and
    ([int]$pre.counts_by_status.retrying    -eq [int]$post.counts_by_status.retrying) -and
    ([int]$pre.counts_by_status.dead_letter -eq [int]$post.counts_by_status.dead_letter))
  $bookmarksUnchanged = ($pre.bookmarks.sha256 -eq $post.bookmarks.sha256)
  $totalUnchanged     = (($pre.total -eq $post.total) -and ($post.total -eq $ExpectedTotalRows))
  $deliveringHeld     = ([int]$post.counts_by_status.delivering -eq $ExpectedDelivering)
  Write-Host ("  outbox.db bytes unchanged    = " + $fileUnchanged)
  if ($sideFilesChanged.Count -gt 0) {
    Write-Host ("  volatile side files touched  = " + ($sideFilesChanged -join ', ') +
                "  (SQLite shm/wal normalisation on open; the database itself is byte-identical)")
  }
  Write-Host ("  status histogram unchanged   = " + $histogramUnchanged)
  Write-Host ("  bookmarks unchanged          = " + $bookmarksUnchanged)
  Write-Host ("  total rows = " + $post.total + " (expected " + $ExpectedTotalRows + ") unchanged = " + $totalUnchanged)
  Write-Host ("  the 50 'delivering' rows still delivering = " + $deliveringHeld)

  # ---- 10 . verdict --------------------------------------------------
  Write-Host "`n=== 10 . VERDICT ===" -ForegroundColor Cyan
  $pass = ($local['UNEXPLAINED'] -eq 0) -and
          ($localTotal -eq $ExpectedIdentities) -and
          ($unknownBucket -eq 0) -and
          ($bucketsAgree -eq $true) -and
          ($rows.Count -eq $ExpectedIdentities) -and
          ($controlOk -eq $true) -and
          ($fileUnchanged -eq $true) -and
          ($histogramUnchanged -eq $true) -and
          ($bookmarksUnchanged -eq $true) -and
          ($totalUnchanged -eq $true) -and
          ($deliveringHeld -eq $true)
  $final = [pscustomobject]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    phase = 'G1-R5 read-only accounting of the 450 already-touched rows'
    delivered_nothing = $true
    outbox_written = (-not $fileUnchanged)
    recovery_performed = $false
    identities_requested = $identities.Count
    identity_source = $identitySource
    duplicate_delivery_keys = $dupes
    endpoint_outcomes = $byOutcome
    reconciliation_runtime_ms = $runtimeMs
    tenant_scope = $resp.tenant_scope
    buckets_local_recount = $local
    buckets_server_reported = $resp.buckets
    buckets_agree = $bucketsAgree
    accounting_equation = 'identities = canonical + retained_raw + retryable/still-queued + terminal + unexplained'
    accounting_equation_holds = ($localTotal -eq $ExpectedIdentities)
    canonical = $local['DELIVERED_CANONICAL']
    retained_raw = $local['DELIVERED_RETAINED_RAW']
    retryable_open = $local['RETRYABLE_STILL_QUEUED']
    terminal = $local['TERMINAL_ACCOUNTED']
    unexplained = $local['UNEXPLAINED']
    delivered_local = @{ count = $deliveredRows.Count; buckets = $deliveredBuckets }
    delivering_local = @{ count = $inflightRows.Count; buckets = $inflightBuckets
                          server_holds_a_record = $inflightLanded
                          server_holds_no_record = $inflightUnknown }
    match_strictness_control = @{ disposition = $controlDisposition; ok = $controlOk }
    endpoint_pre_histogram = $pre.counts_by_status
    endpoint_post_histogram = $post.counts_by_status
    total_rows = $post.total
    total_rows_unchanged = $totalUnchanged
    outbox_file_sha256_unchanged = $fileUnchanged
    outbox_file_sha256 = $postHashes['outbox.db']
    volatile_side_files_touched = $sideFilesChanged
    status_histogram_unchanged = $histogramUnchanged
    bookmarks_unchanged = $bookmarksUnchanged
    bookmark_sha256 = $post.bookmarks.sha256
    acquisition_tables = $post.acquisition_tables
    delivery_health_gate = $post.delivery_health_gate
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
  Write-Host "`nSTOP. Nothing was delivered, nothing was recovered, and outbox.db" -ForegroundColor Yellow
  Write-Host 'was not written to. The 50 delivering rows are untouched.' -ForegroundColor Yellow
  Write-Host 'Send r5-450-accounting.json and r5-inflight-50-disposition.json back.' -ForegroundColor Yellow
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
}
}

Invoke-G1R5ReconcileOnly
