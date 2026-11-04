# =====================================================================
# G1-R5 . FIRST CONTROLLED DELIVERY PROOF . EXACTLY 500 ROWS
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# OWNER-AUTHORIZED. $Execute is PRE-SET to $true for exactly 500 rows.
#
# STAGES (delivery happens only at stage 6, after every gate below passes)
#   0  authoritative repository / lineage verification (HEAD + tool SHA-256)
#   1  writer guard: no collector / delivery worker may hold the outbox
#   2  verified endpoint outbox backup (SHA-256, earlier backups preserved)
#   3  independent pre-run evidence: histogram + bookmark hash + gate row
#   4  backend reachability + ingest auth/tenant probe + RECONCILIATION
#      surface availability check (a drain we cannot reconcile never starts)
#   5  dry-run preflight (constructs nothing, writes nothing)
#   6  EXECUTE exactly <= 500 rows . delivery-only
#   7  independent post-run evidence + bookmark invariance comparison
#   8  MANDATORY identity-level server reconciliation
#   9  final verdict, then STOP regardless of PASS/FAIL
#
# CONTROLS PRESERVED
#   * exactly 500-row maximum, bounded by identity (not best effort)
#   * delivery-only: no WindowsEventLogConnector, no EvtSubscribe, no channel
#     read, no acquisition, no bookmark/checkpoint write
#   * the existing 50 delivering -> queued restart recovery is explicitly
#     measured and reconciled
#   * R3.1 gate OPEN = immediate hard stop + evidence; no cooldown wait and no
#     HALF_OPEN continuation
#   * server reconciliation is MANDATORY and identity-level
#   * B4 retained-raw and terminal outcomes are separately identified
#   * UNEXPLAINED must be 0; endpoint HTTP success alone is never a PASS
#   * no deploy, no merge, no continuation past the first 500 rows
#
# EVIDENCE (C:\nivx\g1-proof\r5\)
#   r5-lineage.json
#   r5-pre-endpoint-evidence.json
#   dry\r5-drain-pre-snapshot.json      dry\r5-drain-post-snapshot.json
#   dry\r5-drain-identities.json        dry\r5-drain-run.json
#   r5-drain-pre-snapshot.json          r5-drain-post-snapshot.json
#   r5-drain-identities.json            r5-drain-run.json
#   r5-post-endpoint-evidence.json
#   r5-server-reconciliation.json
#   r5-retained-raw-outcomes.json       r5-terminal-outcomes.json
#   r5-final-reconciliation.json
#   backup\outbox.pre-r5drain.<stamp>.db (+ -wal / -shm) verified by SHA-256
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Invoke-G1R5First500 {

# ---- configuration ---------------------------------------------------
$StateDir    = 'C:\ProgramData\NivXForge\state'
$Work        = 'C:\nivx'
$Repo        = "$Work\nivxray-xdr-collector"      # adjust if the checkout differs
$VenvPy      = "$Work\.venv\Scripts\python.exe"
$ProofDir    = "$Work\g1-proof\r5"
$BackupDir   = "$Work\g1-proof\backup"
$Tool        = "$Repo\scripts\g1_r5_delivery_drain.py"
$Branch      = 'feature/rc2-alignment'

# The authoritative NivXRay plane the G1 acquisition delivered to. The
# collector enrolment, tenant binding and API keys live there.
$BaseUrl     = 'https://greeting-app-5782.preview.emergentagent.com'

# Identity MUST be the same the acquisition ran under: the delivery identity
# is derived from it, so a different value would deliver and reconcile under a
# different identity.
$TenantId    = $env:NIVX_TENANT_ID
$CollectorId = $env:NIVX_COLLECTOR_ID

# ---- lineage pin -----------------------------------------------------
# SHA-256 of the authored driver. A checkout that does not carry this exact
# tool is refused: the bounding, the gate hard-stop and the identity
# derivation are all properties of THIS file.
$ExpectedToolSha = 'D47DE2DEE87BA4187EB63713B07DE23DCE8307752E0D60C44BCD99734B7CB223'

# ---- ceilings (owner-approved first proof) ---------------------------
$MaxRows     = 500
$BatchSize   = 50
$MaxTicks    = 40
$MaxSeconds  = 600

# ---- OWNER-AUTHORIZED: this run attempts delivery --------------------
$Execute     = $true

$mintedKeyId = $null
$pushed      = $false

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. C:\ProgramData\NivXForge\state is SYSTEM+Administrators only.'
  }
  if (-not (Test-Path $VenvPy)) { throw "venv python not found at $VenvPy" }
  if ([string]::IsNullOrWhiteSpace($TenantId)) {
    throw 'NIVX_TENANT_ID is not set in this window. Nothing was attempted.'
  }
  if ([string]::IsNullOrWhiteSpace($CollectorId)) {
    throw 'NIVX_COLLECTOR_ID is not set in this window. The DELIVERY IDENTITY depends on it, so a drain under the "collector-local" fallback is refused. Set it to the SAME enrolled collector the acquisition ran under. Nothing was attempted.'
  }
  New-Item -ItemType Directory -Force -Path $ProofDir  | Out-Null
  New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

  # ---- 0 . lineage verification --------------------------------------
  Write-Host "`n=== 0 . REPOSITORY / LINEAGE VERIFICATION ===" -ForegroundColor Cyan
  $head = $null; $dirty = $null
  if (Test-Path "$Repo\.git") {
    git -C $Repo fetch origin --prune 2>&1 | Out-Null
    git -C $Repo checkout $Branch 2>&1 | Out-Null
    git -C $Repo pull --ff-only origin $Branch 2>&1 | Out-Null
    $head  = (git -C $Repo rev-parse HEAD).Trim()
    $dirty = (git -C $Repo status --porcelain) -join "`n"
    Write-Host ("  branch : " + $Branch)
    Write-Host ("  HEAD   : " + $head)
    if ([string]::IsNullOrWhiteSpace($dirty)) {
      Write-Host '  worktree: clean' -ForegroundColor Green
    } else {
      Write-Host '  worktree: LOCAL MODIFICATIONS PRESENT' -ForegroundColor Yellow
      Write-Host $dirty
    }
  } else {
    Write-Host '  no .git in the checkout - lineage is asserted by tool hash only' -ForegroundColor Yellow
  }
  if (-not (Test-Path $Tool)) {
    throw "tool not found at $Tool. The R5 driver is not in this checkout: publish the branch and pull again. Nothing was attempted."
  }
  $toolSha = (Get-FileHash $Tool -Algorithm SHA256).Hash
  Write-Host ("  tool   : scripts\g1_r5_delivery_drain.py")
  Write-Host ("  sha256 : " + $toolSha)
  if ($toolSha -ne $ExpectedToolSha) {
    throw ("tool SHA-256 MISMATCH. expected $ExpectedToolSha, found $toolSha. " +
           'The bounding, the gate hard-stop and the identity derivation are properties of the authored file. Nothing was attempted.')
  }
  Write-Host '  tool lineage verified against the authored driver' -ForegroundColor Green
  $helpText = (& $VenvPy $Tool --help) -join ' '
  foreach ($opt in @('max-rows','max-ticks','max-seconds','expect-collector-id','execute')) {
    if ($helpText -notmatch $opt) { throw "the tool has no --$opt option. Nothing was attempted." }
  }
  $db = Join-Path $StateDir 'outbox.db'
  if (-not (Test-Path $db)) { throw "outbox database not found at $db" }
  [pscustomobject]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    branch = $Branch; head = $head
    worktree_dirty = -not [string]::IsNullOrWhiteSpace($dirty)
    worktree_status = $dirty
    tool = $Tool; tool_sha256 = $toolSha
    tool_sha256_expected = $ExpectedToolSha
    tool_sha256_verified = $true
    base_url = $BaseUrl; tenant_id = $TenantId; collector_id = $CollectorId
    ceilings = @{ max_rows = $MaxRows; batch_size = $BatchSize
                  max_ticks = $MaxTicks; max_seconds = $MaxSeconds }
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-lineage.json') -Encoding UTF8

  # ---- 1 . writer guard ----------------------------------------------
  Write-Host "`n=== 1 . WRITER GUARD (no collector may hold the outbox) ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*'   -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object { Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. Stop it first. Nothing was attempted.'
  }
  try {
    $probeFile = [System.IO.File]::Open($db, 'Open', 'ReadWrite', 'None')
    $probeFile.Close(); $probeFile.Dispose()
    Write-Host '  no process holds the outbox' -ForegroundColor Green
  } catch {
    throw ('the outbox is locked by another process. Nothing was attempted. Detail: ' + $_.Exception.Message)
  }

  # ---- 2 . verified backup -------------------------------------------
  Write-Host "`n=== 2 . PRE-RUN BACKUP (SHA-256 verified) ===" -ForegroundColor Cyan
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $pre   = Join-Path $BackupDir ("outbox.pre-r5drain.$stamp.db")
  foreach ($suf in @('', '-wal', '-shm')) {
    if (Test-Path "$db$suf") {
      Copy-Item "$db$suf" ("$pre" + $suf) -Force
      $a = (Get-FileHash "$db$suf"     -Algorithm SHA256).Hash
      $b = (Get-FileHash ("$pre"+$suf) -Algorithm SHA256).Hash
      if ($a -ne $b) { throw "backup hash mismatch for $db$suf" }
      Write-Host ("  outbox.db" + $suf + "  sha256=" + $a.Substring(0,16) + "...")
    }
  }
  Write-Host ("  backup: " + $pre) -ForegroundColor Green

  # ---- independent read-only verifier (NOT the tool's own report) ----
  $verifier = @'
import hashlib, json, sqlite3, sys

db = sys.argv[1]
con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
con.row_factory = sqlite3.Row
one = lambda q, p=(): con.execute(q, p).fetchone()[0]
out = {"db": db}
out["counts_by_status"] = {r[0]: r[1] for r in con.execute(
    "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
out["total"] = one("SELECT COUNT(*) FROM envelopes")
out["dead_letter_http404"] = one(
    "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
    "  AND last_error LIKE 'HTTP 404%'")
out["dead_letter_other"] = one(
    "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
    "  AND (last_error IS NULL OR last_error NOT LIKE 'HTTP 404%')")
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
gate = None
if "delivery_health_gate" in tables:
    r = con.execute("SELECT * FROM delivery_health_gate").fetchone()
    if r is not None:
        gate = {k: r[k] for k in r.keys()}
out["delivery_health_gate"] = gate
cols = {c["name"] for c in con.execute("PRAGMA table_info(envelopes)")}
if "recovery_json" in cols:
    out["r4_rows_tagged"] = one(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json IS NOT NULL")
    out["r4_recovery_ids"] = [r[0] for r in con.execute(
        "SELECT DISTINCT json_extract(recovery_json,'$.recovery_id') "
        "  FROM envelopes WHERE recovery_json IS NOT NULL ORDER BY 1")]
print(json.dumps(out, indent=2))
'@
  $vFile = Join-Path $env:TEMP ("nivx_r5_verify_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $vFile -Value $verifier -Encoding UTF8
  function Verify([string]$database) {
    return (& $VenvPy $vFile $database) -join "`n" | ConvertFrom-Json
  }

  # ---- 3 . independent pre-run evidence ------------------------------
  Write-Host "`n=== 3 . PRE-RUN ENDPOINT EVIDENCE (independent, read-only) ===" -ForegroundColor Cyan
  $pre1 = Verify $db
  $pre1 | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-pre-endpoint-evidence.json') -Encoding UTF8
  Write-Host ("  queued="      + $pre1.counts_by_status.queued +
              "  delivering="  + $pre1.counts_by_status.delivering +
              "  delivered="   + $pre1.counts_by_status.delivered +
              "  retrying="    + $pre1.counts_by_status.retrying +
              "  dead_letter=" + $pre1.counts_by_status.dead_letter +
              "  total="       + $pre1.total)
  Write-Host ("  bookmarks sha256=" +
              $pre1.acquisition_tables.windows_channel_state.sha256 +
              "  rows=" + $pre1.acquisition_tables.windows_channel_state.rows)
  if ($pre1.delivery_health_gate) {
    Write-Host ("  durable gate: " + $pre1.delivery_health_gate.state +
                "  consecutive_failures=" + $pre1.delivery_health_gate.consecutive_failures)
    if ($pre1.delivery_health_gate.state -eq 'OPEN') {
      throw 'the durable delivery health gate is already OPEN. HARD STOP: return for owner decision. Nothing was attempted.'
    }
  } else {
    Write-Host '  durable gate: no persisted row (first boot starts CLOSED)'
  }
  if ($pre1.total -ne 125452) {
    Write-Host ("  NOTE: total is " + $pre1.total + ", the R4 close recorded 125452") -ForegroundColor Yellow
  }
  if ($pre1.dead_letter_other -ne 0) {
    throw ("non-target dead letters present (" + $pre1.dead_letter_other +
           '). HARD STOP: this is outside the R5 scope. Nothing was attempted.')
  }

  # ---- 4 . backend reachability / auth / reconciliation surface -------
  Write-Host "`n=== 4 . BACKEND REACHABILITY . INGEST AUTH . RECONCILE SURFACE ===" -ForegroundColor Cyan
  try { Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 30 | Out-Null }
  catch { throw "NivXRay XDR is not reachable at $BaseUrl : $($_.Exception.Message)" }
  Write-Host "  reachable ($BaseUrl)" -ForegroundColor Green

  function Get-PlainFromSecure([System.Security.SecureString]$sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }

  if (-not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)) {
    Write-Host '  reusing the ingest token already present in this window (not re-displayed)'
  } else {
    Write-Host '  no in-process token found - minting exactly ONE temporary scoped key'
    $adminEmail  = Read-Host '  NivXRay admin e-mail'
    $adminSecret = Read-Host '  NivXRay admin password (not echoed, not stored)' -AsSecureString
    $expires = (Get-Date).ToUniversalTime().AddHours(12).ToString('o')
    try {
      $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
        -ContentType 'application/json' -TimeoutSec 30 `
        -Body (@{ email = $adminEmail
                  password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
      $mint = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/xdr/api-keys" `
        -Headers @{ Authorization = "Bearer $($login.access_token)"
                    'X-Tenant-Id' = $TenantId } `
        -ContentType 'application/json' -TimeoutSec 30 `
        -Body (@{ name = "g1-r5-first500-$([int](Get-Date -UFormat %s))"
                  confirm_tenant_id = $TenantId
                  description = 'G1-R5 first 500-row delivery proof - 12h - collectors.enroll only'
                  scopes = @('collectors.enroll')
                  expires_at = $expires } | ConvertTo-Json)
    } catch {
      Remove-Variable login, mint, adminSecret -ErrorAction SilentlyContinue
      [GC]::Collect()
      throw "key minting failed: $($_.Exception.Message). Nothing was attempted."
    }
    $env:NIVX_INGEST_TOKEN = $mint.data.plaintext
    $mintedKeyId = $mint.data.id
    Write-Host ("  minted key id : " + $mintedKeyId)
    Write-Host ("  prefix        : " + $mint.data.prefix)
    Write-Host  '  scopes        : collectors.enroll  (no control-plane authority)'
    Remove-Variable login, mint, adminSecret, adminEmail -ErrorAction SilentlyContinue
    [GC]::Collect()
  }

  $authStatus = $null
  try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/api/xdr/ingest/telemetry" `
      -Headers @{ 'X-XDR-API-Key' = $env:NIVX_INGEST_TOKEN
                  'X-Tenant-Id'   = $TenantId } `
      -ContentType 'application/json' -Body '{"envelopes":[]}' `
      -TimeoutSec 30 -UseBasicParsing | Out-Null
  } catch { $authStatus = [int]$_.Exception.Response.StatusCode }
  Write-Host ("  ingest auth probe : HTTP $authStatus  (400 = authenticated, tenant resolved, empty batch refused; creates no evidence)")
  if ($authStatus -eq 401 -or $authStatus -eq 403) {
    throw "ingest authentication / tenant binding REFUSED (HTTP $authStatus). Nothing was attempted."
  }
  if ($authStatus -ne 400) {
    throw "unexpected ingest auth-probe result (HTTP $authStatus). Nothing was attempted."
  }

  $reconStatus = $null
  try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
      -ContentType 'application/json' `
      -Body '{"identities":[{"source_event_id":"preflight","endpoint_outcome":"queued"}]}' `
      -TimeoutSec 30 -UseBasicParsing | Out-Null
  } catch { $reconStatus = [int]$_.Exception.Response.StatusCode }
  Write-Host ("  reconcile probe   : HTTP $reconStatus  (401/403 = present and fail-closed)")
  if ($reconStatus -eq 404) {
    throw 'POST /api/xdr/ingest/routing/reconcile is NOT available on this plane. The proof refuses to deliver rows it cannot reconcile at identity level. Nothing was attempted.'
  }
  if ($reconStatus -ne 401 -and $reconStatus -ne 403) {
    throw "unexpected reconcile-probe result (HTTP $reconStatus). Nothing was attempted."
  }
  Write-Host '  authentication, tenant binding and reconciliation surface all verified' -ForegroundColor Green

  # ---- driver environment (DELIVERY ONLY) ----------------------------
  $env:NIVX_INGEST_URL           = "$BaseUrl/api/xdr/ingest/telemetry"
  $env:NIVX_INGEST_AUTH_MODE     = 'api_key'
  $env:XDR_STATE_DIR             = $StateDir
  $env:XDR_AUTO_START_CONNECTORS = '0'   # belt and braces; no service is started

  Push-Location $Repo
  $pushed = $true

  # ---- 5 . dry-run preflight (writes nothing) ------------------------
  Write-Host "`n=== 5 . DRY-RUN PREFLIGHT (constructs nothing, writes nothing) ===" -ForegroundColor Cyan
  $dryDir = Join-Path $ProofDir 'dry'
  & $VenvPy $Tool --state-dir $StateDir --evidence-dir $dryDir `
      --max-rows $MaxRows --batch-size $BatchSize `
      --max-ticks $MaxTicks --max-seconds $MaxSeconds `
      --expect-collector-id $CollectorId
  if ($LASTEXITCODE -ne 0) { throw "dry run did not pass (exit $LASTEXITCODE). Nothing was delivered." }
  $dryRun = Get-Content (Join-Path $dryDir 'r5-drain-run.json') -Raw | ConvertFrom-Json
  $rec0 = $dryRun.invariants.restart_recovery_accounted
  Write-Host ("  restart recovery (predicted): would_reset_to_queued=" + $rec0.would_reset_to_queued +
              "  applied_now=" + $rec0.delivering_reset_to_queued + "  state=" + $rec0.state)
  Write-Host ("  candidate identities sampled : " + $dryRun.identities_count)
  Write-Host ("  acquisition tables unchanged : " + $dryRun.invariants.no_acquisition.unchanged)
  Write-Host ("  gate                         : " + $dryRun.gate.state)
  if ($dryRun.gate.state -eq 'OPEN') { throw 'gate is OPEN. HARD STOP. Nothing was delivered.' }
  if (-not $dryRun.invariants.no_acquisition.unchanged) { throw 'an acquisition table changed during a read-only dry run. HARD STOP.' }
  $dryVerify = Verify $db
  if ($dryVerify.acquisition_tables.windows_channel_state.sha256 -ne
      $pre1.acquisition_tables.windows_channel_state.sha256) {
    throw 'bookmark hash changed during the dry run. HARD STOP. Nothing was delivered.'
  }
  if ($dryVerify.counts_by_status.delivering -ne $pre1.counts_by_status.delivering) {
    throw 'the dry run mutated row status. HARD STOP. Nothing was delivered.'
  }
  Write-Host '  dry run confirmed non-mutating' -ForegroundColor Green

  if (-not $Execute) {
    Write-Host "`n=== DRY RUN ONLY . NOTHING WAS DELIVERED ===" -ForegroundColor Yellow
    Pop-Location; $pushed = $false
    return
  }

  # ---- 6 . EXECUTE exactly <= 500 rows -------------------------------
  Write-Host "`n=== 6 . EXECUTE . BOUNDED DELIVERY PROOF (max $MaxRows rows) ===" -ForegroundColor Cyan
  & $VenvPy $Tool --state-dir $StateDir --evidence-dir $ProofDir `
      --max-rows $MaxRows --batch-size $BatchSize `
      --max-ticks $MaxTicks --max-seconds $MaxSeconds `
      --expect-collector-id $CollectorId --execute
  $driverExit = $LASTEXITCODE
  $run = Get-Content (Join-Path $ProofDir 'r5-drain-run.json') -Raw | ConvertFrom-Json

  Write-Host ("  stop_reason = " + $run.stop_reason)
  Write-Host ("  attempted   = " + $run.attempted +
              "  delivered=" + $run.worker_totals.delivered +
              "  retrying="  + $run.worker_totals.retrying +
              "  dead="      + $run.worker_totals.dead +
              "  released="  + $run.worker_totals.released_unattempted)
  $rec = $run.invariants.restart_recovery_accounted
  Write-Host ("  restart recovery: delivering " + $rec.delivering_before + " -> " + $rec.delivering_after +
              "  reset_to_queued=" + $rec.delivering_reset_to_queued +
              "  queued_delta=" + $rec.queued_delta + "  consistent=" + $rec.consistent)
  Write-Host ("  gate        = " + $run.gate.state + "  opened=" + $run.gate_opened)
  Write-Host ("  endpoint self-report pass = " + $run.pass + "  (driver exit $driverExit)")

  if ($run.gate_opened) {
    Write-Host "`n*** R3.1 HEALTH GATE OPENED . HARD STOP ***" -ForegroundColor Red
    Write-Host '  No cooldown was waited out and no HALF_OPEN probe was attempted.' -ForegroundColor Red
    Write-Host '  The durable gate state, per-tick accounting and every attempted' -ForegroundColor Red
    Write-Host '  identity are preserved. Reconciliation still runs below so the' -ForegroundColor Red
    Write-Host '  attempted population is fully accounted before you decide.' -ForegroundColor Red
  }

  # ---- 7 . independent post-run evidence -----------------------------
  Write-Host "`n=== 7 . POST-RUN ENDPOINT EVIDENCE (independent, read-only) ===" -ForegroundColor Cyan
  $post1 = Verify $db
  $post1 | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-post-endpoint-evidence.json') -Encoding UTF8
  Write-Host ("  queued="      + $post1.counts_by_status.queued +
              "  delivering="  + $post1.counts_by_status.delivering +
              "  delivered="   + $post1.counts_by_status.delivered +
              "  retrying="    + $post1.counts_by_status.retrying +
              "  dead_letter=" + $post1.counts_by_status.dead_letter +
              "  total="       + $post1.total)
  $bookmarksUnchanged = ($post1.acquisition_tables.windows_channel_state.sha256 -eq
                         $pre1.acquisition_tables.windows_channel_state.sha256)
  $totalUnchanged     = ($post1.total -eq $pre1.total)
  $deliveredDelta     = [int]$post1.counts_by_status.delivered - [int]$pre1.counts_by_status.delivered
  Write-Host ("  bookmarks unchanged = " + $bookmarksUnchanged)
  Write-Host ("  total unchanged     = " + $totalUnchanged)
  Write-Host ("  delivered delta     = " + $deliveredDelta)
  if (-not $bookmarksUnchanged) { Write-Host '  *** BOOKMARK HASH CHANGED ***' -ForegroundColor Red }

  # ---- 8 . MANDATORY identity-level server reconciliation ------------
  Write-Host "`n=== 8 . SERVER RECONCILIATION (identity-level, read-only) ===" -ForegroundColor Cyan
  $identities = @((Get-Content (Join-Path $ProofDir 'r5-drain-identities.json') -Raw |
                    ConvertFrom-Json).identities)
  Write-Host ("  attempted identities to reconcile: " + $identities.Count)
  if ($identities.Count -eq 0) { throw 'no identities were recorded; the proof cannot be accounted.' }

  $reconEmail  = Read-Host '  NivXRay admin e-mail (read-only reconciliation)'
  $reconSecret = Read-Host '  NivXRay admin password (not echoed, not stored)' -AsSecureString
  $reconLogin = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
    -ContentType 'application/json' -TimeoutSec 30 `
    -Body (@{ email = $reconEmail
              password = (Get-PlainFromSecure $reconSecret) } | ConvertTo-Json)
  $jwt = $reconLogin.access_token
  Remove-Variable reconLogin, reconSecret, reconEmail -ErrorAction SilentlyContinue
  [GC]::Collect()

  $allRows = @()
  $buckets = [ordered]@{ DELIVERED_CANONICAL = 0; DELIVERED_RETAINED_RAW = 0
                         RETRYABLE_STILL_QUEUED = 0; TERMINAL_ACCOUNTED = 0
                         UNEXPLAINED = 0 }
  for ($i = 0; $i -lt $identities.Count; $i += 500) {
    $slice = $identities[$i..([Math]::Min($i + 499, $identities.Count - 1))]
    $payload = @{ identities = @($slice | ForEach-Object {
      @{ ref              = $_.ref
         delivery_key     = $_.delivery_key
         source_event_id  = $_.source_event_id
         collector_id     = $_.collector_id
         connector_id     = $_.connector_id
         payload_digest   = $_.payload_digest
         endpoint_outcome = $_.endpoint_outcome } }) }
    $resp = Invoke-RestMethod -Method Post `
      -Uri "$BaseUrl/api/xdr/ingest/routing/reconcile" `
      -Headers @{ Authorization = "Bearer $jwt" } `
      -ContentType 'application/json' -TimeoutSec 180 `
      -Body ($payload | ConvertTo-Json -Depth 6)
    $allRows += $resp.rows
    foreach ($k in @($buckets.Keys)) { $buckets[$k] = $buckets[$k] + [int]$resp.buckets.$k }
    Write-Host ("  chunk " + [int]($i/500 + 1) + ": attempted=" + $resp.attempted +
                "  unexplained=" + $resp.unexplained + "  identity_equation=" +
                $resp.accounting_identity.holds)
  }
  Remove-Variable jwt -ErrorAction SilentlyContinue
  [GC]::Collect()

  [pscustomobject]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    attempted = $identities.Count
    buckets = $buckets
    rows = $allRows
  } | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-server-reconciliation.json') -Encoding UTF8

  # B4 retained-raw outcomes, identified separately
  $retainedRows = @($allRows | Where-Object { $_.bucket -eq 'DELIVERED_RETAINED_RAW' })
  $retainedByReason = @{}
  foreach ($r in $retainedRows) {
    $k = $r.retained_raw_reason; if (-not $k) { $k = 'UNSPECIFIED' }
    if ($retainedByReason.ContainsKey($k)) { $retainedByReason[$k] = $retainedByReason[$k] + 1 }
    else { $retainedByReason[$k] = 1 }
  }
  [pscustomobject]@{
    count = $retainedRows.Count
    by_reason = $retainedByReason
    note = 'RAW RETAINED is NOT canonical evidence and NOT evaluated'
    rows = @($retainedRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         retained_raw_id = $_.retained_raw_id
         reason = $_.retained_raw_reason } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-retained-raw-outcomes.json') -Encoding UTF8

  # Terminal outcomes, identified separately
  $terminalRows = @($allRows | Where-Object { $_.bucket -eq 'TERMINAL_ACCOUNTED' })
  [pscustomobject]@{
    count = $terminalRows.Count
    rows = @($terminalRows | ForEach-Object {
      @{ ref = $_.ref; source_event_id = $_.source_event_id
         disposition = $_.disposition
         mismatch_reason = $_.routing_block.mismatch_reason
         routing_result = $_.routing_block.routing_result
         retained_raw_id = $_.routing_block.retained_raw_id
         claim_status = $_.claim.status
         review_reason = $_.claim.review_reason } })
  } | ConvertTo-Json -Depth 6 |
      Set-Content (Join-Path $ProofDir 'r5-terminal-outcomes.json') -Encoding UTF8

  $serverTotal = 0; foreach ($k in $buckets.Keys) { $serverTotal += $buckets[$k] }
  $canonicalCount = $buckets['DELIVERED_CANONICAL']
  $unexplained    = $buckets['UNEXPLAINED']
  $serverPass     = ($unexplained -eq 0) -and ($serverTotal -eq $identities.Count)

  Write-Host ("  DELIVERED_CANONICAL    = " + $canonicalCount)
  Write-Host ("  DELIVERED_RETAINED_RAW = " + $buckets['DELIVERED_RETAINED_RAW'])
  Write-Host ("  TERMINAL_ACCOUNTED     = " + $buckets['TERMINAL_ACCOUNTED'])
  Write-Host ("  RETRYABLE_STILL_QUEUED = " + $buckets['RETRYABLE_STILL_QUEUED'])
  if ($unexplained -eq 0) {
    Write-Host  "  UNEXPLAINED            = 0" -ForegroundColor Green
  } else {
    Write-Host ("  UNEXPLAINED            = " + $unexplained) -ForegroundColor Red
  }

  # ---- 9 . final verdict ---------------------------------------------
  Write-Host "`n=== 9 . FINAL RECONCILIATION ===" -ForegroundColor Cyan
  $inv = $run.invariants
  $final = [pscustomobject]@{
    at                           = (Get-Date).ToUniversalTime().ToString('o')
    phase                        = 'G1-R5 first controlled delivery proof (500 rows)'
    lineage                      = @{ head = $head; tool_sha256 = $toolSha }
    driver_exit_code             = $driverExit
    stop_reason                  = $run.stop_reason
    attempted                    = $run.attempted
    identities_reconciled        = $identities.Count
    identities_note              = 'claimed candidate rows are all reconciled, including any the gate released back to queued unattempted mid-batch; attempted counts only rows the worker actually claimed for delivery'
    ceiling                      = $MaxRows
    ceiling_respected            = $inv.row_ceiling_respected.holds
    worker_totals                = $run.worker_totals
    endpoint_outcomes            = $run.endpoint_outcomes
    restart_recovery             = $rec
    endpoint_pre_histogram       = $pre1.counts_by_status
    endpoint_post_histogram      = $post1.counts_by_status
    endpoint_delivered_delta     = $deliveredDelta
    total_rows_unchanged         = $totalUnchanged
    bookmarks_unchanged          = $bookmarksUnchanged
    bookmark_sha256_pre          = $pre1.acquisition_tables.windows_channel_state.sha256
    bookmark_sha256_post         = $post1.acquisition_tables.windows_channel_state.sha256
    acquisition_tables_unchanged = $inv.no_acquisition.unchanged
    windows_connector_unloaded   = $inv.windows_connector_never_imported.holds
    gate_state                   = $run.gate.state
    gate_opened                  = $run.gate_opened
    endpoint_self_report_pass    = $run.pass
    server_buckets               = $buckets
    server_accounted             = $serverTotal
    server_unexplained           = $unexplained
    server_pass                  = $serverPass
    accounting_equation          = 'attempted = DELIVERED_CANONICAL + DELIVERED_RETAINED_RAW + RETRYABLE_STILL_QUEUED + TERMINAL_ACCOUNTED + UNEXPLAINED'
    accounting_equation_holds    = ($serverTotal -eq $identities.Count)
  }
  $pass = ($final.endpoint_self_report_pass -eq $true) -and
          ($final.server_pass -eq $true) -and
          ($final.server_unexplained -eq 0) -and
          ($final.gate_opened -eq $false) -and
          ($final.acquisition_tables_unchanged -eq $true) -and
          ($final.windows_connector_unloaded -eq $true) -and
          ($final.bookmarks_unchanged -eq $true) -and
          ($final.total_rows_unchanged -eq $true) -and
          ($final.ceiling_respected -eq $true) -and
          ($final.restart_recovery.consistent -eq $true) -and
          ($final.accounting_equation_holds -eq $true) -and
          ($run.stop_reason -eq 'MAX_ROWS_REACHED' -or $run.stop_reason -eq 'QUEUE_EMPTY')
  $final | Add-Member -NotePropertyName overall_pass -NotePropertyValue $pass
  $final | ConvertTo-Json -Depth 8 |
      Set-Content (Join-Path $ProofDir 'r5-final-reconciliation.json') -Encoding UTF8
  $final | ConvertTo-Json -Depth 6 | Write-Host

  if ($pass) {
    Write-Host "`n=== R5 FIRST 500-ROW DELIVERY PROOF: PASS ===" -ForegroundColor Green
    Write-Host '  Every attempted delivery is accounted at IDENTITY level on both sides.' -ForegroundColor Green
    Write-Host '  Zero unexplained loss. No acquisition. Bookmarks unchanged.' -ForegroundColor Green
  } else {
    Write-Host "`n=== R5 FIRST 500-ROW DELIVERY PROOF: FAIL / HALTED ===" -ForegroundColor Red
    Write-Host '  Do NOT widen the drain.' -ForegroundColor Red
  }
  Write-Host "`nSTOP. The authorization covered the first 500 rows only." -ForegroundColor Yellow
  Write-Host 'Send r5-final-reconciliation.json, r5-retained-raw-outcomes.json and' -ForegroundColor Yellow
  Write-Host 'r5-terminal-outcomes.json back before any further delivery.' -ForegroundColor Yellow
  Pop-Location; $pushed = $false
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
}
finally {
  if ($pushed) { try { Pop-Location } catch { } }
  if ($mintedKeyId) {
    Write-Host ("`nNOTE: temporary ingest key " + $mintedKeyId +
                " remains valid for 12h. Revoke it when this phase closes.") -ForegroundColor Yellow
  }
}
}

Invoke-G1R5First500
