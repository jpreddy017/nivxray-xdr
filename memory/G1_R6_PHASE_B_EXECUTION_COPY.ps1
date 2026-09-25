# =====================================================================
# G1-R6 PHASE B . BOUNDED RECOVERY OF THE EXACT 28 RETRYABLE IDENTITIES
# ELEVATED PowerShell (Run as Administrator) on DESKTOP-A9HGFJJ.
#
# WHY THIS EXISTS
#   Phase A repaired the 22 rows the server already held. These 28 were
#   authoritatively RETRYABLE_STILL_QUEUED: never durably accounted for, so
#   they must actually be delivered - once, bounded, and then proven.
#
# THE INVARIANT THIS BLOCK EXISTS TO HONOUR
#   HTTP accepted != canonicalized != durably evidenced.
#   One identity is delivered, then RECONCILED, and only an authoritative
#   canonical/retained-raw disposition authorises the remaining 27.
#
# WHAT IT DOES
#   1. writer guard + pinned tool lineage
#   2. establishes the SAME delivery environment the historically successful
#      G1/R5 deliveries exported (NIVX_INGEST_URL, NIVX_INGEST_AUTH_MODE,
#      XDR_STATE_DIR, XDR_AUTO_START_CONNECTORS=0) and refuses to start if an
#      ingest token is already lying around in the session
#   3. validates the exact-50 authority file (pass=true, 22 canonical + 28
#      retryable, not the FAILED-UNTRUSTED sibling)
#   4. authority banner + explicitly named credential prompt, classified from
#      the actual request destination
#   5. credential-free readiness probes: login 422, unauthenticated reconcile
#      403 from the SAME python client (edge-1010 asymmetry guard)
#   6. READINESS pass: read-only (SQLite mode=ro), zero wire calls, NO ingest
#      secret, proves the 28 are selected, the 22 are intact and excluded, and
#      nothing moved
#   7. only when $Apply = $true: prompt for the existing authorised collector
#      ingest credential, assert PRESENCE (never values) of url/auth-mode/
#      token/collector-id/autostart, back up, then canary(1) -> reconcile ->
#      remainder(27 in batches of 7) -> one reconciliation of all 28 ->
#      transactional accounting
#
# SECRET HANDLING
#   The collector ingest credential is read as a SecureString, handed to the
#   child python process through this session's environment only, and cleared
#   in a `finally` block on EVERY exit path (readiness return, canary stop,
#   reconciliation failure, success, hard stop, exception). It is never
#   printed, logged, hashed, serialised or written to any evidence file, and
#   only its PRESENCE is ever asserted. NIVX_XDR_API_KEY is NOT a substitute:
#   IngestClient reads NIVX_INGEST_TOKEN.
#
# WHAT IT NEVER DOES
#   never constructs Outbox (its constructor resets delivering -> queued) .
#   no DeliveryWorker . no scheduler . no acquisition . no EvtSubscribe .
#   no bookmark write . no backlog drain . no touch of the 121993 queued or
#   125 retrying rows . no change to the 22 Phase-A rows . no schema change .
#   no credential creation, rotation or revocation . no secret in evidence
#
# ACCOUNTING CONTRACT
#   canonical + retained_raw + retryable + terminal + unexplained = 28
#   required: unexplained = 0
#   `delivering -> delivered` ONLY for canonical / retained-raw with evidence.
#   Rows that remain legitimately retryable stay `delivering` with their
#   attempts, next_attempt_at and last_error untouched. A PARTIAL OUTCOME IS
#   NOT A FAILURE.
#
# OUTPUT (C:\ProgramData\NivXForge\state\g1_r6_evidence\)
#   r6-phaseB-readiness.json       (readiness)
#   r6-phaseB-delivery.json        (apply)
#   r6-phaseB-reconciliation.json  (apply)
#   r6-phaseB-final.json           (apply)
#   r6-phaseB-stopped.json         (canary stop)
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ============ THE ONLY SWITCH IN THIS BLOCK ==========================
# Leave $false for the read-only readiness pass. Set $true ONLY after
# reviewing r6-phaseB-readiness.json.
$Apply = $false
# =====================================================================

function Invoke-G1R6PhaseB {

# ---- configuration ---------------------------------------------------
$StateDir  = 'C:\ProgramData\NivXForge\state'
$Work      = 'C:\nivx'
$Repo      = "$Work\apps\nivxray-xdr-collector"
$VenvPy    = "$Work\.venv\Scripts\python.exe"
$Tool      = "$Repo\scripts\g1_r6_phase_b_exact28_recovery.py"
$Exact50   = "$Repo\scripts\g1_r5_inflight50_reconcile.py"
$ProofDir  = "$Work\g1-proof\r5"
$Authority = "$ProofDir\r5-inflight-50-server-reconciliation.json"
$EvidenceDir = "$StateDir\g1_r6_evidence"
$BaseUrl   = 'https://greeting-app-5782.preview.emergentagent.com'

$ExpectTarget   = 28
$ExpectExcluded = 22
$ExpectQueued   = 121993
$ExpectRetrying = 125
$ExpectTotalRows = 125452
$RemainderBatch = 7

$ExpectToolSha    = 'E11642144105941439003E1C4E6590E71B26A7BC33CA134A99A96A5CC843E547'
$ExpectExact50Sha = 'D624C632808B4E1D6F5ECD559D3C176EF8AF82B749CC4B43851CB3D67A3A3C0A'

# ---- authority registry (see the exact-50 block for the convention) --
$AuthTargets = @(
  @{ HostPattern = '*.preview.emergentagent.com'
     Product     = 'NivXRay XDR'
     Environment = 'PREVIEW'
     Database    = 'test_database'
     AuthScope   = 'Cross-Tenant Administrator' }
  @{ HostPattern = 'nivxray.nivxforge.com'
     Product     = 'NivXRay XDR'
     Environment = 'PRODUCTION'
     Database    = 'NOT DISCLOSED BY THIS SCRIPT'
     AuthScope   = 'Cross-Tenant Administrator' }
  # NivXForge EDR PREVIEW / PRODUCTION hosts are deliberately absent: they
  # are unknown here and a fabricated banner would lie. They hard-stop as
  # AMBIGUOUS until the real hosts are registered.
)
$Target = $AuthTargets | Where-Object { ([Uri]$BaseUrl).Host -like $_.HostPattern } |
            Select-Object -First 1

try {
  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'not elevated. Nothing was attempted.'
  }
  $db = Join-Path $StateDir 'outbox.db'
  foreach ($p in @($VenvPy, $db, $Tool, $Exact50, $Authority)) {
    if (-not (Test-Path $p)) { throw "required path not found: $p . Nothing was attempted." }
  }
  if ([string]::IsNullOrWhiteSpace($env:NIVX_COLLECTOR_ID)) {
    throw 'NIVX_COLLECTOR_ID is not set in this window. Nothing was attempted.'
  }

  $bar = '=' * 60
  Write-Host ''
  Write-Host "  $bar" -ForegroundColor Cyan
  Write-Host '   NivXRay XDR - G1-R6 Phase B Exact-28 Recovery' -ForegroundColor Cyan
  Write-Host "  $bar" -ForegroundColor Cyan
  Write-Host ("   Mode         : " + $(if ($Apply) { 'APPLY (delivers, then accounts)' }
                                       else { 'READINESS (read-only, zero wire calls)' })) `
             -ForegroundColor $(if ($Apply) { 'Red' } else { 'Yellow' })
  Write-Host  '   Operation    : canary(1) -> reconcile -> remainder(27) -> reconcile(28) -> account'
  Write-Host  '   Invariant    : HTTP accepted != canonicalized != durably evidenced'
  Write-Host "  $bar" -ForegroundColor Cyan

  # ---- 0 . writer guard + lineage ------------------------------------
  Write-Host "`n=== 0 . WRITER GUARD + LINEAGE ===" -ForegroundColor Cyan
  $live = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
            Where-Object { $_.CommandLine -like '*uvicorn*' -or
                           $_.CommandLine -like '*nivx*' -or
                           $_.CommandLine -like '*collector*' }
  if ($live) {
    $live | ForEach-Object { Write-Host ("  running collector pid " + $_.ProcessId) -ForegroundColor Red }
    throw 'a collector process is running. It would race this recovery and could requeue the 28. Nothing was attempted.'
  }
  $toolSha    = (Get-FileHash $Tool -Algorithm SHA256).Hash
  $exact50Sha = (Get-FileHash $Exact50 -Algorithm SHA256).Hash
  Write-Host ("  phase B tool sha256 : " + $toolSha)
  Write-Host ("  exact-50 lib sha256 : " + $exact50Sha)
  if ($toolSha -ne $ExpectToolSha) {
    throw ('phase B tool sha256 is ' + $toolSha + ', expected ' +
           $ExpectToolSha + '. Pull feature/rc2-alignment again. Nothing was attempted.')
  }
  if ($exact50Sha -ne $ExpectExact50Sha) {
    throw ('the exact-50 library sha256 is ' + $exact50Sha + ', expected ' +
           $ExpectExact50Sha + '. Phase B reuses its reconciliation client; ' +
           'a drifted copy is not the reviewed one. Nothing was attempted.')
  }
  Write-Host ("  outbox.db sha256 (pre): " + (Get-FileHash $db -Algorithm SHA256).Hash)
  Write-Host '  no writer running; both tools verified' -ForegroundColor Green

  # ---- 0b . DELIVERY ENVIRONMENT (the R6-B gap that stopped the canary)
  # `IngestClient` has no config file and no bootstrap object: every field is
  # an `os.environ` property read fresh per call, and `configured()` is
  # literally `bool(NIVX_INGEST_URL)`. The historical successful deliveries
  # (G1_STEP2_EXECUTION_COPY.ps1:506, G1_R5_DELIVERY_DRAIN_EXECUTION_COPY
  # .ps1:246) exported this environment into the PowerShell process; the
  # first R6-B wrapper did not, so the guard correctly refused before the
  # canary. This establishes exactly that historical set - no more.
  Write-Host "`n=== 0b . DELIVERY ENVIRONMENT ===" -ForegroundColor Cyan
  $env:NIVX_INGEST_URL           = "$BaseUrl/api/xdr/ingest/telemetry"
  $env:NIVX_INGEST_AUTH_MODE     = 'api_key'
  $env:XDR_STATE_DIR             = $StateDir
  $env:XDR_AUTO_START_CONNECTORS = '0'
  Write-Host ("  NIVX_INGEST_URL           = " + $env:NIVX_INGEST_URL)
  Write-Host ("  NIVX_INGEST_AUTH_MODE     = " + $env:NIVX_INGEST_AUTH_MODE)
  Write-Host ("  XDR_STATE_DIR             = " + $env:XDR_STATE_DIR)
  Write-Host ("  XDR_AUTO_START_CONNECTORS = " + $env:XDR_AUTO_START_CONNECTORS +
              "   (an accidental service start cannot acquire)")
  Write-Host ("  NIVX_COLLECTOR_ID         = " + $env:NIVX_COLLECTOR_ID)
  # NIVX_XDR_API_KEY is the standalone auditd forwarder's variable and is NOT
  # a substitute: IngestClient reads NIVX_INGEST_TOKEN. Setting the wrong one
  # yields url-set/token-missing -> 401/403 -> RETRYABLE -> canary stop.
  if (-not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)) {
    throw ('NIVX_INGEST_TOKEN is already present in this session. READINESS ' +
           'must be credential-free, and APPLY prompts for it deliberately. ' +
           'Open a clean elevated window. Nothing was attempted.')
  }
  Write-Host '  NIVX_INGEST_TOKEN         = (absent, as required for readiness)' -ForegroundColor Green

  # ---- 1 . authority file ---------------------------------------------
  Write-Host "`n=== 1 . AUTHORITY FILE ===" -ForegroundColor Cyan
  $auth = Get-Content $Authority -Raw | ConvertFrom-Json
  if ($auth.PSObject.Properties.Name -contains 'VERDICT') {
    throw ('this is the FAILED/UNTRUSTED forensic sibling, not authority: ' +
           $auth.VERDICT + ' . Nothing was attempted.')
  }
  if ($auth.pass -ne $true) { throw 'the authority file does not carry pass=true. Nothing was attempted.' }
  $canonical = @($auth.rows | Where-Object { $_.bucket -eq 'DELIVERED_CANONICAL' }).Count
  $retryable = @($auth.rows | Where-Object { $_.bucket -eq 'RETRYABLE_STILL_QUEUED' }).Count
  Write-Host ("  canonical=" + $canonical + " (excluded)   retryable=" +
              $retryable + " (target)   require $ExpectExcluded / $ExpectTarget")
  if ($canonical -ne $ExpectExcluded -or $retryable -ne $ExpectTarget) {
    throw 'the authority file is not the exact-50 22/28 record. Nothing was attempted.'
  }
  Write-Host ("  authority sha256: " + (Get-FileHash $Authority -Algorithm SHA256).Hash)

  # ---- 2 . auth target + readiness probes (no credentials) ------------
  Write-Host "`n=== 2 . AUTH TARGET + READINESS PROBES (no credentials) ===" -ForegroundColor Cyan
  $toolReconcilePath = (& $VenvPy -c "import importlib.util,sys;s=importlib.util.spec_from_file_location('t',r'$Exact50');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.RECONCILE_PATH)") -join ''
  $toolUa            = (& $VenvPy -c "import importlib.util,sys;s=importlib.util.spec_from_file_location('t',r'$Exact50');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.USER_AGENT)") -join ''
  if ([string]::IsNullOrWhiteSpace($toolReconcilePath)) {
    throw 'could not read RECONCILE_PATH from the exact-50 library. Nothing was attempted.'
  }
  $loginUri     = "$BaseUrl/api/auth/login"
  $reconcileUri = "$BaseUrl" + $toolReconcilePath
  $bannerHost   = ([Uri]$BaseUrl).Host
  if (([Uri]$loginUri).Host -ne $bannerHost -or ([Uri]$reconcileUri).Host -ne $bannerHost) {
    throw ('HARD STOP - AUTH TARGET AMBIGUOUS: the displayed backend (' + $bannerHost +
           ') is not the host that would receive login and reconciliation. No credential was requested.')
  }
  if (-not $Target) {
    throw ('HARD STOP - AUTH TARGET AMBIGUOUS: ' + $bannerHost + ' matches no known ' +
           'NivXRay XDR / NivXForge EDR product+environment. No credential was requested.')
  }
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
  $probeLogin = Probe-Status $loginUri '{}'
  Write-Host ("  POST /api/auth/login (invalid shape) -> HTTP " + $probeLogin + "   (require 422)")
  if ($probeLogin -ne 422) {
    Write-Host ''
    Write-Host '  BACKEND NOT READY/BOUND - DO NOT RETYPE PASSWORD. NOTHING ATTEMPTED.' -ForegroundColor Red
    throw ('login readiness probe returned ' + $probeLogin + '; required 422. No credential was requested.')
  }
  # the probe that matters: the SAME python client signature Phase B will use
  $pyProbe = @'
import json, sys, urllib.error, urllib.request
base, ua, path = sys.argv[1], sys.argv[2], sys.argv[3]
req = urllib.request.Request(base.rstrip("/") + path, data=b'{"identities":[]}',
    method="POST", headers={"Content-Type": "application/json",
                            "Accept": "application/json", "User-Agent": ua})
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
  $pFile = Join-Path $env:TEMP ("nivx_r6b_probe_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $pFile -Value $pyProbe -Encoding UTF8
  $pyRes = (& $VenvPy $pFile $BaseUrl $toolUa $toolReconcilePath) -join "`n" | ConvertFrom-Json
  Remove-Item $pFile -ErrorAction SilentlyContinue
  Write-Host ("  python client, unauthenticated reconcile -> HTTP " + $pyRes.status +
              "   edge_banned=" + $pyRes.edge_banned + "   (require 403 / False)")
  if ($pyRes.edge_banned -or [int]$pyRes.status -ne 403) {
    Write-Host ''
    Write-Host '  PYTHON CLIENT REFUSED BEFORE AUTH - DO NOT RETYPE PASSWORD.' -ForegroundColor Red
    throw ('the python client was refused (HTTP ' + $pyRes.status + ', edge_banned=' +
           $pyRes.edge_banned + '): ' + $pyRes.body + ' . No credential was requested.')
  }
  Write-Host '  both routes bound; reconcile still protected' -ForegroundColor Green

  # ---- 3 . READINESS (read-only, zero wire calls) ---------------------
  Write-Host "`n=== 3 . READINESS PASS (read-only) ===" -ForegroundColor Cyan
  $ready = & $VenvPy $Tool `
              --state-dir       $StateDir `
              --authority       $Authority `
              --evidence-dir    $EvidenceDir `
              --base-url        $BaseUrl `
              --expect-total    $ExpectTotalRows `
              --expect-queued   $ExpectQueued `
              --expect-retrying $ExpectRetrying `
              --remainder-batch $RemainderBatch
  $readyExit = $LASTEXITCODE
  ($ready -join "`n") | Write-Host
  Write-Host ("`n  readiness exit code: " + $readyExit)
  if ($readyExit -ne 0) {
    throw ('the readiness pass did not pass (exit ' + $readyExit +
           '). Nothing was delivered or changed. Do not set $Apply.')
  }
  Write-Host ("  outbox.db sha256 (post readiness): " + (Get-FileHash $db -Algorithm SHA256).Hash) -ForegroundColor Green

  if (-not $Apply) {
    Write-Host "`n=== 4 . STOP (READINESS ONLY) ===" -ForegroundColor Cyan
    Write-Host '  Zero wire calls. outbox.db byte-identical. All 28 still' -ForegroundColor Yellow
    Write-Host '  `delivering`; the 22 Phase-A rows untouched.' -ForegroundColor Yellow
    Write-Host ("  Review " + (Join-Path $EvidenceDir 'r6-phaseB-readiness.json')) -ForegroundColor Yellow
    Write-Host '  Confirm: target_count 28, excluded 22, canary_ref set,' -ForegroundColor Yellow
    Write-Host '  remainder_batches [7,7,7,6], gate allowed, every check true.' -ForegroundColor Yellow
    Write-Host '  Then set $Apply = $true and re-run.' -ForegroundColor Yellow
    return 0
  }

  # ---- 4 . credential for the authoritative reconciliation ------------
  Write-Host "`n=== 4 . AUTHENTICATE (for reconciliation proof only) ===" -ForegroundColor Cyan
  Write-Host ("   Product      : " + $Target.Product)
  Write-Host ("   Environment  : " + $Target.Environment) -ForegroundColor $(
    if ($Target.Environment -eq 'PRODUCTION') { 'Red' } else { 'Yellow' })
  Write-Host ("   Backend      : " + $BaseUrl)
  Write-Host ("   Database     : " + $Target.Database)
  Write-Host ("   Auth Scope   : " + $Target.AuthScope)
  Write-Host  "   Operation    : G1-R6 Phase B RECONCILIATION PROOF"
  Write-Host  '   Note         : delivery itself uses the collector ingest'
  Write-Host  '                  credential already configured on this host.'
  Write-Host  '                  This block neither creates, rotates, revokes'
  Write-Host  '                  nor persists any credential.'
  $principal = $Target.Product + ' ' + $Target.Environment + ' Admin'
  Write-Host ''
  Write-Host ("  Enter " + $principal + " credentials") -ForegroundColor Cyan
  function Get-PlainFromSecure([System.Security.SecureString]$sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
  }
  $adminEmail  = Read-Host ("  " + $principal + " Email")
  $adminSecret = Read-Host ("  " + $principal + " Password (not echoed, not stored)") -AsSecureString
  try {
    $login = Invoke-RestMethod -Method Post -Uri $loginUri `
      -ContentType 'application/json' -TimeoutSec 30 `
      -Body (@{ email = $adminEmail
                password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
  } catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    Remove-Variable adminSecret -ErrorAction SilentlyContinue; [GC]::Collect()
    if ($code -eq 429) { throw 'login rate-limited (HTTP 429). Wait for Retry-After. Nothing was delivered or changed.' }
    throw "login failed (HTTP $code). Nothing was delivered or changed."
  }
  $env:NIVX_RECONCILE_TOKEN = $login.access_token
  Remove-Variable login, adminSecret, adminEmail -ErrorAction SilentlyContinue
  [GC]::Collect()
  Write-Host '  authenticated (token held in memory only)' -ForegroundColor Green

  # ---- 4b . COLLECTOR INGEST CREDENTIAL (APPLY only) -----------------
  # The existing authorised collector ingest credential. It is neither
  # created, rotated nor revoked here, and it is never printed, logged,
  # hashed, serialised or written to any evidence file. It is handed to the
  # child python process through this session's environment only, and cleared
  # in the finally block on EVERY exit path.
  Write-Host "`n=== 4b . COLLECTOR INGEST CREDENTIAL (APPLY only) ===" -ForegroundColor Cyan
  Write-Host  '   Authority    : NivXForge EDR Collector ingest credential'
  Write-Host ("   Destination  : " + $env:NIVX_INGEST_URL)
  Write-Host  '   Header       : X-XDR-API-Key (auth_mode api_key)'
  Write-Host  '   Required perm: collectors.enroll'
  $ingestSecret = Read-Host '  NivXRay XDR PREVIEW Collector Ingest API Key (not echoed, not stored)' -AsSecureString
  $env:NIVX_INGEST_TOKEN = Get-PlainFromSecure $ingestSecret
  Remove-Variable ingestSecret -ErrorAction SilentlyContinue
  [GC]::Collect()

  # ---- 4c . PRE-CANARY PRECONDITIONS (presence only, never values) ---
  Write-Host "`n=== 4c . PRE-CANARY PRECONDITIONS (presence only) ===" -ForegroundColor Cyan
  $preconditions = [ordered]@{
    'NIVX_INGEST_URL present'            = -not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_URL)
    'NIVX_INGEST_AUTH_MODE is api_key'   = ($env:NIVX_INGEST_AUTH_MODE -ceq 'api_key')
    'NIVX_INGEST_TOKEN present'          = -not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)
    'NIVX_COLLECTOR_ID present'          = -not [string]::IsNullOrWhiteSpace($env:NIVX_COLLECTOR_ID)
    'XDR_AUTO_START_CONNECTORS is 0'     = ($env:XDR_AUTO_START_CONNECTORS -eq '0')
    'NIVX_RECONCILE_TOKEN present'       = -not [string]::IsNullOrWhiteSpace($env:NIVX_RECONCILE_TOKEN)
  }
  foreach ($name in $preconditions.Keys) {
    Write-Host ("  " + $name.PadRight(36) + " : " + $preconditions[$name]) `
               -ForegroundColor $(if ($preconditions[$name]) { 'Green' } else { 'Red' })
  }
  $unmet = @($preconditions.Keys | Where-Object { -not $preconditions[$_] })
  if ($unmet.Count -gt 0) {
    throw ('pre-canary preconditions unmet: ' + ($unmet -join '; ') +
           '. Nothing was delivered or changed. (Only presence was checked; ' +
           'no secret value was inspected, printed or stored.)')
  }

  # ---- 5 . backup before the first mutating operation -----------------
  Write-Host "`n=== 5 . BACKUP BEFORE THE FIRST MUTATING OPERATION ===" -ForegroundColor Cyan
  $stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $backup = Join-Path $ProofDir ("outbox-pre-r6b-" + $stamp + ".db")
  Copy-Item $db $backup
  foreach ($side in @("$db-wal", "$db-shm")) {
    if (Test-Path $side) { Copy-Item $side ($backup + [IO.Path]::GetExtension($side)) }
  }
  Write-Host ("  backup: " + $backup)
  Write-Host ("  backup sha256: " + (Get-FileHash $backup -Algorithm SHA256).Hash)

  # ---- 6 . APPLY ------------------------------------------------------
  Write-Host "`n=== 6 . APPLY (canary 1 -> reconcile -> 27 -> reconcile 28) ===" -ForegroundColor Cyan
  $app = & $VenvPy $Tool `
            --state-dir       $StateDir `
            --authority       $Authority `
            --evidence-dir    $EvidenceDir `
            --base-url        $BaseUrl `
            --expect-total    $ExpectTotalRows `
            --expect-queued   $ExpectQueued `
            --expect-retrying $ExpectRetrying `
            --remainder-batch $RemainderBatch `
            --apply
  $appExit = $LASTEXITCODE
  # earliest possible clear; the finally block is the backstop
  Remove-Item Env:\NIVX_RECONCILE_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:\NIVX_INGEST_TOKEN    -ErrorAction SilentlyContinue
  [GC]::Collect()
  ($app -join "`n") | Write-Host
  Write-Host ("`n  apply exit code: " + $appExit + "   (3 = canary stop, nothing accounted)")

  # ---- 7 . independent post-state re-check ----------------------------
  Write-Host "`n=== 7 . INDEPENDENT POST-STATE RE-CHECK ===" -ForegroundColor Cyan
  $hist = @'
import json, sqlite3, sys
con = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
print(json.dumps({
    "counts_by_status": {r[0]: r[1] for r in con.execute(
        "SELECT status, COUNT(*) FROM envelopes GROUP BY status")},
    "total": con.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0],
    "phase_a_markers": con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json LIKE '%G1-R6-A%'"
        ).fetchone()[0],
    "phase_b_markers": con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json LIKE '%G1-R6-B%'"
        ).fetchone()[0]}))
'@
  $hFile = Join-Path $env:TEMP ("nivx_r6b_hist_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".py")
  Set-Content -Path $hFile -Value $hist -Encoding UTF8
  $after = (& $VenvPy $hFile $db) -join "`n" | ConvertFrom-Json
  Remove-Item $hFile -ErrorAction SilentlyContinue
  $c = $after.counts_by_status
  $deliveredN  = [int]$c.delivered
  $deliveringN = [int]$c.delivering
  Write-Host ("  delivered="   + $deliveredN + "  delivering=" + $deliveringN +
              "  queued="      + $c.queued   + "  retrying="   + $c.retrying +
              "  dead_letter=" + $c.dead_letter + "  total="     + $after.total)
  Write-Host ("  G1-R6-A markers: " + $after.phase_a_markers + " (must stay " + $ExpectExcluded + ")")
  Write-Host ("  G1-R6-B markers: " + $after.phase_b_markers)
  # A PARTIAL OUTCOME IS NOT A FAILURE: what must hold is the conservation
  # law, not a particular split.
  $ok = ($appExit -eq 0 -and
         [int]$after.total -eq $ExpectTotalRows -and
         [int]$c.queued -eq $ExpectQueued -and
         [int]$c.retrying -eq $ExpectRetrying -and
         [int]$after.phase_a_markers -eq $ExpectExcluded -and
         ($deliveredN + $deliveringN) -eq (3306 + 28) -and
         [int]$after.phase_b_markers -eq ($deliveredN - 3306))
  Write-Host ("  conservation + accounting consistent: " + $ok) -ForegroundColor $(
    if ($ok) { 'Green' } else { 'Red' })

  Write-Host "`n=== 8 . VERDICT ===" -ForegroundColor Cyan
  if ($appExit -eq 3) {
    Write-Host '  R6 PHASE B: STOPPED AT THE CANARY.' -ForegroundColor Yellow
    Write-Host '  The remaining 27 were NOT sent and nothing was accounted.' -ForegroundColor Yellow
    Write-Host ("  Review " + (Join-Path $EvidenceDir 'r6-phaseB-stopped.json')) -ForegroundColor Yellow
    return 3
  }
  if ($ok) {
    Write-Host '  R6 PHASE B: PASS' -ForegroundColor Green
    Write-Host ("  " + $after.phase_b_markers + " identities are now durably evidenced and accounted.") -ForegroundColor Green
    Write-Host ("  " + $deliveringN + " remain legitimately retryable and are STILL `delivering`,") -ForegroundColor Green
    Write-Host '  with their retry metadata untouched. Not converted to delivered.' -ForegroundColor Green
    Write-Host ("  Review " + (Join-Path $EvidenceDir 'r6-phaseB-final.json')) -ForegroundColor Green
    return 0
  }
  Write-Host '  R6 PHASE B: FAIL - report before any further action.' -ForegroundColor Red
  Write-Host ("  restore from: " + $backup) -ForegroundColor Yellow
  return 1
}
catch {
  Write-Host ("`nHARD STOP: " + $_.Exception.Message) -ForegroundColor Red
  return 1
}
finally {
  # EVERY exit path: readiness return, canary stop, reconciliation failure,
  # success, hard stop and exception. Secrets outlive nothing.
  Remove-Item Env:\NIVX_RECONCILE_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:\NIVX_INGEST_TOKEN    -ErrorAction SilentlyContinue
  [GC]::Collect()
  $leaked = @()
  if (-not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN))    { $leaked += 'NIVX_INGEST_TOKEN' }
  if (-not [string]::IsNullOrWhiteSpace($env:NIVX_RECONCILE_TOKEN)) { $leaked += 'NIVX_RECONCILE_TOKEN' }
  if ($leaked.Count -gt 0) {
    Write-Host ("`n*** WARNING: could not clear " + ($leaked -join ', ') +
                ' from this session. Close this window. ***') -ForegroundColor Red
  } else {
    Write-Host "`n  session secrets cleared (ingest + reconciliation)" -ForegroundColor Green
  }
}
}

$NivxExit = Invoke-G1R6PhaseB
if ($null -eq $NivxExit) { $NivxExit = 1 }
Write-Host ("`nPROCESS EXIT CODE: " + $NivxExit) -ForegroundColor $(
  if ($NivxExit -eq 0) { 'Green' } else { 'Red' })
$global:LASTEXITCODE = $NivxExit
if ($PSCommandPath) { exit $NivxExit }
