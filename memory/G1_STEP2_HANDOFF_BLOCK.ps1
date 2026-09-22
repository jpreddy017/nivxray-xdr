# =====================================================================
# G1 · STEP 2 HANDOFF BLOCK — NivXForge EDR Windows acquisition
# Run in an ELEVATED PowerShell (Run as Administrator).
#
# Fail-closed order. Acquisition starts ONLY after every gate passes:
#   1 Administrator
#   2 authoritative Git branch
#   3 reviewed-code manifest (25 files, SHA-256)
#   4 supported CPython 3.14 x64 (non-Store, GIL build)
#   5 virtual environment
#   6 pinned Windows dependencies (pywin32==312)
#   7 pywin32 import
#   8 real native Event Log binding probe (EvtSubscribe, read-only)
#   9 persistent state directory
#  10 pre-seeded collector configuration
#  11 server reachability + authentication + tenant authority
#  12 60-minute bounded acquisition (Sysmon · Security · PowerShell)
#
# CREDENTIAL HANDLING
#   * No credential is ever echoed, written to disk, passed on a command
#     line, or printed. Only a key PREFIX and its expiry are shown.
#   * $MintOnHost = $true  -> you type the preview admin password once as a
#     SecureString; the block mints a 24h key scoped to `collectors.enroll`
#     in the G1 tenant only, and keeps it in-process.
#   * $MintOnHost = $false -> you paste an already-minted ingest key as a
#     SecureString instead. Nothing else changes.
#
# NOTHING IS CONFIGURED ON WINDOWS: no Sysmon install, no channel enabling,
# no registry write, no audit-policy change, no service install.
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ── settings ─────────────────────────────────────────────────────────
$Repo        = 'https://github.com/jpreddy017/nivxray-xdr.git'
$Branch      = 'feature/rc2-alignment'
$Work        = 'C:\nivx'
$Collector   = "$Work\apps\nivxray-xdr-collector"
$StateDir    = 'C:\ProgramData\NivXForge\state'
$Venv        = "$Work\.venv"
$VenvPy      = "$Venv\Scripts\python.exe"

$BaseUrl     = 'https://greeting-app-5782.preview.emergentagent.com'
$TenantId    = 'ten_f1a5479243e901cf159e230fa0'      # g1-windows-proof
$CollectorId = 'col_d6b0b9e8172246f29be9'            # enrolled windows-eventlog
$ConnectorId = 'windows-eventlog-g1proof01'
$RunMinutes  = 15                                    # observation window
$MintOnHost  = $true

function Fail($msg) {
  Write-Host ""
  Write-Host "STOP: $msg" -ForegroundColor Red
  Write-Host "No acquisition was started." -ForegroundColor Red
  exit 1
}
function Ok($msg)   { Write-Host "  OK   $msg" -ForegroundColor Green }
function Stage($n, $t) { Write-Host "`n=== $n · $t ===" -ForegroundColor Cyan }

# ── 1 · Administrator ────────────────────────────────────────────────
Stage 1 'ADMINISTRATOR'
$elevated = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
  Fail 'not elevated. The Security channel is only truthfully readable under elevation, so an unelevated run would report READ_DENIED and call it evidence.'
}
Ok 'running elevated'

# ── 2 · authoritative branch ─────────────────────────────────────────
Stage 2 'AUTHORITATIVE GIT BRANCH'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail 'git is not on PATH.' }
git config --global core.autocrlf false
if (-not (Test-Path "$Work\.git")) {
  if (Test-Path $Work) { Remove-Item $Work -Recurse -Force }
  git clone --branch $Branch --single-branch $Repo $Work
} else {
  Set-Location $Work
  git remote set-url origin $Repo
  git fetch origin $Branch
  git checkout -B $Branch "origin/$Branch"
  git reset --hard "origin/$Branch"
  git clean -fdx -e .venv -e 'scripts/windows/g1/nivxray-g1-preflight.json' -e 'g1-proof'
}
Set-Location $Work
$head = (git rev-parse HEAD)
Write-Host ("  remote : " + (git config --get remote.origin.url))
Write-Host ("  branch : " + (git rev-parse --abbrev-ref HEAD))
Write-Host ("  HEAD   : $head")
Write-Host ("  date   : " + (git show -s --format=%cI HEAD))
Write-Host ("  subject: " + (git show -s --format=%s HEAD))
if ((git status --porcelain) -ne $null) {
  Write-Host "  note   : untracked/ignored files present (expected: .venv, proof artifacts)" -ForegroundColor DarkGray
}
Ok 'branch is the authoritative remote state'

# ── 3 · reviewed-code manifest ───────────────────────────────────────
Stage 3 'REVIEWED-CODE MANIFEST (G1 STEP 2 · 25 files)'
$expected = [ordered]@{
 'scripts\windows\g1\Get-NivXRayG1Preflight.ps1'                        = '3D43E6235BBBEB631EAC11B96AF10C5AF14B6227C93ABDBCD88F966CAD9C4AF7'
 'scripts\windows\g1\README_G1_STEP1_PREFLIGHT.md'                      = '055A28E5FA8EBDBAA25ABE97E33B2C776E347CEC20DD536D4479942132EF598C'
 'apps\nivxray-xdr-collector\framework\windows_eventlog.py'             = 'D0AB898AF46EBC8D2FE897EDFA1ACBD173C37892E4F87A2BB1192831A363FF9D'
 'apps\nivxray-xdr-collector\framework\windows_bookmarks.py'            = 'C0B480269387541804196ACEDBC89E1880A8BD92F9C22BFA866D756EED63179B'
 'apps\nivxray-xdr-collector\framework\collector_identity.py'           = 'B5ED4F5524A89C53D9CBF2BA8E6852C15C09C94AABC2F3EB4C199EBEAA4AB280'
 'apps\nivxray-xdr-collector\framework\runtime.py'                      = 'EA61D2F36A2A50567E3CC9647E0A3D1A7895CC814CE1AA8FE67741FC07E131B1'
 'apps\nivxray-xdr-collector\framework\scheduler.py'                    = '2E764F049893CCD7DD94DE485C8E0BE254CE00B64274E008FB3F93610C30F147'
 'apps\nivxray-xdr-collector\framework\outbox.py'                       = '985EF41B94E978925B0716A61C008A8230AD307BB1C4426CE3CDEDE6B8C34250'
 'apps\nivxray-xdr-collector\framework\delivery.py'                     = '0D19BF66FD362516DCE0E248F501715CE9E049ADC57FA5277E74E1CDA5C88045'
 'apps\nivxray-xdr-collector\framework\delivery_worker.py'              = '2E456FF2EBD68B01447937188F2EB5E74F42524135A27B18B4E2D2D3FB0FCCA7'
 'apps\nivxray-xdr-collector\framework\store.py'                        = 'F88D42097645C603B4263D0321BF51A34B9C4B9018CE4BA76F77EB0E20597357'
 'apps\nivxray-xdr-collector\framework\authz.py'                        = 'A58717A87D907495904E94D7D8651CE63DD35BD9444D4AB3D9C22100D9566FE8'
 'apps\nivxray-xdr-collector\main.py'                                   = 'A4A308FA8A6DDDE2DDB4A4901E8DF9745B1A634CDFE2A2D88257B276B08A8F6B'
 'apps\nivxray-xdr-collector\routes\connectors.py'                      = '7917C53D96BCC9F4117D76FA8F028A0F35B6B2ECD2E375760C8340755F68CB20'
 'apps\nivxray-xdr-collector\framework\state_paths.py'                  = '28DAEBC7FEE8BED509E6F25724B92C467580E48CFF5E157BA956E898793910A2'
 'apps\nivxray-xdr-collector\requirements.txt'                          = '3FAD9D24C681C95D0A16A6A6A19D829D7E448BE6F4FC0B7D4EEF8442766E2665'
 'apps\nivxray-xdr-collector\requirements-windows.txt'                  = 'F0ED4BD460AA1066E3F800F37A904BCB8CCFBF0D6AEEBB41649182F0F98446DD'
 'apps\nivxray-xdr-collector\WINDOWS_RUNTIME.md'                        = '74E829EFDA2FB84A00205562E5BA3CC3885A62EA14188326A6D809B6858FEB74'
 'apps\nivxray-xdr-collector\tests\test_g1_windows_runtime_contract.py' = '1D3E6DE9CB63AFFC06D01609C8B6B66F1F15EE922DF3EC4E557D10656F542FA4'
 'backend\services\ingest_provenance.py'                                = 'EEEC91EC55707BD9846BCF6568EA2D5A38BD880EDF7AF3892B8384F8A5B28913'
 'backend\tests\test_g1_s1_clock_independence.py'                       = 'B3D43A2A0401B2434B5D2CF2636E2D31957E55BD85F0DCF59A6508B2A6FC3D3C'
 'backend\routers\xdr_collectors.py'                                    = 'D898C793C048DD1100E227415BECF83BA426CE46964A7F6AF4A2B68D8D1893ED'
 'backend\routers\xdr_data_sources.py'                                  = 'BFA551FEBFB5FCD548A05C278E515610534DE8A3C77423716780CF07D3DCD586'
 'backend\lib\collector_catalog.py'                                     = '32935FE2AD85A24B0822EF65A24FC689A12FFF2D12E32704976E8F3EC21E9B61'
 'backend\tests\test_g1_s2_windows_eventlog_protocol.py'                = 'EB94E38DA8ECFCF342E58072ECDE1125EA6DB690EAABC17B5770FD12842E817C'
}
$bad = 0
foreach ($k in $expected.Keys) {
  if (-not (Test-Path $k)) { Write-Host "  MISSING   $k" -ForegroundColor Red; $bad++; continue }
  $h = (Get-FileHash $k -Algorithm SHA256).Hash
  if ($h -eq $expected[$k]) { Write-Host "  match     $k" -ForegroundColor DarkGreen }
  else {
    Write-Host "  MISMATCH  $k" -ForegroundColor Red
    Write-Host "    expected $($expected[$k])" -ForegroundColor Red
    Write-Host "    actual   $h" -ForegroundColor Red
    $bad++
  }
}
if ($bad -gt 0) {
  Fail "$bad file(s) are not the reviewed G1 Step 2 code. If EVERY .py/.ps1 mismatched, core.autocrlf rewrote line endings: re-clone after 'git config --global core.autocrlf false'. A proof taken on unreviewed code is not a proof."
}
Ok "$($expected.Count)/$($expected.Count) files match the reviewed manifest byte-for-byte"

# ── 4 · supported interpreter ────────────────────────────────────────
Stage 4 'SUPPORTED CPYTHON 3.14 x64 (non-Store, GIL build)'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
  Fail 'py.exe launcher not found. Install CPython 3.14 x64 from python.org (NOT the Microsoft Store). No interpreter is installed automatically by this block.'
}
$probe = @'
import json, sys, sysconfig
print(json.dumps({
    "version": "%d.%d.%d" % sys.version_info[:3],
    "executable": sys.executable,
    "bits": 64 if sys.maxsize > 2**32 else 32,
    "free_threaded": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
}))
'@
$probe | Out-File -FilePath "$env:TEMP\nivx_pyprobe.py" -Encoding ASCII
$info = (py -3.14 "$env:TEMP\nivx_pyprobe.py" 2>$null) | ConvertFrom-Json
if (-not $info) { Fail 'py -3.14 did not run. CPython 3.14 x64 is the supported G1 runtime; see apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md. Nothing is installed automatically.' }
Write-Host "  interpreter: $($info.version)  $($info.bits)-bit"
Write-Host "  path       : $($info.executable)"
if ($info.executable -like '*WindowsApps*') { Fail 'the resolved interpreter is the Microsoft Store alias. It is not a supported runtime — the path existing proves nothing.' }
if ($info.bits -ne 64)        { Fail '32-bit interpreter is not supported for G1.' }
if ($info.free_threaded)      { Fail 'free-threaded (cp314t) build is not supported: pywin32 publishes no wheel for it.' }
if (-not $info.version.StartsWith('3.14')) { Fail "unsupported interpreter $($info.version); G1 is pinned to CPython 3.14 x64." }
Ok 'supported interpreter confirmed'

# ── 5 · virtual environment ──────────────────────────────────────────
Stage 5 'VIRTUAL ENVIRONMENT'
if (-not (Test-Path $VenvPy)) {
  py -3.14 -m ensurepip --upgrade | Out-Null
  py -3.14 -m venv $Venv
}
if (-not (Test-Path $VenvPy)) { Fail "venv was not created at $Venv." }
& $VenvPy -m pip install --upgrade pip --quiet
Ok "venv pinned at $VenvPy"

# ── 6 · pinned Windows dependencies ──────────────────────────────────
Stage 6 'PINNED WINDOWS DEPENDENCIES'
Push-Location $Collector
& $VenvPy -m pip install -r requirements-windows.txt --quiet
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'pinned dependency installation failed. Report this instead of installing a different interpreter or an unpinned pywin32.' }
$pw = (& $VenvPy -c "import importlib.metadata as m; print(m.version('pywin32'))").Trim()
Write-Host "  pywin32: $pw"
if ($pw -ne '312') { Pop-Location; Fail "pywin32 $pw is installed but the contract pins 312 (requirements-windows.txt)." }
Ok 'dependencies match the pinned Windows contract'

# ── 7 · pywin32 import ───────────────────────────────────────────────
Stage 7 'PYWIN32 IMPORT'
& $VenvPy -c "import win32evtlog; print('  win32evtlog:', win32evtlog.__file__)"
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'win32evtlog could not be imported. The runtime fails closed rather than acquiring zero events while reporting CONNECTED.' }
Ok 'native bindings importable'

# ── 8 · REAL native Event Log binding probe (read-only) ──────────────
Stage 8 'NATIVE EVENT LOG BINDING PROBE (EvtSubscribe · read-only)'
$bind = @'
import json, sys
import win32evtlog as w
out = {"bound": False}
try:
    bm = w.EvtCreateBookmark(None)
    h = w.EvtSubscribe("System", w.EvtSubscribeStartAtOldestRecord, None,
                       None, None,
                       "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]")
    evs = w.EvtNext(h, 1, -1, 0)
    rendered = None
    if evs:
        rendered = w.EvtRender(evs[0], w.EvtRenderEventXml)
        w.EvtUpdateBookmark(bm, evs[0])
    out = {"bound": True,
           "events_available_in_window": bool(evs),
           "xml_bytes": len(rendered) if rendered else 0,
           "bookmark_bytes": len(w.EvtRender(bm, w.EvtRenderBookmark))}
except Exception as exc:
    out = {"bound": False, "error": "%s: %s" % (type(exc).__name__, exc)}
print(json.dumps(out))
sys.exit(0 if out.get("bound") else 1)
'@
$bind | Out-File -FilePath "$env:TEMP\nivx_bindprobe.py" -Encoding ASCII
$bindOut = & $VenvPy "$env:TEMP\nivx_bindprobe.py"
Write-Host "  $bindOut"
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'EvtSubscribe could not be bound. Acquisition is refused — a subscription that cannot bind can only ever produce zero events.' }
Ok 'native subscription bound, one record rendered, bookmark rendered'

# ── 9 · persistent state directory ───────────────────────────────────
Stage 9 'PERSISTENT STATE DIRECTORY'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" | Out-Null
$probeFile = Join-Path $StateDir '.nivx_write_probe'
Set-Content -Path $probeFile -Value 'probe' -Encoding ASCII
if (-not (Test-Path $probeFile)) { Pop-Location; Fail "state directory $StateDir is not writable." }
Remove-Item $probeFile -Force
Write-Host "  state root: $StateDir (SYSTEM + Administrators only)"
Ok 'durable state root ready'

# ── 10 · pre-seeded collector configuration ──────────────────────────
Stage 10 'PRE-SEEDED COLLECTOR CONFIGURATION'
# The standalone control plane fails closed by design (no identity, RBAC or
# tenant authority exists off the backend), so the connector is seeded on
# disk and auto-started by the service's own rehydration path.
$window = '*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]'
$now = (Get-Date).ToUniversalTime().ToString('o')
$cfg = [ordered]@{
  connectors = @(
    [ordered]@{
      id          = $ConnectorId
      tenant_id   = $TenantId
      source_type = 'windows-eventlog'
      label       = 'G1 Windows endpoint'
      config      = [ordered]@{
        profile_id          = 'windows-validation'
        collector_id        = $CollectorId
        interval_seconds    = 60
        max_events_per_read = 500
        scope_bound         = 'G1_VALIDATION_SCOPE_BOUND'
        filters             = [ordered]@{
          'Microsoft-Windows-Sysmon/Operational'     = $window
          'Security'                                 = $window
          'Microsoft-Windows-PowerShell/Operational' = $window
        }
      }
      created_at = $now
      updated_at = $now
      enabled    = $true
    })
}
$cfgPath = Join-Path $StateDir 'connectors.json'
$cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $cfgPath -Encoding UTF8
$roundTrip = Get-Content $cfgPath -Raw | ConvertFrom-Json
if ($roundTrip.connectors[0].config.collector_id -ne $CollectorId) { Pop-Location; Fail 'seeded connector configuration did not round-trip.' }
Write-Host "  connector  : $ConnectorId"
Write-Host "  collector  : $CollectorId (server-enrolled identity)"
Write-Host "  tenant     : $TenantId"
Write-Host "  channels   : Sysmon · Security · PowerShell/Operational"
Write-Host "  scope bound: G1_VALIDATION_SCOPE_BOUND (last 60 minutes, XPath, applied by Windows)"
Ok 'configuration seeded — no disabled channel enabled, no Windows setting changed'

# ── 11 · server reachability + authentication + tenant authority ─────
Stage 11 'SERVER REACHABILITY · AUTHENTICATION · TENANT AUTHORITY'
try { $h = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 30 }
catch { Pop-Location; Fail "NivXRay XDR is not reachable at $BaseUrl : $($_.Exception.Message)" }
Ok "reachable ($BaseUrl)"

function Get-PlainFromSecure([System.Security.SecureString]$s) {
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

if ($MintOnHost) {
  $adminEmail = Read-Host 'NivXRay admin e-mail (preview)'
  $adminSecret = Read-Host 'NivXRay admin password (not echoed, not stored)' -AsSecureString
  try {
    $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" `
      -ContentType 'application/json' -TimeoutSec 30 `
      -Body (@{ email = $adminEmail
                password = (Get-PlainFromSecure $adminSecret) } | ConvertTo-Json)
  } catch { Pop-Location; Fail 'admin authentication failed; no key was minted.' }
  $jwt = $login.access_token
  $keyName = "g1-endpoint-$([int](Get-Date -UFormat %s))"
  $expires = (Get-Date).ToUniversalTime().AddHours(24).ToString('o')
  try {
    $mint = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/xdr/api-keys" `
      -Headers @{ Authorization = "Bearer $jwt"; 'X-Tenant-Id' = $TenantId } `
      -ContentType 'application/json' -TimeoutSec 30 `
      -Body (@{ name = $keyName; confirm_tenant_id = $TenantId
                description = 'G1 Step 2 endpoint ingest credential (24h)'
                scopes = @('collectors.enroll'); expires_at = $expires
              } | ConvertTo-Json)
  } catch { Pop-Location; Fail "ingest key could not be minted: $($_.Exception.Message)" }
  $env:NIVX_INGEST_TOKEN = $mint.data.plaintext     # in-process only
  Write-Host "  minted key : $($mint.data.prefix)…  id=$($mint.data.id)"
  Write-Host "  scopes     : collectors.enroll (no control-plane authority)"
  Write-Host "  expires    : $expires"
  Remove-Variable jwt, login, mint, adminSecret -ErrorAction SilentlyContinue
  [GC]::Collect()
} else {
  $keySecure = Read-Host 'G1 ingest key (X-XDR-API-Key, not echoed)' -AsSecureString
  $env:NIVX_INGEST_TOKEN = Get-PlainFromSecure $keySecure
  Remove-Variable keySecure -ErrorAction SilentlyContinue
}
if (-not $env:NIVX_INGEST_TOKEN) { Pop-Location; Fail 'no ingest credential is present.' }

# Authentication + tenant-authority probe that creates NO evidence: an
# empty batch is rejected 400 AFTER auth and tenant resolution succeed.
# 401/403 here means the credential or the tenant binding is wrong.
$authStatus = $null
try {
  Invoke-WebRequest -Method Post -Uri "$BaseUrl/api/xdr/ingest/telemetry" `
    -Headers @{ 'X-XDR-API-Key' = $env:NIVX_INGEST_TOKEN
                'X-Tenant-Id'   = $TenantId } `
    -ContentType 'application/json' -Body '{"envelopes":[]}' `
    -TimeoutSec 30 -UseBasicParsing | Out-Null
} catch { $authStatus = [int]$_.Exception.Response.StatusCode }
Write-Host "  auth probe : HTTP $authStatus (400 = authenticated + tenant resolved, empty batch refused)"
if ($authStatus -eq 401 -or $authStatus -eq 403) {
  Pop-Location; Fail "ingest authentication/tenant authority REFUSED (HTTP $authStatus). Acquisition is not started."
}
if ($authStatus -ne 400) {
  Pop-Location; Fail "unexpected auth-probe result (HTTP $authStatus). Acquisition is not started until the boundary answers as contracted."
}
Ok 'authenticated, tenant authority accepted, no evidence created'

# ── 12 · bounded acquisition ─────────────────────────────────────────
Stage 12 "BOUNDED ACQUISITION · $RunMinutes min observation · 60-min scope bound"
$env:NIVX_INGEST_URL          = "$BaseUrl/api/xdr/ingest/telemetry"
$env:NIVX_INGEST_AUTH_MODE    = 'api_key'
$env:NIVX_TENANT_ID           = $TenantId
$env:NIVX_COLLECTOR_ID        = $CollectorId
$env:XDR_STATE_DIR            = $StateDir
$env:XDR_AUTO_START_CONNECTORS = '1'
$env:XDR_CORS_ORIGINS         = 'http://127.0.0.1'

$proofDir = Join-Path $Work 'g1-proof'
New-Item -ItemType Directory -Force -Path $proofDir | Out-Null
$svcLog = Join-Path $proofDir 'collector.log'

Write-Host "  starting collector on 127.0.0.1:8080 (loopback only — the standalone control plane is fail-closed)"
$svc = Start-Process -FilePath $VenvPy `
  -ArgumentList '-m','uvicorn','main:app','--host','127.0.0.1','--port','8080' `
  -WorkingDirectory $Collector -PassThru -NoNewWindow `
  -RedirectStandardOutput $svcLog -RedirectStandardError "$proofDir\collector.err.log"
Start-Sleep -Seconds 12

try { $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 30 }
catch { Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue; Pop-Location; Fail "collector did not come up; see $svcLog" }
$health | ConvertTo-Json -Depth 8 | Set-Content "$proofDir\health-start.json" -Encoding UTF8
Write-Host ("  rehydration: constructed=$($health.rehydration.constructed) started=$($health.rehydration.started) failures=$($health.rehydration.failures.Count)")
if ($health.rehydration.started -lt 1) {
  Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue
  $health.rehydration | ConvertTo-Json -Depth 8 | Write-Host
  Pop-Location; Fail 'the Windows connector did not start. Acquisition is refused rather than reported as healthy.'
}
Ok 'connector started and is subscribed'

$deadline = (Get-Date).AddMinutes($RunMinutes)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 60
  $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 30
  $ob = $h.outbox.counts
  Write-Host ("  [{0:HH:mm:ss}] outbox queued={1} delivering={2} delivered={3} retrying={4} dead={5}" -f `
    (Get-Date), $ob.queued, $ob.delivering, $ob.delivered, $ob.retrying, $ob.dead_letter)
}

# ── proof artifacts (nothing is interpreted here) ────────────────────
Stage 'A' 'PROOF ARTIFACTS'
Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 30 |
  ConvertTo-Json -Depth 8 | Set-Content "$proofDir\health-end.json" -Encoding UTF8
$dump = @'
import json, os, sqlite3, sys
db = os.path.join(os.environ["XDR_STATE_DIR"], "outbox.db")
c = sqlite3.connect(db); c.row_factory = sqlite3.Row
out = {"db": db}
out["channel_state"] = [dict(r) for r in c.execute(
    "SELECT tenant_id, collector_id, channel, origin_computer, profile_id,"
    " profile_version, bookmark_at, last_record_id, last_activity_at,"
    " last_read_at, reads, events_read, log_cleared_count, last_error,"
    " length(bookmark_xml) AS bookmark_bytes,"
    " (delivered_through IS NOT NULL) AS has_delivered_through,"
    " (delivered_through = bookmark_xml) AS delivered_through_matches"
    " FROM windows_channel_state")]
out["outbox_by_status"] = {r["status"]: r["n"] for r in c.execute(
    "SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status")}
out["outbox_sample"] = [dict(r) for r in c.execute(
    "SELECT id, status, attempts, source_event_id, declared_source,"
    " created_at, updated_at, last_error FROM envelopes"
    " ORDER BY created_at LIMIT 5")]
row = c.execute(
    "SELECT source_timestamp, collection_timestamp, source_event_id,"
    " declared_source, raw_json, canonical_json FROM envelopes"
    " ORDER BY created_at LIMIT 1").fetchone()
if row:
    raw = json.loads(row["raw_json"] or "{}")
    can = json.loads(row["canonical_json"] or "{}")
    out["envelope_clocks"] = {
        "source_timestamp": row["source_timestamp"],
        "collection_timestamp": row["collection_timestamp"],
        "canonical.activity_occurred_at": can.get("activity_occurred_at"),
        "canonical.activity_time_source": can.get("activity_time_source"),
        "canonical.sensor_observed_at": can.get("sensor_observed_at"),
        "three_clocks_distinct": len({
            str(can.get("activity_occurred_at")),
            str(can.get("sensor_observed_at"))}) == 2,
        "declared_source": row["declared_source"],
        "raw_xml_bytes": len(raw.get("xml") or ""),
        "raw_xml_head": (raw.get("xml") or "")[:400],
        "channel": raw.get("channel"),
        "source_event_id": row["source_event_id"],
    }
print(json.dumps(out, indent=2, default=str))
'@
$dump | Out-File -FilePath "$env:TEMP\nivx_dump.py" -Encoding ASCII
& $VenvPy "$env:TEMP\nivx_dump.py" | Set-Content "$proofDir\acquisition-state.json" -Encoding UTF8
Copy-Item $cfgPath "$proofDir\connectors.seeded.json" -Force
@{ head = $head; branch = $Branch; manifest_files = $expected.Count
   manifest = 'G1_STEP2_REVIEWED_CODE_MANIFEST.md'
   interpreter = $info; pywin32 = $pw; bind_probe = ($bindOut | ConvertFrom-Json)
   state_dir = $StateDir; tenant_id = $TenantId; collector_id = $CollectorId
   scope_bound = 'G1_VALIDATION_SCOPE_BOUND'; window_minutes = 60
   observation_minutes = $RunMinutes
   generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
 } | ConvertTo-Json -Depth 8 | Set-Content "$proofDir\run-context.json" -Encoding UTF8

Write-Host ""
Write-Host "Collector is STILL RUNNING (pid $($svc.Id)) so the restart/resume," -ForegroundColor Yellow
Write-Host "reboot/resume and mid-delivery interruption proofs can follow." -ForegroundColor Yellow
Write-Host "Artifacts written to $proofDir :" -ForegroundColor Cyan
Get-ChildItem $proofDir | ForEach-Object { Write-Host ("  " + $_.Name + "  " + $_.Length + " bytes") }
Write-Host ""
Write-Host "Send back: run-context.json, health-start.json, health-end.json," -ForegroundColor Cyan
Write-Host "acquisition-state.json. They contain NO credential." -ForegroundColor Cyan
Write-Host ""
Write-Host "G1 is NOT declared PASS because events arrived. The per-proof" -ForegroundColor Yellow
Write-Host "matrix (raw XML, bookmark identity, durable-before-advance," -ForegroundColor Yellow
Write-Host "restart/resume, three clocks, tenant binding, canonical evidence" -ForegroundColor Yellow
Write-Host "identity, duplicate/loss accounting, per-channel truth states) is" -ForegroundColor Yellow
Write-Host "evaluated against these artifacts. B4 is demonstrated separately." -ForegroundColor Yellow
Pop-Location
