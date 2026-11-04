# =====================================================================
# G1 . STEP 2 . NivXForge EDR native Windows acquisition -> NivXRay XDR
# ELEVATED PowerShell (Run as Administrator). Single run, fail closed.
#
# EXECUTION COPY: sanitized for paste. ASCII-only characters. No semantic,
# gate, tenant, collector, channel, scope, manifest or credential change
# relative to the reviewed block. Stage 9/10 stays CLOSED. B4/G2 untouched.
#
# GATE ORDER (acquisition starts only if every gate passes):
#   1  Administrator
#   2  repository + branch identity (no reclone, no delete, no clean)
#   3  safe update to the exact reviewed HEAD
#   4  reviewed-code manifest 26/26 verified locally
#   5  supported standard CPython 3.14 x64 (RESOLVED interpreter judged;
#      py.exe launcher location is informational only)
#   6  isolated venv
#   7  exactly the pinned Windows dependencies
#   8  pywin32 verified
#   9  acquisition capability (the Stage 9/10 PROOF IS CLOSED and is
#      NOT re-run; only the runtime's own capability question is asked)
#   11 persistent state root + write/persistence validation
#   12 collector identity + server authority configured
#   13 server reachability + authentication + tenant binding
#   14 bounded acquisition (60-minute scope bound)
#
# NOT DONE HERE: no Python installation, no Sysmon install/reconfigure,
# no channel enabling, no log clearing, no registry or audit-policy
# change, no service install, no B4, no G2.
#
# CREDENTIAL LIFECYCLE (stage 13/14) - STATED EXACTLY, NO OVERCLAIM:
#   * if $env:NIVX_INGEST_TOKEN already exists in this window it is REUSED
#     and never re-displayed - there is no second prompt;
#   * otherwise ONE key is minted here: tenant ten_f1a5479243e901cf159e230fa0,
#     scopes ["collectors.enroll"] exactly, 12h expiry;
#   * the plaintext goes only into the process environment - never echoed,
#     logged, persisted to disk/config, committed, or passed on a command line;
#   * the admin bearer token is destroyed the instant the key exists;
#   * IMPORTANT AND TRUE: the collector is launched WHILE the token is present
#     in this PowerShell environment, so the collector CHILD PROCESS INHERITS
#     a copy of the plaintext. Clearing this PowerShell's environment does NOT
#     clear the collector's inherited copy. That copy lives in the collector
#     process memory only, for exactly as long as the collector needs it to
#     perform authenticated delivery;
#   * therefore this block TERMINATES the collector at the end of the bounded
#     60-minute acquisition, immediately after proof capture. Terminating the
#     process destroys the process-held copy. Only then is this PowerShell's
#     own copy cleared. Restart/resume is a SEPARATE controlled gate and is
#     deliberately NOT proved here;
#   * on ANY failure after the collector process exists, the collector is
#     terminated before returning - a failed run never leaves a collector,
#     or its inherited credential, alive;
#   * only the NON-SECRET key id/prefix is kept (console + proof artifact), so
#     the exact key can be revoked AFTER server-side evidence verification -
#     never before. The plaintext is never written to any artifact or log.
#
# OPERATOR SAFETY: no `exit` anywhere. A failed gate throws, is caught, and
# prints STAGE + REASON; the elevated console stays open and no later G1
# step runs. Every gate outcome is also appended to C:\nivx\g1-proof\
# gate-log.txt so a reason survives even a lost window.
# =====================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# OPERATOR-SAFE FAILURE HANDLING
# Everything runs inside a function. A failed gate throws, the function's
# own catch prints the exact stage and reason, clears any in-memory token
# and returns - so the elevated console STAYS OPEN and no later G1 step
# runs. No `exit` anywhere: `exit` is what closed your window.
function Invoke-G1Step2 {

# ---- settings (no secrets) ------------------------------------------
$Repo        = 'https://github.com/jpreddy017/nivxray-xdr.git'
$Branch      = 'feature/rc2-alignment'
$ReviewedHead= '4a6b71049d535728b524aa8b1b48554a042f0876'
$Work        = 'C:\nivx'
$Collector   = "$Work\apps\nivxray-xdr-collector"
$StateDir    = 'C:\ProgramData\NivXForge\state'
$Venv        = "$Work\.venv"
$VenvPy      = "$Venv\Scripts\python.exe"

$BaseUrl     = 'https://greeting-app-5782.preview.emergentagent.com'
$TenantId    = 'ten_f1a5479243e901cf159e230fa0'   # g1-windows-proof
$CollectorId = 'col_d6b0b9e8172246f29be9'         # enrolled windows-eventlog
$ConnectorId = 'windows-eventlog-g1proof01'
$ScopeMinutes   = 60                              # G1_VALIDATION_SCOPE_BOUND
$ObserveMinutes = 60                              # foreground observation

$Channels = @('Microsoft-Windows-Sysmon/Operational',
              'Security',
              'Microsoft-Windows-PowerShell/Operational')

$script:G1Stage    = 'init'
$script:G1GateLog  = $null
#: NON-SECRET credential reference, so the exact temporary key can be
#: revoked AFTER server-side evidence verification - never before.
$script:G1KeyId     = $null
$script:G1KeyPrefix = $null
$script:G1KeyExpires = $null
#: the collector child process, once it exists. It holds an INHERITED copy of
#: the plaintext token, so every exit path must terminate it.
$script:G1Svc       = $null
$script:G1SvcStopped = $false

function Note($line) {
  # Durable gate trail, so a reason survives even a lost console.
  if ($script:G1GateLog) {
    try { Add-Content -Path $script:G1GateLog -Value `
      ("{0:o}  {1}" -f (Get-Date).ToUniversalTime(), $line) -Encoding UTF8 } catch { }
  }
}
function Fail($msg) {
  # Throws. Never exits: the caller's catch prints and returns.
  Note "FAIL [$script:G1Stage] $msg"
  throw "G1_GATE_FAILED|$script:G1Stage|$msg"
}
function Ok($m)   { Write-Host "  OK   $m" -ForegroundColor Green; Note "OK   [$script:G1Stage] $m" }
function Info($m) { Write-Host "  $m"; Note "info [$script:G1Stage] $m" }
function Stage($n,$t) {
  $script:G1Stage = "$n - $t"
  Write-Host "`n=== $n - $t ===" -ForegroundColor Cyan
  Note "STAGE $n - $t"
}
function Stop-G1Collector($why) {
  # Terminating the collector is the ONLY way to destroy the plaintext copy it
  # inherited at launch. Called on success (after proof capture) and on every
  # failure path once the process exists.
  if (-not $script:G1Svc) { return }
  if ($script:G1SvcStopped) { return }
  $pidToStop = $script:G1Svc.Id
  try {
    Stop-Process -Id $pidToStop -Force -ErrorAction Stop
    try { Wait-Process -Id $pidToStop -Timeout 30 -ErrorAction SilentlyContinue } catch { }
    $script:G1SvcStopped = $true
    Write-Host ("  collector pid " + $pidToStop + " terminated (" + $why +
      "); its inherited credential copy died with the process") -ForegroundColor DarkGray
    Note ("collector pid " + $pidToStop + " terminated: " + $why)
  } catch {
    Write-Host ("  WARNING: could not terminate collector pid " + $pidToStop +
      ": " + $_.Exception.Message) -ForegroundColor Red
    Write-Host  "  That process still holds the inherited plaintext token. Kill it" -ForegroundColor Red
    Write-Host ("  manually (Stop-Process -Id " + $pidToStop + " -Force) before revoking the key.") -ForegroundColor Red
    Note ("WARN collector pid " + $pidToStop + " NOT terminated: " + $_.Exception.Message)
  }
}

try {
# Gate trail lives beside the proof artifacts. Creating this directory
# touches no Windows configuration and deletes nothing - in particular
# scripts/windows/g1/nivxray-g1-preflight.json (Step 1 evidence) and any
# existing g1-proof content are left exactly as they are.
$script:G1GateLog = $null
if (Test-Path $Work) {
  $proofDirEarly = Join-Path $Work 'g1-proof'
  New-Item -ItemType Directory -Force -Path $proofDirEarly | Out-Null
  $script:G1GateLog = Join-Path $proofDirEarly 'gate-log.txt'
  Note "--- G1 Step 2 run start - host $env:COMPUTERNAME - PS $($PSVersionTable.PSVersion) ---"
}

# ---- 1 . Administrator ----------------------------------------------
Stage 1 'ADMINISTRATOR'
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail 'not elevated. Security is only truthfully readable under elevation; an unelevated run would record READ_DENIED and call it evidence.'
}
Ok 'running elevated'

# ---- 2 . repository + branch identity (non-destructive) -------------
Stage 2 'REPOSITORY IDENTITY (no reclone - no delete - no clean)'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail 'git is not on PATH.' }
if (-not (Test-Path "$Work\.git")) { Fail "$Work is not a git working tree. Step 1 left it in place; this block does not create or destroy it." }
Set-Location $Work
$origin = (git config --get remote.origin.url)
Info "origin: $origin"
if ($origin -notmatch 'jpreddy017/nivxray-xdr') { Fail "unexpected origin '$origin'." }
$autocrlf = (git config --get core.autocrlf)
Info "core.autocrlf: $autocrlf"
if ($autocrlf -eq 'true' -or $autocrlf -eq 'input') {
  Fail "core.autocrlf=$autocrlf rewrites line endings, so every .py/.ps1 hash would differ legitimately. Set 'git config --global core.autocrlf false' and re-checkout before running this block."
}
$dirty = (git status --porcelain --untracked-files=no)
if ($dirty) {
  Write-Host $dirty -ForegroundColor Red
  Fail 'tracked files are modified in the working tree. This block will not discard your changes; resolve them deliberately first.'
}
Ok 'working tree is the expected repository and is clean on tracked files'

# ---- 3 . safe update to the EXACT reviewed HEAD ---------------------
Stage 3 "UPDATE TO REVIEWED HEAD $($ReviewedHead.Substring(0,12))"
git fetch --no-tags origin $Branch
if ($LASTEXITCODE -ne 0) { Fail 'git fetch failed.' }
git cat-file -e "$ReviewedHead^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { Fail "the reviewed commit $ReviewedHead is not present after fetching origin/$Branch. Verification of the remote is a prerequisite; nothing is forced." }
$tip = (git rev-parse "origin/$Branch")
Info "origin/$Branch tip: $tip"
$isAncestorOrEqual = $false
if ($tip -eq $ReviewedHead) { $isAncestorOrEqual = $true }
else {
  git merge-base --is-ancestor $ReviewedHead $tip 2>$null
  if ($LASTEXITCODE -eq 0) { $isAncestorOrEqual = $true }
}
if (-not $isAncestorOrEqual) { Fail "the reviewed HEAD is not the tip of origin/$Branch and is not an ancestor of it. The remote diverged from what was verified; STOP." }
# Detached checkout of the exact reviewed commit: the local branch ref is
# never rewritten and nothing is deleted or cleaned.
git checkout --detach $ReviewedHead
if ($LASTEXITCODE -ne 0) { Fail 'checkout of the reviewed commit failed.' }
$head = (git rev-parse HEAD)
Info "HEAD now : $head"
Info ("date     : " + (git show -s --format=%cI HEAD))
Info ("subject  : " + (git show -s --format=%s HEAD))
if ($head -ne $ReviewedHead) { Fail "HEAD is $head, expected $ReviewedHead." }
Ok 'checked out the exact reviewed commit (detached; branch ref untouched)'

# ---- 4 . reviewed-code manifest -------------------------------------
Stage 4 'REVIEWED-CODE MANIFEST (G1 STEP 2 - 26 files)'
$expected = [ordered]@{
 'scripts\windows\g1\Get-NivXRayG1Preflight.ps1'                        = '3D43E6235BBBEB631EAC11B96AF10C5AF14B6227C93ABDBCD88F966CAD9C4AF7'
 'scripts\windows\g1\README_G1_STEP1_PREFLIGHT.md'                      = '055A28E5FA8EBDBAA25ABE97E33B2C776E347CEC20DD536D4479942132EF598C'
 'apps\nivxray-xdr-collector\framework\windows_eventlog.py'             = 'EC747671ED0156C3814C458A2A07C41B98901620E506842040E77C04F72A39E6'
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
 'apps\nivxray-xdr-collector\tests\test_g1_evtsubscribe_contract.py'    = '754764F133895435844DB4D7E795B052B7C5E9368371C159E901A3D1037847B3'
 'backend\services\ingest_provenance.py'                                = 'EEEC91EC55707BD9846BCF6568EA2D5A38BD880EDF7AF3892B8384F8A5B28913'
 'backend\tests\test_g1_s1_clock_independence.py'                       = 'B3D43A2A0401B2434B5D2CF2636E2D31957E55BD85F0DCF59A6508B2A6FC3D3C'
 'backend\routers\xdr_collectors.py'                                    = 'D898C793C048DD1100E227415BECF83BA426CE46964A7F6AF4A2B68D8D1893ED'
 'backend\routers\xdr_data_sources.py'                                  = 'BFA551FEBFB5FCD548A05C278E515610534DE8A3C77423716780CF07D3DCD586'
 'backend\lib\collector_catalog.py'                                     = '32935FE2AD85A24B0822EF65A24FC689A12FFF2D12E32704976E8F3EC21E9B61'
 'backend\tests\test_g1_s2_windows_eventlog_protocol.py'                = 'EB94E38DA8ECFCF342E58072ECDE1125EA6DB690EAABC17B5770FD12842E817C'
}
$bad = 0; $manifestRows = @()
foreach ($k in $expected.Keys) {
  if (-not (Test-Path $k)) { Write-Host "  MISSING   $k" -ForegroundColor Red; $bad++; continue }
  $h = (Get-FileHash $k -Algorithm SHA256).Hash
  $manifestRows += [pscustomobject]@{ path=$k; expected=$expected[$k]; actual=$h; match=($h -eq $expected[$k]) }
  if ($h -eq $expected[$k]) { Write-Host "  match     $k" -ForegroundColor DarkGreen }
  else {
    Write-Host "  MISMATCH  $k" -ForegroundColor Red
    Write-Host "    expected $($expected[$k])" -ForegroundColor Red
    Write-Host "    actual   $h" -ForegroundColor Red
    $bad++
  }
}
if ($bad -gt 0) { Fail "$bad of $($expected.Count) file(s) are not the reviewed G1 Step 2 code. A proof taken on unreviewed code is not a proof." }
Ok "$($expected.Count)/$($expected.Count) reviewed files match byte-for-byte"

# ---- 5 . supported interpreter (validate, never install) ------------
Stage 5 'SUPPORTED CPYTHON 3.14 x64 - RESOLVED INTERPRETER IS AUTHORITATIVE'
$probe = @'
import json, sys, sysconfig
print(json.dumps({
    "version": "%d.%d.%d" % sys.version_info[:3],
    "executable": sys.executable,
    "prefix": sys.prefix,
    "bits": 64 if sys.maxsize > 2**32 else 32,
    "free_threaded": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
}))
'@
$probePath = Join-Path $env:TEMP 'nivx_pyprobe.py'
$probe | Out-File -FilePath $probePath -Encoding ASCII
# The LAUNCHER's own location is informational only. py.exe ships under
# WindowsApps on this host, and that says nothing about the runtime it
# resolves. What is judged is the interpreter py -3.14 actually resolves to
# (sys.executable / sys.prefix). On this endpoint that is
#   C:\Users\<user>\AppData\Local\Python\pythoncore-3.14-64\python.exe
# which is a real CPython with a working pip, so it PASSES. Only a runtime
# that itself lives in WindowsApps (the Store alias/package, which has no
# usable pip) is rejected.
$launcher = (Get-Command py -ErrorAction SilentlyContinue)
if (-not $launcher) { Fail 'py.exe launcher is not present. This block installs no interpreter: report this and we decide the runtime change deliberately (see apps/nivxray-xdr-collector/WINDOWS_RUNTIME.md).' }
Info "py.exe launcher (informational, not judged): $($launcher.Source)"
Write-Host "  py.exe launcher inventory:"
try { (py -0p) 2>$null | ForEach-Object { Write-Host "    $_" } } catch { }
$info = $null
try { $info = (py -3.14 $probePath 2>$null) | ConvertFrom-Json } catch { }
if (-not $info) { Fail 'py -3.14 did not produce a usable interpreter. Nothing is installed automatically - report this and we decide the runtime change deliberately.' }
Info "resolved interpreter (authoritative): $($info.executable)"
Info "version   : $($info.version)  $($info.bits)-bit  free_threaded=$($info.free_threaded)"
Info "sys.prefix: $($info.prefix)"
if ($info.executable -like '*\WindowsApps\*' -or $info.prefix -like '*\WindowsApps\*') {
  Fail 'the RESOLVED interpreter itself lives under WindowsApps (Microsoft Store alias/package). That is not a supported runtime: it carries no usable pip. The launcher living under WindowsApps is fine; the runtime must not.'
}
if (-not $info.version.StartsWith('3.14')) { Fail "resolved $($info.version); G1 is pinned to CPython 3.14 x64 standard build." }
if ($info.bits -ne 64)   { Fail '32-bit interpreter is not supported for G1.' }
if ($info.free_threaded) { Fail 'free-threaded (cp314t) build is not supported: pywin32 publishes no wheel for it.' }
Ok 'supported standard CPython 3.14 x64 confirmed (nothing installed)'

# ---- 6 . isolated venv ----------------------------------------------
Stage 6 'ISOLATED VIRTUAL ENVIRONMENT'
if (-not (Test-Path $VenvPy)) {
  py -3.14 -m ensurepip --upgrade | Out-Null
  py -3.14 -m venv $Venv
}
if (-not (Test-Path $VenvPy)) { Fail "venv was not created at $Venv." }
$venvInfo = (& $VenvPy $probePath) | ConvertFrom-Json
Info "venv python: $($venvInfo.version) $($venvInfo.bits)-bit  $VenvPy"
if (-not $venvInfo.version.StartsWith('3.14') -or $venvInfo.bits -ne 64) { Fail 'the venv interpreter is not the supported runtime.' }
if ($venvInfo.executable -like '*\WindowsApps\*') { Fail 'the venv resolves to the Store alias.' }
Ok 'venv pinned; every later command uses it by absolute path'

# ---- 7 . pinned Windows dependencies --------------------------------
Stage 7 'PINNED WINDOWS DEPENDENCIES'
Push-Location $Collector
& $VenvPy -m pip install --disable-pip-version-check -r requirements-windows.txt --quiet
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'installation of the pinned Windows dependencies failed. Report it - no unpinned pywin32 and no different interpreter are substituted.' }
Ok 'requirements-windows.txt installed (pinned)'

# ---- 8 . pywin32 verified -------------------------------------------
Stage 8 'PYWIN32 VERIFICATION'
$pw = (& $VenvPy -c "import importlib.metadata as m; print(m.version('pywin32'))" 2>$null)
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'pywin32 is not installed in the venv.' }
$pw = $pw.Trim()
Info "pywin32: $pw"
if ($pw -ne '312') { Pop-Location; Fail "pywin32 $pw installed but the contract pins 312." }
& $VenvPy -c "import win32evtlog; print('  win32evtlog:', win32evtlog.__file__)"
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'win32evtlog could not be imported. The runtime fails closed instead of acquiring zero events while looking healthy.' }
Ok 'pinned pywin32 present and importable'

# ---- 9 . capability only . the Stage 9/10 PROOF IS CLOSED -----------
Stage 9 'ACQUISITION CAPABILITY (Stage 9/10 proof is CLOSED - not re-run)'
Info 'Stage 9/10 was proved on THIS host against this reviewed code:'
Info '  bound=true - Sysmon/Security/PowerShell READ_OK - bookmark + resume READ_OK - ERROR 87 resolved'
Info 'It is frozen. This is only the cheap capability question the runtime'
Info 'itself asks before it will start a connector - no subscription is opened here.'
Push-Location $Collector
$capOut = (& $VenvPy -c @"
import json, sys
sys.path.insert(0, '.')
from framework.windows_eventlog import NativeEvtReader
st = NativeEvtReader().binding_status()
print(json.dumps(st))
sys.exit(0 if st.get('bound') else 1)
"@) -join "`n"
Write-Host "  $capOut"
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail 'the native bindings are no longer available on this host. Acquisition is refused; nothing is downgraded.' }
Ok 'native acquisition capability present (production NativeEvtReader)'

# ---- 11 . persistent state root -------------------------------------
Stage 11 'PERSISTENT STATE ROOT'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" | Out-Null
$persist = @'
import json, os, sqlite3, sys
d = sys.argv[1]
p = os.path.join(d, ".nivx_persist_probe.db")
try:
    c = sqlite3.connect(p); c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS t(k TEXT)")
    c.execute("INSERT INTO t VALUES ('probe')"); c.commit(); c.close()
    c = sqlite3.connect(p)
    n = c.execute("SELECT COUNT(*) FROM t").fetchone()[0]; c.close()
    os.remove(p)
    for suf in ("-wal", "-shm"):
        if os.path.exists(p + suf): os.remove(p + suf)
    print(json.dumps({"writable": True, "reopened_rows": n, "dir": d}))
    sys.exit(0 if n >= 1 else 1)
except Exception as exc:
    print(json.dumps({"writable": False,
                      "error": "%s: %s" % (type(exc).__name__, exc)}))
    sys.exit(1)
'@
$persistPath = Join-Path $env:TEMP 'nivx_persistprobe.py'
$persist | Out-File -FilePath $persistPath -Encoding ASCII
$persistOut = (& $VenvPy $persistPath $StateDir)
Info $persistOut
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "state root $StateDir failed the durability probe. Bookmarks and the outbox must share one durable fsync domain; acquisition is refused." }
Info "state root: $StateDir (SYSTEM + Administrators only)"
Ok 'durable state validated (write, WAL commit, reopen, read back)'

# ---- 12 . collector identity + server authority ---------------------
Stage 12 'COLLECTOR IDENTITY + SERVER AUTHORITY'
$window = "*[System[TimeCreated[timediff(@SystemTime) <= $($ScopeMinutes * 60 * 1000)]]]"
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
        scope_bound_minutes = $ScopeMinutes
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
$rt = Get-Content $cfgPath -Raw | ConvertFrom-Json
if ($rt.connectors[0].config.collector_id -ne $CollectorId -or
    $rt.connectors[0].tenant_id -ne $TenantId) { Pop-Location; Fail 'seeded collector configuration did not round-trip.' }
Info "connector  : $ConnectorId"
Info "collector  : $CollectorId  (identity enrolled server-side; never generated)"
Info "tenant     : $TenantId"
Info "channels   : Sysmon - Security - PowerShell/Operational"
Info "scope bound: G1_VALIDATION_SCOPE_BOUND = last $ScopeMinutes minutes (XPath, applied by Windows)"
Ok 'identity + bounded scope configured; no Windows setting changed'

# ---- 13 . reachability + authentication + tenant binding ------------
Stage 13 'SERVER REACHABILITY - AUTHENTICATION - TENANT BINDING'
try { Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 30 | Out-Null }
catch { Pop-Location; Fail "NivXRay XDR is not reachable at $BaseUrl : $($_.Exception.Message)" }
Ok "reachable ($BaseUrl)"

function Get-PlainFromSecure([System.Security.SecureString]$sec) {
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

if (-not [string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)) {
  # A token already lives in this window (you minted it earlier). Reuse it.
  # No second prompt, and the value is never re-displayed. The key id/prefix
  # stay $null if that token was minted outside this block; revocation then
  # uses the id you already recorded when it was created.
  Info 'reusing the ingest token already present in this window (not re-displayed)'
  Ok 'credential source: existing in-process environment token'
} else {
  Info 'no in-process token found - minting exactly ONE temporary key on this host'
  $adminEmail  = Read-Host '  NivXRay admin e-mail (preview)'
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
      -Body (@{ name = "g1-endpoint-$([int](Get-Date -UFormat %s))"
                confirm_tenant_id = $TenantId
                description = 'G1 Step 2 acquisition proof - 12h - collectors.enroll only'
                scopes = @('collectors.enroll')
                expires_at = $expires } | ConvertTo-Json)
  } catch {
    # The admin session dies with this scope either way.
    Remove-Variable login, mint, adminSecret -ErrorAction SilentlyContinue
    [GC]::Collect()
    Pop-Location
    Fail "key minting failed: $($_.Exception.Message). No credential exists and nothing was started."
  }
  # Plaintext goes straight into the process environment and nowhere else:
  # not a file, not a log, not a command line, not this transcript.
  $env:NIVX_INGEST_TOKEN = $mint.data.plaintext
  $script:G1KeyId     = $mint.data.id
  $script:G1KeyPrefix = $mint.data.prefix
  $script:G1KeyExpires = $expires
  Info "minted key id : $script:G1KeyId"
  Info "prefix        : $script:G1KeyPrefix"
  Info "scopes        : collectors.enroll  (no control-plane authority)"
  Info "expires       : $expires"
  # The admin bearer token is destroyed the instant the key exists: it is
  # far more powerful than the credential it just created, and it is never
  # needed again in this run.
  Remove-Variable login, mint, adminSecret, adminEmail -ErrorAction SilentlyContinue
  [GC]::Collect()
  Ok 'admin session discarded from memory; only the scoped ingest token remains'
}
if ([string]::IsNullOrWhiteSpace($env:NIVX_INGEST_TOKEN)) {
  Pop-Location; Fail 'no ingest credential is present; acquisition cannot start.'
}

$authStatus = $null
try {
  Invoke-WebRequest -Method Post -Uri "$BaseUrl/api/xdr/ingest/telemetry" `
    -Headers @{ 'X-XDR-API-Key' = $env:NIVX_INGEST_TOKEN
                'X-Tenant-Id'   = $TenantId } `
    -ContentType 'application/json' -Body '{"envelopes":[]}' `
    -TimeoutSec 30 -UseBasicParsing | Out-Null
} catch { $authStatus = [int]$_.Exception.Response.StatusCode }
Info "auth probe : HTTP $authStatus  (400 = authenticated, tenant resolved, empty batch refused; creates no evidence)"
if ($authStatus -eq 401 -or $authStatus -eq 403) { Pop-Location; Fail "ingest authentication / tenant binding REFUSED (HTTP $authStatus)." }
if ($authStatus -ne 400) { Pop-Location; Fail "unexpected auth-probe result (HTTP $authStatus); acquisition is not started until the boundary answers as contracted." }
Ok 'authenticated; tenant binding accepted; no evidence created by the probe'

# ---- 14 . bounded acquisition ---------------------------------------
Stage 14 "BOUNDED ACQUISITION - scope $ScopeMinutes min - observe $ObserveMinutes min"
$env:NIVX_INGEST_URL           = "$BaseUrl/api/xdr/ingest/telemetry"
$env:NIVX_INGEST_AUTH_MODE     = 'api_key'
$env:NIVX_TENANT_ID            = $TenantId
$env:NIVX_COLLECTOR_ID         = $CollectorId
$env:XDR_STATE_DIR             = $StateDir
$env:XDR_AUTO_START_CONNECTORS = '1'
$env:XDR_CORS_ORIGINS          = 'http://127.0.0.1'

$proofDir = Join-Path $Work 'g1-proof'
New-Item -ItemType Directory -Force -Path $proofDir | Out-Null
$svcLog = Join-Path $proofDir 'collector.log'

Info 'starting collector on 127.0.0.1:8080 (loopback only - the standalone control plane is fail-closed by design)'
Info 'the collector INHERITS a copy of the plaintext token at launch (that is how it authenticates);'
Info 'it is terminated at the end of this bounded run, which destroys that copy.'
$svc = Start-Process -FilePath $VenvPy `
  -ArgumentList '-m','uvicorn','main:app','--host','127.0.0.1','--port','8080' `
  -WorkingDirectory $Collector -PassThru -NoNewWindow `
  -RedirectStandardOutput $svcLog -RedirectStandardError "$proofDir\collector.err.log"
# Registered immediately: from here on EVERY exit path terminates it.
$script:G1Svc = $svc
Start-Sleep -Seconds 15

try { $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 30 }
catch { Pop-Location; Fail "the collector did not come up; see $svcLog" }
$health | ConvertTo-Json -Depth 10 | Set-Content "$proofDir\health-start.json" -Encoding UTF8
Info ("rehydration: constructed=$($health.rehydration.constructed) started=$($health.rehydration.started) failures=$($health.rehydration.failures.Count)")
if ($health.rehydration.started -lt 1) {
  $health.rehydration | ConvertTo-Json -Depth 10 | Write-Host
  Pop-Location; Fail 'the Windows connector did not start. Acquisition is refused rather than reported as healthy.'
}
Ok "connector started (pid $($svc.Id)); acquiring"

$deadline = (Get-Date).AddMinutes($ObserveMinutes)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 60
  try {
    $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 30
    $c = $h.outbox.counts
    Write-Host ("  [{0:HH:mm:ss}] outbox received={1} queued={2} delivering={3} delivered={4} retrying={5} dead={6}" -f `
      (Get-Date), $c.received, $c.queued, $c.delivering, $c.delivered, $c.retrying, $c.dead_letter)
  } catch { Write-Host "  [$(Get-Date -Format HH:mm:ss)] health unavailable: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ---- proof capture + independent verification (no interpretation) ---
Stage 'A' 'PROOF CAPTURE + INDEPENDENT WINDOWS RE-READ'
Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 30 |
  ConvertTo-Json -Depth 10 | Set-Content "$proofDir\health-end.json" -Encoding UTF8

# The bounded acquisition is over and the last health snapshot is captured, so
# the collector has no remaining job in THIS gate. It is stopped now, which
# destroys the plaintext token copy it inherited at launch. The local SQLite
# state is then read with no writer attached, so the dump is a quiescent read.
# Restart/resume, reboot/resume and mid-delivery interruption are a SEPARATE
# controlled gate and are deliberately not attempted here.
Stop-G1Collector 'bounded acquisition complete - proof captured'

$dump = @'
import json, os, re, sqlite3, subprocess, sys

db = os.path.join(os.environ["XDR_STATE_DIR"], "outbox.db")
c = sqlite3.connect(db); c.row_factory = sqlite3.Row
out = {"db": db}

out["channel_state"] = [dict(r) for r in c.execute(
    "SELECT tenant_id, collector_id, channel, origin_computer, profile_id,"
    " profile_version, bookmark_at, last_record_id, last_activity_at,"
    " last_read_at, reads, events_read, log_cleared_count, last_error,"
    " length(bookmark_xml) AS bookmark_bytes,"
    " (bookmark_xml IS NOT NULL) AS has_bookmark,"
    " (delivered_through IS NOT NULL) AS has_delivered_through,"
    " (delivered_through = bookmark_xml) AS delivered_through_matches_bookmark"
    " FROM windows_channel_state")]

out["outbox_by_status"] = {r["status"]: r["n"] for r in c.execute(
    "SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status")}
out["outbox_total"] = c.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]
out["outbox_distinct_source_event_ids"] = c.execute(
    "SELECT COUNT(DISTINCT source_event_id) FROM envelopes").fetchone()[0]
out["duplicate_accounting"] = {
    "rows": out["outbox_total"],
    "distinct_identities": out["outbox_distinct_source_event_ids"],
    "note": ("a unique index on (tenant_id, connector_id, source_event_id)"
             " makes a second row for one identity impossible; equality of"
             " these two numbers is the local no-duplicate statement"),
}

# One fully traced event per channel: identity, clocks, raw XML, delivery.
traced = []
for ch in sorted({r["channel"] for r in out["channel_state"]}):
    row = c.execute(
        "SELECT id, status, attempts, source_event_id, declared_source,"
        " source_timestamp, collection_timestamp, event_type, parser_version,"
        " raw_json, canonical_json, created_at, updated_at, last_error"
        " FROM envelopes WHERE canonical_json LIKE ? ORDER BY created_at LIMIT 1",
        ("%" + ch + "%",)).fetchone()
    if not row:
        traced.append({"channel": ch, "acquired": False,
                       "note": "no event acquired for this channel in the bounded window"})
        continue
    raw = json.loads(row["raw_json"] or "{}")
    can = json.loads(row["canonical_json"] or "{}")
    xml = raw.get("xml") or ""
    rec_id = can.get("event_record_id")
    entry = {
        "channel": ch, "acquired": True,
        "outbox_id": row["id"], "outbox_status": row["status"],
        "attempts": row["attempts"],
        "identity": {
            "source_event_id": row["source_event_id"],
            "event_id": can.get("event_id"),
            "event_record_id": rec_id,
            "provider": can.get("provider"),
            "origin_computer": can.get("origin_computer"),
            "collector_host": can.get("collector_host"),
            "user_sid": can.get("user_sid"),
        },
        "clocks": {
            "activity_occurred_at": can.get("activity_occurred_at"),
            "activity_time_source": can.get("activity_time_source"),
            "sensor_observed_at": can.get("sensor_observed_at"),
            "envelope.source_timestamp": row["source_timestamp"],
            "envelope.collection_timestamp": row["collection_timestamp"],
            "activity_differs_from_sensor": (
                can.get("activity_occurred_at") != can.get("sensor_observed_at")),
            "nivx_received_at": "SERVER-SIDE ONLY -- not visible from the endpoint",
        },
        "binding": {
            "declared_source": row["declared_source"],
            "tenant_id": os.environ.get("NIVX_TENANT_ID"),
            "collector_id": os.environ.get("NIVX_COLLECTOR_ID"),
            "parser_version": row["parser_version"],
            "profile_id": can.get("profile_id"),
            "profile_version": can.get("profile_version"),
        },
        "raw_xml": {"bytes": len(xml), "head": xml[:600]},
    }
    # INDEPENDENT re-read of the SAME record straight from Windows.
    if rec_id is not None:
        q = "*[System[EventRecordID=%s]]" % rec_id
        try:
            p = subprocess.run(["wevtutil", "qe", ch, "/q:" + q, "/f:xml",
                                "/c:1", "/e:root"],
                               capture_output=True, text=True, timeout=120)
            ref = p.stdout or ""
            norm = lambda s: re.sub(r"\s+", "", s)
            entry["independent_reread"] = {
                "tool": "wevtutil qe (separate Windows API consumer)",
                "returned_bytes": len(ref),
                "contains_record_id": ("<EventRecordID>%s</EventRecordID>" % rec_id) in ref,
                "stored_xml_found_in_reread": norm(xml) in norm(ref) if xml else False,
                "stderr": (p.stderr or "")[:300],
            }
        except Exception as exc:
            entry["independent_reread"] = {"error": "%s: %s" % (type(exc).__name__, exc)}
    traced.append(entry)
out["traced_events"] = traced

out["chain_local_segments"] = {
    "windows_event": "proved by independent_reread per traced event",
    "native_acquisition": "proved by channel_state.reads/events_read + bookmark bytes",
    "durable_local_record": "proved by outbox rows holding the raw XML",
    "bookmark_advance": ("proved by has_bookmark + "
                         "delivered_through_matches_bookmark"),
    "authenticated_transport": "proved by outbox status delivered (2xx acknowledged)",
    "server_receipt_and_canonical_evidence": (
        "NOT PROVED HERE -- the endpoint credential holds collectors.enroll "
        "only and has no read authority. canonical_evidence_id, parser/"
        "normalizer status and ingest provenance are verified server-side."),
}
print(json.dumps(out, indent=2, default=str))
'@
$dumpPath = Join-Path $env:TEMP 'nivx_dump.py'
$dump | Out-File -FilePath $dumpPath -Encoding ASCII
& $VenvPy $dumpPath | Set-Content "$proofDir\acquisition-state.json" -Encoding UTF8
Copy-Item $cfgPath "$proofDir\connectors.seeded.json" -Force
# NON-SECRET credential reference. Enough to revoke the exact key later,
# useless to anyone who finds the file.
@{ key_id = $script:G1KeyId; prefix = $script:G1KeyPrefix
   expires_at = $script:G1KeyExpires
   scopes = @('collectors.enroll'); tenant_id = $TenantId
   plaintext_handling = 'NEVER PERSISTED - process environment only; collector process copy destroyed by terminating the collector, PowerShell copy cleared at exit'
   revoke_after = 'server-side receipt + canonical evidence verification'
 } | ConvertTo-Json -Depth 5 |
   Set-Content "$proofDir\g1-credential-ref.json" -Encoding UTF8
$manifestRows | ConvertTo-Json -Depth 4 | Set-Content "$proofDir\manifest-verification.json" -Encoding UTF8
$capOut | Set-Content "$proofDir\capability.json" -Encoding UTF8
@{ reviewed_head = $head; branch = $Branch
   manifest = 'G1_STEP2_REVIEWED_CODE_MANIFEST.md'; manifest_files = $expected.Count
   manifest_result = "$($expected.Count)/$($expected.Count) MATCH"
   interpreter = $info; venv_interpreter = $venvInfo; pywin32 = $pw
   stage_9_10 = 'CLOSED - real-Windows PASS - not re-run in this block'
   state_dir = $StateDir; tenant_id = $TenantId; collector_id = $CollectorId
   connector_id = $ConnectorId; channels = $Channels
   scope_bound = 'G1_VALIDATION_SCOPE_BOUND'; scope_bound_minutes = $ScopeMinutes
   observed_minutes = $ObserveMinutes
   hostname = $env:COMPUTERNAME
   generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
   credential = 'process environment only - never printed, persisted to disk/config/command line, or committed'
   credential_key_id = $script:G1KeyId; credential_prefix = $script:G1KeyPrefix
   credential_inheritance = 'the collector child process inherited a plaintext copy at launch; that copy was destroyed by terminating the collector after proof capture'
   collector_state_at_exit = 'TERMINATED - restart/resume is a separate controlled gate'
 } | ConvertTo-Json -Depth 8 | Set-Content "$proofDir\run-context.json" -Encoding UTF8

Write-Host ""
Write-Host "Collector is STOPPED. The plaintext copy it inherited at launch died" -ForegroundColor Yellow
Write-Host "with the process. Restart/resume, reboot/resume and mid-delivery" -ForegroundColor Yellow
Write-Host "interruption are a SEPARATE controlled gate and were NOT attempted." -ForegroundColor Yellow
Write-Host "Artifacts in $proofDir :" -ForegroundColor Cyan
Get-ChildItem $proofDir | ForEach-Object { Write-Host ("  " + $_.Name + "  " + $_.Length + " bytes") }
Write-Host ""
Write-Host "Send back: run-context.json - health-start.json - health-end.json -" -ForegroundColor Cyan
Write-Host "acquisition-state.json - manifest-verification.json -" -ForegroundColor Cyan
Write-Host "capability.json - g1-credential-ref.json - gate-log.txt" -ForegroundColor Cyan
Write-Host "(none contains a credential - only the key id and prefix)" -ForegroundColor Cyan
Write-Host ""
if ($script:G1KeyId) {
  Write-Host ("Temporary key " + $script:G1KeyId + " (" + $script:G1KeyPrefix + ") is STILL VALID and is") -ForegroundColor Yellow
  Write-Host "NOT auto-revoked: if server verification shows a retryable delivery" -ForegroundColor Yellow
  Write-Host "problem, destroying the credential first would cost us the diagnosis." -ForegroundColor Yellow
  Write-Host "It is revoked immediately AFTER server-side evidence verification." -ForegroundColor Yellow
  Write-Host ""
}
Write-Host "A 2xx from ingest is DELIVERY, not end-to-end evidence processing." -ForegroundColor Yellow
Write-Host "Canonical evidence identity, parser/normalizer status and ingest" -ForegroundColor Yellow
Write-Host "provenance are verified server-side against these artifacts." -ForegroundColor Yellow
Write-Host "B4 is NOT part of this run and remains OPEN/MANDATORY/UNWAIVED." -ForegroundColor Yellow
Pop-Location

}
catch {
  $parts = ($_.Exception.Message -split '\|', 3)
  Write-Host ""
  if ($parts[0] -eq 'G1_GATE_FAILED') {
    Write-Host "================ G1 GATE FAILED ================" -ForegroundColor Red
    Write-Host ("STAGE : " + $parts[1]) -ForegroundColor Red
    Write-Host ("REASON: " + $parts[2]) -ForegroundColor Red
  } else {
    Write-Host "============ G1 UNEXPECTED FAILURE ============" -ForegroundColor Red
    Write-Host ("STAGE : " + $script:G1Stage) -ForegroundColor Red
    Write-Host ("ERROR : " + $_.Exception.Message) -ForegroundColor Red
    if ($_.InvocationInfo) {
      Write-Host ("WHERE : line " + $_.InvocationInfo.ScriptLineNumber + " - " +
                  $_.InvocationInfo.Line.Trim()) -ForegroundColor DarkGray
    }
    Note ("UNEXPECTED [" + $script:G1Stage + "] " + $_.Exception.Message)
  }
  # If the collector was already launched, it holds an inherited plaintext copy.
  # A failed run must never leave that process - or that credential - alive.
  Stop-G1Collector 'failure path - collector must not outlive a failed run'
  Write-Host "No gate was downgraded or bypassed." -ForegroundColor Red
  if ($script:G1GateLog) { Write-Host ("Gate trail: " + $script:G1GateLog) -ForegroundColor DarkGray }
  Write-Host "This console stays open. Re-run Invoke-G1Step2 after fixing the cause." -ForegroundColor Yellow
  Write-Host "===============================================" -ForegroundColor Red
  return
}
finally {
  # Last-resort guarantee: the collector is never left running by this block,
  # on any path. Stop-G1Collector is idempotent.
  Stop-G1Collector 'final guarantee - no collector outlives this block'
  # THIS PowerShell's copy of the plaintext is cleared here, pass or fail.
  # Clearing it does NOT reach any other process; that is why the collector is
  # terminated above rather than merely left running.
  if ($env:NIVX_INGEST_TOKEN) {
    $env:NIVX_INGEST_TOKEN = $null
    Remove-Item Env:\NIVX_INGEST_TOKEN -ErrorAction SilentlyContinue
    Write-Host "  ingest token cleared from THIS PowerShell process's environment" -ForegroundColor DarkGray
    Write-Host "  (the collector's inherited copy was destroyed by terminating that process)" -ForegroundColor DarkGray
  }
  Pop-Location -ErrorAction SilentlyContinue
}
}

# Run it. Nothing above executed on its own.
Invoke-G1Step2
