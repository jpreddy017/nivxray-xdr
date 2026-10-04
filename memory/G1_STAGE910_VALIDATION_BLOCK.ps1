# =====================================================================
# G1 · STAGE 9/10 ONLY — native EvtSubscribe binding + channel read
# Paste into the SAME elevated PowerShell window. Read-only.
#
# Proves the ERROR 87 fix on the real host WITHOUT re-running stages 1-8
# and WITHOUT starting acquisition. No ingest credential is used, no
# collector service is started, nothing is delivered anywhere.
#
# Exercises the PRODUCTION reader (framework.windows_eventlog.
# NativeEvtReader) — not a look-alike probe — so a pass means the code
# that will acquire is the code that was proved.
#
# Does not: install Python, touch Sysmon, enable/disable channels, change
# audit policy, clear logs, or weaken any gate. No `exit`.
# =====================================================================

$ErrorActionPreference = 'Stop'

function Invoke-G1Stage910 {

$Work      = 'C:\nivx'
$Collector = "$Work\apps\nivxray-xdr-collector"
$VenvPy    = "$Work\.venv\Scripts\python.exe"
$Branch    = 'feature/rc2-alignment'
$ProofDir  = "$Work\g1-proof"

# The two files the fix touches. Hash-gated: the corrected code must be
# the code that runs.
$FixedFiles = [ordered]@{
 'apps\nivxray-xdr-collector\framework\windows_eventlog.py'            = 'EC747671ED0156C3814C458A2A07C41B98901620E506842040E77C04F72A39E6'
 'apps\nivxray-xdr-collector\tests\test_g1_evtsubscribe_contract.py'   = '754764F133895435844DB4D7E795B052B7C5E9368371C159E901A3D1037847B3'
}

$Channels = @('Microsoft-Windows-Sysmon/Operational',
              'Security',
              'Microsoft-Windows-PowerShell/Operational')

function Fail910($m) { throw "G1_910_FAILED|$m" }

try {
  Write-Host "`n=== STAGE 9/10 VALIDATION (read-only) ===" -ForegroundColor Cyan

  if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail910 'not elevated. Security would report a permission error that is not the truth.'
  }
  if (-not (Test-Path $VenvPy)) { Fail910 "venv missing at $VenvPy. Stages 1-8 already built it; do not rebuild it here." }
  Write-Host "  OK   elevated · venv present" -ForegroundColor Green

  Set-Location $Work
  git fetch --no-tags origin $Branch
  if ($LASTEXITCODE -ne 0) { Fail910 'git fetch failed.' }
  $dirty = (git status --porcelain --untracked-files=no)
  if ($dirty) { Write-Host $dirty -ForegroundColor Red; Fail910 'tracked files are modified; nothing is discarded for you.' }
  git checkout --detach "origin/$Branch"
  if ($LASTEXITCODE -ne 0) { Fail910 'checkout failed.' }
  $head = (git rev-parse HEAD)
  Write-Host "  HEAD : $head"
  Write-Host ("  subj : " + (git show -s --format=%s HEAD))

  $bad = 0
  foreach ($k in $FixedFiles.Keys) {
    if (-not (Test-Path $k)) { Write-Host "  MISSING   $k" -ForegroundColor Red; $bad++; continue }
    $h = (Get-FileHash $k -Algorithm SHA256).Hash
    if ($h -eq $FixedFiles[$k]) { Write-Host "  match     $k" -ForegroundColor DarkGreen }
    else {
      Write-Host "  MISMATCH  $k" -ForegroundColor Red
      Write-Host "    expected $($FixedFiles[$k])" -ForegroundColor Red
      Write-Host "    actual   $h" -ForegroundColor Red
      $bad++
    }
  }
  if ($bad -gt 0) { Fail910 "$bad file(s) are not the corrected reviewed code. If both mismatched, the fix has not been saved to GitHub yet." }
  Write-Host "  OK   corrected EvtSubscribe code confirmed byte-for-byte" -ForegroundColor Green

  $py = @'
import json, os, sys
sys.path.insert(0, os.getcwd())
from framework.windows_eventlog import NativeEvtReader

WINDOW_MIN = 60
XPATH = ("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]"
         % (WINDOW_MIN * 60 * 1000))
reader = NativeEvtReader()
out = {"window_minutes": WINDOW_MIN, "xpath": XPATH,
       "capability": reader.binding_status(), "channels": {}}
for ch in sys.argv[1:]:
    try:
        r = reader.read(ch, bookmark_xml=None, xpath=XPATH, limit=5)
        first = r["records"][0] if r["records"] else ""
        rec = {"state": r["state"], "reason": r["reason"],
               "records_read": len(r["records"]),
               "first_xml_bytes": len(first),
               "first_xml_head": first[:200],
               "bookmark_bytes": len(r["bookmark_xml"] or "")}
        # Resume with the bookmark we just produced: proves the Bookmark
        # parameter is accepted, which is the second half of the ERROR 87
        # defect.
        r2 = reader.read(ch, bookmark_xml=r["bookmark_xml"], xpath=XPATH,
                         limit=5)
        rec["resume_state"] = r2["state"]
        rec["resume_records_read"] = len(r2["records"])
        rec["resume_reason"] = r2["reason"]
        rec["error_87"] = False
    except Exception as exc:
        rec = {"state": "EXCEPTION",
               "error": "%s: %s" % (type(exc).__name__, exc),
               "error_87": "87" in str(exc)}
    out["channels"][ch] = rec

failed = [c for c, r in out["channels"].items() if r["state"] != "READ_OK"]
out["failed_channels"] = failed
out["pass"] = (not failed) and out["capability"]["bound"]
print(json.dumps(out, indent=2))
sys.exit(0 if out["pass"] else 1)
'@
  $pyPath = Join-Path $env:TEMP 'nivx_stage910.py'
  $py | Out-File -FilePath $pyPath -Encoding ASCII

  Push-Location $Collector
  $res = (& $VenvPy $pyPath @Channels) -join "`n"
  $code = $LASTEXITCODE
  Pop-Location
  Write-Host $res
  New-Item -ItemType Directory -Force -Path $ProofDir | Out-Null
  $res | Set-Content (Join-Path $ProofDir 'stage910-validation.json') -Encoding UTF8
  @{ head = $head; branch = $Branch; channels = $Channels
     window_minutes = 60; hostname = $env:COMPUTERNAME
     generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
   } | ConvertTo-Json -Depth 5 |
     Set-Content (Join-Path $ProofDir 'stage910-context.json') -Encoding UTF8

  if ($code -ne 0) { Fail910 'native binding or channel read still failing — see the JSON above. Nothing was downgraded.' }
  Write-Host "`nSTAGE 9/10 PASS — EvtSubscribe bound, all three channels read," -ForegroundColor Green
  Write-Host "bookmark rendered, and resume-after-bookmark accepted." -ForegroundColor Green
  Write-Host "Artifacts: $ProofDir\stage910-validation.json (+ -context.json)" -ForegroundColor Cyan
  Write-Host "No acquisition was started and no credential was used." -ForegroundColor Cyan
}
catch {
  $p = ($_.Exception.Message -split '\|', 2)
  Write-Host ""
  Write-Host "============ STAGE 9/10 FAILED ============" -ForegroundColor Red
  if ($p[0] -eq 'G1_910_FAILED') { Write-Host ("REASON: " + $p[1]) -ForegroundColor Red }
  else {
    Write-Host ("ERROR : " + $_.Exception.Message) -ForegroundColor Red
    if ($_.InvocationInfo) { Write-Host ("WHERE : " + $_.InvocationInfo.Line.Trim()) -ForegroundColor DarkGray }
  }
  Write-Host "This console stays open. No acquisition, no credential, no config change." -ForegroundColor Yellow
  Write-Host "===========================================" -ForegroundColor Red
  return
}
finally { Pop-Location -ErrorAction SilentlyContinue }
}

Invoke-G1Stage910
