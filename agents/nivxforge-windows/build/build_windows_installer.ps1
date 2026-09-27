# =====================================================================
# NivXForge EDR · Windows installer build (Track B V1)
#
# MUST run on Windows. PyInstaller does not cross-compile: a Windows PE
# that embeds a Python runtime can only be produced on Windows, which is
# why `.github/workflows/windows-sensor-installer.yml` uses
# `windows-latest`. This script is the single build definition used both
# in CI and on a developer machine, so the artifact is reproducible.
#
# Output (in .\dist):
#   NivXForgeEDRSetup.exe   one-file installer + Windows Service host
#   SHA256SUMS.txt          hash manifest
#   build-info.json         version / commit / runner provenance
#
# The artifact carries NO credential. This script therefore refuses to
# finish if anything credential-shaped is found inside the binary.
# =====================================================================
[CmdletBinding()]
param(
  [string]$PythonExe = 'python',
  [string]$OutDir    = (Join-Path $PSScriptRoot '..\dist'),
  [string]$Commit    = $env:GITHUB_SHA,
  [switch]$SkipInstallDeps
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$SensorDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Entry     = Join-Path $SensorDir 'nivxforge_setup.py'
$WorkDir   = Join-Path $PSScriptRoot 'work'

if ($env:OS -ne 'Windows_NT') {
  throw 'This build MUST run on Windows. A Linux host cannot produce a Windows PE.'
}
foreach ($required in @('nivxforge_setup.py', 'nivxforge_sensor.py',
                        'nivxforge_exclusions.py')) {
  if (-not (Test-Path (Join-Path $SensorDir $required))) {
    throw "missing source file: $required"
  }
}

if (-not $SkipInstallDeps) {
  Write-Host '=== 1 . BUILD DEPENDENCIES ===' -ForegroundColor Cyan
  & $PythonExe -m pip install --disable-pip-version-check --quiet `
      'pyinstaller==6.11.1' 'pywin32==308'
  if ($LASTEXITCODE -ne 0) { throw 'dependency installation failed' }
}

Write-Host '=== 2 . FREEZE ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $OutDir  | Out-Null
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# `--paths $SensorDir` lets the frozen entry import the EXISTING sensor and
# the Gate 7 exclusion evaluator unchanged — one implementation, not two.
& $PythonExe -m PyInstaller `
  --onefile `
  --name NivXForgeEDRSetup `
  --distpath $OutDir `
  --workpath $WorkDir `
  --specpath $WorkDir `
  --paths $SensorDir `
  --hidden-import nivxforge_sensor `
  --hidden-import nivxforge_exclusions `
  --hidden-import win32timezone `
  --hidden-import servicemanager `
  --hidden-import win32serviceutil `
  --hidden-import win32service `
  --hidden-import win32event `
  --noconfirm `
  --clean `
  $Entry
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }

$Exe = Join-Path $OutDir 'NivXForgeEDRSetup.exe'
if (-not (Test-Path $Exe)) { throw 'NivXForgeEDRSetup.exe was not produced' }

Write-Host '=== 3 . PE SANITY ===' -ForegroundColor Cyan
$bytes = [System.IO.File]::ReadAllBytes($Exe)
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
  throw 'artifact is not a Windows PE (missing MZ header)'
}
Write-Host ('  PE header OK · size ' + [math]::Round($bytes.Length/1MB,2) + ' MB')

Write-Host '=== 4 . CREDENTIAL SCAN ===' -ForegroundColor Cyan
# Same secret shapes the backend refuses to publish (edr_onboarding).
$shapes = @('nvx_[0-9a-f]{48}', 'nvxenr_[A-Za-z0-9_\-]{16,}',
            'nvxses_[A-Za-z0-9_\-]{16,}', 'nvxcrd_[A-Za-z0-9_\-]{16,}',
            'ten_[0-9a-f]{26}', 'EDR_AUTH_PEPPER',
            'preview\.emergentagent\.com')
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
foreach ($shape in $shapes) {
  if ([regex]::IsMatch($text, $shape)) {
    Remove-Item $Exe -Force
    throw "REFUSED: artifact contains something matching $shape"
  }
}
Write-Host '  no credential shape, no preview origin found'

Write-Host '=== 5 . MANIFEST ===' -ForegroundColor Cyan
$hash = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower()
"$hash  NivXForgeEDRSetup.exe" |
  Set-Content (Join-Path $OutDir 'SHA256SUMS.txt') -Encoding ascii

$setupVersion = (Select-String -Path $Entry -Pattern '^SETUP_VERSION\s*=' |
                 Select-Object -First 1).Line -replace '.*=\s*"([^"]+)".*', '$1'
$sensorVersion = (Select-String -Path (Join-Path $SensorDir 'nivxforge_sensor.py') `
                   -Pattern '^SENSOR_VERSION\s*=' |
                 Select-Object -First 1).Line -replace '.*=\s*"([^"]+)".*', '$1'

[ordered]@{
  artifact       = 'NivXForgeEDRSetup.exe'
  sha256         = $hash
  size_bytes     = $bytes.Length
  setup_version  = $setupVersion
  sensor_version = $sensorVersion
  architecture   = $env:PROCESSOR_ARCHITECTURE
  signing_status = 'UNSIGNED_INTERNAL_VALIDATION_BUILD'
  python_required_on_endpoint = $false
  startup        = 'WINDOWS_SERVICE'
  service_name   = 'NivXForgeSensor'
  default_backend = 'https://nivxray.nivxforge.com'
  commit         = $(if ($Commit) { $Commit } else { 'local' })
  built_at       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  built_on       = 'windows'
} | ConvertTo-Json -Depth 4 |
  Set-Content (Join-Path $OutDir 'build-info.json') -Encoding ascii

Write-Host ''
Write-Host 'NIVXFORGE WINDOWS INSTALLER BUILD: PASS' -ForegroundColor Green
Write-Host ('  ' + $Exe)
Write-Host ('  sha256 ' + $hash)
Write-Host '  signing: UNSIGNED_INTERNAL_VALIDATION_BUILD (not customer-production-ready)'
