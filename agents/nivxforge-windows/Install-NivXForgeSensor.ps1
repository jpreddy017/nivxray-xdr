# =====================================================================
# NivXForge EDR · REUSABLE Windows sensor installer (V1 onboarding)
#
# ONE build installs on every Windows computer. It contains NO tenant
# credential, NO API key and NO device identity: the enrollment token is
# supplied at INSTALL TIME and is exchanged once for this computer's OWN
# durable credential, which never leaves the machine.
#
#   .\Install-NivXForgeSensor.ps1 `
#        -BackendUrl 'https://<edr-backend>' `
#        -TenantId   'ten_...' `
#        -EnrollmentToken 'nvxenr_...'
#
# WHAT IT DOES
#   1. refuses to run without Administrator rights
#   2. stages the sensor into C:\Program Files\NivXForge\sensor
#   3. creates C:\ProgramData\NivXForge\sensor with an ACL limited to
#      SYSTEM + Administrators (the per-device credential lives there)
#   4. enrols ONCE (platform mints endpoint_id from durable machine
#      attributes) and stores the returned device credential
#   5. registers and starts the sensor as a SYSTEM scheduled task
#   6. prints the endpoint identity; never prints a secret
#
# RE-RUN BEHAVIOUR (deterministic, documented)
#   Already enrolled + no -ReEnroll  -> keeps the existing identity and
#     credential, refreshes the program files and restarts the task. The
#     computer keeps ONE identity across upgrades and reinstalls.
#   -ReEnroll                        -> requires a NEW enrollment token and
#     replaces the local credential. The platform mints the SAME endpoint_id
#     from the same machine attributes, so re-enrolment refreshes the
#     credential of the SAME computer; it never creates a second Computers
#     entry for one machine.
#   -Uninstall                       -> stops and removes the task and the
#     program files. The state directory (identity + journal) is kept unless
#     -Purge is given, so evidence is not destroyed silently.
# =====================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)][string]$BackendUrl,
  [Parameter(Mandatory = $false)][string]$TenantId,
  [Parameter(Mandatory = $false)][string]$EnrollmentToken,
  [int]$IntervalSeconds = 30,
  [switch]$ReEnroll,
  [switch]$Uninstall,
  [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$InstallDir = Join-Path $env:ProgramFiles 'NivXForge\sensor'
$StateDir   = Join-Path $env:ProgramData  'NivXForge\sensor'
$TaskName   = 'NivXForgeSensor'
$Sensor     = Join-Path $InstallDir 'nivxforge_sensor.py'
$Identity   = Join-Path $StateDir   'identity.json'

function Assert-Administrator {
  $principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this installer from an ELEVATED PowerShell (Administrator).'
  }
}

function Resolve-Python {
  foreach ($candidate in @('python.exe', 'py.exe')) {
    $found = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
  }
  throw ('Python 3 was not found on this computer. Install Python 3.11+ ' +
         '(or ship the bundled runtime) and re-run this installer.')
}

function Protect-StateDirectory {
  # SYSTEM + Administrators only. The per-device credential lives here, so a
  # standard user must not be able to read it.
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  $acl = Get-Acl $StateDir
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
      $who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None',
      'Allow')))
  }
  Set-Acl -Path $StateDir -AclObject $acl
}

try {
  Assert-Administrator

  if ($Uninstall) {
    schtasks /End /TN $TaskName 2>$null | Out-Null
    schtasks /Delete /TN $TaskName /F 2>$null | Out-Null
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    if ($Purge -and (Test-Path $StateDir)) {
      Remove-Item $StateDir -Recurse -Force
      Write-Host '  state directory PURGED (identity and journal removed)'
    } else {
      Write-Host ('  state directory kept at ' + $StateDir +
                  '  (use -Purge to remove the identity and journal)')
    }
    Write-Host 'NivXForge sensor uninstalled.' -ForegroundColor Green
    return 0
  }

  if (-not $BackendUrl) { throw '-BackendUrl is required.' }
  $python = Resolve-Python

  Write-Host "`n=== 1 . STAGE ===" -ForegroundColor Cyan
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item (Join-Path $PSScriptRoot 'nivxforge_sensor.py') $InstallDir -Force
  # The canonical endpoint exclusion evaluator ships with the release and
  # is imported by the connector. Without it the connector cannot honour
  # an exclusion, so a missing copy must fail the install loudly.
  Copy-Item (Join-Path $PSScriptRoot 'nivxforge_exclusions.py') $InstallDir -Force
  Write-Host ('  sensor    : ' + $Sensor)
  Write-Host ('  python    : ' + $python)

  Write-Host "`n=== 2 . STATE DIRECTORY (restricted) ===" -ForegroundColor Cyan
  Protect-StateDirectory
  Write-Host ('  state     : ' + $StateDir + '   (SYSTEM + Administrators only)')

  Write-Host "`n=== 3 . ENROLMENT ===" -ForegroundColor Cyan
  $alreadyEnrolled = Test-Path $Identity
  if ($alreadyEnrolled -and -not $ReEnroll) {
    $existing = Get-Content $Identity -Raw | ConvertFrom-Json
    Write-Host ('  already enrolled: endpoint_id=' + $existing.endpoint_id)
    Write-Host '  keeping this computer''s existing identity and credential.'
    Write-Host '  (use -ReEnroll with a NEW token to replace the credential)'
  } else {
    if (-not $TenantId)        { throw '-TenantId is required to enrol.' }
    if (-not $EnrollmentToken) { throw '-EnrollmentToken is required to enrol.' }
    $env:NIVXFORGE_SENSOR_STATE = $StateDir
    & $python $Sensor enrol --api $BackendUrl --tenant $TenantId `
        --token $EnrollmentToken
    if ($LASTEXITCODE -ne 0) {
      throw ('enrolment failed (exit ' + $LASTEXITCODE + '). Nothing was ' +
             'installed as a service and no telemetry was sent.')
    }
  }

  Write-Host "`n=== 4 . SERVICE ===" -ForegroundColor Cyan
  $action = ('"' + $python + '" "' + $Sensor + '" run --api ' + $BackendUrl +
             ' --interval ' + $IntervalSeconds)
  schtasks /Delete /TN $TaskName /F 2>$null | Out-Null
  schtasks /Create /TN $TaskName /SC ONSTART /RU SYSTEM /RL HIGHEST /F `
           /TR $action | Out-Null
  schtasks /Run /TN $TaskName | Out-Null
  Write-Host ('  task      : ' + $TaskName + ' (SYSTEM, ONSTART, running)')

  Write-Host "`n=== 5 . IDENTITY ===" -ForegroundColor Cyan
  $env:NIVXFORGE_SENSOR_STATE = $StateDir
  & $python $Sensor status
  Write-Host "`nNivXForge sensor installed. This computer will appear under" `
             -ForegroundColor Green
  Write-Host 'Management > Computers once authenticated telemetry arrives.' `
             -ForegroundColor Green
  return 0
}
catch {
  Write-Host ("`nINSTALL FAILED: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host '  nothing was enrolled or started by this attempt.' -ForegroundColor Yellow
  return 1
}
