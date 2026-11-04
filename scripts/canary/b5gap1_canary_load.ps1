# =====================================================================
# B5-GAP-1 CANARY · SOURCE LOAD GENERATOR — DISPOSABLE CANARY HOST ONLY
#
# Produces REAL Windows Event Log / Sysmon records on the canary so the
# acquisition path is exercised by genuine source records rather than
# synthetic payloads injected past it.
#
# REFUSES TO RUN on DESKTOP-A9HGFJJ, and refuses any host not explicitly
# designated as a canary. Nothing here writes to the sensor state, the
# journal, channels.json or the outbox.
#
#   .\b5gap1_canary_load.ps1 -Scenario NORMAL   -Seconds 900
#   .\b5gap1_canary_load.ps1 -Scenario BURST    -Seconds 120 -Rate 200
#   .\b5gap1_canary_load.ps1 -Scenario MULTI_CHANNEL -Seconds 600
#   .\b5gap1_canary_load.ps1 -Scenario SOURCE_DISCONTINUITY -Confirm
# =====================================================================
[CmdletBinding()]
param(
  [ValidateSet('NORMAL','BURST','MULTI_CHANNEL','JOURNAL_PRESSURE',
               'SOURCE_DISCONTINUITY')]
  [string]$Scenario = 'NORMAL',
  [int]$Seconds = 900,
  [int]$Rate = 20                        # source records per second target
)

$ErrorActionPreference = 'Stop'

# ── SAFETY: this must never touch the production validation host ──────
# The guard is NOT bypassable with a switch. A host qualifies only if it
# is (a) not on the forbidden list, (b) named NVX-CANARY* or on the
# owner-authorised list below, and (c) carrying an owner-written
# designation file. All three, every run.
$forbidden  = @('DESKTOP-A9HGFJJ')
$authorized = @('KUSHU')     # owner-authorised disposable canary hosts
$designation = 'C:\NivXForgeCanary\CANARY_DESIGNATION.json'

if ($forbidden -contains $env:COMPUTERNAME) {
  throw "REFUSED: $env:COMPUTERNAME is the production validation host. " +
        "This generator runs on a DISPOSABLE canary only."
}
if (-not ($env:COMPUTERNAME -like 'NVX-CANARY*' -or
          $authorized -contains $env:COMPUTERNAME)) {
  throw ("REFUSED: $env:COMPUTERNAME is neither named NVX-CANARY* nor on " +
         "the owner-authorised canary list. Add it to `$authorized only " +
         "with owner approval.")
}
if (-not (Test-Path $designation)) {
  throw ("REFUSED: no owner designation at $designation. A disposable " +
         "canary must be declared before it can be loaded.")
}
Write-Host "canary host: $env:COMPUTERNAME  scenario: $Scenario"
Write-Host ("designation: " + ((Get-Content $designation -Raw) -replace '\s+', ' '))

function New-BenignProcessActivity {
  # Sysmon EventID 1/5 from a harmless, short-lived process. No network
  # egress, no file writes outside TEMP, nothing persistent.
  param([int]$Count = 1)
  for ($i = 0; $i -lt $Count; $i++) {
    Start-Process -FilePath $env:ComSpec `
      -ArgumentList '/c', 'ver' -WindowStyle Hidden -Wait
  }
}

function New-SecurityChannelActivity {
  param([int]$Count = 1)
  # Logon/audit records without creating accounts: query a privileged
  # local object, which the audit policy records.
  for ($i = 0; $i -lt $Count; $i++) {
    Get-Acl $env:SystemRoot | Out-Null
  }
}

function New-SystemChannelActivity {
  param([int]$Count = 1)
  for ($i = 0; $i -lt $Count; $i++) {
    if (-not (Get-EventLog -LogName Application -Source 'NivXForgeCanary' `
                -Newest 1 -ErrorAction SilentlyContinue)) {
      New-EventLog -LogName Application -Source 'NivXForgeCanary' `
        -ErrorAction SilentlyContinue
    }
    Write-EventLog -LogName Application -Source 'NivXForgeCanary' `
      -EntryType Information -EventId 9000 `
      -Message "NIVXFORGE CANARY SYNTHETIC SOURCE RECORD $(Get-Date -Format o)"
  }
}

$deadline = (Get-Date).AddSeconds($Seconds)
$emitted = 0

switch ($Scenario) {
  'SOURCE_DISCONTINUITY' {
    # A DELIBERATE source RecordID discontinuity: clear a channel the
    # sensor is reading, on the canary only. The sensor must DECLARE a gap
    # with cause NOT_PROVEN — never absorb it silently, never call it
    # benign.
    Write-Host 'clearing Microsoft-Windows-Sysmon/Operational on the CANARY'
    New-BenignProcessActivity -Count 50
    Start-Sleep -Seconds 30
    & wevtutil cl 'Microsoft-Windows-Sysmon/Operational'
    Start-Sleep -Seconds 5
    New-BenignProcessActivity -Count 50
    Write-Host 'discontinuity injected; expect exactly one declared gap'
    exit 0
  }
  'JOURNAL_PRESSURE' {
    Write-Host ('drive the journal toward its configured ceiling. Set a ' +
                'SMALL ceiling on the canary first, e.g. ' +
                'NIVXFORGE_JOURNAL_MAX_BYTES, and keep delivery impaired.')
  }
}

while ((Get-Date) -lt $deadline) {
  $batch = switch ($Scenario) {
    'BURST'         { [math]::Max(1, $Rate) }
    'NORMAL'        { [math]::Max(1, [int]($Rate / 4)) }
    'MULTI_CHANNEL' { [math]::Max(1, [int]($Rate / 4)) }
    default         { [math]::Max(1, [int]($Rate / 4)) }
  }
  New-BenignProcessActivity -Count $batch
  if ($Scenario -eq 'MULTI_CHANNEL') {
    New-SecurityChannelActivity -Count $batch
    New-SystemChannelActivity   -Count $batch
  }
  $emitted += $batch
  Start-Sleep -Milliseconds 250
}

Write-Host "source activity generated: ~$emitted process records"
Write-Host 'the collector measures what the sensor did with them'
