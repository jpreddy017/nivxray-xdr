# =====================================================================
# NIVXFORGE · B5 · EID 5 (ProcessTerminate) · PRE BASELINE
# MODE: READ-ONLY   ·   $Label = 'PRE'
#
# This is the LAST UNTOUCHED BASELINE before ProcessTerminate is enabled.
# It establishes, from the endpoint's own evidence:
#   0  window + clock + run identity
#   1  Sysmon log retention + channel configuration (validity guard)
#   2  configuration stability (a config change or log clear invalidates)
#   3  the ACTIVE Sysmon rule fingerprint (registry read only)
#   4  what Sysmon wrote in the window, per Event ID, with RecordId span
#   5  EID 1 vs EID 5 in the window + ProcessGuid pairing
#   6  EID 5 across the WHOLE retained log (proves it was never collected)
#   7  the NivXForge sensor's own delivery state (outbox / bookmarks)
#   8  capability flags (both new capabilities must read as OFF)
#   9  delivery-tail warning + PRE completion stamp
#
# IT DOES NOT: modify Sysmon configuration, run sysmon.exe, change audit
# policy, start/stop/restart/reconfigure any service, write or delete any
# registry value, clear or export any event log, install anything, alter
# sensor configuration or state, or print any token, key, credential,
# identity value or event payload.
#
# THE ONLY WRITE ANYWHERE: one transcript file in %TEMP%. If you want a
# run with ZERO writes, delete the Start-Transcript / Stop-Transcript
# lines and copy the console output instead.
#
# RUN ELEVATED (Sysmon/Security channels and the sensor state directory
# are readable by Administrators/SYSTEM only).
# =====================================================================
$ErrorActionPreference = 'Continue'
$Label = 'PRE'

# --- WINDOW -----------------------------------------------------------
# A rolling, ALREADY-ELAPSED one-hour window: it can never be in the
# future and can never straddle "now", which are the two ways a fidelity
# count gets silently understated. To use an agreed fixed window instead,
# set $WindowEndUtc / $WindowStartUtc explicitly here.
$WindowEndUtc   = (Get-Date).ToUniversalTime().AddMinutes(-5)
$WindowStartUtc = $WindowEndUtc.AddHours(-1)
# ---------------------------------------------------------------------

$StartLocal = $WindowStartUtc.ToLocalTime()
$EndLocal   = $WindowEndUtc.ToLocalTime()
$sysLog     = 'Microsoft-Windows-Sysmon/Operational'
$RunId      = [guid]::NewGuid().ToString()
$OutFile    = Join-Path $env:TEMP ("nivxforge_eid5_{0}_{1}.txt" -f $Label, (Get-Date -Format 'yyyyMMdd_HHmmss'))
Start-Transcript -Path $OutFile -Force | Out-Null

function Count-Events($logName, $id, $s, $e) {
  try {
    $q = @{ LogName = $logName }
    if ($id) { $q['ID'] = $id }
    if ($s)  { $q['StartTime'] = $s }
    if ($e)  { $q['EndTime'] = $e }
    return @(Get-WinEvent -FilterHashtable $q -ErrorAction Stop).Count
  } catch {
    if ($_.Exception.Message -match 'No events') { return 0 }
    return "UNREADABLE: $($_.Exception.Message)"
  }
}

Write-Host "=== 0 · WINDOW + CLOCK + RUN IDENTITY ==="
Write-Host ("label              : {0}" -f $Label)
Write-Host ("run_id             : {0}" -f $RunId)
Write-Host ("hostname           : {0}" -f $env:COMPUTERNAME)
Write-Host ("elevated           : {0}" -f ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Host ("window UTC         : {0} -> {1}" -f $WindowStartUtc.ToString('o'), $WindowEndUtc.ToString('o'))
Write-Host ("window LOCAL       : {0} -> {1}" -f $StartLocal.ToString('o'), $EndLocal.ToString('o'))
Write-Host ("now UTC            : {0}" -f (Get-Date).ToUniversalTime().ToString('o'))
Write-Host ("timezone / offset  : {0} / {1} min" -f (Get-TimeZone).Id, [int]([datetime]::Now - [datetime]::UtcNow).TotalMinutes)
$os = Get-CimInstance Win32_OperatingSystem
Write-Host ("os / build         : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Host ("last boot UTC      : {0}" -f $os.LastBootUpTime.ToUniversalTime().ToString('o'))

Write-Host ""
Write-Host "=== 1 · RETENTION GUARD + CHANNEL CONFIG ==="
# If the oldest retained record is NEWER than the window start, the
# window has already rolled out of the circular log and the run is
# INVALID — repeat it with a more recent window.
try {
  $oldest    = Get-WinEvent -LogName $sysLog -Oldest -MaxEvents 1 -ErrorAction Stop
  $newest    = Get-WinEvent -LogName $sysLog -MaxEvents 1 -ErrorAction Stop
  $oldestUtc = $oldest.TimeCreated.ToUniversalTime()
  Write-Host ("oldest retained UTC : {0}" -f $oldestUtc.ToString('o'))
  Write-Host ("newest retained UTC : {0}" -f $newest.TimeCreated.ToUniversalTime().ToString('o'))
  Write-Host ("retention verdict   : {0}" -f $(if ($oldestUtc -le $WindowStartUtc) { 'VALID' } else { 'INVALID_ROLLOVER — repeat with a more recent window' }))
} catch { Write-Host ("retention unreadable: {0}" -f $_.Exception.Message) }
Get-WinEvent -ListLog $sysLog -ErrorAction SilentlyContinue |
  Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, FileSize, RecordCount | Format-List

Write-Host ""
Write-Host "=== 2 · CONFIG STABILITY (a change or a log clear invalidates the run) ==="
Write-Host ("Sysmon EID 16 (config change) in window  : {0}" -f (Count-Events $sysLog 16 $StartLocal $EndLocal))
Write-Host ("Sysmon EID 16 (config change) last 7 days: {0}" -f (Count-Events $sysLog 16 (Get-Date).AddDays(-7) $null))
Write-Host ("Sysmon EID 255 (sysmon error) in window   : {0}" -f (Count-Events $sysLog 255 $StartLocal $EndLocal))
Write-Host ("Security 1102 (log cleared) last 7 days   : {0}" -f (Count-Events 'Security' 1102 (Get-Date).AddDays(-7) $null))
Get-Service -Name 'Sysmon64','Sysmon','SysmonDrv' -ErrorAction SilentlyContinue |
  Select-Object Name, Status, StartType | Format-Table -AutoSize
Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'nivx' } |
  Select-Object Name, Status, StartType | Format-Table -AutoSize

Write-Host ""
Write-Host "=== 3 · ACTIVE SYSMON RULE FINGERPRINT (registry READ only) ==="
# The rule blob itself is NOT printed: it is the operator's own policy and
# can name paths. What is printed is a SHA-256 FINGERPRINT plus size, so
# PRE and POST can be compared byte-for-byte without disclosing content.
# (Deliberately NOT doing this by running `sysmon.exe -c`: that invokes
#  the Sysmon binary, and this baseline runs no third-party executable.)
try {
  $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' -ErrorAction Stop
  $rules = $p.Rules
  if ($rules -is [byte[]]) {
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($rules)).Replace('-','').ToLower()
    Write-Host ("rules blob bytes    : {0}" -f $rules.Length)
    Write-Host ("rules blob sha256   : {0}" -f $sha)
  } else {
    Write-Host  "rules blob          : not present as a binary value"
  }
  Write-Host ("parameter names     : {0}" -f (($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name) -join ', '))
  Write-Host ("HashingAlgorithm    : {0}" -f $p.HashingAlgorithm)
  Write-Host ("CheckRevocation     : {0}" -f $p.CheckRevocation)
  Write-Host ("Options             : {0}" -f $p.Options)
} catch { Write-Host ("SysmonDrv parameters unreadable: {0}" -f $_.Exception.Message) }
try {
  $drv = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv' -ErrorAction Stop
  Write-Host ("driver image path   : {0}" -f $drv.ImagePath)
} catch { Write-Host ("SysmonDrv service key unreadable: {0}" -f $_.Exception.Message) }

Write-Host ""
Write-Host "=== 4 · WHAT SYSMON WROTE IN THE WINDOW ==="
# Per-Event-ID counts plus the RecordId span — the authoritative
# denominator, because a RecordId range cannot be inflated or deflated
# by query shape.
try {
  $rows = Get-WinEvent -FilterHashtable @{ LogName = $sysLog; StartTime = $StartLocal; EndTime = $EndLocal } -ErrorAction Stop
  Write-Host ("TOTAL Sysmon records in window : {0}" -f @($rows).Count)
  if (@($rows).Count -gt 0) {
    $ids = $rows | ForEach-Object { $_.RecordId }
    $min = ($ids | Measure-Object -Minimum).Minimum
    $max = ($ids | Measure-Object -Maximum).Maximum
    Write-Host ("RecordId span                  : {0} -> {1}  (span = {2})" -f $min, $max, ($max - $min + 1))
    $rows | Group-Object Id | Sort-Object { [int]$_.Name } |
      Select-Object @{n='EventID';e={$_.Name}},
                    @{n='Count';e={$_.Count}},
                    @{n='FirstUtc';e={($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated.ToUniversalTime().ToString('o')}},
                    @{n='LastUtc';e={($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated.ToUniversalTime().ToString('o')}} |
      Format-Table -AutoSize
  } else {
    Write-Host "no Sysmon records in this window — pick a window with real activity before enabling EID 5"
  }
} catch { Write-Host ("window unreadable: {0}" -f $_.Exception.Message) }

Write-Host ""
Write-Host "=== 5 · PROCESS CREATE / TERMINATE PAIRING IN THE WINDOW ==="
Write-Host ("EID 1 (ProcessCreate) in window    : {0}" -f (Count-Events $sysLog 1 $StartLocal $EndLocal))
Write-Host ("EID 5 (ProcessTerminate) in window : {0}" -f (Count-Events $sysLog 5 $StartLocal $EndLocal))
Write-Host "EXPECTED FOR PRE : EID 5 = 0. ProcessTerminate is not being collected yet, so process lifetime"
Write-Host "                   is honestly PROCESS_LIFETIME_UNKNOWN, never assumed."
Write-Host "EXPECTED FOR POST: EID 5 of the same ORDER as EID 1 — never an exact match, because processes"
Write-Host "                   that started before the window or ended after it are legitimately unpaired."
try {
  $creates = @{}; $exits = @{}
  Get-WinEvent -FilterHashtable @{ LogName=$sysLog; ID=1; StartTime=$StartLocal; EndTime=$EndLocal } -ErrorAction Stop |
    ForEach-Object { $x=[xml]$_.ToXml(); $g=($x.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessGuid' }).'#text'; if ($g) { $creates[$g]=$true } }
  Get-WinEvent -FilterHashtable @{ LogName=$sysLog; ID=5; StartTime=$StartLocal; EndTime=$EndLocal } -ErrorAction Stop |
    ForEach-Object { $x=[xml]$_.ToXml(); $g=($x.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessGuid' }).'#text'; if ($g) { $exits[$g]=$true } }
  Write-Host ("distinct ProcessGuid created : {0}" -f $creates.Count)
  Write-Host ("distinct ProcessGuid exited  : {0}" -f $exits.Count)
  Write-Host ("created AND exited in window : {0}" -f (@($creates.Keys | Where-Object { $exits.ContainsKey($_) })).Count)
} catch { Write-Host ("pairing not computable (expected for PRE if EID 5 is absent): {0}" -f $_.Exception.Message) }

Write-Host ""
Write-Host "=== 6 · EID 5 ACROSS THE WHOLE RETAINED LOG ==="
# The window alone cannot prove ProcessTerminate was never collected. This
# does, for everything still retained.
Write-Host ("EID 5 anywhere in retained log : {0}" -f (Count-Events $sysLog 5 $null $null))
Write-Host ("EID 5 in the last 7 days       : {0}" -f (Count-Events $sysLog 5 (Get-Date).AddDays(-7) $null))
Write-Host ("EID 1 in the last 7 days       : {0}" -f (Count-Events $sysLog 1 (Get-Date).AddDays(-7) $null))
Write-Host ("EID 11 (FileCreate) last 7 days: {0}" -f (Count-Events $sysLog 11 (Get-Date).AddDays(-7) $null))
Write-Host ("EID 3 (NetworkConnect) 7 days  : {0}" -f (Count-Events $sysLog 3 (Get-Date).AddDays(-7) $null))

Write-Host ""
Write-Host "=== 7 · NIVXFORGE SENSOR DELIVERY STATE (metadata only) ==="
# File SIZES and LINE COUNTS only. No event payload, no identity value and
# no credential is read or printed: identity.json is reported as PRESENT or
# ABSENT and is never opened.
$StateDir = Join-Path $env:ProgramData 'NivXForge\sensor'
Write-Host ("state directory      : {0}" -f $StateDir)
if (Test-Path $StateDir) {
  Get-ChildItem $StateDir -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastWriteTimeUtc | Format-Table -AutoSize
  $queue  = Join-Path $StateDir 'outbox.jsonl'
  $offset = Join-Path $StateDir 'outbox.offset'
  if (Test-Path $queue) {
    $qLines = (Get-Content $queue -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    $qBytes = (Get-Item $queue).Length
    $oBytes = if (Test-Path $offset) { [int64](Get-Content $offset -Raw -ErrorAction SilentlyContinue).Trim() } else { 0 }
    Write-Host ("outbox lines (total) : {0}" -f $qLines)
    Write-Host ("outbox bytes         : {0}" -f $qBytes)
    Write-Host ("delivered offset     : {0}" -f $oBytes)
    Write-Host ("undelivered bytes    : {0}   (backlog, NOT loss)" -f ($qBytes - $oBytes))
  } else { Write-Host "outbox               : ABSENT (nothing queued)" }
  Write-Host ("identity.json        : {0}   (never opened by this script)" -f $(if (Test-Path (Join-Path $StateDir 'identity.json')) { 'PRESENT' } else { 'ABSENT' }))
  Write-Host ("channels.json        : {0}" -f $(if (Test-Path (Join-Path $StateDir 'channels.json')) { 'PRESENT' } else { 'ABSENT' }))
} else {
  Write-Host "state directory ABSENT — is the sensor installed on this host?"
}

Write-Host ""
Write-Host "=== 8 · NEW CAPABILITY FLAGS (both MUST be OFF for a clean PRE) ==="
# Sensor delivery counters and B3 file-content hashing are implemented but
# default OFF and are NOT deployed. If either reads as enabled here, this
# endpoint is not in the PRE state we intend to baseline.
foreach ($flag in 'NIVX_SENSOR_DELIVERY_COUNTERS','NIVX_SENSOR_FILE_HASHING') {
  $proc = [Environment]::GetEnvironmentVariable($flag, 'Process')
  $mach = [Environment]::GetEnvironmentVariable($flag, 'Machine')
  Write-Host ("{0,-34} process='{1}' machine='{2}'  => {3}" -f $flag, $proc, $mach, $(if ($proc -or $mach) { 'ENABLED — STOP, this is not a clean PRE' } else { 'OFF (expected)' }))
}
Write-Host ("sensor counter file   : {0}   (expected ABSENT while the capability is off)" -f $(if (Test-Path (Join-Path $StateDir 'delivery_counters.json')) { 'PRESENT' } else { 'ABSENT' }))

Write-Host ""
Write-Host "=== 9 · DELIVERY TAIL WARNING + PRE COMPLETION STAMP ==="
Write-Host "Measured on the existing corpus: sensor->collector p50 = 59 min, collector->NivX p50 = 43 min,"
Write-Host "worst case 2.9 DAYS. So do NOT compare this endpoint count against the backend until at least"
Write-Host "24 h after the window closes, and re-count at 72 h before calling any record LOST. Latency is"
Write-Host "not loss, and deduplication is not loss."
Write-Host ""
Write-Host ("PRE_RUN_ID           : {0}" -f $RunId)
Write-Host ("PRE_WINDOW_UTC       : {0} -> {1}" -f $WindowStartUtc.ToString('o'), $WindowEndUtc.ToString('o'))
Write-Host ("PRE_CAPTURED_AT_UTC  : {0}" -f (Get-Date).ToUniversalTime().ToString('o'))
Write-Host ("Transcript           : {0}" -f $OutFile)
Write-Host "NOTHING on this endpoint was changed: no Sysmon config, no service, no audit policy, no"
Write-Host "registry value, no event log, no sensor state. The only write was this transcript file."
Stop-Transcript | Out-Null
