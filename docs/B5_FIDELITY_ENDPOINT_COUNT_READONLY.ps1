# =====================================================================
# NIVXFORGE · B5-4 · DELIVERY-FIDELITY · ENDPOINT HALF (B0)
# TARGET: DESKTOP-A9HGFJJ   ·   MODE: READ-ONLY
#
# Counts what SYSMON WROTE for one agreed UTC window, plus the retention
# and config-stability guards that make the number trustworthy.
#
# It does NOT: modify Sysmon config, touch audit policy, start/stop/
# restart any service, write to the registry, clear any log, install
# anything, or print any token/key/credential. The only write anywhere is
# one transcript file in %TEMP% (delete the Start/Stop-Transcript lines
# if you want zero writes).
#
# Run ELEVATED. Run it TWICE: once as PRE (before the ProcessTerminate
# change) and once as POST (after), with the SAME kind of window.
# =====================================================================
$ErrorActionPreference = 'Continue'

# --- EDIT: the agreed window, in UTC. -------------------------------
$WindowStartUtc = [datetime]::SpecifyKind('2026-06-01 09:00:00', 'Utc')
$WindowEndUtc   = [datetime]::SpecifyKind('2026-06-01 10:00:00', 'Utc')
$Label          = 'PRE'     # 'PRE' or 'POST'
# ---------------------------------------------------------------------

$StartLocal = $WindowStartUtc.ToLocalTime()
$EndLocal   = $WindowEndUtc.ToLocalTime()
$sysLog     = 'Microsoft-Windows-Sysmon/Operational'
$OutFile    = Join-Path $env:TEMP ("nivxforge_fidelity_{0}_{1}.txt" -f $Label, (Get-Date -Format 'yyyyMMdd_HHmmss'))
Start-Transcript -Path $OutFile -Force | Out-Null

Write-Host "=== 0 · WINDOW + CLOCK ==="
Write-Host ("label              : {0}" -f $Label)
Write-Host ("hostname           : {0}" -f $env:COMPUTERNAME)
Write-Host ("window UTC         : {0} -> {1}" -f $WindowStartUtc.ToString('o'), $WindowEndUtc.ToString('o'))
Write-Host ("window LOCAL       : {0} -> {1}" -f $StartLocal.ToString('o'), $EndLocal.ToString('o'))
Write-Host ("now UTC            : {0}" -f (Get-Date).ToUniversalTime().ToString('o'))
Write-Host ("timezone / offset  : {0} / {1} min" -f (Get-TimeZone).Id, [int]([datetime]::Now - [datetime]::UtcNow).TotalMinutes)

Write-Host ""
Write-Host "=== 1 · RETENTION GUARD (read AFTER the window has passed) ==="
# If the oldest retained record is NEWER than the window start, the
# window has rolled out of the circular log and the run is INVALID.
try {
  $oldest = Get-WinEvent -LogName $sysLog -Oldest -MaxEvents 1 -ErrorAction Stop
  $newest = Get-WinEvent -LogName $sysLog -MaxEvents 1 -ErrorAction Stop
  $oldestUtc = $oldest.TimeCreated.ToUniversalTime()
  Write-Host ("oldest retained UTC : {0}" -f $oldestUtc.ToString('o'))
  Write-Host ("newest retained UTC : {0}" -f $newest.TimeCreated.ToUniversalTime().ToString('o'))
  Write-Host ("retention verdict   : {0}" -f $(if ($oldestUtc -le $WindowStartUtc) { 'VALID' } else { 'INVALID_ROLLOVER — repeat the run with a more recent window' }))
} catch { Write-Host ("retention unreadable: {0}" -f $_.Exception.Message) }
Get-WinEvent -ListLog $sysLog -ErrorAction SilentlyContinue |
  Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, FileSize, RecordCount | Format-List

Write-Host ""
Write-Host "=== 2 · CONFIG STABILITY (a change or a log clear invalidates the run) ==="
function Count-Events($logName, $id, $s, $e) {
  try {
    $q = @{ LogName = $logName; StartTime = $s; EndTime = $e }
    if ($id) { $q['ID'] = $id }
    return @(Get-WinEvent -FilterHashtable $q -ErrorAction Stop).Count
  } catch {
    if ($_.Exception.Message -match 'No events') { return 0 }
    return "UNREADABLE: $($_.Exception.Message)"
  }
}
Write-Host ("Sysmon EID 16 (config change) in window : {0}" -f (Count-Events $sysLog 16 $StartLocal $EndLocal))
Write-Host ("Sysmon EID 255 (sysmon error) in window  : {0}" -f (Count-Events $sysLog 255 $StartLocal $EndLocal))
Write-Host ("Security 1102 (log cleared) in window    : {0}" -f (Count-Events 'Security' 1102 $StartLocal $EndLocal))
Write-Host ("Sysmon service state                     : {0}" -f ((Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1).Status))
Write-Host ("Sensor service state                     : {0}" -f ((Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'nivx' } | Select-Object -First 1).Status))

Write-Host ""
Write-Host "=== 3 · B0 · WHAT SYSMON WROTE IN THE WINDOW ==="
# Per-Event-ID counts, and the RecordId span — the authoritative
# denominator, because a RecordId range cannot be inflated or deflated
# by query shape.
try {
  $rows = Get-WinEvent -FilterHashtable @{ LogName = $sysLog; StartTime = $StartLocal; EndTime = $EndLocal } -ErrorAction Stop
  Write-Host ("TOTAL Sysmon records in window : {0}" -f @($rows).Count)
  if (@($rows).Count -gt 0) {
    $ids = $rows | ForEach-Object { $_.RecordId }
    Write-Host ("RecordId span                  : {0} -> {1}  (span = {2})" -f ($ids | Measure-Object -Minimum).Minimum, ($ids | Measure-Object -Maximum).Maximum, (($ids | Measure-Object -Maximum).Maximum - ($ids | Measure-Object -Minimum).Minimum + 1))
    $rows | Group-Object Id | Sort-Object { [int]$_.Name } |
      Select-Object @{n='EventID';e={$_.Name}},
                    @{n='Count';e={$_.Count}},
                    @{n='FirstUtc';e={($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated.ToUniversalTime().ToString('o')}},
                    @{n='LastUtc';e={($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated.ToUniversalTime().ToString('o')}} |
      Format-Table -AutoSize
  }
} catch { Write-Host ("window unreadable: {0}" -f $_.Exception.Message) }

Write-Host ""
Write-Host "=== 4 · PROCESS CREATE / EXIT PAIRING (the point of the exercise) ==="
Write-Host ("EID 1 (ProcessCreate) in window    : {0}" -f (Count-Events $sysLog 1 $StartLocal $EndLocal))
Write-Host ("EID 5 (ProcessTerminate) in window : {0}" -f (Count-Events $sysLog 5 $StartLocal $EndLocal))
Write-Host "NOTE for PRE: EID 5 = 0 is EXPECTED. ProcessTerminate is switched off in the active config."
Write-Host "NOTE for POST: EID 5 should be of the same order as EID 1. It will not match exactly — processes"
Write-Host "               that started before the window or ended after it are legitimately unpaired."
# GUID-level pairing, so the POST run can be checked without guessing.
try {
  $creates = @{}; $exits = @{}
  Get-WinEvent -FilterHashtable @{ LogName=$sysLog; ID=1; StartTime=$StartLocal; EndTime=$EndLocal } -ErrorAction Stop |
    ForEach-Object { $x=[xml]$_.ToXml(); $g=($x.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessGuid' }).'#text'; if ($g) { $creates[$g]=$true } }
  Get-WinEvent -FilterHashtable @{ LogName=$sysLog; ID=5; StartTime=$StartLocal; EndTime=$EndLocal } -ErrorAction Stop |
    ForEach-Object { $x=[xml]$_.ToXml(); $g=($x.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessGuid' }).'#text'; if ($g) { $exits[$g]=$true } }
  Write-Host ("distinct ProcessGuid created : {0}" -f $creates.Count)
  Write-Host ("distinct ProcessGuid exited  : {0}" -f $exits.Count)
  Write-Host ("created AND exited in window : {0}" -f (@($creates.Keys | Where-Object { $exits.ContainsKey($_) })).Count)
} catch { Write-Host ("pairing not computable: {0}" -f $_.Exception.Message) }

Write-Host ""
Write-Host "=== 5 · DELIVERY TAIL WARNING ==="
Write-Host "The backend measured sensor->collector p50 = 59 min and collector->NivX p50 = 43 min, with a"
Write-Host "worst case of 2.9 DAYS for the September corpus. So do NOT compare this output against the"
Write-Host "backend until at least 24 h after the window closes, and re-run the backend count after 72 h"
Write-Host "before declaring any record LOST. Latency is not loss."

Write-Host ""
Write-Host ("Transcript: {0}" -f $OutFile)
Write-Host "NOTHING on this endpoint was changed."
Stop-Transcript | Out-Null
