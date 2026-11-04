# =====================================================================
# NIVXFORGE · WAVE B · WINDOWS PROCESS-TELEMETRY PRE-CHECK
# TARGET: DESKTOP-A9HGFJJ
# MODE:   READ-ONLY.  MAKES NO CHANGE TO THIS ENDPOINT.
#
# It does NOT: modify Sysmon config, modify audit policy, start/stop/
# restart any service, write to the registry, clear/resize any event log,
# install or reinstall anything, or print any enrolment token, API key,
# password or secret.
#
# Every command used is one of:
#   Get-Process / Get-Service / Get-CimInstance   (read)
#   Get-WinEvent -ListLog / -FilterHashtable      (read)
#   auditpol /get                                 (read; /set is NOT used)
#   reg query                                     (read; reg add is NOT used)
#   Get-Content / Test-Path / Get-ChildItem       (read)
#   sysmon64.exe -c  with NO config file argument (DUMPS the active
#       config to stdout; supplying a path is what would APPLY one — no
#       path is supplied anywhere below)
#
# Run in an ELEVATED PowerShell (admin) — Security log and Sysmon config
# are not readable otherwise. Elevation is required to READ, not to write.
#
# Output: prints to the console AND writes a transcript next to itself.
# The transcript file in %TEMP% is the ONLY thing this script writes
# anywhere. If you would rather it write nothing at all, delete the
# Start-Transcript / Stop-Transcript lines and copy the console output.
# Review the file before sending it back; §4 deliberately prints only
# selected process-create fields, never a full record dump.
# =====================================================================

$ErrorActionPreference = 'Continue'

# --- the comparison window. EDIT ONLY THESE TWO LINES. ---------------
# Defaults reproduce the Wave A corpus window exactly (UTC).
$WindowStartUtc = [datetime]::SpecifyKind('2026-09-22 15:43:00', 'Utc')
$WindowEndUtc   = [datetime]::SpecifyKind('2026-09-22 16:46:00', 'Utc')
# ---------------------------------------------------------------------

$StartLocal = $WindowStartUtc.ToLocalTime()
$EndLocal   = $WindowEndUtc.ToLocalTime()

$OutFile = Join-Path $env:TEMP ("nivxforge_precheck_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
Start-Transcript -Path $OutFile -Force | Out-Null

function Section([string]$n) {
  Write-Host ""
  Write-Host ("=" * 70)
  Write-Host "== $n"
  Write-Host ("=" * 70)
}

Section "0 · CLOCK + WINDOW (needed to compare endpoint vs backend counts)"
Write-Host ("Hostname            : {0}" -f $env:COMPUTERNAME)
Write-Host ("Now (local)         : {0}" -f (Get-Date -Format 'o'))
Write-Host ("Now (UTC)           : {0}" -f (Get-Date).ToUniversalTime().ToString('o'))
Write-Host ("TimeZone            : {0}" -f (Get-TimeZone).Id)
Write-Host ("UTC offset (mins)   : {0}" -f [int]([datetime]::Now - [datetime]::UtcNow).TotalMinutes)
Write-Host ("Window UTC          : {0}  ->  {1}" -f $WindowStartUtc.ToString('o'), $WindowEndUtc.ToString('o'))
Write-Host ("Window LOCAL        : {0}  ->  {1}" -f $StartLocal.ToString('o'), $EndLocal.ToString('o'))
Write-Host ("Elevated            : {0}" -f ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Host ("Last boot (UTC)     : {0}" -f (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'))

Section "1 · SYSMON SERVICE / DRIVER / VERSION / STATUS"
Get-Service -Name 'Sysmon','Sysmon64','SysmonDrv' -ErrorAction SilentlyContinue |
  Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
Get-Process -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue |
  Select-Object Name, Id, StartTime, Path | Format-Table -AutoSize
foreach ($svc in 'Sysmon','Sysmon64','SysmonDrv') {
  $c = Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue
  if ($c) { Write-Host ("{0,-10} state={1,-8} start={2,-10} path={3}" -f $c.Name, $c.State, $c.StartMode, $c.PathName) }
}
foreach ($p in "$env:SystemRoot\Sysmon64.exe", "$env:SystemRoot\Sysmon.exe") {
  if (Test-Path $p) {
    $v = (Get-Item $p).VersionInfo
    Write-Host ("binary {0}  fileversion={1}  product={2}" -f $p, $v.FileVersion, $v.ProductVersion)
  }
}

Section "2 · ACTIVE SYSMON CONFIG (dump only — no config path is passed)"
# `-c` WITHOUT a filename PRINTS the configuration currently in force.
# This is the single unproven variable from Wave A.
$sysmonExe = @("$env:SystemRoot\Sysmon64.exe", "$env:SystemRoot\Sysmon.exe") |
  Where-Object { Test-Path $_ } | Select-Object -First 1
if ($sysmonExe) {
  $cfg = & $sysmonExe -c 2>&1 | Out-String
  Write-Host $cfg
  Write-Host "---- ProcessCreate / EventID-1 relevant lines only ----"
  ($cfg -split "`r?`n") | Select-String -Pattern 'ProcessCreate','EventID','RuleName','include','exclude','HashAlgorithms','SchemaVersion' |
    ForEach-Object { $_.Line.Trim() } | Select-Object -First 120
} else {
  Write-Host "RESULT: no Sysmon binary found at %SystemRoot% — record this as NOT_OBSERVED, do not infer absence of Sysmon."
}

Section "3 · SYSMON CHANNEL STATE + EVENT ID 1 COUNT IN WINDOW"
$sysLog = 'Microsoft-Windows-Sysmon/Operational'
Get-WinEvent -ListLog $sysLog -ErrorAction SilentlyContinue |
  Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, RecordCount, OldestRecordNumber, FileSize |
  Format-List
try {
  $oldest = Get-WinEvent -LogName $sysLog -Oldest -MaxEvents 1 -ErrorAction Stop
  $newest = Get-WinEvent -LogName $sysLog -MaxEvents 1 -ErrorAction Stop
  Write-Host ("channel retains : {0}  ->  {1}  (UTC)" -f $oldest.TimeCreated.ToUniversalTime().ToString('o'), $newest.TimeCreated.ToUniversalTime().ToString('o'))
  Write-Host "NOTE: if the window predates the oldest retained record, a low count proves ROLLOVER, not low activity."
} catch { Write-Host ("channel retention range unreadable: {0}" -f $_.Exception.Message) }

function Count-Events($logName, $id, $s, $e) {
  try {
    $q = @{ LogName = $logName; StartTime = $s; EndTime = $e }
    if ($id) { $q['ID'] = $id }
    $r = Get-WinEvent -FilterHashtable $q -ErrorAction Stop
    return @($r).Count
  } catch {
    if ($_.Exception.Message -match 'No events') { return 0 }
    return "UNREADABLE: $($_.Exception.Message)"
  }
}

Write-Host ("Sysmon EventID 1 in WINDOW      : {0}" -f (Count-Events $sysLog 1 $StartLocal $EndLocal))
Write-Host ("Sysmon EventID 1 last 24h       : {0}" -f (Count-Events $sysLog 1 (Get-Date).AddHours(-24) (Get-Date)))
Write-Host ("Sysmon EventID 1 last 1h        : {0}" -f (Count-Events $sysLog 1 (Get-Date).AddHours(-1) (Get-Date)))
Write-Host ("Sysmon EventID 5 (exit) WINDOW   : {0}" -f (Count-Events $sysLog 5 $StartLocal $EndLocal))
Write-Host ("Sysmon ALL events in WINDOW      : {0}" -f (Count-Events $sysLog $null $StartLocal $EndLocal))
Write-Host "---- per-Event-ID histogram for the WINDOW ----"
try {
  Get-WinEvent -FilterHashtable @{ LogName = $sysLog; StartTime = $StartLocal; EndTime = $EndLocal } -ErrorAction Stop |
    Group-Object Id | Sort-Object Count -Descending |
    Select-Object @{n='EventID';e={$_.Name}}, Count | Format-Table -AutoSize
} catch { Write-Host ("histogram unreadable: {0}" -f $_.Exception.Message) }

Section "4 · SAMPLE EVENT ID 1 FIELDS (selected fields only — not a full dump)"
# Deliberately narrow: proves WHICH fields the sensor is emitting without
# exporting command lines wholesale. Command line is TRUNCATED to 120 chars.
try {
  Get-WinEvent -FilterHashtable @{ LogName = $sysLog; ID = 1 } -MaxEvents 3 -ErrorAction Stop |
    ForEach-Object {
      $x = [xml]$_.ToXml()
      $d = @{}
      $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
      [pscustomobject]@{
        UtcTime          = $d['UtcTime']
        RecordId         = $_.RecordId
        ProcessGuid      = $d['ProcessGuid']
        ProcessId        = $d['ProcessId']
        Image            = $d['Image']
        OriginalFileName = $d['OriginalFileName']
        HashesPresent    = [bool]$d['Hashes']
        HashAlgorithms   = (($d['Hashes'] -split ',') | ForEach-Object { ($_ -split '=')[0] }) -join '+'
        ParentProcessGuid= $d['ParentProcessGuid']
        ParentImage      = $d['ParentImage']
        CmdLineLen       = ($d['CommandLine'] | Measure-Object -Character).Characters
        CmdLineHead      = if ($d['CommandLine']) { $d['CommandLine'].Substring(0, [Math]::Min(120, $d['CommandLine'].Length)) } else { $null }
        FieldsPresent    = ($d.Keys | Sort-Object) -join ','
      }
    } | Format-List
} catch { Write-Host ("no readable Sysmon EventID 1 sample: {0}" -f $_.Exception.Message) }

Section "5 · SECURITY AUDIT POLICY FOR PROCESS CREATION (read-only)"
Write-Host "--- auditpol /get (READ) ---"
& auditpol.exe /get /subcategory:"Process Creation" 2>&1 | Out-String | Write-Host
& auditpol.exe /get /subcategory:"Process Termination" 2>&1 | Out-String | Write-Host
Write-Host "--- command-line-in-4688 policy (reg query = READ) ---"
& reg.exe query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled 2>&1 | Out-String | Write-Host

Section "6 · SECURITY CHANNEL — DOES 4688 EXIST LOCALLY IN THE SAME WINDOW?"
Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue |
  Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, RecordCount, OldestRecordNumber | Format-List
Write-Host ("Security 4688 in WINDOW   : {0}" -f (Count-Events 'Security' 4688 $StartLocal $EndLocal))
Write-Host ("Security 4688 last 24h    : {0}" -f (Count-Events 'Security' 4688 (Get-Date).AddHours(-24) (Get-Date)))
Write-Host ("Security 4689 (exit) 24h  : {0}" -f (Count-events 'Security' 4689 (Get-Date).AddHours(-24) (Get-Date)))
Write-Host ("Security 4624 in WINDOW   : {0}" -f (Count-Events 'Security' 4624 $StartLocal $EndLocal))
Write-Host ("Security 4672 in WINDOW   : {0}" -f (Count-Events 'Security' 4672 $StartLocal $EndLocal))
Write-Host ("Security ALL in WINDOW    : {0}" -f (Count-Events 'Security' $null $StartLocal $EndLocal))
Write-Host ("Security 1102 (log clear) : {0}" -f (Count-Events 'Security' 1102 $StartLocal $EndLocal))

Section "7 · NIVXFORGE / WINDOWS COLLECTOR SERVICE STATE"
Get-Service -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'nivx|nivxforge|nivxray|collector|winlogbeat|beat|fluent|nxlog|otelcol' } |
  Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'nivx|collector|winlogbeat|beat|fluent|nxlog|otelcol' } |
  Select-Object Name, State, StartMode, PathName, StartName | Format-List
Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.ProcessName -match 'nivx|collector|winlogbeat|fluent|nxlog|otelcol' } |
  Select-Object ProcessName, Id, StartTime, Path | Format-Table -AutoSize
Write-Host "--- Windows Event Collector / WinRM (subscription transport) ---"
Get-Service -Name 'Wecsvc','WinRM' -ErrorAction SilentlyContinue |
  Select-Object Name, Status, StartType | Format-Table -AutoSize

Section "8 · COLLECTOR CONFIG / SUBSCRIPTION RELEVANT TO SYSMON + SECURITY"
# SECRET-SAFE: prints only lines that mention a CHANNEL or an EVENT ID,
# and redacts anything that looks like a token/key/secret/password.
$candidateDirs = @(
  "$env:ProgramFiles\NivXForge", "$env:ProgramFiles\NivXRay",
  "${env:ProgramFiles(x86)}\NivXForge", "$env:ProgramData\NivXForge",
  "$env:ProgramData\NivXRay", "$env:ProgramFiles\nivx", "$env:ProgramData\nivx"
) | Where-Object { Test-Path $_ }
if (-not $candidateDirs) { Write-Host "no NivXForge install directory found in the standard locations — record as NOT_OBSERVED" }
foreach ($d in $candidateDirs) {
  Write-Host ("--- install dir: {0} ---" -f $d)
  Get-ChildItem -Path $d -Recurse -Include *.json,*.yml,*.yaml,*.xml,*.conf,*.ini -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTimeUtc | Format-Table -AutoSize
  Get-ChildItem -Path $d -Recurse -Include *.json,*.yml,*.yaml,*.xml,*.conf,*.ini -ErrorAction SilentlyContinue |
    ForEach-Object {
      $f = $_.FullName
      Get-Content -LiteralPath $f -ErrorAction SilentlyContinue |
        Select-String -Pattern 'Sysmon','Security','channel','Channel','event_id','EventID','filter','subscription','profile' |
        ForEach-Object {
          $line = $_.Line
          $line = $line -replace '(?i)("?(api[_-]?key|token|secret|password|passphrase|enrol(?:l)?ment[_-]?key|bearer|client[_-]?secret)"?\s*[:=]\s*)("?)[^"'',}\s]+', '$1$3<REDACTED>'
          "{0}:{1}: {2}" -f (Split-Path $f -Leaf), $_.LineNumber, $line.Trim()
        }
    } | Select-Object -First 200
}
Write-Host "--- Windows Event Log SUBSCRIPTIONS (wecutil = READ) ---"
try {
  $subs = & wecutil.exe es 2>&1
  $subs | ForEach-Object { Write-Host ("subscription: {0}" -f $_) }
  foreach ($s in $subs) {
    if ($s -and $s -notmatch '^Failed|^The ') {
      (& wecutil.exe gs "$s" 2>&1) | Select-String -Pattern 'Query|Channel|Enabled|Uri','EventID' |
        ForEach-Object { "  {0}" -f $_.Line.Trim() }
    }
  }
} catch { Write-Host "wecutil not available / no subscriptions (this is normal for an agent-based collector)" }

Section "9 · CHANNEL ACCESS SANITY (can the collector identity even read these?)"
foreach ($log in @($sysLog, 'Security', 'System', 'Application')) {
  $l = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
  if ($l) { Write-Host ("{0,-45} enabled={1,-6} records={2,-10} mode={3}" -f $l.LogName, $l.IsEnabled, $l.RecordCount, $l.LogMode) }
  else    { Write-Host ("{0,-45} NOT READABLE by this identity" -f $log) }
}

Section "DONE"
Write-Host ("Transcript written to: {0}" -f $OutFile)
Write-Host "Review the transcript, then return it. NOTHING on this endpoint was changed."
Stop-Transcript | Out-Null
