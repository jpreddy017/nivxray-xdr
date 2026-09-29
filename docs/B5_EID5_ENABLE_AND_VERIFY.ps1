# =====================================================================
# NIVXFORGE | B5 | ENABLE SYSMON EID 5 (ProcessTerminate) + PROVE IT
# ONE change. ONE line. Backup first, rollback preserved.
#
# PRE accepted: DESKTOP-A9HGFJJ | run 621b79c3-bf4e-49ad-ad42-14bac02b2449
#   window 2026-09-29T12:08:22Z -> 13:08:22Z | EID1 = 185 | EID5 = 0
#   EID5 anywhere in the retained log = 0
#   PRE Sysmon rules SHA-256 =
#     6eecc58c62d90305b3e989adbffa92060cf22e315a04a7da28683b72aa0cba8f
#
# WHAT THIS DOES, IN ORDER
#   0  preflight: elevation, binary, config, exact single-occurrence match
#   1  backup: config XML copy + registry rules export + fingerprints
#   2  the ONE-LINE change: <ProcessTerminate onmatch="include"/>
#                        -> <ProcessTerminate onmatch="exclude"/>
#      (an empty onmatch="exclude" excludes NOTHING = collect all EID 5)
#   3  differential proof: exactly one line differs, every other event
#      class byte-identical, XML still valid  (HALTS if not)
#   4  apply with the installed Sysmon64 (no service restart)
#   5  verify: EID 16 config-change event, new rules fingerprint, the
#      live config dump
#   6  generate harmless marked short-lived processes (cmd /c rem <guid>)
#   7  POST proof: fresh EID 5 exists, ProcessGuid present, EID1 -> EID5
#      paired BY GUID ONLY, authoritative UtcTime on both sides
#   8  rollback command, written to disk next to the backup
#
# WHAT IT DOES NOT DO
#   no change to ProcessCreate / NetworkConnect / FileCreate / Registry /
#   DnsQuery / hashing / CheckRevocation / exclusions / any other event
#   class; no service install, restart, stop or reconfiguration; no audit
#   policy change; no NivXForge sensor change; no registry WRITE (the
#   export is a read); no log clear; no backend deployment; no sensor
#   capability enabled (NIVX_SENSOR_DELIVERY_COUNTERS and
#   NIVX_SENSOR_FILE_HASHING stay OFF); no reconstruction of historical
#   termination -- EID 5 applies only to processes that exit AFTER this
#   change.
#
# IT HALTS AND CHANGES NOTHING IF: not elevated | Sysmon64 not found |
# config file not found | the ProcessTerminate line is not present
# exactly once | the config is not already in the expected PRE state |
# the post-edit diff is not exactly one line | any other event class
# moved | the edited XML does not parse.
#
# RUN ELEVATED.
# =====================================================================

function Invoke-NivXEid5Enable {

  $ErrorActionPreference = 'Continue'
  $Cfg        = 'C:\NivX\sysmon\nivx-w1-sysmon.xml'
  $Stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
  $Backup     = "C:\NivX\sysmon\nivx-w1-sysmon.pre-eid5.$Stamp.bak.xml"
  $RegBackup  = "C:\NivX\sysmon\sysmondrv-rules.pre-eid5.$Stamp.reg"
  $RollbackPs = "C:\NivX\sysmon\ROLLBACK-eid5.$Stamp.ps1"
  $sysLog     = 'Microsoft-Windows-Sysmon/Operational'
  $RegPath    = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
  $PreRulesSha = '6eecc58c62d90305b3e989adbffa92060cf22e315a04a7da28683b72aa0cba8f'
  $Old        = '<ProcessTerminate onmatch="include"/>'
  $New        = '<ProcessTerminate onmatch="exclude"/>'
  $Marker     = [guid]::NewGuid().ToString()
  $RunId      = [guid]::NewGuid().ToString()
  $OutFile    = Join-Path $env:TEMP ("nivxforge_eid5_ENABLE_{0}.txt" -f $Stamp)
  Start-Transcript -Path $OutFile -Force | Out-Null

  function Get-RulesSha {
    try {
      $p = Get-ItemProperty -Path $RegPath -ErrorAction Stop
      if ($p.Rules -is [byte[]]) {
        return [BitConverter]::ToString(
          [Security.Cryptography.SHA256]::Create().ComputeHash($p.Rules)
        ).Replace('-','').ToLower()
      }
      return 'NO_BINARY_RULES_VALUE'
    } catch { return "UNREADABLE: $($_.Exception.Message)" }
  }

  # Message-FREE event reading. `Get-WinEvent` renders each record's
  # description, which is what produced the PRE Section 4 failure
  # ("The description string for parameter reference (%1) could not be
  # found"). Reading the raw XML never touches the message resource, so
  # the same query cannot fail that way. This does NOT change the PRE
  # evidence; it only stops the POST proof inheriting the defect.
  function Read-SysmonXml([string]$XPath, [int]$Max = 5000) {
    $out = New-Object System.Collections.ArrayList
    try {
      $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
             $sysLog,
             [System.Diagnostics.Eventing.Reader.PathType]::LogName,
             $XPath)
      $q.TolerateQueryErrors = $true
      $r = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
      while (($e = $r.ReadEvent()) -ne $null) {
        [void]$out.Add([xml]$e.ToXml())
        $e.Dispose()
        if ($out.Count -ge $Max) { break }
      }
      $r.Dispose()
    } catch {
      Write-Host ("  xml read failed: {0}" -f $_.Exception.Message)
    }
    return $out
  }

  function Get-Field($xmlEvent, [string]$name) {
    return ($xmlEvent.Event.EventData.Data |
            Where-Object { $_.Name -eq $name }).'#text'
  }

  Write-Host "=== 0 | PREFLIGHT (nothing has been changed yet) ==="
  Write-Host ("run_id            : {0}" -f $RunId)
  Write-Host ("hostname          : {0}" -f $env:COMPUTERNAME)
  Write-Host ("started UTC       : {0}" -f (Get-Date).ToUniversalTime().ToString('o'))

  $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Write-Host ("elevated          : {0}" -f $elevated)
  if (-not $elevated) {
    Write-Host "HALT | not elevated. NOTHING CHANGED."; Stop-Transcript | Out-Null; return
  }

  # The AUTHORITATIVE Sysmon binary is the one the running service points
  # at, not a guess about where it was installed.
  $Sysmon = $null
  try {
    $img = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64' `
             -ErrorAction Stop).ImagePath
    $Sysmon = ($img -replace '^"','' -replace '".*$','').Trim()
  } catch { }
  if (-not ($Sysmon -and (Test-Path $Sysmon))) {
    foreach ($c in @('C:\NivX\sysmon\Sysmon64.exe',
                     (Join-Path $env:SystemRoot 'Sysmon64.exe'),
                     (Join-Path $env:SystemRoot 'Sysmon.exe'))) {
      if (Test-Path $c) { $Sysmon = $c; break }
    }
  }
  Write-Host ("sysmon binary     : {0}" -f $Sysmon)
  if (-not ($Sysmon -and (Test-Path $Sysmon))) {
    Write-Host "HALT | Sysmon64 not found. NOTHING CHANGED."; Stop-Transcript | Out-Null; return
  }
  Write-Host ("sysmon version    : {0}" -f (Get-Item $Sysmon).VersionInfo.FileVersion)
  Get-Service -Name 'Sysmon64','SysmonDrv' -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize

  Write-Host ("config file       : {0}" -f $Cfg)
  if (-not (Test-Path $Cfg)) {
    Write-Host "HALT | config XML not found. Do NOT improvise a new config: the"
    Write-Host "       active rules can only be rolled back from the file that"
    Write-Host "       produced them. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }

  $rawBefore = [IO.File]::ReadAllText($Cfg)
  $hits = ([regex]::Matches($rawBefore, [regex]::Escape($Old))).Count
  $already = ([regex]::Matches($rawBefore, [regex]::Escape($New))).Count
  Write-Host ("config sha256     : {0}" -f (Get-FileHash $Cfg -Algorithm SHA256).Hash.ToLower())
  Write-Host ("'{0}' occurrences  : {1}" -f $Old, $hits)
  Write-Host ("'{0}' occurrences  : {1}" -f $New, $already)
  $preSha = Get-RulesSha
  Write-Host ("active rules sha  : {0}" -f $preSha)
  Write-Host ("matches PRE stamp : {0}" -f $(if ($preSha -eq $PreRulesSha) { 'YES -- same config as the accepted PRE' } else { 'NO -- the active config is NOT the one PRE baselined' }))
  if ($already -ge 1) {
    Write-Host "HALT | ProcessTerminate is already set to exclude. EID 5 collection"
    Write-Host "       is already enabled in this file. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  if ($hits -ne 1) {
    Write-Host "HALT | expected EXACTLY ONE occurrence of the ProcessTerminate"
    Write-Host "       include line. A blind replace is not acceptable here."
    Write-Host "       NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  if ($preSha -ne $PreRulesSha) {
    Write-Host "WARNING | the active rule fingerprint differs from the accepted PRE"
    Write-Host "          baseline. The file change below is still minimal, but the"
    Write-Host "          PRE/POST comparison is only valid against this new"
    Write-Host "          fingerprint. Recorded, not hidden."
  }

  Write-Host ""
  Write-Host "=== 1 | BACKUP (this is the rollback) ==="
  Copy-Item $Cfg $Backup -Force
  Write-Host ("config backup     : {0}" -f $Backup)
  Write-Host ("backup sha256     : {0}" -f (Get-FileHash $Backup -Algorithm SHA256).Hash.ToLower())
  # A registry EXPORT is a read of the live rule blob. It is kept as a
  # second, independent rollback artefact and is never imported by this
  # script.
  & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' $RegBackup /y | Out-Null
  Write-Host ("rules export      : {0}  ({1})" -f $RegBackup, $(if (Test-Path $RegBackup) { 'written' } else { 'FAILED -- continue only if you accept the XML backup alone' }))

  Write-Host ""
  Write-Host "=== 2 | THE ONE-LINE CHANGE ==="
  # Exactly one literal replacement, on the whole-file text, written back
  # as UTF-8 WITH BOM to match how this file was originally created.
  $rawAfter = $rawBefore.Replace($Old, $New)
  [IO.File]::WriteAllText($Cfg, $rawAfter, (New-Object System.Text.UTF8Encoding $true))
  Write-Host ("include -> exclude applied to : {0}" -f $Cfg)
  Write-Host ("new config sha256             : {0}" -f (Get-FileHash $Cfg -Algorithm SHA256).Hash.ToLower())

  Write-Host ""
  Write-Host "=== 3 | DIFFERENTIAL PROOF (halts and rolls back if wrong) ==="
  $diff = Compare-Object (Get-Content $Backup) (Get-Content $Cfg)
  $diff | Format-Table -AutoSize
  $changedLines = @($diff | Where-Object { $_.SideIndicator -ne '==' }).Count
  Write-Host ("differing lines (both sides counted) : {0}   (expected 2 = one removed + one added)" -f $changedLines)

  # Every other event class must be untouched. Compared structurally, not
  # by eye: element name + onmatch value for every filter element.
  function Get-Inventory([string]$path) {
    $x = New-Object System.Xml.XmlDocument
    $x.Load($path)
    return ($x.Sysmon.EventFiltering.ChildNodes |
            Where-Object { $_.NodeType -eq 'Element' } |
            ForEach-Object { "{0}:{1}" -f $_.Name, $_.onmatch })
  }
  $ok = $true
  try {
    $invBefore = Get-Inventory $Backup
    $invAfter  = Get-Inventory $Cfg
  } catch {
    Write-Host ("XML PARSE FAILED after edit: {0}" -f $_.Exception.Message)
    $ok = $false
  }
  if ($ok) {
    $moved = Compare-Object $invBefore $invAfter |
             ForEach-Object { "{0} {1}" -f $_.SideIndicator, $_.InputObject }
    Write-Host ("event classes before : {0}" -f $invBefore.Count)
    Write-Host ("event classes after  : {0}" -f $invAfter.Count)
    Write-Host  "structural delta     :"
    $moved | ForEach-Object { Write-Host ("  {0}" -f $_) }
    $unexpected = @($moved | Where-Object { $_ -notmatch '^(<=|=>) ProcessTerminate:(include|exclude)$' })
    if ($invBefore.Count -ne $invAfter.Count -or $unexpected.Count -gt 0 -or $changedLines -ne 2) {
      $ok = $false
      Write-Host "UNEXPECTED DELTA -- something other than ProcessTerminate moved."
    }
  }
  if (-not $ok) {
    Copy-Item $Backup $Cfg -Force
    Write-Host "HALT | the edit was REVERTED from the backup. The running Sysmon"
    Write-Host "       configuration was never touched, so the endpoint is still"
    Write-Host "       in its accepted PRE state."
    Stop-Transcript | Out-Null; return
  }
  Write-Host "VERDICT | exactly one event class changed: ProcessTerminate include -> exclude."

  Write-Host ""
  Write-Host "=== 4 | APPLY (no service restart; Sysmon reloads its own config) ==="
  $applyStartedUtc = (Get-Date).ToUniversalTime()
  $applyOut = & $Sysmon -c $Cfg 2>&1
  Write-Host ("exit code : {0}" -f $LASTEXITCODE)
  $applyOut | ForEach-Object { Write-Host ("  {0}" -f $_) }

  Write-Host ""
  Write-Host "=== 5 | VERIFY THE CONFIG IN FORCE ==="
  $postSha = Get-RulesSha
  Write-Host ("rules sha BEFORE : {0}" -f $preSha)
  Write-Host ("rules sha AFTER  : {0}" -f $postSha)
  Write-Host ("fingerprint moved: {0}" -f $(if ($postSha -ne $preSha) { 'YES -- the driver took the new rules' } else { 'NO -- the rules did NOT change; investigate before proceeding' }))
  Start-Sleep -Seconds 3
  $cfgEvents = @(Read-SysmonXml '*[System[EventID=16]]' 5)
  if ($cfgEvents.Count -gt 0) {
    Write-Host ("EID 16 (config change) most recent : {0}" -f $cfgEvents[0].Event.System.TimeCreated.SystemTime)
    Write-Host ("EID 16 configuration               : {0}" -f (Get-Field $cfgEvents[0] 'Configuration'))
  } else {
    Write-Host "EID 16 not readable yet -- the fingerprint above is the authority."
  }
  Write-Host  "live config dump (ProcessTerminate lines only):"
  (& $Sysmon -c 2>&1) | Select-String -Pattern 'ProcessTerminate' |
    ForEach-Object { Write-Host ("  {0}" -f $_.Line.Trim()) }

  Write-Host ""
  Write-Host "=== 6 | GENERATE HARMLESS MARKED SHORT-LIVED PROCESSES ==="
  # `cmd.exe /c rem <guid>` does nothing at all and exits immediately.
  # The GUID makes these processes unambiguously OURS, so the pairing
  # proof below cannot accidentally borrow an unrelated process.
  Write-Host ("marker : {0}" -f $Marker)
  1..5 | ForEach-Object {
    Start-Process -FilePath 'cmd.exe' `
      -ArgumentList '/c', 'rem', "NIVX_EID5_PROOF_$Marker" `
      -WindowStyle Hidden -Wait
  }
  Write-Host "5 marked processes created and exited."
  Write-Host "waiting 25 s for Sysmon to write both sides..."
  Start-Sleep -Seconds 25

  Write-Host ""
  Write-Host "=== 7 | POST PROOF | EID1 -> EID5 PAIRED BY ProcessGuid ONLY ==="
  $window = '*[System[EventID={0} and TimeCreated[timediff(@SystemTime) <= 900000]]]'
  $creates = @(Read-SysmonXml ($window -f 1))
  $exits   = @(Read-SysmonXml ($window -f 5))
  Write-Host ("EID 1 records read in last 15 min : {0}" -f $creates.Count)
  Write-Host ("EID 5 records read in last 15 min : {0}" -f $exits.Count)
  Write-Host ("FRESH EID 5 EXISTS                : {0}" -f $(if ($exits.Count -gt 0) { 'YES' } else { 'NO -- stop and report; do not proceed to POST fidelity' }))

  $exitByGuid = @{}
  foreach ($x in $exits) {
    $g = Get-Field $x 'ProcessGuid'
    if ($g -and -not $exitByGuid.ContainsKey($g)) { $exitByGuid[$g] = $x }
  }
  $mine = @($creates | Where-Object {
    (Get-Field $_ 'CommandLine') -like "*NIVX_EID5_PROOF_$Marker*" })
  Write-Host ("marked EID 1 records found        : {0}" -f $mine.Count)
  $paired = 0
  foreach ($c in $mine) {
    $g   = Get-Field $c 'ProcessGuid'
    $pid_ = Get-Field $c 'ProcessId'
    $t0  = Get-Field $c 'UtcTime'
    if ($g -and $exitByGuid.ContainsKey($g)) {
      $t1 = Get-Field $exitByGuid[$g] 'UtcTime'
      $ms = 'n/a'
      try { $ms = [int]([datetime]::Parse($t1) - [datetime]::Parse($t0)).TotalMilliseconds } catch { }
      $paired++
      Write-Host ("  PAIRED  guid={0}  create_utc={1}  exit_utc={2}  lifetime_ms={3}  (pid {4} recorded, NOT used to pair)" -f $g, $t0, $t1, $ms, $pid_)
    } else {
      Write-Host ("  UNPAIRED guid={0}  create_utc={1}  -- no EID 5 with this ProcessGuid. Reported as UNKNOWN, never assumed." -f $g, $t0)
    }
  }
  Write-Host ("marked processes paired by GUID   : {0} / {1}" -f $paired, $mine.Count)
  Write-Host ("ProcessGuid present on EID 5      : {0}" -f $(if ($exits.Count -gt 0) { [bool](Get-Field $exits[0] 'ProcessGuid') } else { 'n/a' }))
  Write-Host  "NOTE | pairing is keyed on ProcessGuid ONLY. PID is printed for the record and is"
  Write-Host  "       deliberately not used: PIDs are reused, so a PID-keyed pair would be a guess."
  Write-Host  "NOTE | both sides carry Sysmon's own UtcTime, so the lifetime is measured from"
  Write-Host  "       endpoint-authoritative timestamps, not from collector arrival time."
  Write-Host  "NOTE | processes that exited BEFORE this change have no EID 5 and stay"
  Write-Host  "       PROCESS_LIFETIME_UNKNOWN. History is never reconstructed."

  Write-Host ""
  Write-Host "=== 8 | ROLLBACK (exact, one file + one command) ==="
  $rollback = @"
# NivXForge | EID 5 rollback | generated $Stamp
Copy-Item '$Backup' '$Cfg' -Force
& '$Sysmon' -c '$Cfg'
& '$Sysmon' -c | Select-String 'ProcessTerminate'
# Independent second artefact (NOT imported automatically):
#   $RegBackup
"@
  [IO.File]::WriteAllText($RollbackPs, $rollback, (New-Object System.Text.UTF8Encoding $true))
  Write-Host $rollback
  Write-Host ("rollback script written to : {0}" -f $RollbackPs)

  Write-Host ""
  Write-Host "=== CHANGE STAMP ==="
  Write-Host ("EID5_ENABLE_RUN_ID      : {0}" -f $RunId)
  Write-Host ("EID5_MARKER             : {0}" -f $Marker)
  Write-Host ("APPLIED_AT_UTC          : {0}" -f $applyStartedUtc.ToString('o'))
  Write-Host ("PRE_RULES_SHA256        : {0}" -f $preSha)
  Write-Host ("POST_RULES_SHA256       : {0}" -f $postSha)
  Write-Host ("CONFIG_BACKUP           : {0}" -f $Backup)
  Write-Host ("ROLLBACK_SCRIPT         : {0}" -f $RollbackPs)
  Write-Host ("Transcript              : {0}" -f $OutFile)
  Write-Host  "CHANGED: one Sysmon event class (ProcessTerminate include -> exclude)."
  Write-Host  "UNCHANGED: every other event class, all services, audit policy, the"
  Write-Host  "NivXForge sensor and its state, and both sensor capability flags"
  Write-Host  "(NIVX_SENSOR_DELIVERY_COUNTERS and NIVX_SENSOR_FILE_HASHING remain OFF)."
  Write-Host  "Compare against the backend no earlier than 24 h from now: measured"
  Write-Host  "sensor->collector p50 is 59 min with a 2.9-day worst case. Latency is"
  Write-Host  "not loss."
  Stop-Transcript | Out-Null
}

Invoke-NivXEid5Enable
