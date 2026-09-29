# =====================================================================
# NIVXFORGE | B5 | ENABLE SYSMON EID 5 (ProcessTerminate) + PROVE IT
# CORRECTED PER OWNER REVIEW. FAIL-CLOSED AT EVERY GATE.
#
# ACCEPTED PRE STATE (this script refuses to run against anything else)
#   endpoint            : DESKTOP-A9HGFJJ
#   PRE run id          : 621b79c3-bf4e-49ad-ad42-14bac02b2449
#   PRE rules SHA-256   : 6eecc58c62d90305b3e989adbffa92060cf22e315a04a7da28683b72aa0cba8f
#   retention VALID | EID1 in window 185 | EID5 in window 0
#   EID5 anywhere retained 0 | Sysmon64 + SysmonDrv + NivXForgeSensor running
#   delivery counters OFF | file hashing OFF
#
# GATE ORDER (every gate is HARD; a failed gate ends the run)
#   G1  elevation                      -> HALT, nothing changed
#   G2  Sysmon binary + config present -> HALT, nothing changed
#   G3  ACCEPTED PRE FINGERPRINT       -> HALT, nothing changed
#       (an unexpected fingerprint is NOT re-baselined and NOT warned
#        past: only the OWNER may accept a divergence)
#   G4  verified XML backup            -> HALT, nothing changed
#   G5  one-change invariant           -> restore file, HALT
#   G6  apply exit code                -> ROLLBACK + verify, HALT
#   G7  POST fingerprint readable and  -> ROLLBACK + verify, HALT
#       different from PRE
#   G8  live ProcessTerminate state    -> ROLLBACK + verify, HALT
#   then, and only then: 5 marked processes + raw-XML GUID pairing proof
#
# THE CHANGE, AND NOTHING ELSE
#   <ProcessTerminate onmatch="include"/>  (matches nothing = EID 5 off)
#   -> <ProcessTerminate onmatch="exclude"/> (excludes nothing = EID 5 on)
#
# NOT TOUCHED BY THIS SCRIPT
#   ProcessCreate, NetworkConnect, FileCreate, RegistryEvent, DnsQuery,
#   HashAlgorithms, CheckRevocation, exclusions, every other event class;
#   services (no install/start/stop/restart/reconfigure); Windows audit
#   policy; event logs (never cleared); the NivXForge sensor, its config
#   or its state; the backend; deployment. Sensor capabilities stay OFF:
#   NIVX_SENSOR_DELIVERY_COUNTERS and NIVX_SENSOR_FILE_HASHING are not
#   set, read for change, or enabled anywhere below.
#
# HISTORY IS NOT RECONSTRUCTED. Processes that exited BEFORE this change
# have no EID 5 and remain PROCESS_LIFETIME_UNKNOWN. No PID inference,
# no timestamp inference, no "probably terminated".
#
# RUN ELEVATED.
# =====================================================================

function Invoke-NivXEid5Enable {

  $ErrorActionPreference = 'Continue'

  # --- accepted PRE gate values (do not edit without OWNER review) ----
  $AcceptedPreRulesSha = '6eecc58c62d90305b3e989adbffa92060cf22e315a04a7da28683b72aa0cba8f'
  $AcceptedPreRunId    = '621b79c3-bf4e-49ad-ad42-14bac02b2449'
  $AcceptedEndpoint    = 'DESKTOP-A9HGFJJ'
  # -------------------------------------------------------------------

  $Cfg        = 'C:\NivX\sysmon\nivx-w1-sysmon.xml'
  $Stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
  $Backup     = "C:\NivX\sysmon\nivx-w1-sysmon.pre-eid5.$Stamp.bak.xml"
  $RegBackup  = "C:\NivX\sysmon\sysmondrv-rules.pre-eid5.$Stamp.reg"
  $RollbackPs = "C:\NivX\sysmon\ROLLBACK-eid5.$Stamp.ps1"
  $sysLog     = 'Microsoft-Windows-Sysmon/Operational'
  $RegPath    = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
  $Old        = '<ProcessTerminate onmatch="include"/>'
  $New        = '<ProcessTerminate onmatch="exclude"/>'
  $Marker     = [guid]::NewGuid().ToString()
  $RunId      = [guid]::NewGuid().ToString()
  $OutFile    = Join-Path $env:TEMP ("nivxforge_eid5_ENABLE_{0}.txt" -f $Stamp)
  Start-Transcript -Path $OutFile -Force | Out-Null

  # ---------------------------------------------------------------- #
  # helpers
  # ---------------------------------------------------------------- #

  function Get-RulesSha {
    # The ACTIVE rules, as the driver holds them. Read-only.
    try {
      $p = Get-ItemProperty -Path $RegPath -ErrorAction Stop
      if ($p.Rules -is [byte[]] -and $p.Rules.Length -gt 0) {
        return [BitConverter]::ToString(
          [Security.Cryptography.SHA256]::Create().ComputeHash($p.Rules)
        ).Replace('-','').ToLower()
      }
      return 'UNREADABLE_NO_BINARY_RULES_VALUE'
    } catch {
      return "UNREADABLE_$($_.Exception.Message)"
    }
  }

  function Test-ShaReadable([string]$sha) {
    return ($sha -match '^[0-9a-f]{64}$')
  }

  # Message-FREE event reading. Get-WinEvent renders every record's
  # DESCRIPTION, which is exactly what failed in PRE Section 4
  # ("The description string for parameter reference (%1) could not be
  # found"). Raw XML never touches the message resource, so this query
  # cannot inherit that defect. The PRE evidence is NOT restated or
  # altered by this - the PRE caveat stands as recorded.
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
      Write-Host ("  raw xml read failed: {0}" -f $_.Exception.Message)
    }
    return $out
  }

  function Get-Field($xmlEvent, [string]$name) {
    return ($xmlEvent.Event.EventData.Data |
            Where-Object { $_.Name -eq $name }).'#text'
  }

  function Get-Inventory([string]$path) {
    # Structural inventory: every event-filter element and its onmatch.
    $x = New-Object System.Xml.XmlDocument
    $x.Load($path)
    return ($x.Sysmon.EventFiltering.ChildNodes |
            Where-Object { $_.NodeType -eq 'Element' } |
            ForEach-Object { "{0}:{1}" -f $_.Name, $_.onmatch })
  }

  function Get-LiveProcessTerminateState([string]$sysmonExe) {
    # What the RUNNING Sysmon says its ProcessTerminate filter is.
    $lines = @()
    try { $lines = @(& $sysmonExe -c 2>&1) } catch { }
    $hit = @($lines | Where-Object { $_ -match 'ProcessTerminate' })
    $joined = ($hit -join ' | ')
    $state = 'UNVERIFIABLE'
    if ($joined -match '(?i)exclude') { $state = 'COLLECTING' }
    elseif ($joined -match '(?i)include') { $state = 'NOT_COLLECTING' }
    return @{ State = $state; Lines = $hit }
  }

  function Invoke-Rollback([string]$sysmonExe, [string]$why) {
    # ONE rollback path, always verified against the ACCEPTED PRE SHA.
    Write-Host ""
    Write-Host "=== ROLLBACK ==="
    Write-Host ("reason : {0}" -f $why)
    $result = @{ FileRestored = $false; ApplyExit = $null;
                 ShaAfter = $null; PreRestored = $false }
    try {
      Copy-Item $Backup $Cfg -Force
      $result.FileRestored = ((Get-FileHash $Cfg -Algorithm SHA256).Hash.ToLower() -eq
                              (Get-FileHash $Backup -Algorithm SHA256).Hash.ToLower())
    } catch {
      Write-Host ("  file restore FAILED: {0}" -f $_.Exception.Message)
    }
    Write-Host ("  config file restored from backup : {0}" -f $result.FileRestored)
    if ($sysmonExe -and (Test-Path $sysmonExe)) {
      $out = & $sysmonExe -c $Cfg 2>&1
      $result.ApplyExit = $LASTEXITCODE
      $out | ForEach-Object { Write-Host ("    {0}" -f $_) }
      Write-Host ("  rollback apply exit code         : {0}" -f $result.ApplyExit)
      Start-Sleep -Seconds 2
      $result.ShaAfter = Get-RulesSha
      $result.PreRestored = ($result.ShaAfter -eq $AcceptedPreRulesSha)
      Write-Host ("  active rules sha after rollback  : {0}" -f $result.ShaAfter)
      Write-Host ("  equals ACCEPTED PRE sha          : {0}" -f $result.PreRestored)
      $live = Get-LiveProcessTerminateState $sysmonExe
      Write-Host ("  live ProcessTerminate state      : {0}" -f $live.State)
    } else {
      Write-Host "  sysmon binary unavailable - config file restored but the"
      Write-Host "  RUNNING rules were NOT reapplied. Escalate to OWNER."
    }
    if ($result.PreRestored) {
      Write-Host "  ROLLBACK VERIFIED: the endpoint is back in its accepted PRE state."
    } else {
      Write-Host "  ROLLBACK NOT VERIFIED. Do not proceed. Report this transcript to"
      Write-Host "  OWNER with the rollback script path printed at the end."
    }
    return $result
  }

  # ---------------------------------------------------------------- #
  # G1 | ELEVATION
  # ---------------------------------------------------------------- #
  Write-Host "=== G1 | ELEVATION (nothing has been changed yet) ==="
  Write-Host ("run_id              : {0}" -f $RunId)
  Write-Host ("hostname            : {0}" -f $env:COMPUTERNAME)
  Write-Host ("accepted PRE host   : {0}" -f $AcceptedEndpoint)
  Write-Host ("accepted PRE run id : {0}" -f $AcceptedPreRunId)
  Write-Host ("started UTC         : {0}" -f (Get-Date).ToUniversalTime().ToString('o'))

  $CurrentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
  $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
  $IsElevated       = $CurrentPrincipal.IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator
  )
  Write-Host ("elevated            : {0}" -f $IsElevated)
  if (-not $IsElevated) {
    Write-Host "HALT G1 | not elevated. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  if ($env:COMPUTERNAME -ne $AcceptedEndpoint) {
    Write-Host ("HALT G1 | this is {0}, but the accepted PRE baseline is for {1}." -f $env:COMPUTERNAME, $AcceptedEndpoint)
    Write-Host "         A PRE baseline is not transferable between endpoints."
    Write-Host "         NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }

  # ---------------------------------------------------------------- #
  # G2 | SYSMON BINARY + CONFIG FILE
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G2 | SYSMON BINARY + CONFIG FILE ==="
  # The AUTHORITATIVE binary is the one the running service points at,
  # not a guess about where it was installed.
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
  Write-Host ("sysmon binary       : {0}" -f $Sysmon)
  if (-not ($Sysmon -and (Test-Path $Sysmon))) {
    Write-Host "HALT G2 | Sysmon64 not found. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  Write-Host ("sysmon version      : {0}" -f (Get-Item $Sysmon).VersionInfo.FileVersion)
  Get-Service -Name 'Sysmon64','SysmonDrv' -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize
  Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'nivx' } |
    Select-Object Name, Status, StartType | Format-Table -AutoSize

  Write-Host ("config file         : {0}" -f $Cfg)
  if (-not (Test-Path $Cfg)) {
    Write-Host "HALT G2 | config XML not found. A new config is NOT improvised:"
    Write-Host "         the active rules can only be rolled back from the file"
    Write-Host "         that produced them. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }

  # ---------------------------------------------------------------- #
  # G3 | ACCEPTED PRE FINGERPRINT - HARD GATE
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G3 | ACCEPTED PRE FINGERPRINT (hard gate) ==="
  $preSha = Get-RulesSha
  Write-Host ("active rules sha    : {0}" -f $preSha)
  Write-Host ("accepted PRE sha    : {0}" -f $AcceptedPreRulesSha)
  if (-not (Test-ShaReadable $preSha)) {
    Write-Host "HALT G3 | the active rule fingerprint could not be read. Without it"
    Write-Host "         there is no way to prove what state this endpoint is in,"
    Write-Host "         and no way to prove a rollback succeeded. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  if ($preSha -ne $AcceptedPreRulesSha) {
    Write-Host "HALT G3 | FINGERPRINT DIVERGENCE. The active Sysmon rules are NOT the"
    Write-Host "         rules the accepted PRE baseline was captured against. This is"
    Write-Host "         not warned past and not re-baselined here: only the OWNER may"
    Write-Host "         accept a divergence, after reviewing what changed and when."
    Write-Host "         NOTHING CHANGED."
    Write-Host ("         observed : {0}" -f $preSha)
    Write-Host ("         accepted : {0}" -f $AcceptedPreRulesSha)
    Stop-Transcript | Out-Null; return
  }
  Write-Host "GATE PASSED | the endpoint is in its accepted PRE rule state."

  $rawBefore = [IO.File]::ReadAllText($Cfg)
  $cfgShaBefore = (Get-FileHash $Cfg -Algorithm SHA256).Hash.ToLower()
  $hits    = ([regex]::Matches($rawBefore, [regex]::Escape($Old))).Count
  $already = ([regex]::Matches($rawBefore, [regex]::Escape($New))).Count
  Write-Host ("config sha256       : {0}" -f $cfgShaBefore)
  Write-Host ("include-line count  : {0}   (expected 1)" -f $hits)
  Write-Host ("exclude-line count  : {0}   (expected 0)" -f $already)
  if ($already -ge 1) {
    Write-Host "HALT G3 | ProcessTerminate is already set to exclude in this file."
    Write-Host "         EID 5 collection is already enabled. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  if ($hits -ne 1) {
    Write-Host "HALT G3 | expected EXACTLY ONE ProcessTerminate include line. A blind"
    Write-Host "         replace across an unknown number of matches is not acceptable."
    Write-Host "         NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }

  # ---------------------------------------------------------------- #
  # G4 | VERIFIED BACKUP - HARD GATE
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G4 | VERIFIED BACKUP (hard gate) ==="
  $backupOk = $false
  try {
    Copy-Item $Cfg $Backup -Force -ErrorAction Stop
    $backupSha = (Get-FileHash $Backup -Algorithm SHA256).Hash.ToLower()
    $readBack  = [IO.File]::ReadAllText($Backup)
    $backupOk  = ((Test-Path $Backup) -and
                  ($backupSha -eq $cfgShaBefore) -and
                  ($readBack.Length -eq $rawBefore.Length))
    Write-Host ("backup path         : {0}" -f $Backup)
    Write-Host ("backup sha256       : {0}" -f $backupSha)
    Write-Host ("backup readable     : {0}" -f ($readBack.Length -gt 0))
    Write-Host ("backup == original  : {0}" -f ($backupSha -eq $cfgShaBefore))
  } catch {
    Write-Host ("backup FAILED       : {0}" -f $_.Exception.Message)
  }
  if (-not $backupOk) {
    Write-Host "HALT G4 | the XML backup could not be created and verified. The XML"
    Write-Host "         backup is the rollback; without it this change is not"
    Write-Host "         reversible. NOTHING CHANGED."
    Stop-Transcript | Out-Null; return
  }
  # Secondary artefact only. A registry EXPORT is a read; it is never
  # imported by this script and its failure is not a gate.
  try {
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' $RegBackup /y | Out-Null
  } catch { }
  Write-Host ("rules export (2nd)  : {0}  ({1})" -f $RegBackup, $(if (Test-Path $RegBackup) { 'written' } else { 'not written - secondary artefact only, not a gate' }))
  Write-Host "GATE PASSED | verified rollback artefact in place."

  # ---------------------------------------------------------------- #
  # G5 | THE ONE-LINE CHANGE + STRUCTURAL DIFFERENTIAL PROOF
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G5 | ONE-LINE CHANGE + STRUCTURAL PROOF (hard gate) ==="
  # One literal replacement on the whole-file text, written back as
  # UTF-8 WITH BOM to match how this file was originally created.
  $rawAfter = $rawBefore.Replace($Old, $New)
  [IO.File]::WriteAllText($Cfg, $rawAfter, (New-Object System.Text.UTF8Encoding $true))
  Write-Host ("edited              : {0}" -f $Cfg)
  Write-Host ("new config sha256   : {0}" -f (Get-FileHash $Cfg -Algorithm SHA256).Hash.ToLower())

  $diff = Compare-Object (Get-Content $Backup) (Get-Content $Cfg)
  $diff | Format-Table -AutoSize
  $removed = @($diff | Where-Object { $_.SideIndicator -eq '<=' })
  $added   = @($diff | Where-Object { $_.SideIndicator -eq '=>' })
  Write-Host ("lines removed       : {0}   (expected 1)" -f $removed.Count)
  Write-Host ("lines added         : {0}   (expected 1)" -f $added.Count)

  $structOk = $true
  $invBefore = $null; $invAfter = $null
  try {
    $invBefore = Get-Inventory $Backup
    $invAfter  = Get-Inventory $Cfg
  } catch {
    Write-Host ("XML PARSE FAILED after edit: {0}" -f $_.Exception.Message)
    $structOk = $false
  }
  if ($structOk) {
    $moved = @(Compare-Object $invBefore $invAfter |
               ForEach-Object { "{0} {1}" -f $_.SideIndicator, $_.InputObject })
    Write-Host ("event classes before: {0}" -f @($invBefore).Count)
    Write-Host ("event classes after : {0}" -f @($invAfter).Count)
    Write-Host  "structural delta    :"
    if ($moved.Count -eq 0) { Write-Host "  (none)" }
    $moved | ForEach-Object { Write-Host ("  {0}" -f $_) }
    $unexpected = @($moved | Where-Object {
      $_ -notmatch '^(<=|=>) ProcessTerminate:(include|exclude)$' })
    $removedOldLine = @($removed | Where-Object { $_.InputObject -match 'ProcessTerminate' }).Count
    $addedNewLine   = @($added   | Where-Object { $_.InputObject -match 'ProcessTerminate' }).Count
    if (@($invBefore).Count -ne @($invAfter).Count -or
        $unexpected.Count -gt 0 -or
        $moved.Count -ne 2 -or
        $removed.Count -ne 1 -or $added.Count -ne 1 -or
        $removedOldLine -ne 1 -or $addedNewLine -ne 1) {
      $structOk = $false
      Write-Host "UNEXPECTED DELTA | something other than ProcessTerminate moved, or"
      Write-Host "                  more than one line changed."
    }
  }
  if (-not $structOk) {
    # The RUNNING configuration has not been touched at this point, so
    # restoring the file is a complete restoration.
    Copy-Item $Backup $Cfg -Force
    $restored = ((Get-FileHash $Cfg -Algorithm SHA256).Hash.ToLower() -eq $cfgShaBefore)
    Write-Host ("HALT G5 | edit REVERTED from backup (file restored: {0})." -f $restored)
    Write-Host "         The running Sysmon configuration was never modified, so the"
    Write-Host "         endpoint is still in its accepted PRE state. Nothing was"
    Write-Host "         applied."
    Write-Host ("         active rules sha (unchanged): {0}" -f (Get-RulesSha))
    Stop-Transcript | Out-Null; return
  }
  Write-Host "GATE PASSED | exactly one event class changed: ProcessTerminate include -> exclude."

  # ---------------------------------------------------------------- #
  # G6 | APPLY + APPLY-RESULT HARD GATE
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G6 | APPLY (no service restart; Sysmon reloads its own config) ==="
  $applyStartedUtc = (Get-Date).ToUniversalTime()
  $applyOut = & $Sysmon -c $Cfg 2>&1
  $applyExit = $LASTEXITCODE
  $applyOut | ForEach-Object { Write-Host ("  {0}" -f $_) }
  Write-Host ("apply exit code     : {0}   (expected 0)" -f $applyExit)
  if ($applyExit -ne 0) {
    $rb = Invoke-Rollback $Sysmon ("Sysmon apply returned exit code {0}" -f $applyExit)
    Write-Host ""
    Write-Host "HALT G6 | apply FAILED. No test processes were generated and no proof"
    Write-Host "         was attempted. Rollback result printed above."
    Write-Host ("         rollback apply exit : {0}" -f $rb.ApplyExit)
    Write-Host ("         PRE sha restored    : {0}" -f $rb.PreRestored)
    Stop-Transcript | Out-Null; return
  }
  Write-Host "GATE PASSED | Sysmon accepted the configuration."

  # ---------------------------------------------------------------- #
  # G7 | POST FINGERPRINT HARD GATE
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G7 | POST FINGERPRINT (hard gate) ==="
  Start-Sleep -Seconds 3
  $postSha = Get-RulesSha
  Write-Host ("rules sha BEFORE    : {0}" -f $preSha)
  Write-Host ("rules sha AFTER     : {0}" -f $postSha)
  if (-not (Test-ShaReadable $postSha)) {
    $rb = Invoke-Rollback $Sysmon "the POST rule fingerprint could not be read"
    Write-Host ""
    Write-Host "HALT G7 | the active rule fingerprint is unreadable after apply, so the"
    Write-Host "         change cannot be proven. Rollback result printed above."
    Write-Host ("         PRE sha restored : {0}" -f $rb.PreRestored)
    Stop-Transcript | Out-Null; return
  }
  if ($postSha -eq $preSha) {
    $rb = Invoke-Rollback $Sysmon "the active rules did not change after apply"
    Write-Host ""
    Write-Host "HALT G7 | the driver is still holding the PRE rules: the apply reported"
    Write-Host "         success but nothing changed. Rollback result printed above."
    Write-Host ("         PRE sha restored : {0}" -f $rb.PreRestored)
    Stop-Transcript | Out-Null; return
  }
  Write-Host "GATE PASSED | the driver took the new rules (fingerprint moved)."

  # ---------------------------------------------------------------- #
  # G8 | LIVE ProcessTerminate STATE - BEFORE any proof process
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== G8 | LIVE ProcessTerminate STATE (hard gate) ==="
  $live = Get-LiveProcessTerminateState $Sysmon
  Write-Host  "live config dump (ProcessTerminate lines only):"
  if (@($live.Lines).Count -eq 0) { Write-Host "  (no ProcessTerminate line in the dump)" }
  $live.Lines | ForEach-Object { Write-Host ("  {0}" -f $_) }
  Write-Host ("live state          : {0}   (expected COLLECTING)" -f $live.State)

  # EID 16 is CORROBORATION, not authority: it proves a config change was
  # recorded, not that ProcessTerminate is now collected.
  $cfgEvents = @(Read-SysmonXml '*[System[EventID=16]]' 5)
  if ($cfgEvents.Count -gt 0) {
    Write-Host ("EID 16 most recent  : {0}" -f $cfgEvents[0].Event.System.TimeCreated.SystemTime)
    Write-Host ("EID 16 config file  : {0}" -f (Get-Field $cfgEvents[0] 'Configuration'))
    Write-Host ("EID 16 config hash  : {0}" -f (Get-Field $cfgEvents[0] 'ConfigurationFileHash'))
  } else {
    Write-Host "EID 16              : not readable (corroboration only, not the authority)"
  }
  if ($live.State -ne 'COLLECTING') {
    $rb = Invoke-Rollback $Sysmon ("live ProcessTerminate state is {0}, not COLLECTING" -f $live.State)
    Write-Host ""
    Write-Host "HALT G8 | the running configuration does not consistently show"
    Write-Host "         ProcessTerminate collection. No test processes were"
    Write-Host "         generated. Rollback result printed above."
    Write-Host ("         PRE sha restored : {0}" -f $rb.PreRestored)
    Stop-Transcript | Out-Null; return
  }
  Write-Host "GATE PASSED | the running configuration collects ProcessTerminate."

  # ---------------------------------------------------------------- #
  # PROOF | 5 harmless marked short-lived processes
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== PROOF 1 | 5 HARMLESS MARKED SHORT-LIVED PROCESSES ==="
  # `cmd.exe /c rem <guid>` does nothing at all and exits immediately.
  # The GUID makes these processes unambiguously OURS, so the pairing
  # proof cannot accidentally borrow an unrelated process.
  Write-Host ("marker              : {0}" -f $Marker)
  $spawned = 0
  foreach ($i in 1..5) {
    try {
      Start-Process -FilePath 'cmd.exe' `
        -ArgumentList '/c', 'rem', "NIVX_EID5_PROOF_$Marker" `
        -WindowStyle Hidden -Wait -ErrorAction Stop
      $spawned++
    } catch {
      Write-Host ("  spawn {0} failed: {1}" -f $i, $_.Exception.Message)
    }
  }
  Write-Host ("processes spawned and exited : {0}   (expected 5)" -f $spawned)
  Write-Host "waiting 25 s for Sysmon to write both sides..."
  Start-Sleep -Seconds 25

  # ---------------------------------------------------------------- #
  # PROOF | EID1 -> EID5 paired by ProcessGuid ONLY
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== PROOF 2 | EID1 -> EID5 PAIRED BY ProcessGuid ONLY ==="
  $window  = '*[System[EventID={0} and TimeCreated[timediff(@SystemTime) <= 900000]]]'
  $creates = @(Read-SysmonXml ($window -f 1))
  $exits   = @(Read-SysmonXml ($window -f 5))
  Write-Host ("EID 1 records read (15 min)  : {0}" -f $creates.Count)
  Write-Host ("EID 5 records read (15 min)  : {0}" -f $exits.Count)
  Write-Host ("FRESH EID 5 EXISTS           : {0}" -f $(if ($exits.Count -gt 0) { 'YES' } else { 'NO' }))

  $exitByGuid = @{}
  $exitsWithGuid = 0
  foreach ($x in $exits) {
    $g = Get-Field $x 'ProcessGuid'
    if ($g) {
      $exitsWithGuid++
      if (-not $exitByGuid.ContainsKey($g)) { $exitByGuid[$g] = $x }
    }
  }
  $mine = @($creates | Where-Object {
    (Get-Field $_ 'CommandLine') -like "*NIVX_EID5_PROOF_$Marker*" })
  $minesWithGuid = @($mine | Where-Object { Get-Field $_ 'ProcessGuid' }).Count
  Write-Host ("marked EID 1 records found   : {0}   (expected 5)" -f $mine.Count)
  Write-Host ("marked EID 1 with ProcessGuid: {0}   (expected 5)" -f $minesWithGuid)
  Write-Host ("EID 5 records with ProcessGuid: {0} / {1}" -f $exitsWithGuid, $exits.Count)

  $paired = 0
  foreach ($c in $mine) {
    $g    = Get-Field $c 'ProcessGuid'
    $pid_ = Get-Field $c 'ProcessId'
    $t0   = Get-Field $c 'UtcTime'
    if ($g -and $exitByGuid.ContainsKey($g)) {
      $t1 = Get-Field $exitByGuid[$g] 'UtcTime'
      $ms = 'n/a'
      try { $ms = [int]([datetime]::Parse($t1) - [datetime]::Parse($t0)).TotalMilliseconds } catch { }
      $paired++
      Write-Host ("  PAIRED   guid={0}  create_utc={1}  exit_utc={2}  lifetime_ms={3}  (pid {4} printed, NOT a join key)" -f $g, $t0, $t1, $ms, $pid_)
    } else {
      Write-Host ("  UNPAIRED guid={0}  create_utc={1}  -- no EID 5 carries this ProcessGuid. Reported as UNKNOWN; nothing is inferred." -f $g, $t0)
    }
  }
  Write-Host ("MARKED PROCESSES PAIRED BY GUID : {0} / {1}   (expected 5 / 5)" -f $paired, $mine.Count)
  Write-Host  "NOTE | the join key is ProcessGuid ONLY. PID is printed for the record and is"
  Write-Host  "       deliberately not used: PIDs are reused, so a PID-keyed pair is a guess."
  Write-Host  "NOTE | both sides carry Sysmon's own UtcTime, so lifetime is measured from"
  Write-Host  "       endpoint-authoritative timestamps, never from collector arrival time."
  Write-Host  "NOTE | processes that exited BEFORE this change have no EID 5 and remain"
  Write-Host  "       PROCESS_LIFETIME_UNKNOWN. History is not reconstructed, and no PID"
  Write-Host  "       or timestamp inference is used to fill it in."
  if ($paired -ne 5 -or $mine.Count -ne 5) {
    Write-Host ""
    Write-Host "PROOF INCOMPLETE | fewer than 5 / 5 marked processes paired."
    Write-Host "                  Nothing is invented, inferred or repaired, and this"
    Write-Host "                  test is NOT re-run automatically. The configuration"
    Write-Host "                  change is left in place and the rollback script below"
    Write-Host "                  is ready. STOP and send this transcript to OWNER."
  }

  # ---------------------------------------------------------------- #
  # ROLLBACK ARTEFACT
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== ROLLBACK ARTEFACT (exact, verified) ==="
  $rollback = @"
# NivXForge | EID 5 rollback | generated $Stamp
# Restores the ACCEPTED PRE configuration and PROVES the restoration by
# comparing the active rule fingerprint to the accepted PRE SHA-256.
`$Cfg    = '$Cfg'
`$Backup = '$Backup'
`$Sysmon = '$Sysmon'
`$PreSha = '$AcceptedPreRulesSha'
`$RegPath = '$RegPath'

Copy-Item `$Backup `$Cfg -Force
& `$Sysmon -c `$Cfg
"rollback apply exit code : `$LASTEXITCODE"
Start-Sleep -Seconds 3
`$p = Get-ItemProperty -Path `$RegPath
`$sha = [BitConverter]::ToString(
          [Security.Cryptography.SHA256]::Create().ComputeHash(`$p.Rules)
        ).Replace('-','').ToLower()
"active rules sha         : `$sha"
"equals accepted PRE sha  : `$(`$sha -eq `$PreSha)"
& `$Sysmon -c | Select-String 'ProcessTerminate'
# Independent second artefact (NEVER imported automatically):
#   $RegBackup
"@
  [IO.File]::WriteAllText($RollbackPs, $rollback, (New-Object System.Text.UTF8Encoding $true))
  Write-Host $rollback
  Write-Host ("rollback script written to : {0}" -f $RollbackPs)

  # ---------------------------------------------------------------- #
  # CHANGE STAMP
  # ---------------------------------------------------------------- #
  Write-Host ""
  Write-Host "=== CHANGE STAMP ==="
  Write-Host ("EID5_ENABLE_RUN_ID       : {0}" -f $RunId)
  Write-Host ("ACCEPTED_PRE_RUN_ID      : {0}" -f $AcceptedPreRunId)
  Write-Host ("EID5_MARKER              : {0}" -f $Marker)
  Write-Host ("APPLIED_AT_UTC           : {0}" -f $applyStartedUtc.ToString('o'))
  Write-Host ("APPLY_EXIT_CODE          : {0}" -f $applyExit)
  Write-Host ("PRE_RULES_SHA256         : {0}" -f $preSha)
  Write-Host ("POST_RULES_SHA256        : {0}" -f $postSha)
  Write-Host ("LIVE_PROCESSTERMINATE    : {0}" -f $live.State)
  Write-Host ("FRESH_EID5_COUNT_15MIN   : {0}" -f $exits.Count)
  Write-Host ("MARKED_PAIRED_BY_GUID    : {0} / {1}" -f $paired, $mine.Count)
  Write-Host ("CONFIG_BACKUP            : {0}" -f $Backup)
  Write-Host ("REG_RULES_EXPORT         : {0}" -f $RegBackup)
  Write-Host ("ROLLBACK_SCRIPT          : {0}" -f $RollbackPs)
  Write-Host ("Transcript               : {0}" -f $OutFile)
  Write-Host  "CHANGED  : one Sysmon event class (ProcessTerminate include -> exclude)."
  Write-Host  "UNCHANGED: every other event class and setting, all services, Windows"
  Write-Host  "           audit policy, all event logs, the NivXForge sensor with its"
  Write-Host  "           config and state, and the backend. Both sensor capabilities"
  Write-Host  "           remain OFF (NIVX_SENSOR_DELIVERY_COUNTERS,"
  Write-Host  "           NIVX_SENSOR_FILE_HASHING). Nothing was deployed."
  Write-Host  "Do not compare against the backend before 24 h: measured"
  Write-Host  "sensor->collector p50 is 59 min with a 2.9-day worst case. Latency is"
  Write-Host  "not loss, and deduplication is not loss."
  Stop-Transcript | Out-Null
}

Invoke-NivXEid5Enable
