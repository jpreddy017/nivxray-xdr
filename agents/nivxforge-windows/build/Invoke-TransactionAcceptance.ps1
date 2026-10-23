#Requires -Version 7.0
# PREPARED ONLY. Execution needs separate owner approval and a disposable VM.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Candidate,
  [Parameter(Mandatory)][string]$CandidateSha256,
  [Parameter(Mandatory)][string]$CandidateCommit,
  [string]$Previous,
  [string]$PreviousSha256,
  [ValidateSet('Clean','UpgradeRunning','UpgradeStopped','MappedPyd','MetadataReplaceFailure',
               'KillBeforeCommit','KillAfterCommit','Recover','RebootPrepare','RebootResume','NativeDenied','Repeat',
               'SlowStopRecoverable','UnsupportedPredecessor')]
  [Parameter(Mandatory)][string]$Scenario,
  [string]$PythonExe = 'python',
  [switch]$OwnerApprovedDisposableExecution,
  [string]$Evidence = 'C:\NivXForge-acceptance-evidence'
)
$ErrorActionPreference = 'Stop'
if (-not $OwnerApprovedDisposableExecution) { throw 'UNVERIFIED: explicit disposable execution approval is required' }
if (-not $IsWindows) { throw 'Windows-native acceptance requires Windows' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated VM administrator required' }
$marker = Get-Content 'C:\NivXForge-Disposable-VM.json' -Raw | ConvertFrom-Json
if ($marker.MachineName -ne $env:COMPUTERNAME -or -not $marker.OwnerApproved) { throw 'No matching disposable VM marker' }
if (@(Get-NetAdapter -IncludeHidden | Where-Object Status -eq 'Up').Count) { throw 'UNVERIFIED: disconnect every VM network adapter before synthetic sensor execution' }
New-Item -ItemType Directory -Force $Evidence | Out-Null
$state = Join-Path $env:ProgramData 'NivXForge Transaction Lab\sensor'
$install = Join-Path $env:ProgramFiles 'NivXForge\sensor'
$recordPath = Join-Path $install 'transaction.json'
$activePath = Join-Path $install 'active.json'
$result = [ordered]@{ scenario=$Scenario; native=$true; verdict='UNVERIFIED'; candidate=$CandidateCommit; mock_scm=$false; reboot_proved=$false }

function Start-Tool([string]$Exe, [string[]]$Arguments, [string]$InputText='', [pscredential]$User=$null) {
  $pi = [Diagnostics.ProcessStartInfo]::new($Exe)
  $pi.UseShellExecute=$false; $pi.RedirectStandardOutput=$true; $pi.RedirectStandardError=$true; $pi.RedirectStandardInput=$true
  foreach ($arg in $Arguments) { [void]$pi.ArgumentList.Add($arg) }
  $pi.Environment['NIVXFORGE_SENSOR_STATE']=$state
  if ($User) {
    $parts=$User.UserName.Split('\',2)
    $pi.UserName=$parts[-1]; $pi.Domain=$(if ($parts.Count -eq 2) { $parts[0] } else { $env:COMPUTERNAME })
    $pi.Password=$User.Password; $pi.LoadUserProfile=$true
  }
  $p=[Diagnostics.Process]::new(); $p.StartInfo=$pi; [void]$p.Start()
  $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
  $p.StandardInput.Write($InputText); $p.StandardInput.Close()
  return @{process=$p; stdout=$stdout; stderr=$stderr}
}
function Finish-Tool($Run) {
  if (-not $Run.process.WaitForExit(180000)) { $Run.process.Kill($true); throw 'UNVERIFIED: installer timed out; retain recovery record' }
  return @{code=$Run.process.ExitCode; stdout=$Run.stdout.GetAwaiter().GetResult(); stderr=$Run.stderr.GetAwaiter().GetResult()}
}
function Tool([string]$Exe,[string[]]$Arguments,[string]$InputText='',[pscredential]$User=$null) { Finish-Tool (Start-Tool $Exe $Arguments $InputText $User) }
function Observe { (Tool $Candidate @('--transaction-scm-worker') '{"action":"observe","service":"NivXForgeSensor"}').stdout | ConvertFrom-Json -Depth 40 }
function Record { Get-Content $recordPath -Raw | ConvertFrom-Json -Depth 60 }
function Require-Success($r) { if ($r.code -ne 0) { throw "installer failed: $($r.stdout) $($r.stderr)" } }
function Control([string]$Action) { Require-Success (Tool $Candidate @('--transaction-scm-worker') (@{action=$Action;service='NivXForgeSensor'} | ConvertTo-Json)) }
function Verify-Build([string]$Exe,[string]$Hash,[string]$Commit) {
  if (-not $Hash -or (Get-FileHash $Exe -Algorithm SHA256).Hash -ne $Hash) { throw 'artifact hash mismatch' }
  $v=Tool $Exe @('version'); Require-Success $v
  if (($v.stdout | ConvertFrom-Json).build_commit -ne $Commit) { throw 'embedded build commit mismatch' }
}
function Verify-Final {
  $r=Record; $o=Observe
  if ($r.record.phase -notin @('COMPLETE','ROLLED_BACK')) { throw 'UNVERIFIED: transaction incomplete' }
  $target=$(if ($r.record.phase -eq 'COMPLETE') { $r.record.target } else { $r.record.original })
  if ($target.presence -eq 'ABSENT') {
    if ($o.presence -ne 'ABSENT' -or $o.error -ne 1060) { throw 'original absence not proven' }
  } else {
    if ($o.presence -ne 'PRESENT' -or $o.state -ne $target.state) { throw 'state not restored' }
    # JSON property order is stable in worker/record; canonicalize recursively via
    # the frozen recovery verifier as well as native observations below.
    if ($o.config.binpath -ne $target.config.binpath) { throw 'binPath round-trip mismatch' }
    if ($target.state -eq 'RUNNING' -and (-not $o.image -or $o.image -ne $target.image -or $o.pid -le 0)) { throw 'live executable identity unverified' }
    if ($target.state -eq 'STOPPED' -and $o.pid -ne 0) { throw 'stopped process absence unverified' }
  }
  $recovery=Tool $Candidate @('recover-transaction'); Require-Success $recovery
  $o | ConvertTo-Json -Depth 60 | Set-Content (Join-Path $Evidence "$Scenario-observation.json")
  $r | ConvertTo-Json -Depth 60 | Set-Content (Join-Path $Evidence "$Scenario-transaction.json")
  & sc.exe qc NivXForgeSensor | Set-Content (Join-Path $Evidence "$Scenario-sc-qc.txt")
  & sc.exe queryex NivXForgeSensor | Set-Content (Join-Path $Evidence "$Scenario-sc-queryex.txt")
}
try {
  Verify-Build $Candidate $CandidateSha256 $CandidateCommit
  $selftestDir=Join-Path $Evidence 'frozen-journal-selftest'
  foreach ($phase in @('PRIMARY','RESTART')) {
    $arguments=@('journal-selftest','--dir',$selftestDir)
    if ($phase -eq 'RESTART') { $arguments += '--restart-check' }
    $probe=Tool $Candidate $arguments; Require-Success $probe
    $probe.stdout | Set-Content (Join-Path $Evidence "selftest-$phase.json")
    if (($probe.stdout | ConvertFrom-Json -Depth 50).result -ne 'PASS') { throw 'frozen SQLite/journal provenance failed' }
  }
  if ($Scenario -eq 'Clean') {
    $o=Observe
    if ($o.presence -ne 'ABSENT' -or $o.error -ne 1060 -or (Test-Path $state)) { throw 'Clean case requires a fresh VM snapshot, absent service and absent lab state' }
    New-Item -ItemType Directory -Force $state | Out-Null
    @{tenant_id='LAB_SYNTHETIC';endpoint_id='LAB_ENDPOINT';credential_id='LAB_CREDENTIAL';agent_credential='INVALID_LAB_ONLY_NEVER_SENT'} |
      ConvertTo-Json | Set-Content (Join-Path $state 'identity.json')
  } elseif ($Scenario -notin @('Recover','RebootResume')) {
    Verify-Build $Previous $PreviousSha256 'a14c6693a7013ea7ef86b6fc8d698bae28e87491'
    if ((Observe).presence -eq 'ABSENT') {
      if (Test-Path $state) { throw 'Use a fresh snapshot for previous-build setup' }
      New-Item -ItemType Directory -Force $state | Out-Null
      @{tenant_id='LAB_SYNTHETIC';endpoint_id='LAB_ENDPOINT';credential_id='LAB_CREDENTIAL';agent_credential='INVALID_LAB_ONLY_NEVER_SENT'} |
        ConvertTo-Json | Set-Content (Join-Path $state 'identity.json')
      Require-Success (Tool $Previous @('install'))
    }
  }
  $identityBefore = $(if (Test-Path (Join-Path $state 'identity.json')) { (Get-FileHash (Join-Path $state 'identity.json')).Hash } else { '' })
  if ($Scenario -eq 'NativeDenied') {
    # Genuine OS denial on this disposable service, not an injected error code.
    # Deny QUERY_CONFIG to Administrators, retaining WRITE_DAC for restoration.
    $before=Observe; $security=$before.config.security
    $oldDacl=$security.Substring($security.IndexOf('D:'))
    try {
      & sc.exe sdset NivXForgeSensor 'D:P(D;;0x1;;;BA)(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)' | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'UNVERIFIED: denial DACL could not be installed' }
      $denied=Tool $Candidate @('--transaction-scm-worker') '{"action":"observe","service":"NivXForgeSensor"}'
      $obs=$denied.stdout | ConvertFrom-Json
      if ($obs.presence -ne 'UNREADABLE' -or $obs.error -ne 5) { throw 'UNVERIFIED: genuine native SCM access denial not observed' }
      $refusal=Tool $Candidate @('install')
      if ($refusal.code -eq 0 -or $refusal.stdout + $refusal.stderr -notmatch 'UNREADABLE') { throw 'preflight did not refuse native denial' }
      $denied.stdout | Set-Content (Join-Path $Evidence 'NativeDenied.json')
    } finally {
      & sc.exe sdset NivXForgeSensor $oldDacl | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'MANUAL_RECOVERY: restore disposable service DACL before proceeding' }
    }
    $after=Observe
    if ($after.state -ne $before.state -or $after.config.binpath -ne $before.config.binpath -or $after.image -ne $before.image) { throw 'service changed during failed preflight' }
  } elseif ($Scenario -in @('Recover','RebootResume')) {
    if ($Scenario -eq 'RebootResume') {
      $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
      if ($boot -eq (Get-Content (Join-Path $Evidence 'previous-boot.txt') -Raw).Trim()) { throw 'UNVERIFIED: VM has not rebooted' }
      $result.reboot_proved=$true
    }
    Require-Success (Tool $Candidate @('recover-transaction')); Verify-Final
  } elseif ($Scenario -in @('KillBeforeCommit','KillAfterCommit','RebootPrepare')) {
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') | Set-Content (Join-Path $Evidence 'previous-boot.txt')
    $run=Start-Tool $Candidate @('install'); $wanted=$(if ($Scenario -eq 'KillAfterCommit') { 'COMMITTED' } else { 'CONFIGURED' })
    $deadline=(Get-Date).AddSeconds(90); $hit=$false
    while (-not $run.process.HasExited -and (Get-Date) -lt $deadline) {
      if (Test-Path $recordPath) {
        $r=Record
        if ($r.record.phase -eq $wanted) { $run.process.Kill($true); $hit=$true; break }
      }
      Start-Sleep -Milliseconds 5
    }
    if (-not $hit) { throw 'UNVERIFIED: requested termination window was not hit; do not count this case as PASS' }
    [void](Finish-Tool $run)
    if ($Scenario -eq 'RebootPrepare') {
      throw 'UNVERIFIED: prepared interrupted state; reboot this disposable VM with separate approval, then run RebootResume'
    }
    Require-Success (Tool $Candidate @('recover-transaction')); Verify-Final
  } else {
    if ($Scenario -eq 'UpgradeStopped') { Control 'stop' }
    $mapper=$null; $held=$null
    try {
      if ($Scenario -eq 'MappedPyd') {
        $old=Observe; $pyd=Get-ChildItem (Split-Path $old.image) -Filter servicemanager.pyd -Recurse | Select-Object -First 1
        if (-not $pyd) { throw 'UNVERIFIED: previous PYD unavailable' }
        $mappedBefore=(Get-FileHash $pyd.FullName).Hash; $ready=Join-Path $Evidence 'mapper-ready.txt'
        Remove-Item $ready -ErrorAction SilentlyContinue
        $helper=Join-Path $Evidence 'mapper.py'
        @'
import ctypes,os,sys,time
from pathlib import Path
roots={Path(sys.argv[1]).parent,Path(sys.argv[1]).parent.parent,Path(sys.argv[1]).parent.parent/'pywin32_system32'}
dirs=[os.add_dll_directory(str(p)) for p in roots if p.exists()]
mapped=ctypes.WinDLL(sys.argv[1])
Path(sys.argv[2]).write_text(str(Path(sys.argv[1]).resolve()))
time.sleep(900)
'@ | Set-Content $helper -Encoding utf8
        $mapper=Start-Tool $PythonExe @($helper,$pyd.FullName,$ready)
        $until=(Get-Date).AddSeconds(20)
        while (-not (Test-Path $ready) -and -not $mapper.process.HasExited -and (Get-Date) -lt $until) { Start-Sleep -Milliseconds 100 }
        if (-not (Test-Path $ready) -or $mapper.process.HasExited) { throw 'UNVERIFIED: LoadLibrary handshake failed' }
        Control 'stop'
        $denied=$false
        try { [IO.File]::Open($pyd.FullName,'Open','Write','None').Dispose() } catch { $denied=$true }
        if (-not $denied -or $mapper.process.HasExited) { throw 'UNVERIFIED: mapping did not survive old-service stop' }
      }
      if ($Scenario -eq 'MetadataReplaceFailure') { $held=[IO.File]::Open($activePath,'Open','Read','Read') }
      # E3 P0-1. A stop that is merely SLOW must not be terminal. The
      # sensor is given a cycle interval far longer than the old fixed 25s
      # ceiling, so a real stop takes longer than the budget that used to
      # lock this endpoint for good. Prove the operation settles against
      # the real SCM, that the record is kept with its evidence, and that
      # a later install still runs.
      # E3 P0-1 / G2. The scenario must CREATE and MEASURE a genuinely slow
      # busy stop. An ordinary fast install must NOT satisfy it: the
      # assertions below fail unless STOP_PENDING was actually observed for
      # longer than the single 20s WaitHint the sensor declares, with
      # CHECKPOINT stagnant throughout, and the service still reached
      # STOPPED and the install still succeeded.
      if ($Scenario -eq 'SlowStopRecoverable') {
        $ops = Join-Path (Split-Path $activePath) 'operations'
        $before = @(Get-ChildItem $ops -Filter *.json -ErrorAction SilentlyContinue).Count
        # Force a long collection cycle so the stop is slow for a REAL
        # reason: the sensor finishes its current cycle before reporting
        # SERVICE_STOPPED, and SvcStop() never advances CheckPoint.
        $slowPath = (& sc.exe qc NivXForgeSensor | Select-String 'BINARY_PATH_NAME').ToString()
        $slowPath = $slowPath.Substring($slowPath.IndexOf(':') + 1).Trim()
        if ($slowPath -notmatch '--interval') { throw 'UNVERIFIED: cannot locate the service cycle interval' }
        $slowPath = [regex]::Replace($slowPath, '--interval\s+\d+', '--interval 90')
        & sc.exe config NivXForgeSensor binPath= $slowPath | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'could not configure a slow cycle' }
        & sc.exe start NivXForgeSensor | Out-Null
        $up = [Diagnostics.Stopwatch]::StartNew()
        while ((Observe).state -ne 'RUNNING') {
          if ($up.Elapsed.TotalSeconds -gt 60) { throw 'UNVERIFIED: the slow-cycle service never reached RUNNING' }
          Start-Sleep -Milliseconds 250
        }
        Start-Sleep -Seconds 5          # let it get INTO a collection cycle
        $samples = Join-Path $Evidence "$Scenario-scm-samples.csv"
        $sampler = Start-Job -ScriptBlock {
          param($out)
          't,state,checkpoint,wait_hint' | Set-Content $out
          $w = [Diagnostics.Stopwatch]::StartNew()
          while ($w.Elapsed.TotalSeconds -lt 300) {
            $q = (& sc.exe queryex NivXForgeSensor) -join ' '
            $s = if ($q -match 'STATE\s+:\s+\d+\s+(\S+)') { $Matches[1] } else { 'UNREADABLE' }
            $c = if ($q -match 'CHECKPOINT\s+:\s+(\S+)') { $Matches[1] } else { '' }
            $h = if ($q -match 'WAIT_HINT\s+:\s+(\S+)') { $Matches[1] } else { '' }
            ('{0},{1},{2},{3}' -f $w.Elapsed.TotalSeconds, $s, $c, $h) | Add-Content $out
            Start-Sleep -Milliseconds 250
          }
        } -ArgumentList $samples
        try {
          $run = Tool $Candidate @('install')
          $run.stdout | Set-Content (Join-Path $Evidence "$Scenario-output.txt")
        } finally { Stop-Job $sampler -ErrorAction SilentlyContinue; Remove-Job $sampler -Force -ErrorAction SilentlyContinue }
        Require-Success $run
        Verify-Final
        # PROVE the stop was actually slow, from the sampled SCM itself.
        $rows = Import-Csv $samples
        $pendingRows = @($rows | Where-Object state -match 'PENDING')
        if (-not $pendingRows.Count) { throw 'UNVERIFIED: no STOP_PENDING was ever observed; this was a fast stop and proves nothing' }
        $window = [double]$pendingRows[-1].t - [double]$pendingRows[0].t
        $result.slow_stop_pending_seconds = $window
        if ($window -le 20) { throw "UNVERIFIED: STOP_PENDING lasted only ${window}s; the 20s single-WaitHint bound was never exercised" }
        $checkpoints = @($pendingRows | Select-Object -ExpandProperty checkpoint -Unique)
        $result.slow_stop_checkpoints = $checkpoints
        if ($checkpoints.Count -gt 1) { throw 'UNVERIFIED: CheckPoint advanced, so the stagnant-CheckPoint path was not exercised' }
        if (-not @($rows | Where-Object state -eq 'STOPPED').Count) { throw 'the slow stop never completed' }
        $result.slow_stop_proved = $true
        # And the operation evidence must be settled, retained and auditable.
        $records = @(Get-ChildItem $ops -Filter *.json)
        if ($records.Count -lt $before) { throw 'UNVERIFIED: an operation record was deleted' }
        foreach ($record in $records) {
          $r = (Get-Content $record.FullName -Raw | ConvertFrom-Json).record
          if ($r.state -notin @('FINISHED','RESOLVED_BY_OBSERVATION','RESOLVED_BY_OPERATOR')) {
            throw "UNVERIFIED: operation $($record.Name) left unsettled as $($r.state)"
          }
        }
        # A legitimate recoverable interruption must not deadlock the next install.
        Require-Success (Tool $Candidate @('install')); Verify-Final
        # FAILING CONTROL 1 - a PENDING service must never be settled.
        & sc.exe start NivXForgeSensor | Out-Null
        & sc.exe stop NivXForgeSensor | Out-Null
        $pendingClaim = Tool $Candidate @('resolve-operation','--id',$records[0].BaseName,'--expect-state','STOPPED')
        if ($pendingClaim.code -eq 0 -and $pendingClaim.stdout -notmatch 'not in a final state|RESOLVED') {
          throw 'UNVERIFIED: operator settlement accepted an unproved state'
        }
        $result.pending_control = $pendingClaim.stdout
        while ((Observe).state -ne 'STOPPED') { Start-Sleep -Milliseconds 250 }
        # FAILING CONTROL 2 - a wrong operator claim must be refused.
        $wrong = Tool $Candidate @('resolve-operation','--id',$records[0].BaseName,'--expect-state','RUNNING')
        if ($wrong.code -eq 0) { throw 'UNVERIFIED: a contradicted operator claim was accepted' }
        if ($wrong.stdout -notmatch 'but the SCM reports|RESOLVED') { throw 'UNVERIFIED: refusal diagnostic is not actionable' }
        $result.wrong_claim_control = $wrong.stdout
      }
      # E3 P0-2. An installer whose predecessor policy does not pin what is
      # installed must refuse SAFELY and ACTIONABLY, with no mutation.
      if ($Scenario -eq 'UnsupportedPredecessor') {
        $before = Observe
        $run = Tool $Candidate @('install'); $run.stdout | Set-Content (Join-Path $Evidence "$Scenario-output.txt")
        if ($run.code -eq 0) { throw 'UNVERIFIED: an unpinned predecessor was accepted' }
        if ($run.stdout -notmatch 'UNSUPPORTED_PREDECESSOR') { throw 'UNVERIFIED: diagnostic is not actionable' }
        $after = Observe
        if (($after | ConvertTo-Json -Depth 60) -ne ($before | ConvertTo-Json -Depth 60)) { throw 'service was mutated by a refused install' }
        if (Test-Path (Join-Path (Split-Path $activePath) 'transaction.json')) { throw 'a refused install opened a transaction' }
      }
      if ($Scenario -notin @('SlowStopRecoverable','UnsupportedPredecessor')) {
      $run=Tool $Candidate @('install'); $run.stdout | Set-Content (Join-Path $Evidence "$Scenario-output.txt")
      if ($Scenario -eq 'MetadataReplaceFailure') {
        if ($run.code -eq 0 -or (Record).record.phase -ne 'ROLLED_BACK') { throw 'UNVERIFIED: real replacement failure and verified rollback not demonstrated' }
      } else { Require-Success $run }
      Verify-Final
      }
      if ($Scenario -eq 'MappedPyd' -and ((Get-FileHash $pyd.FullName).Hash -ne $mappedBefore -or $mapper.process.HasExited)) { throw 'mapped old image was changed or mapper exited' }
      if ($Scenario -eq 'Repeat') { Require-Success (Tool $Candidate @('install')); Verify-Final; Require-Success (Tool $Candidate @('recover-transaction')) }
    } finally {
      if ($held) { $held.Dispose() }
      if ($mapper -and -not $mapper.process.HasExited) { $mapper.process.Kill($true); [void]$mapper.process.WaitForExit(5000) }
    }
  }
  if ($identityBefore -and (Get-FileHash (Join-Path $state 'identity.json')).Hash -ne $identityBefore) { throw 'endpoint identity/credential changed' }
  $result.verdict='PASS'
} catch {
  $result.reason=$_.Exception.Message
  throw
} finally {
  $result | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $Evidence "$Scenario-result.json")
}
# No uninstall/purge: preserve all journal/queue/cursor/payload/recovery evidence.
# Discard/revert only the disposable VM under its separately approved lifecycle.
