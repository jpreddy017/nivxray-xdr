<#
    G1 · NivXForge EDR Windows Event Log acquisition — READ-ONLY PRE-FLIGHT.

    Makes NO configuration change. It does not install anything, does not
    create or modify Event Log channels, does not touch the registry for
    write, does not enable auditing, does not install Sysmon, and does not
    start any NivX component. It reads host facts and prints ONE JSON
    document to stdout (and writes the same JSON beside itself).

    Usage (an elevated shell is preferred so Security-channel readability can
    be established truthfully; it also runs unelevated and says so):

        powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-NivXRayG1Preflight.ps1

    Then paste the JSON back to the NivXRay engineering thread.

    TRUTH RULES honoured by this script
      * absent ≠ zero:      a channel that does not exist is reported
                            "NOT_PRESENT", never "0 records".
      * not observed ≠ absent: an existing channel with 0 records is
                            "PRESENT_NO_RECORDS".
      * unreadable ≠ empty: a read that was denied is "READ_DENIED", with the
                            error, never "empty".
      * unsupported ≠ failed: a missing prerequisite is reported as missing,
                            not as a failure of acquisition.
#>

$ErrorActionPreference = 'Continue'
$R = [ordered]@{}
$R['report']            = 'nivxray-g1-windows-preflight'
$R['report_version']    = '1.0.0'
$R['generated_at_utc']  = (Get-Date).ToUniversalTime().ToString('o')
$R['read_only']         = $true

# ── host identity ───────────────────────────────────────────────────
$os  = $null
$cs  = $null
try { $os = Get-CimInstance Win32_OperatingSystem } catch { $R['os_query_error'] = $_.Exception.Message }
try { $cs = Get-CimInstance Win32_ComputerSystem } catch { $R['cs_query_error'] = $_.Exception.Message }

$host_facts = [ordered]@{}
$host_facts['hostname']        = $env:COMPUTERNAME
if ($os) {
    $host_facts['os_caption']  = $os.Caption
    $host_facts['os_version']  = $os.Version
    $host_facts['os_build']    = $os.BuildNumber
    $host_facts['os_arch']     = $os.OSArchitecture
    $host_facts['install_date']= $os.InstallDate
    $host_facts['last_boot']   = $os.LastBootUpTime
    switch ([int]$os.ProductType) {
        1 { $host_facts['sku_role'] = 'CLIENT' }
        2 { $host_facts['sku_role'] = 'DOMAIN_CONTROLLER' }
        3 { $host_facts['sku_role'] = 'SERVER' }
        default { $host_facts['sku_role'] = 'UNKNOWN' }
    }
} else {
    $host_facts['sku_role'] = 'NOT_DETERMINED'
}
if ($cs) {
    $host_facts['manufacturer']   = $cs.Manufacturer
    $host_facts['model']          = $cs.Model
    $host_facts['domain']         = $cs.Domain
    $host_facts['part_of_domain'] = [bool]$cs.PartOfDomain
    if ($cs.PartOfDomain) { $host_facts['domain_state'] = 'DOMAIN_JOINED' }
    else                  { $host_facts['domain_state'] = 'WORKGROUP' }
    $host_facts['logical_processors'] = $cs.NumberOfLogicalProcessors
    $host_facts['total_memory_bytes'] = $cs.TotalPhysicalMemory
}
$host_facts['processor_arch_env'] = $env:PROCESSOR_ARCHITECTURE
$R['host'] = $host_facts

# ── shell / elevation ───────────────────────────────────────────────
$shell = [ordered]@{}
$shell['powershell_version'] = $PSVersionTable.PSVersion.ToString()
$shell['powershell_edition'] = $PSVersionTable.PSEdition
$shell['clr_version']        = $PSVersionTable.CLRVersion -as [string]
$shell['execution_policy']   = (Get-ExecutionPolicy).ToString()
$shell['current_user']       = "$env:USERDOMAIN\$env:USERNAME"
try {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr  = New-Object Security.Principal.WindowsPrincipal($id)
    $shell['is_elevated'] = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $shell['is_elevated'] = $null
    $shell['elevation_error'] = $_.Exception.Message
}
$R['shell'] = $shell

# ── runtime prerequisites (NivXForge EDR collector) ─────────────────
function Get-CommandVersion([string]$exe, [string[]]$argList) {
    $out = [ordered]@{}
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $out['state'] = 'NOT_PRESENT'; return $out }
    $out['state'] = 'PRESENT'
    $out['path']  = $cmd.Source
    try   { $out['version'] = (& $exe @argList 2>&1 | Out-String).Trim() }
    catch { $out['version'] = $null; $out['error'] = $_.Exception.Message }
    return $out
}

$pre = [ordered]@{}
$pre['python']  = Get-CommandVersion 'python' @('--version')
$pre['py']      = Get-CommandVersion 'py'     @('-3','--version')
$pre['pip']     = Get-CommandVersion 'pip'    @('--version')
$pre['git']     = Get-CommandVersion 'git'    @('--version')
# pywin32 is the ONLY hard Windows-specific dependency of the acquisition
# path (win32evtlog · EvtSubscribe/EvtCreateBookmark).
$pywin32 = [ordered]@{}
if ($pre['python']['state'] -eq 'PRESENT') {
    $probe = & python -c "import win32evtlog,sys;print('OK',getattr(win32evtlog,'__file__','?'))" 2>&1 | Out-String
    if ($probe -match '^OK') {
        $pywin32['state'] = 'IMPORTABLE'
        $pywin32['detail'] = $probe.Trim()
    } else {
        $pywin32['state'] = 'NOT_IMPORTABLE'
        $pywin32['detail'] = $probe.Trim()
        $pywin32['note']   = 'expected before setup; pip install pywin32 happens in the runbook, not here'
    }
} else {
    $pywin32['state'] = 'NOT_EVALUATED'
    $pywin32['note']  = 'python not present on PATH'
}
$pre['pywin32'] = $pywin32
$pre['dotnet_framework_release'] = $null
try {
    $ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
    $pre['dotnet_framework_release'] = $ndp.Release
} catch { }
$R['prerequisites'] = $pre

# ── Sysmon (reported, never installed) ──────────────────────────────
$sysmon = [ordered]@{}
$svc = Get-Service -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue
if ($svc) {
    $sysmon['state']       = 'INSTALLED'
    $sysmon['services']    = @($svc | ForEach-Object { @{ name = $_.Name; status = $_.Status.ToString() } })
    $drv = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match 'Sysmon' }
    if ($drv) { $sysmon['drivers'] = @($drv | ForEach-Object { @{ name = $_.Name; state = $_.State } }) }
    $bin = Get-Command 'Sysmon64.exe','Sysmon.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($bin) {
        $sysmon['binary_path'] = $bin.Source
        try { $sysmon['binary_version'] = (Get-Item $bin.Source).VersionInfo.ProductVersion } catch { }
    }
} else {
    $sysmon['state'] = 'NOT_INSTALLED'
    $sysmon['consequence'] = 'Microsoft-Windows-Sysmon/Operational will be reported NOT_PRESENT. That is NOT_OBSERVED, not "no activity", and Sysmon will not be installed without separate owner approval.'
}
$R['sysmon'] = $sysmon

# ── Windows Event Log channel inventory ─────────────────────────────
# The channel list the existing NivXForge EDR adapter declares
# (`framework/windows_eventlog.py :: CHANNELS`) plus the G1 representative
# set. Reading a log's configuration is read-only.
$channels = @(
    'Security',
    'System',
    'Application',
    'Setup',
    'ForwardedEvents',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Windows PowerShell',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-WinRM/Operational',
    'Microsoft-Windows-DNS-Client/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-SmbClient/Security',
    'Microsoft-Windows-DNSServer/Audit',
    'Microsoft-Windows-BitLocker/BitLocker Management',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Directory Service'
)

$rows = @()
foreach ($ch in $channels) {
    $row = [ordered]@{}
    $row['channel'] = $ch
    $log = $null
    try { $log = Get-WinEvent -ListLog $ch -ErrorAction Stop } catch { $row['list_error'] = $_.Exception.Message }
    if (-not $log) {
        $row['presence'] = 'NOT_PRESENT'
        $row['readable'] = 'NOT_EVALUATED'
        $rows += $row
        continue
    }
    $row['presence']          = 'PRESENT'
    $row['is_enabled']        = [bool]$log.IsEnabled
    $row['log_mode']          = $log.LogMode.ToString()
    $row['max_size_bytes']    = $log.MaximumSizeInBytes
    $row['file_size_bytes']   = $log.FileSize
    $row['record_count']      = $log.RecordCount
    $row['oldest_record_number'] = $log.OldestRecordNumber
    $row['last_write_time']   = $log.LastWriteTime
    $row['log_file_path']     = $log.LogFilePath
    if ($log.RecordCount -eq 0) { $row['observation'] = 'PRESENT_NO_RECORDS' }
    else                        { $row['observation'] = 'PRESENT_WITH_RECORDS' }
    # One-record read probe: proves THIS account can actually read the
    # channel (Security in particular). Read-only, no bookmark written.
    try {
        $probe = Get-WinEvent -LogName $ch -MaxEvents 1 -ErrorAction Stop
        if ($probe) {
            $row['readable'] = 'READ_OK'
            $row['probe_provider'] = $probe.ProviderName
            $row['probe_event_id'] = $probe.Id
            $row['probe_record_id'] = $probe.RecordId
            $row['probe_time_created_utc'] = $probe.TimeCreated.ToUniversalTime().ToString('o')
        } else {
            $row['readable'] = 'READ_OK_NO_RECORD'
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') { $row['readable'] = 'READ_OK_NO_RECORD' }
        elseif ($msg -match 'Attempted to perform an unauthorized operation|Access is denied') {
            $row['readable'] = 'READ_DENIED'
            $row['read_error'] = $msg
        } else {
            $row['readable'] = 'READ_ERROR'
            $row['read_error'] = $msg
        }
    }
    $rows += $row
}
$R['channels'] = $rows

$summary = [ordered]@{}
$summary['channels_queried']  = $rows.Count
$summary['channels_present']  = @($rows | Where-Object { $_.presence -eq 'PRESENT' }).Count
$summary['channels_readable'] = @($rows | Where-Object { $_.readable -eq 'READ_OK' }).Count
$summary['channels_denied']   = @($rows | Where-Object { $_.readable -eq 'READ_DENIED' }).Count
$summary['channels_absent']   = @($rows | Where-Object { $_.presence -eq 'NOT_PRESENT' }).Count
$summary['truth_note'] = 'NOT_PRESENT means the channel does not exist on this host. PRESENT_NO_RECORDS means it exists and has not recorded anything. READ_DENIED means this account could not read it. None of these mean "no activity occurred".'
$R['summary'] = $summary

# ── collector-side environment already set on this host (read-only) ─
$envs = [ordered]@{}
foreach ($k in @('NIVX_TENANT_ID','NIVX_COLLECTOR_ID','NIVX_INGEST_URL',
                 'NIVX_INGEST_AUTH_MODE','XDR_STATE_DIR',
                 'XDR_AUTO_START_CONNECTORS')) {
    $v = [Environment]::GetEnvironmentVariable($k)
    if ($null -eq $v -or $v -eq '') { $envs[$k] = 'NOT_SET' } else { $envs[$k] = $v }
}
# The credential is never printed — only whether one is present.
$tok = [Environment]::GetEnvironmentVariable('NIVX_INGEST_TOKEN')
if ($null -eq $tok -or $tok -eq '') { $envs['NIVX_INGEST_TOKEN'] = 'NOT_SET' }
else { $envs['NIVX_INGEST_TOKEN'] = 'SET_VALUE_NOT_PRINTED' }
$R['collector_environment'] = $envs

$net = [ordered]@{}
if ($envs['NIVX_INGEST_URL'] -ne 'NOT_SET') {
    try {
        $u = [Uri]$envs['NIVX_INGEST_URL']
        $port = $u.Port
        $t = $null
        if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
            $t = Test-NetConnection -ComputerName $u.Host -Port $port -InformationLevel Quiet -ErrorAction Stop
        } else {
            $c = New-Object Net.Sockets.TcpClient
            $t = $c.ConnectAsync($u.Host, $port).Wait(5000)
            $c.Close()
        }
        $net['ingest_host'] = $u.Host
        $net['ingest_port'] = $port
        $net['tcp_reachable'] = $t
    } catch { $net['probe_error'] = $_.Exception.Message }
} else {
    $net['state'] = 'NOT_EVALUATED_NO_INGEST_URL'
}
$R['network'] = $net

# ── emit ────────────────────────────────────────────────────────────
$json = $R | ConvertTo-Json -Depth 8
$out  = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'nivxray-g1-preflight.json'
try { $json | Out-File -FilePath $out -Encoding UTF8 } catch { }
Write-Output $json
Write-Output ''
Write-Output "# JSON also written to: $out"
Write-Output '# READ-ONLY: nothing on this host was installed, enabled or modified.'
