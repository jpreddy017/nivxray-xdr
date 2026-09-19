<#
  W2-R0 · READ-ONLY WINDOWS PRE-FLIGHT for the NivXRay XDR collector.

  This script CHANGES NOTHING. It does not install Python, pywin32 or Sysmon,
  does not register a service, does not touch audit policy, Defender, the
  firewall or any Event Log, and does not enrol the machine. Every call is a
  query.

  Values are taken from the actual implementation, not from examples:
    · channel names           framework/windows_eventlog.py :: CHANNELS
    · first profile           framework/windows_eventlog.py :: VALIDATION_PROFILE
    · runtime + dependencies  apps/nivxray-xdr-collector/requirements.txt,
                              Dockerfile (python:3.11-slim), pywin32 for
                              win32evtlog
    · ingest endpoint         frontend/.env REACT_APP_BACKEND_URL +
                              routers/xdr_ingest.py (prefix /api/xdr/ingest,
                              POST /telemetry)

  It prints NO secrets — at this gate none exist yet.
#>

$ErrorActionPreference = 'SilentlyContinue'
$INGEST = 'https://greeting-app-5782.preview.emergentagent.com/api/xdr/ingest/telemetry'
$STATE  = 'C:\ProgramData\NivXRay\state'
$R = [ordered]@{}

Write-Host "`n=== W2-R0 · NivXRay XDR Windows pre-flight (READ-ONLY) ===`n" -ForegroundColor Cyan

# ── R0-1 · host identity, edition, role, privilege ───────────────
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$adm = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
       ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# DomainRole: 0/1 workstation · 2/3 member server · 4/5 domain controller
$R['os_caption']       = $os.Caption
$R['os_version']       = $os.Version
$R['os_build']         = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
$R['architecture']     = $os.OSArchitecture
$R['hostname']         = $env:COMPUTERNAME
$R['is_administrator'] = $adm
$R['product_type']     = switch ($os.ProductType) { 1 {'WORKSTATION'} 2 {'DOMAIN_CONTROLLER'} 3 {'SERVER'} default {'UNKNOWN'} }
$R['domain_role']      = $cs.DomainRole
$R['is_domain_controller'] = ($cs.DomainRole -in 4,5)
$R['domain_joined']    = $cs.PartOfDomain
$R['domain_or_workgroup'] = if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup }
$R['time_sync']        = (w32tm /query /status 2>&1 | Select-String 'Source' | Out-String).Trim()

# ── R0-2 · runtime the collector actually needs ──────────────────
$py = @()
foreach ($c in @('py -3.11','python','python3')) {
  $v = & cmd /c "$c --version 2>&1"
  if ($LASTEXITCODE -eq 0 -and $v) { $py += "$c => $v" }
}
$R['python_found']   = if ($py) { $py -join ' | ' } else { 'NONE' }
$R['python_bitness'] = & cmd /c "py -3.11 -c ""import struct,sys;print(struct.calcsize('P')*8,'bit',sys.version.split()[0])"" 2>&1"
$R['pywin32']        = & cmd /c "py -3.11 -c ""import win32evtlog;print('win32evtlog OK')"" 2>&1"
foreach ($m in 'httpx','fastapi','uvicorn','dotenv') {
  $R["pkg_$m"] = & cmd /c "py -3.11 -c ""import $m;print(getattr($m,'__version__','present'))"" 2>&1"
}

# ── R0-3 · Sysmon (presence only — NOT installed by this script) ─
$sys = Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue
$R['sysmon_service'] = if ($sys) { ($sys | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ',' } else { 'NOT INSTALLED' }
$R['sysmon_driver']  = if (Get-Service -Name SysmonDrv -ErrorAction SilentlyContinue) { 'present' } else { 'absent' }

# ── R0-4 · channel availability · EXACT names from CHANNELS ──────
$channels = @(
  'Microsoft-Windows-Sysmon/Operational',                      # windows-validation
  'Security',                                                  # windows-validation
  'Microsoft-Windows-PowerShell/Operational',                  # windows-validation
  'Windows PowerShell',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-TaskScheduler/Operational',
  'Microsoft-Windows-WMI-Activity/Operational',
  'Microsoft-Windows-AppLocker/EXE and DLL',
  'System',
  'Application'
)
$chanRows = foreach ($c in $channels) {
  $log = Get-WinEvent -ListLog $c -ErrorAction SilentlyContinue
  if ($log) {
    [pscustomobject]@{
      Channel = $c; State = 'PRESENT'; Enabled = $log.IsEnabled
      Records = $log.RecordCount; MaxSizeMB = [math]::Round($log.MaximumSizeInBytes/1MB,0)
      Newest  = try { (Get-WinEvent -LogName $c -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { 'UNREADABLE_AS_THIS_USER' }
    }
  } else {
    [pscustomobject]@{ Channel=$c; State='NOT PRESENT'; Enabled=$null
                       Records=$null; MaxSizeMB=$null; Newest=$null }
  }
}

# ── R0-5 · audit policy VISIBILITY (read-only; nothing changed) ──
$R['audit_policy_readable'] = if ((auditpol /get /category:* 2>&1 | Measure-Object -Line).Lines -gt 5) { 'READABLE' } else { 'NOT READABLE' }
$R['audit_process_creation'] = (auditpol /get /subcategory:"Process Creation" 2>&1 | Select-String 'Process Creation' | Out-String).Trim()
$R['audit_logon'] = (auditpol /get /subcategory:"Logon" 2>&1 | Select-String 'Logon' | Select-Object -First 1 | Out-String).Trim()

# ── R0-6 · outbound reachability + TLS to the REAL endpoint ──────
$u = [uri]$INGEST
$R['ingest_url'] = $INGEST
$tnc = Test-NetConnection -ComputerName $u.Host -Port 443 -WarningAction SilentlyContinue
$R['tcp_443'] = if ($tnc.TcpTestSucceeded) { 'PASS' } else { 'BLOCKED' }
$R['dns_resolves'] = ($tnc.RemoteAddress).IPAddressToString
$R['proxy_env'] = "HTTPS_PROXY=$($env:HTTPS_PROXY) HTTP_PROXY=$($env:HTTP_PROXY)"
$R['winhttp_proxy'] = (netsh winhttp show proxy 2>&1 | Out-String).Trim()
# An UNAUTHENTICATED probe. 401/403 is the CORRECT answer: it proves TLS and
# reachability while proving the endpoint refuses unauthenticated delivery.
try {
  $resp = Invoke-WebRequest -Uri $INGEST -Method POST -Body '{"envelopes":[]}' `
            -ContentType 'application/json' -UseBasicParsing -TimeoutSec 20
  $R['ingest_unauth_status'] = $resp.StatusCode
} catch {
  $R['ingest_unauth_status'] = $_.Exception.Response.StatusCode.value__
  if (-not $R['ingest_unauth_status']) { $R['ingest_unauth_status'] = "NO RESPONSE: $($_.Exception.Message)" }
}
$R['tls_cert_subject'] = try {
  $c = [Net.HttpWebRequest]::Create("https://$($u.Host)")
  $c.Timeout = 15000; $null = $c.GetResponse(); $c.ServicePoint.Certificate.Subject
} catch { "TLS CHECK FAILED: $($_.Exception.Message)" }

# ── R0-7 · durable-queue disk + state path ───────────────────────
$drive = Get-PSDrive -Name ($STATE.Substring(0,1))
$R['state_dir']        = $STATE
$R['state_dir_exists'] = Test-Path $STATE
$R['free_gb']          = [math]::Round($drive.Free/1GB,2)
$R['free_gb_required'] = 2

Write-Host '--- HOST / RUNTIME / CONNECTIVITY ---' -ForegroundColor Yellow
$R.GetEnumerator() | ForEach-Object { '{0,-26} {1}' -f $_.Key, $_.Value }
Write-Host "`n--- EVENT LOG CHANNELS ---" -ForegroundColor Yellow
$chanRows | Format-Table -AutoSize

Write-Host "`n--- PASTE THIS JSON BACK (contains no secrets) ---" -ForegroundColor Cyan
[pscustomobject]@{ host=$R; channels=$chanRows } | ConvertTo-Json -Depth 5
