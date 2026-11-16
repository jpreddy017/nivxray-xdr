"""Bounded Windows forensic metadata collection. No caller-supplied code runs.

Each category is an independent, timestamped observation, not an atomic disk
or memory image. Registry execution artifacts are preserved as raw values;
their presence is not interpreted as proof that a program executed.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from datetime import datetime, timezone

VERSION = '2026.11.16.1'
MAX_ROWS = 256
MAX_CATEGORY_BYTES = 262144
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_CATEGORY_SECONDS = 15
MAX_TOTAL_SECONDS = 300

# Fixed PowerShell programs only. A request can select keys, never script text,
# paths, SQL, filters, arguments, or executable names.
CATALOG = {
 'autoexec': ('Autoexec items', "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User", False),
 'bitlocker': ('BitLocker encryption', "Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod,LockStatus", False),
 'dns_cache': ('DNS cache', "Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,Status,Section,TimeToLive,Data", True),
 'hosts': ('Hosts file', "$p=Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'; if([IO.File]::Exists($p)){if(([IO.FileInfo]$p).Length -gt 262144){throw 'Hosts file exceeds read limit'};$n=0;[IO.File]::ReadAllLines($p)|Select-Object -First 257|ForEach-Object{$n++;[pscustomobject]@{line=$n;text=$_}}}", False),
 'installed_programs': ('Installed programs', "@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*') | ForEach-Object {Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue} | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,PSPath", False),
 'listening_ports': ('Listening ports', "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime; Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime", False),
 'module_hashes': ('Loaded module hashes', "Modules | Select-Object -ExpandProperty FileName -Unique | ForEach-Object {HashFile $_}", False),
 'module_processes': ('Loaded module processes', "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate", False),
 'module_mapping': ('Modules mapped to processes', "Modules", False),
 'logon_sessions': ('Logon sessions', "Get-CimInstance Win32_LogonSession | Select-Object LogonId,LogonType,StartTime,AuthenticationPackage", False),
 'mapped_drives': ('Mapped drives', "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,ProviderName,FileSystem,VolumeName,Size,FreeSpace;Get-CimInstance Win32_MappedLogicalDisk | Select-Object Name,ProviderName,SessionID", False),
 'network_processes': ('Network connections and processes', "$p=@{};Get-CimInstance Win32_Process|ForEach-Object{$p[[int]$_.ProcessId]=$_};Get-NetTCPConnection|ForEach-Object{$x=$p[[int]$_.OwningProcess];[pscustomobject]@{protocol='TCP';local_address=$_.LocalAddress;local_port=$_.LocalPort;remote_address=$_.RemoteAddress;remote_port=$_.RemotePort;state=[string]$_.State;pid=$_.OwningProcess;image=$x.ExecutablePath;command_line=$x.CommandLine}}", True),
 'network_interfaces': ('Network interfaces', "Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description,InterfaceIndex,MACAddress,IPEnabled,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,DHCPEnabled", False),
 'network_profiles': ('Network profile registry', "RegTree 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles' 1", True),
 'os_version': ('Operating system', "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime,LocalDateTime", False),
 'powershell_history': ('PowerShell history', "Profiles | ForEach-Object {$p=Join-Path $_ 'AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt';if(Test-Path -LiteralPath $p){$n=0;Get-Content -LiteralPath $p -Tail 257|ForEach-Object{$n++;[pscustomobject]@{path=$p;tail_line=$n;text=$_}}}}", True),
 'prefetch': ('Prefetch directory', "$p=Join-Path $env:SystemRoot 'Prefetch';if(Test-Path -LiteralPath $p){Get-ChildItem -LiteralPath $p -File|Select-Object Name,FullName,Length,CreationTimeUtc,LastWriteTimeUtc}", True),
 'recent_files': ('Recent files', "Profiles|ForEach-Object{$p=Join-Path $_ 'AppData\\Roaming\\Microsoft\\Windows\\Recent';if(Test-Path -LiteralPath $p){Get-ChildItem -LiteralPath $p -File|Select-Object Name,FullName,Length,CreationTimeUtc,LastWriteTimeUtc}}", True),
 'running_hashes': ('Running executable hashes', "Get-CimInstance Win32_Process|ForEach-Object{$h=HashFile $_.ExecutablePath;[pscustomobject]@{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;command_line=$_.CommandLine;sha256=$h.sha256;hash_state=$h.state}}", True),
 'services': ('Running services', "Get-CimInstance Win32_Service|Select-Object Name,DisplayName,State,StartMode,ProcessId,PathName,StartName,ServiceType", False),
 'scheduled_tasks': ('Scheduled tasks', "Get-ScheduledTask|Select-Object TaskName,TaskPath,State,@{n='Actions';e={@($_.Actions|Select-Object Execute,Arguments,WorkingDirectory)}},@{n='Principal';e={$_.Principal.UserId}}", False),
 'shares': ('Shared resources', "Get-CimInstance Win32_Share|Select-Object Name,Path,Type,Description", False),
 'startup': ('Startup registry items', "@('Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce','Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run')|ForEach-Object{RegTree $_ 0};UserReg 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' 0;UserReg 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' 0", False),
 'network_state': ('System network statistics', "Get-NetAdapterStatistics | Select-Object Name,InterfaceDescription,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets,ReceivedDiscardedPackets,OutboundDiscardedPackets", False),
 'temp_files': ('Temporary file metadata', "@($env:TEMP,(Join-Path $env:SystemRoot 'Temp'))|Select-Object -Unique|ForEach-Object{if(Test-Path -LiteralPath $_){Get-ChildItem -LiteralPath $_ -File|Select-Object Name,FullName,Length,CreationTimeUtc,LastWriteTimeUtc}}", True),
 'root_certificates': ('Trusted root certificates', "$store=New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');try{$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly);$store.Certificates|Select-Object Subject,Issuer,Thumbprint,SerialNumber,NotBefore,NotAfter,HasPrivateKey}finally{$store.Close()}", False),
 'usb_history': ('USB storage registry', "RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR' 2", True),
 'groups': ('Local user groups', "Get-CimInstance Win32_Group -Filter 'LocalAccount=True'|Select-Object Name,Domain,SID,Description,Status", False),
 'userassist': ('UserAssist registry', "UserReg 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist' 2", True),
 'users': ('Local users', "Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True'|Select-Object Name,Domain,SID,Disabled,Lockout,Status,PasswordRequired", False),
 'logged_in_users': ('Logged-in users', "Get-CimInstance Win32_LoggedOnUser|Select-Object @{n='user';e={[string]$_.Antecedent}},@{n='session';e={[string]$_.Dependent}}", False),
 'wmi_filters': ('WMI event filters', "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter|Select-Object Name,Query,QueryLanguage,EventNamespace;Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding|Select-Object Filter,Consumer", False),
 'antivirus': ('Windows antivirus products', "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|Select-Object displayName,instanceGuid,pathToSignedProductExe,pathToSignedReportingExe,productState,timestamp", False),
 'bam': ('Windows BAM registry', "RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings' 2;RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings' 2", True),
 'environment': ('Windows environment variables', "[Environment]::GetEnvironmentVariables('Machine').GetEnumerator()|ForEach-Object{[pscustomobject]@{scope='Machine';name=$_.Key;value=$_.Value}};UserReg 'Environment' 0", True),
 'hotfixes': ('Windows hotfixes', "Get-CimInstance Win32_QuickFixEngineering|Select-Object HotFixID,Description,InstalledBy,InstalledOn,Caption", False),
 'nt_domains': ('Windows NT domains', "Get-CimInstance Win32_NTDomain|Select-Object DomainName,DnsForestName,DomainControllerName,DomainControllerAddress,Status", False),
 'shellbags': ('Windows ShellBags registry', "UserReg 'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU' 3;UserReg 'Software\\Microsoft\\Windows\\Shell\\BagMRU' 3", True),
 'shimcache': ('Windows ShimCache registry', "RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache' 0", True),
 'chrome_extensions': ('Chrome extensions', "Profiles|ForEach-Object{$root=Join-Path $_ 'AppData\\Local\\Google\\Chrome\\User Data';if(Test-Path -LiteralPath $root){Get-ChildItem -LiteralPath $root -Directory|Select-Object -First 32|ForEach-Object{$ext=Join-Path $_.FullName 'Extensions';if(Test-Path -LiteralPath $ext){Get-ChildItem -Path ($ext+'\\*\\*\\manifest.json') -File|Select-Object -First 257|ForEach-Object{if($_.Length -lt 131072){$m=Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json;[pscustomobject]@{path=$_.FullName;name=$m.name;version=$m.version;permissions=$m.permissions}}}}}}}", True),
 'office_mru': ('Office recent files registry', "UserReg 'Software\\Microsoft\\Office\\16.0\\Word\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\16.0\\Excel\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\15.0\\Word\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\15.0\\Excel\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\15.0\\PowerPoint\\File MRU' 0", True),
}

HELPERS = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$script:issues=New-Object System.Collections.Generic.List[string]
function Issue($s){if($script:issues.Count -lt 20){$script:issues.Add([string]$s)}}
function Profiles {Get-CimInstance Win32_UserProfile|Where-Object {$_.LocalPath -and -not $_.Special}|Select-Object -First 32 -ExpandProperty LocalPath}
function RegTree($path,$depth){
 if(-not(Test-Path -LiteralPath $path)){return}
 $keys=@(Get-Item -LiteralPath $path)
 if($depth -gt 0){$regErrors=@();$children=@(Get-ChildItem -LiteralPath $path -Recurse -Depth $depth -ErrorAction SilentlyContinue -ErrorVariable regErrors|Select-Object -First 257);if($regErrors.Count){Issue 'Registry traversal had inaccessible keys'};if($children.Count -gt 256){Issue 'Registry key limit reached'};$keys+=@($children|Select-Object -First 256)}
 foreach($key in $keys){try{$names=@($key.GetValueNames());if($names.Count -gt 64){Issue 'Registry value count limit reached'};foreach($name in $names|Select-Object -First 64){$v=$key.GetValue($name,$null,'DoNotExpandEnvironmentNames');$truncated=$false;$encoding='native';if($v -is [byte[]]){$encoding='base64';if($v.Length -gt 32768){$v=$v[0..32767];$truncated=$true;Issue 'Registry binary value was truncated'};$v=[Convert]::ToBase64String($v)};[pscustomobject]@{path=$key.Name;name=$name;kind=[string]$key.GetValueKind($name);value=$v;encoding=$encoding;value_truncated=$truncated}}}catch{Issue 'One or more registry values could not be read'}}
}
function UserReg($suffix,$depth){Get-ChildItem Registry::HKEY_USERS|Where-Object {$_.PSChildName -match '^S-1-5-21-'}|Select-Object -First 32|ForEach-Object{RegTree ('Registry::'+$_.Name+'\'+$suffix) $depth}}
function HashFile($path){if(-not $path){return [pscustomobject]@{path=$path;state='PATH_UNAVAILABLE';sha256=$null}};try{$f=Get-Item -LiteralPath $path;if($f.Length -gt 67108864){return [pscustomobject]@{path=$path;state='SIZE_LIMIT';sha256=$null}};[pscustomobject]@{path=$path;state='HASHED';sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}}catch{[pscustomobject]@{path=$path;state='UNREADABLE';sha256=$null}}}
function Modules {Get-Process|Select-Object -First 256|ForEach-Object{$p=$_;try{$p.Modules|Select-Object -First 256|ForEach-Object{[pscustomobject]@{pid=$p.Id;process=$p.ProcessName;ModuleName=$_.ModuleName;FileName=$_.FileName;BaseAddress=[string]$_.BaseAddress;ModuleMemorySize=$_.ModuleMemorySize}}}catch{Issue 'Modules of one or more processes were inaccessible'}}}
'''

def now():
    return datetime.now(timezone.utc).isoformat()

def manifest():
    return [{'id': key, 'name': row[0], 'sensitive': row[2],
             'platform': 'windows', 'collector_version': VERSION}
            for key, row in CATALOG.items()]

def script_for(key):
    # Pipeline row bound is inside the process, before serialization.
    return HELPERS + '\ntry{$rows=@(& {\n' + CATALOG[key][1] + '\n}|Select-Object -First 257);[pscustomobject]@{rows=@($rows|Select-Object -First 256);truncated=($rows.Count -gt 256);issues=@($script:issues.ToArray())}|ConvertTo-Json -Depth 8 -Compress}catch{[pscustomobject]@{error=$_.Exception.GetType().Name;message="Collector query failed; provider may be unavailable or access denied"}|ConvertTo-Json -Compress;exit 2}'

def run_query(key, timeout=MAX_CATEGORY_SECONDS, cancelled=lambda:False):
    executable = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if os.name != 'nt' or not executable.is_file():
        return {'state': 'UNSUPPORTED_PLATFORM', 'rows': [], 'detail': 'Requires Windows PowerShell and the named Windows providers.'}
    encoded = base64.b64encode(script_for(key).encode('utf-16le')).decode('ascii')
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], stdin=subprocess.DEVNULL, stdout=output, stderr=errors, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        started = time.monotonic()
        failure = None
        try:
            while process.poll() is None:
                if cancelled():
                    failure = 'INTERRUPTED'; break
                if time.monotonic() - started > timeout:
                    failure = 'TIMED_OUT'; break
                if os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > MAX_CATEGORY_BYTES:
                    failure = 'OUTPUT_LIMIT'; break
                time.sleep(.05)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        if failure:
            return {'state': failure, 'rows': [], 'detail': 'Collection stopped at its resource bound; no complete result is claimed.'}
        output.seek(0)
        raw = output.read(MAX_CATEGORY_BYTES + 1)
        if len(raw) > MAX_CATEGORY_BYTES:
            return {'state': 'OUTPUT_LIMIT', 'rows': []}
        try:
            value = json.loads(raw.decode('utf-8-sig'))
        except (ValueError, UnicodeError):
            return {'state': 'FAILED', 'rows': [], 'detail': 'Provider did not return valid JSON.'}
        if process.returncode or value.get('error'):
            return {'state': 'UNAVAILABLE', 'rows': [], 'detail': value.get('message', 'Provider unavailable.'), 'error_type': value.get('error')}
        rows = value.get('rows')
        if not isinstance(rows, list):
            return {'state': 'FAILED', 'rows': [], 'detail': 'Provider returned an invalid row envelope.'}
        partial = bool(value.get('truncated') or value.get('issues'))
        return {'state': 'PARTIAL' if partial else 'COLLECTED', 'rows': rows[:MAX_ROWS], 'rows_truncated': bool(value.get('truncated')), 'issues': value.get('issues', [])}

def collect(categories=None, *, include_sensitive=False, runner=run_query, cancelled=lambda:False):
    keys = list(CATALOG) if categories is None else list(categories)
    if not keys or len(keys) > len(CATALOG) or len(set(keys)) != len(keys) or any(k not in CATALOG for k in keys):
        raise ValueError('Unknown, duplicate or empty snapshot category selection')
    started = now(); deadline = time.monotonic() + MAX_TOTAL_SECONDS
    results = []; total = 0
    for key in keys:
        begin = now()
        if CATALOG[key][2] and not include_sensitive:
            result = {'state': 'NOT_SELECTED', 'rows': [], 'detail': 'Sensitive-artifact profile was not selected.'}
        elif cancelled() or time.monotonic() >= deadline or total >= MAX_TOTAL_BYTES:
            result = {'state': 'BUDGET_EXHAUSTED', 'rows': [], 'detail': 'Snapshot time or size budget exhausted.'}
        else:
            try:
                result = runner(key, timeout=max(.1,min(MAX_CATEGORY_SECONDS,deadline-time.monotonic())))
            except Exception as exc:
                result = {'state': 'FAILED', 'rows': [], 'detail': type(exc).__name__}
        result = {**result, 'category_id': key, 'name': CATALOG[key][0], 'capture_started_at': begin, 'capture_finished_at': now()}
        size = len(json.dumps(result, ensure_ascii=False).encode('utf-8'))
        if total + size > MAX_TOTAL_BYTES:
            result.update(state='OUTPUT_LIMIT', rows=[], detail='Snapshot total output limit reached.')
        result['row_count'] = len(result.get('rows', []))
        total += len(json.dumps(result,ensure_ascii=False).encode('utf-8'))
        results.append(result)
    evidence = {'schema':'nivxforge.windows-forensic-snapshot.v1','collector_version':VERSION,
                'capture_started_at':started,'capture_finished_at':now(),'categories':results,
                'collection_basis':'Independent bounded endpoint queries during the capture interval; not an atomic disk or memory image.',
                'limitations':['Registry values are raw artifacts, not parsed execution verdicts.','User registry collection covers loaded hives only; offline hives are not mounted.','History can contain credentials and is collected only in the sensitive profile.','Filesystem artifact categories contain metadata; file contents are not a disk acquisition.','Permissions, missing providers, row limits and deadline limits can reduce coverage.']}
    evidence['sha256'] = hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()
    return evidence
