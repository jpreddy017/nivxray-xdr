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

VERSION = '2026.11.16.4'
MAX_ROWS = 10000
MAX_CATEGORY_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_CATEGORY_SECONDS = 30
MAX_TOTAL_SECONDS = 600

# Fixed PowerShell programs only. A request can select keys, never script text,
# paths, SQL, filters, arguments, or executable names.
CATALOG = {
 'autoexec': ('Autoexec items', "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User", False),
 'bitlocker': ('BitLocker encryption', "Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod,LockStatus", False),
 'dns_cache': ('DNS cache', "Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,Status,Section,TimeToLive,Data", True),
 'hosts': ('Hosts file', "$p=Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'; if([IO.File]::Exists($p)){if(([IO.FileInfo]$p).Length -gt 262144){throw 'Hosts file exceeds read limit'};$n=0;[IO.File]::ReadAllLines($p)|Select-Object -First 10001|ForEach-Object{$n++;[pscustomobject]@{line=$n;text=$_}}}", False),
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
 'powershell_history': ('PowerShell history', "PowerShellHistory", True),
 'prefetch': ('Prefetch directory', "$p=Join-Path $env:SystemRoot 'Prefetch';if(Test-Path -LiteralPath $p){Get-ChildItem -LiteralPath $p -File|Select-Object Name,FullName,Length,CreationTimeUtc,LastWriteTimeUtc}", True),
 'recent_files': ('Recent files', "Profiles|ForEach-Object{$p=Join-Path $_ 'AppData\\Roaming\\Microsoft\\Windows\\Recent';if(Test-Path -LiteralPath $p){Get-ChildItem -LiteralPath $p -File|Select-Object Name,FullName,Length,CreationTimeUtc,LastWriteTimeUtc}}", True),
 'running_hashes': ('Running executable hashes', "Get-CimInstance Win32_Process|ForEach-Object{$h=HashFile $_.ExecutablePath;$owner=$null;$ownerState='UNAVAILABLE';try{$o=Invoke-CimMethod -InputObject $_ -MethodName GetOwner;if($o.ReturnValue -eq 0){$owner=$o.Domain+'\'+$o.User;$ownerState='COLLECTED'}}catch{Issue 'Process owner was inaccessible'};[pscustomobject]@{owner=$owner;owner_state=$ownerState;pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;command_line=$_.CommandLine;sha256=$h.sha256;hash_state=$h.state}}", True),
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
 'logged_in_users': ('Logged-in users', "$sessions=@{};Get-CimInstance Win32_LogonSession|ForEach-Object{$sessions[[string]$_.LogonId]=$_};Get-CimInstance Win32_LoggedOnUser|ForEach-Object{$u=$_.Antecedent;$s=$sessions[[string]$_.Dependent.LogonId];[pscustomobject]@{user=$u.Name;domain=$u.Domain;logon_id=$_.Dependent.LogonId;logon_type=$s.LogonType;start_time=$s.StartTime;authentication_package=$s.AuthenticationPackage}}", False),
 'wmi_filters': ('WMI event filters', "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter|Select-Object Name,Query,QueryLanguage,EventNamespace;Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding|Select-Object Filter,Consumer", False),
 'antivirus': ('Windows antivirus products', "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|Select-Object displayName,instanceGuid,pathToSignedProductExe,pathToSignedReportingExe,productState,timestamp", False),
 'bam': ('Windows BAM registry', "RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings' 2;RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings' 2", True),
 'environment': ('Windows environment variables', "[Environment]::GetEnvironmentVariables('Machine').GetEnumerator()|ForEach-Object{[pscustomobject]@{scope='Machine';name=$_.Key;value=$_.Value}};UserReg 'Environment' 0", True),
 'hotfixes': ('Windows hotfixes', "Get-CimInstance Win32_QuickFixEngineering|Select-Object HotFixID,Description,InstalledBy,InstalledOn,Caption", False),
 'nt_domains': ('Windows NT domains', "Get-CimInstance Win32_NTDomain|Select-Object DomainName,DnsForestName,DomainControllerName,DomainControllerAddress,Status", False),
 'shellbags': ('Windows ShellBags registry', "UserReg 'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU' 3;UserReg 'Software\\Microsoft\\Windows\\Shell\\BagMRU' 3", True),
 'shimcache': ('Windows ShimCache registry', "RegTree 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache' 0", True),
 'chrome_extensions': ('Chrome extensions', "Profiles|ForEach-Object{$root=Join-Path $_ 'AppData\\Local\\Google\\Chrome\\User Data';if(Test-Path -LiteralPath $root){Get-ChildItem -LiteralPath $root -Directory|Select-Object -First 32|ForEach-Object{$ext=Join-Path $_.FullName 'Extensions';if(Test-Path -LiteralPath $ext){Get-ChildItem -Path ($ext+'\\*\\*\\manifest.json') -File|Select-Object -First 10001|ForEach-Object{if($_.Length -lt 131072){$m=Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json;[pscustomobject]@{path=$_.FullName;name=$m.name;version=$m.version;permissions=$m.permissions}}}}}}}", True),
 'office_mru': ('Office recent files registry', "UserReg 'Software\\Microsoft\\Office\\16.0\\Word\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\16.0\\Excel\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\15.0\\Word\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\15.0\\Excel\\File MRU' 0;UserReg 'Software\\Microsoft\\Office\\15.0\\PowerPoint\\File MRU' 0", True),
}

HELPERS = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$script:historyLimited=$false
$script:issues=New-Object System.Collections.Generic.List[string]
function Issue($s){if($script:issues.Count -lt 20){$script:issues.Add([string]$s)}}
function Profiles {Get-CimInstance Win32_UserProfile|Where-Object {$_.LocalPath -and -not $_.Special}|Select-Object -First 32 -ExpandProperty LocalPath}
function RegTree($path,$depth){
 if(-not(Test-Path -LiteralPath $path)){return}
 $keys=@(Get-Item -LiteralPath $path)
 if($depth -gt 0){$regErrors=@();$children=@(Get-ChildItem -LiteralPath $path -Recurse -Depth $depth -ErrorAction SilentlyContinue -ErrorVariable regErrors|Select-Object -First 10001);if($regErrors.Count){Issue 'Registry traversal had inaccessible keys'};if($children.Count -gt 10000){Issue 'Registry key limit reached'};$keys+=@($children|Select-Object -First 10000)}
 foreach($key in $keys){try{$names=@($key.GetValueNames());if($names.Count -gt 64){Issue 'Registry value count limit reached'};foreach($name in $names|Select-Object -First 64){$v=$key.GetValue($name,$null,'DoNotExpandEnvironmentNames');$truncated=$false;$encoding='native';$originalBytes=$null;$retainedBytes=$null;$digest=$null;if($v -is [byte[]]){$encoding='base64';$originalBytes=$v.Length;$sha=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($sha.ComputeHash($v))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($v.Length -gt 1048576){$v=[byte[]]$v[0..1048575];$truncated=$true;Issue 'Registry binary value exceeded 1048576 bytes; original size and SHA-256 retained'};$retainedBytes=$v.Length;$v=[Convert]::ToBase64String($v)};[pscustomobject]@{path=$key.Name;name=$name;kind=[string]$key.GetValueKind($name);value=$v;encoding=$encoding;value_truncated=$truncated;original_bytes=$originalBytes;retained_bytes=$retainedBytes;original_sha256=$digest}}}catch{Issue 'One or more registry values could not be read'}}
}
function UserReg($suffix,$depth){Get-ChildItem Registry::HKEY_USERS|Where-Object {$_.PSChildName -match '^S-1-5-21-'}|Select-Object -First 32|ForEach-Object{RegTree ('Registry::'+$_.Name+'\'+$suffix) $depth}}
function HashFile($path){if(-not $path){return [pscustomobject]@{path=$path;state='PATH_UNAVAILABLE';sha256=$null}};try{$f=Get-Item -LiteralPath $path;if($f.Length -gt 67108864){return [pscustomobject]@{path=$path;state='SIZE_LIMIT';sha256=$null}};[pscustomobject]@{path=$path;state='HASHED';sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}}catch{[pscustomobject]@{path=$path;state='UNREADABLE';sha256=$null}}}

function PowerShellEventRow($event){
 $xml=[xml]$event.ToXml();$data=@{};foreach($node in $xml.Event.EventData.Data){$data[[string]$node.Name]=[string]$node.'#text'}
 [pscustomobject]@{source='event_log';time=([DateTimeOffset]$event.TimeCreated).ToUnixTimeSeconds();datetime=$event.TimeCreated.ToUniversalTime().ToString('o');script_block_id=$data.ScriptBlockId;script_block_count=$data.MessageTotal;message_number=$data.MessageNumber;script_text=$data.ScriptBlockText;script_name=[IO.Path]::GetFileName($data.Path);script_path=$data.Path;event_id=$event.Id;record_id=$event.RecordId;log_name=$event.LogName;user_sid=[string]$event.UserId}
}
function HistoryBucket($name,$budget,$rowLimit){
 return @{name=$name;budget=$budget;row_limit=$rowLimit;used=0;kept=0;omitted=0}
}
function HistoryRow($row,$bucket){
 $bytes=[Text.Encoding]::UTF8.GetByteCount(($row|ConvertTo-Json -Depth 7 -Compress))+1
 if(($bucket.used+$bytes) -gt $bucket.budget -or $bucket.kept -ge $bucket.row_limit){$bucket.omitted++;$script:historyLimited=$true;return}
 $bucket.used+=$bytes;$bucket.kept++;$row
}
function HistorySummary($bucket){
 if($bucket.omitted){Issue ('History source limit: '+$bucket.name+'; retained '+$bucket.kept+' rows; omitted at least '+$bucket.omitted+' rows')}
}
function PowerShellHistory {
 # Reserve independent budgets: neither event log can suppress interactive history.
 foreach($log in @('Microsoft-Windows-PowerShell/Operational','PowerShellCore/Operational')){
  $bucket=HistoryBucket $log 614400 3000
  try{
   $info=Get-WinEvent -ListLog $log -ErrorAction Stop
   if(-not $info.IsEnabled){Issue ('PowerShell event log is disabled: '+$log);continue}
   $eventErrors=@();$events=@(Get-WinEvent -FilterHashtable @{LogName=$log;Id=4104} -MaxEvents 3001 -ErrorAction SilentlyContinue -ErrorVariable eventErrors)
   foreach($err in $eventErrors){if($err.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){Issue ('PowerShell event log could not be completely read: '+$log)}}
   foreach($event in $events){HistoryRow (PowerShellEventRow $event) $bucket}
  }catch{Issue ('PowerShell event log unavailable: '+$log)}
  HistorySummary $bucket
 }
 $paths=@(Profiles|ForEach-Object{
  $profile=$_
  foreach($relative in @('AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt','AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt')){
   $p=Join-Path $profile $relative
   try{if(Test-Path -LiteralPath $p){[pscustomobject]@{profile=$profile;path=$p}}}catch{Issue 'PSReadLine history path was inaccessible'}
  }
 })
 if($paths.Count){
  $budget=[int][Math]::Floor(614400/$paths.Count);$rows=[int][Math]::Floor(3000/$paths.Count)
  foreach($file in $paths){
   $bucket=HistoryBucket $file.path $budget $rows
   try{
    $lines=@(Get-Content -LiteralPath $file.path -Tail ($rows+1));$n=$lines.Count
    # Keep newest commands first. tail_line is a position in the bounded tail,
    # never presented as an absolute file line number or execution timestamp.
    for($i=$lines.Count-1;$i -ge 0;$i--){HistoryRow ([pscustomobject]@{source='PSReadLine';user_profile=$file.profile;path=$file.path;tail_line=($i+1);script_text=$lines[$i];datetime=$null;script_path=$null;script_block_id=$null;script_block_count=$null}) $bucket}
   }catch{Issue 'PSReadLine history file was inaccessible'}
   HistorySummary $bucket
  }
 }
}
function Modules {Get-Process|Select-Object -First 10000|ForEach-Object{$p=$_;try{$p.Modules|Select-Object -First 10000|ForEach-Object{[pscustomobject]@{pid=$p.Id;process=$p.ProcessName;ModuleName=$_.ModuleName;FileName=$_.FileName;BaseAddress=[string]$_.BaseAddress;ModuleMemorySize=$_.ModuleMemorySize}}}catch{Issue 'Modules of one or more processes were inaccessible'}}}
'''

def now():
    return datetime.now(timezone.utc).isoformat()

def manifest():
    return [{'id': key, 'name': row[0], 'sensitive': row[2],
             'platform': 'windows', 'collector_version': VERSION}
            for key, row in CATALOG.items()]

def script_for(key):
    # Pipeline row bound is inside the process, before serialization.
    return HELPERS + '\ntry{$rows=@(& {\n' + CATALOG[key][1] + '\n}|Select-Object -First 10001);$kept=New-Object System.Collections.Generic.List[object];$used=0;$sizeLimited=$false;foreach($row in $rows|Select-Object -First 10000){$bytes=[Text.Encoding]::UTF8.GetByteCount(($row|ConvertTo-Json -Depth 7 -Compress));if(($used+$bytes+1) -gt 1966080){$sizeLimited=$true;Issue "Category byte limit reached; retained preceding rows";break};$kept.Add($row);$used+=$bytes+1};[pscustomobject]@{rows=@($kept.ToArray());truncated=(($rows.Count -gt 10000) -or $sizeLimited -or $script:historyLimited);issues=@($script:issues.ToArray())}|ConvertTo-Json -Depth 8 -Compress}catch{[pscustomobject]@{error=$_.Exception.GetType().Name;message="Collector query failed; provider may be unavailable or access denied"}|ConvertTo-Json -Compress;exit 2}'

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
                'collection_limits':{'rows_per_category':MAX_ROWS,'bytes_per_category':MAX_CATEGORY_BYTES,'total_bytes':MAX_TOTAL_BYTES,'total_seconds':MAX_TOTAL_SECONDS},
                'collection_basis':'Independent bounded endpoint queries during the capture interval; not an atomic disk or memory image.',
                'limitations':['Registry values are raw artifacts, not parsed execution verdicts.','User registry collection covers loaded hives only; offline hives are not mounted.','History can contain credentials and is collected only in the sensitive profile.','Filesystem artifact categories contain metadata; file contents are not a disk acquisition.','Permissions, missing providers, row limits and deadline limits can reduce coverage.']}
    evidence['sha256'] = hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()
    return evidence
