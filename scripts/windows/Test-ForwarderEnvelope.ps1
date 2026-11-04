# W1 - exercise the FORWARDER'S OWN CODE, not a replica.
#
# The Phase 2 contract test posted an envelope shape written in Python. This
# script removes that gap: it loads the function definitions out of the real
# .ps1 via the PowerShell AST and calls ConvertTo-Envelope on synthetic
# Sysmon records, so the envelope that is then posted to the live route was
# built by the artifact itself.
#
# Get-WinEvent does not exist off Windows, so the event objects are stubs
# that expose exactly what ConvertTo-RawEvent reads: .Id, .RecordId and
# .ToXml(). The XML is the real Windows EventLog rendering.
param(
  [Parameter(Mandatory = $true)][string] $ForwarderPath,
  [Parameter(Mandatory = $true)][string] $OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
         $ForwarderPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
  throw ("the forwarder does not parse: " + $errors[0].Message)
}
$funcs = $ast.FindAll({
  param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true)
foreach ($f in $funcs) {
  if ($f.Name -in @('ConvertTo-RawEvent', 'ConvertTo-Envelope', 'Get-Prop')) {
    Invoke-Expression $f.Extent.Text
  }
}
# the script-scope constants the functions read, taken from the artifact
# itself rather than duplicated here
$assigns = $ast.FindAll({
  param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]
}, $true)
foreach ($a in $assigns) {
  if ($a.Left.Extent.Text -like '$script:*') {
    Invoke-Expression $a.Extent.Text
  }
}
if (-not (Get-Command ConvertTo-Envelope -ErrorAction SilentlyContinue)) {
  throw 'ConvertTo-Envelope was not found in the forwarder'
}

function New-StubEvent {
  param([int] $Id, [int64] $RecordId, [string] $Xml)
  $e = [pscustomobject]@{ Id = $Id; RecordId = $RecordId }
  $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this._xml }
  $e | Add-Member -MemberType NoteProperty -Name _xml -Value $Xml
  return $e
}

function New-SysmonXml {
  param([int] $Id, [int64] $RecordId, [string] $Computer,
        [hashtable] $Data, [string] $SystemTime)
  $sb = New-Object Text.StringBuilder
  [void]$sb.Append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">')
  [void]$sb.Append('<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>')
  [void]$sb.Append("<EventID>$Id</EventID><Version>5</Version><Level>4</Level>")
  [void]$sb.Append("<Task>$Id</Task><Opcode>0</Opcode>")
  [void]$sb.Append("<TimeCreated SystemTime=`"$SystemTime`"/>")
  [void]$sb.Append("<EventRecordID>$RecordId</EventRecordID>")
  [void]$sb.Append('<Channel>Microsoft-Windows-Sysmon/Operational</Channel>')
  [void]$sb.Append("<Computer>$Computer</Computer>")
  [void]$sb.Append('<Security UserID="S-1-5-18"/></System><EventData>')
  foreach ($k in $Data.Keys) {
    $v = [Security.SecurityElement]::Escape([string]$Data[$k])
    [void]$sb.Append("<Data Name=`"$k`">$v</Data>")
  }
  [void]$sb.Append('</EventData></Event>')
  return $sb.ToString()
}

$host_name = 'PSGEN-' + [int][double]::Parse(
  (Get-Date -UFormat %s)).ToString()
$sha256 = ('c' * 64)
$md5 = ('b' * 32)
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.0000000Z')

$eid1 = [ordered]@{
  RuleName = '-'
  UtcTime = '2026-06-01 10:00:00.123'
  ProcessGuid = '{c0ffee01-0000-0000-0000-000000000001}'
  ProcessId = '4711'
  Image = 'C:\Windows\System32\cmd.exe'
  FileVersion = '10.0.19041.1'
  Description = 'Windows Command Processor'
  Product = 'Microsoft Windows Operating System'
  Company = 'Microsoft Corporation'
  OriginalFileName = 'Cmd.Exe'
  CommandLine = 'cmd.exe /c whoami'
  CurrentDirectory = 'C:\Users\owner\'
  User = 'PSGEN\owner'
  LogonGuid = '{c0ffee01-0000-0000-0000-000000000009}'
  LogonId = '0x3e7'
  TerminalSessionId = '1'
  IntegrityLevel = 'High'
  Hashes = "MD5=$md5,SHA256=$sha256"
  ParentProcessGuid = '{c0ffee01-0000-0000-0000-000000000000}'
  ParentProcessId = '500'
  ParentImage = 'C:\Windows\explorer.exe'
  ParentCommandLine = 'C:\Windows\Explorer.EXE'
  ParentUser = 'PSGEN\owner'
  # an attempt to impersonate NivX transport provenance: must be dropped
  _nivx_collector_id = 'col_attacker_controlled'
}
$eid13 = [ordered]@{
  UtcTime = '2026-06-01 10:00:01.123'
  EventType = 'SetValue'
  ProcessGuid = '{c0ffee01-0000-0000-0000-000000000001}'
  ProcessId = '4711'
  Image = 'C:\Windows\regedit.exe'
  TargetObject = ('HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion' +
                  '\Run\PsGen')
  Details = 'C:\Users\Public\psgen.exe'
}
$eid22 = [ordered]@{
  UtcTime = '2026-06-01 10:00:02.123'
  ProcessGuid = '{c0ffee01-0000-0000-0000-000000000001}'
  ProcessId = '4711'
  QueryName = 'example.com'
  QueryStatus = '0'
  QueryResults = 'type:  1 93.184.216.34;'
  Image = 'C:\Windows\System32\svchost.exe'
}

$cfg = [pscustomobject]@{
  TenantId = 'default'; CollectorId = '<COLLECTOR>'
  SourceLabel = $host_name; BatchSize = 200 }

$events = @(
  (New-StubEvent -Id 1  -RecordId 910001 -Xml (New-SysmonXml -Id 1 `
     -RecordId 910001 -Computer $host_name -Data $eid1  -SystemTime $stamp)),
  (New-StubEvent -Id 13 -RecordId 910002 -Xml (New-SysmonXml -Id 13 `
     -RecordId 910002 -Computer $host_name -Data $eid13 -SystemTime $stamp)),
  (New-StubEvent -Id 22 -RecordId 910003 -Xml (New-SysmonXml -Id 22 `
     -RecordId 910003 -Computer $host_name -Data $eid22 -SystemTime $stamp))
)
$envelopes = @($events | ForEach-Object {
  ConvertTo-Envelope -Event $_ -Config $cfg })

($envelopes | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 $OutFile
Write-Output ("WROTE {0} envelope(s) to {1}" -f $envelopes.Count, $OutFile)
Write-Output ("HOSTNAME {0}" -f $host_name)
foreach ($e in $envelopes) {
  Write-Output ("  {0} eid={1} fields={2} keys={3}" -f
    $e.source_event_id, $e.raw['event_id'], @($e.raw.Keys).Count,
    (($e.Keys) -join ','))
}
