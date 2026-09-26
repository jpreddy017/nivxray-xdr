<#
.SYNOPSIS
  NivXRay XDR - Windows Sysmon forwarder (W1).

.DESCRIPTION
  Reads genuine Sysmon records from Microsoft-Windows-Sysmon/Operational and
  delivers them to the EXISTING authenticated ingest route
  POST /api/xdr/ingest/telemetry. It creates no second pipeline, invents no
  identity and holds no authority: NivXRay re-parses `raw` itself.

  Authority chain preserved, in this order:
    Windows Sysmon
      -> this forwarder (transport only)
      -> X-XDR-API-Key  scoped ingest key, read from a local ACL'd file
      -> X-Tenant-Id    must equal every envelope's tenant_id AND the
                        collector's tenant on the server
      -> collector_id   server-side identity; one collector per batch
      -> declared_source: microsoft-sysmon, which must be in the collector's
                        server-side authorized_sources or D15 refuses it
      -> Sysmon DSM -> canonical evidence -> provenance

  Design rules this script obeys, on purpose:
    * only the event ids the Sysmon DSM supports are read
      (1, 3, 11, 12, 13, 14, 22). Anything else would be refused at the DSM
      boundary, so it is never sent.
    * EventData is forwarded VERBATIM. No field is renamed, defaulted,
      derived or dropped, so the DSM decides meaning, not the forwarder.
    * exactly-once: source_event_id = <Computer>|<EventRecordID> plus a
      durable bookmark. The bookmark advances only for records the server
      actually accounted for.
    * nothing is silently lost: any record the server refuses is written to
      refused.jsonl locally with the server's stated reason, and any skipped
      record range is written to gap.jsonl.
    * HTTPS only, TLS 1.2+, no certificate-validation bypass anywhere.
    * the ingest key is never logged, echoed or written by this script.

  COMPATIBILITY: this file is deliberately pure ASCII with no BOM. Windows
  PowerShell 5.1 decodes a BOM-less .ps1 using the machine ANSI code page,
  so a single non-ASCII character (an em dash, for instance) becomes
  mojibake and breaks quoting. The source gate
  backend/tests/test_w1_forwarder_source_gate.py enforces this.

.PARAMETER DryRun
  Render the envelopes that WOULD be sent to a local file and print a
  redacted summary. Requires no key, no collector id and no network, and
  does not move the bookmark. This is the W1 Phase 2 review step.
#>
[CmdletBinding()]
param(
  [string] $ConfigPath = 'C:\ProgramData\NivXRay\config\forwarder.json',
  [string] $KeyPath    = 'C:\ProgramData\NivXRay\config\ingest.key',
  [string] $StateDir   = 'C:\ProgramData\NivXRay\state',
  [string] $LogDir     = 'C:\ProgramData\NivXRay\logs',
  [int]    $MaxEvents  = 5000,
  [switch] $DryRun,
  [switch] $Loop,
  [int]    $PollSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The Sysmon DSM's SUPPORTED_EVENT_IDS. Keep in step with
# detection_content/telemetry/sysmon_dsm.py.
$script:SupportedEventIds = @(1, 3, 11, 12, 13, 14, 22)
$script:Channel   = 'Microsoft-Windows-Sysmon/Operational'
$script:Declared  = 'microsoft-sysmon'
$script:Method    = 'windows_eventlog_pull'
$script:Version   = 'nivx-sysmon-forwarder/1.0'

function Get-Prop {
  # StrictMode-safe read of an optional property. A field the server did
  # not send reads as $null instead of throwing.
  param($Object, [string] $Name, $Default = $null)
  if ($null -eq $Object) { return $Default }
  if ($Object -is [Collections.IDictionary]) {
    if ($Object.Contains($Name)) { return $Object[$Name] }
    return $Default
  }
  $p = $Object.PSObject.Properties[$Name]
  if ($null -eq $p) { return $Default }
  return $p.Value
}

function Write-ForwarderLog {
  param([string] $Level, [string] $Message)
  $line = ('{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('o'),
                               $Level, $Message)
  Write-Host $line
  if (-not $DryRun) {
    New-Item -ItemType Directory -Force $LogDir | Out-Null
    Add-Content -Path (Join-Path $LogDir 'forwarder.log') -Value $line
  }
}

function Get-ForwarderConfig {
  if (-not (Test-Path $ConfigPath)) {
    throw "config not found: $ConfigPath"
  }
  $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
  foreach ($f in @('ApiBaseUrl', 'TenantId', 'CollectorId', 'SourceLabel')) {
    if (-not (Get-Prop $cfg $f)) {
      throw "config is missing required field: $f"
    }
  }
  if ($cfg.ApiBaseUrl -notmatch '^https://') {
    throw ('ApiBaseUrl must be https:// - telemetry is never sent in ' +
           'clear text')
  }
  if (-not (Get-Prop $cfg 'BatchSize')) {
    $cfg | Add-Member -NotePropertyName BatchSize -NotePropertyValue 200 -Force
  }
  return $cfg
}

function Get-IngestKey {
  if (-not (Test-Path $KeyPath)) { throw "ingest key file not found: $KeyPath" }
  $acl = Get-Acl $KeyPath
  $loose = @($acl.Access | Where-Object {
    $_.IdentityReference -match '(Everyone|BUILTIN\\Users|Authenticated Users)'
  })
  if ($loose.Count -gt 0) {
    throw ("refusing to read $KeyPath - it is readable by " +
           (($loose | ForEach-Object { $_.IdentityReference }) -join ', ') +
           ". Restrict it to SYSTEM + Administrators first.")
  }
  $k = (Get-Content $KeyPath -Raw).Trim()
  if (-not $k) { throw "ingest key file is empty: $KeyPath" }
  return $k          # never logged, never echoed
}

function Get-Bookmark {
  $p = Join-Path $StateDir 'sysmon-bookmark.json'
  if (Test-Path $p) {
    $state = Get-Content $p -Raw | ConvertFrom-Json
    return [int64](Get-Prop $state 'LastRecordId' 0)
  }
  return [int64]0
}

function Set-Bookmark {
  param([int64] $RecordId)
  New-Item -ItemType Directory -Force $StateDir | Out-Null
  @{ LastRecordId = $RecordId
     UpdatedUtc   = (Get-Date).ToUniversalTime().ToString('o') } |
    ConvertTo-Json | Set-Content -Encoding UTF8 `
      (Join-Path $StateDir 'sysmon-bookmark.json')
}

function ConvertTo-RawEvent {
  # Sysmon record -> the flat EventData document the Sysmon DSM parses.
  # VERBATIM: every EventData name is kept exactly as Sysmon wrote it.
  param($Event)
  $x = [xml]$Event.ToXml()
  $raw = [ordered]@{
    event_id  = [int]$Event.Id
    provider  = $x.Event.System.Provider.Name      # must contain "Sysmon"
    channel   = $x.Event.System.Channel
    Computer  = $x.Event.System.Computer
    record_id = [int64]$Event.RecordId
  }
  $created = $x.Event.System.TimeCreated
  if ($null -ne $created -and $created.SystemTime) {
    $raw['TimeCreated'] = [string]$created.SystemTime
  }
  $eventData = $x.Event.SelectSingleNode('*[local-name()="EventData"]')
  if ($null -ne $eventData) {
    foreach ($d in @($eventData.ChildNodes)) {
      $name = $d.GetAttribute('Name')
      if (-not $name) { continue }
      # D13: nothing the source sends may impersonate NivX transport
      # provenance. A field in the reserved namespace is refused, not
      # renamed.
      if ($name -like '_nivx*') { continue }
      $raw[$name] = [string]$d.InnerText
    }
  }
  return $raw
}

function ConvertTo-Envelope {
  param($Event, $Config)
  $raw = ConvertTo-RawEvent -Event $Event
  return [ordered]@{
    tenant_id         = $Config.TenantId
    collector_id      = $Config.CollectorId
    source_event_id   = ('{0}|{1}' -f $raw.Computer, $raw.record_id)
    collection_method = $script:Method
    source            = $Config.SourceLabel
    connector_id      = ('{0}@{1}' -f $script:Version, $env:COMPUTERNAME)
    declared_source   = $script:Declared
    parser_version    = $script:Version
    raw               = $raw
  }
}

function Get-PendingEvents {
  # Fetch FORWARD from the bookmark.
  #
  # A newest-first -MaxEvents fetch would silently skip a backlog older than
  # the window, so the record id is pushed into the query and the oldest
  # records are taken first. If the cap is still hit, the skipped range is
  # RECORDED as a gap rather than lost quietly.
  param([int64] $AfterRecordId)
  $ids = ($script:SupportedEventIds | ForEach-Object { "EventID=$_" }) -join ' or '
  $xpath = "*[System[EventRecordID > $AfterRecordId and ($ids)]]"
  $evts = $null
  try {
    $evts = Get-WinEvent -LogName $script:Channel -FilterXPath $xpath `
                         -MaxEvents $MaxEvents -Oldest -ErrorAction Stop
  } catch {
    if ($_.Exception.Message -match 'NoMatchingEventsFound|No events were found') {
      return @()
    }
    Write-ForwarderLog WARN ("forward fetch failed ({0}); retrying newest-first" -f
                    $_.Exception.Message)
    $evts = Get-WinEvent -LogName $script:Channel -FilterXPath $xpath `
                         -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
  }
  if (-not $evts) { return @() }
  $sorted = @($evts | Sort-Object { [int64]$_.RecordId })
  $firstId = [int64]$sorted[0].RecordId
  if ($sorted.Count -ge $MaxEvents -and $firstId -gt ($AfterRecordId + 1)) {
    if ($AfterRecordId -eq 0) {
      # FIRST RUN, no bookmark: records older than $firstId are not records
      # this forwarder failed to deliver - they had already rolled out of
      # the channel before it ever ran. Saying "not delivered" would be a
      # false gap, so the earliest AVAILABLE record is stated instead.
      Write-ForwarderLog INFO (
        ("first run, no bookmark: the channel's earliest available record " +
         "is {0} and the fetch window is {1}. Records before {0} were never " +
         "available to this forwarder and are NOT counted as a gap.") -f
        $firstId, $MaxEvents)
    } else {
      # a genuine hole: we had a bookmark and the records after it are gone
      if (-not $DryRun) {
        New-Item -ItemType Directory -Force $StateDir | Out-Null
        Add-Content -Path (Join-Path $StateDir 'gap.jsonl') -Value (
          @{ kind = 'BACKLOG_WINDOW_EXCEEDED'
             skipped_from = ($AfterRecordId + 1); skipped_to = ($firstId - 1)
             observed_at = (Get-Date).ToUniversalTime().ToString('o') } |
          ConvertTo-Json -Compress)
      }
      Write-ForwarderLog WARN (
        ("GAP RECORDED: records {0}..{1} were not delivered - raise " +
         "-MaxEvents or shorten -PollSeconds") -f
        ($AfterRecordId + 1), ($firstId - 1))
    }
  }
  return $sorted
}

function Set-TlsFloor {
  # TLS 1.2 minimum, 1.3 where the OS supports it. No certificate
  # validation is ever bypassed.
  $tls12 = [Net.SecurityProtocolType]::Tls12
  try {
    [Net.ServicePointManager]::SecurityProtocol = $tls12 -bor 12288
  } catch {
    [Net.ServicePointManager]::SecurityProtocol = $tls12
  }
}

function Send-Batch {
  param($Envelopes, $Config, [string] $Key)
  $body = @{ envelopes = $Envelopes } | ConvertTo-Json -Depth 8 -Compress
  $headers = @{ 'X-XDR-API-Key' = $Key
                'X-Tenant-Id'   = $Config.TenantId
                'Content-Type'  = 'application/json' }
  Set-TlsFloor
  $uri = ($Config.ApiBaseUrl.TrimEnd('/') + '/api/xdr/ingest/telemetry')
  try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers `
                                  -Body $body -TimeoutSec 120
  } catch {
    $resp = $_.Exception.Response
    $status = 0
    if ($null -ne $resp) { $status = [int]$resp.StatusCode }
    $detail = ''
    if ($null -ne $resp) {
      try {
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        $detail = $sr.ReadToEnd()
        if ($detail.Length -gt 600) { $detail = $detail.Substring(0, 600) }
      } catch { $detail = '<response body unavailable>' }
    }
    # the key is in the request headers, never in this message
    throw "ingest HTTP $status : $detail"
  }
  # the route wraps its receipt in `data`
  $inner = Get-Prop $response 'data'
  if ($null -ne $inner) { return $inner }
  return $response
}

function Write-RefusedRows {
  param($Rows)
  if (-not $Rows -or @($Rows).Count -eq 0) { return }
  New-Item -ItemType Directory -Force $StateDir | Out-Null
  $p = Join-Path $StateDir 'refused.jsonl'
  foreach ($r in @($Rows)) {
    Add-Content -Path $p -Value ($r | ConvertTo-Json -Depth 6 -Compress)
  }
}

function Invoke-ForwardCycle {
  $cfg = $null
  if ($DryRun -and -not (Test-Path $ConfigPath)) {
    # Phase 2 review: no config has been created yet.
    $cfg = [pscustomobject]@{ ApiBaseUrl = 'https://DRYRUN.invalid'
                              TenantId = '<TENANT>'
                              CollectorId = '<COLLECTOR>'
                              SourceLabel = $env:COMPUTERNAME
                              BatchSize = 200 }
  } else {
    $cfg = Get-ForwarderConfig
  }

  $bookmark = [int64]0
  if (-not $DryRun) { $bookmark = Get-Bookmark }
  $pending = @(Get-PendingEvents -AfterRecordId $bookmark)
  Write-ForwarderLog INFO ("pending records after bookmark {0}: {1}" -f $bookmark,
                  $pending.Count)
  if ($pending.Count -eq 0) { return }

  if ($DryRun) {
    $envs = @($pending | Select-Object -First 5 |
              ForEach-Object { ConvertTo-Envelope -Event $_ -Config $cfg })
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $out = Join-Path $StateDir ('dryrun-{0}.json' -f
             (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
    ($envs | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 $out
    Write-ForwarderLog INFO (
      ("DRY RUN - {0} envelope(s) written to {1}. Nothing was sent, no key " +
       "was read, the bookmark was not moved.") -f $envs.Count, $out)
    $envs | ForEach-Object {
      $raw = $_.raw
      $algos = ''
      if ($raw.Contains('Hashes')) {
        $algos = ((($raw['Hashes'] -split ',') |
                   ForEach-Object { ($_ -split '=')[0] }) -join '+')
      }
      $utc = ''
      if ($raw.Contains('UtcTime')) { $utc = $raw['UtcTime'] }
      [pscustomobject]@{
        source_event_id = $_.source_event_id
        declared_source = $_.declared_source
        event_id        = $raw['event_id']
        provider        = $raw['provider']
        utc_time        = $utc
        fields          = @($raw.Keys).Count
        has_guid        = $raw.Contains('ProcessGuid')
        has_parent_cmd  = $raw.Contains('ParentCommandLine')
        has_orig_name   = $raw.Contains('OriginalFileName')
        hash_algos      = $algos
      }
    } | Format-Table -AutoSize
    return
  }

  $key = Get-IngestKey
  $i = 0
  while ($i -lt $pending.Count) {
    $last = [Math]::Min($i + $cfg.BatchSize - 1, $pending.Count - 1)
    $chunk = @($pending[$i..$last])
    $envs = @($chunk | ForEach-Object {
      ConvertTo-Envelope -Event $_ -Config $cfg })
    $receipt = Send-Batch -Envelopes $envs -Config $cfg -Key $key
    $accounted = @('REASONED', 'DUPLICATE', 'RESUME_FROM_RAW', 'STITCHED_INTO')
    $refused = @()
    foreach ($o in @(Get-Prop $receipt 'reasoning')) {
      $status = [string](Get-Prop $o 'status' 'UNKNOWN')
      if ($accounted -notcontains $status) {
        $refused += [pscustomobject]@{
          source_event_id = (Get-Prop $o 'source_event_id')
          status          = $status
          blocker         = (Get-Prop $o 'blocker')
          error           = (Get-Prop $o 'error')
          observed_at     = (Get-Date).ToUniversalTime().ToString('o') }
      }
    }
    Write-RefusedRows -Rows $refused
    Write-ForwarderLog INFO (
      ("sent={0} accepted={1} duplicates={2} resumed={3} " +
       "routing_blocked={4} reasoned={5} refused_recorded={6} " +
       "collector_state={7}") -f
      $envs.Count,
      (Get-Prop $receipt 'accepted' 0),
      (Get-Prop $receipt 'duplicates' 0),
      (Get-Prop $receipt 'resumed' 0),
      (Get-Prop $receipt 'routing_blocked' 0),
      (Get-Prop $receipt 'reasoned' 0),
      $refused.Count,
      (Get-Prop $receipt 'collector_state' 'UNKNOWN'))
    # The bookmark advances only after the server accounted for this chunk.
    Set-Bookmark -RecordId ([int64]($chunk[-1].RecordId))
    $i += $chunk.Count
  }
}

try {
  Write-ForwarderLog INFO ("{0} starting - host={1} - dryrun={2}" -f $script:Version,
                  $env:COMPUTERNAME, [bool]$DryRun)
  if ($Loop -and -not $DryRun) {
    while ($true) {
      try { Invoke-ForwardCycle } catch { Write-ForwarderLog ERROR $_.Exception.Message }
      Start-Sleep -Seconds $PollSeconds
    }
  } else {
    Invoke-ForwardCycle
  }
  exit 0
} catch {
  Write-ForwarderLog ERROR $_.Exception.Message
  exit 1
}
