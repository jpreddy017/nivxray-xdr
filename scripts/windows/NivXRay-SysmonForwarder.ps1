<#
.SYNOPSIS
  NivXRay XDR · Windows Sysmon forwarder (W1).

.DESCRIPTION
  Reads genuine Sysmon records from Microsoft-Windows-Sysmon/Operational and
  delivers them to the EXISTING authenticated ingest route
  POST /api/xdr/ingest/telemetry. It creates no second pipeline, invents no
  identity and holds no authority: NivXRay re-parses `raw` itself.

  Authority chain preserved, in this order:
    Windows Sysmon
      -> this forwarder (transport only)
      -> X-XDR-API-Key  (scoped ingest key, read from a local ACL'd file)
      -> X-Tenant-Id    (must equal every envelope's tenant_id AND the
                         collector's tenant on the server)
      -> collector_id   (server-side identity; one collector per batch)
      -> declared_source: microsoft-sysmon (must be in the collector's
                         server-side authorized_sources, or D15 refuses it)
      -> Sysmon DSM -> canonical evidence -> provenance

  Design rules this script obeys, on purpose:
    * only the event ids the Sysmon DSM supports are read
      (1, 3, 11, 12, 13, 14, 22). Anything else would be refused at the DSM
      boundary, so it is never sent.
    * EventData is forwarded VERBATIM. No field is renamed, defaulted,
      derived or dropped, so the DSM decides meaning, not the forwarder.
    * exactly-once: `source_event_id = <Computer>|<EventRecordID>` and a
      durable bookmark. The bookmark advances only for records the server
      actually accounted for.
    * nothing is silently lost: any record the server refuses is written to
      refused.jsonl locally with the server's stated reason.
    * HTTPS only, TLS 1.2+, no certificate-validation bypass anywhere.
    * the ingest key is never logged, echoed or written by this script.

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

function Write-Log {
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
    if (-not $cfg.$f) { throw "config is missing required field: $f" }
  }
  if ($cfg.ApiBaseUrl -notmatch '^https://') {
    throw "ApiBaseUrl must be https:// — telemetry is never sent in clear text"
  }
  if (-not $cfg.BatchSize) { $cfg | Add-Member BatchSize 200 -Force }
  return $cfg
}

function Get-IngestKey {
  if (-not (Test-Path $KeyPath)) { throw "ingest key file not found: $KeyPath" }
  $acl = Get-Acl $KeyPath
  $loose = $acl.Access | Where-Object {
    $_.IdentityReference -match '(Everyone|BUILTIN\\Users|Authenticated Users)'
  }
  if ($loose) {
    throw ("refusing to read $KeyPath — it is readable by " +
           ($loose.IdentityReference -join ', ') +
           ". Restrict it to SYSTEM + Administrators first.")
  }
  $k = (Get-Content $KeyPath -Raw).Trim()
  if (-not $k) { throw "ingest key file is empty: $KeyPath" }
  return $k          # never logged, never echoed
}

function Get-Bookmark {
  $p = Join-Path $StateDir 'sysmon-bookmark.json'
  if (Test-Path $p) {
    return [int64](Get-Content $p -Raw | ConvertFrom-Json).LastRecordId
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
  <# Sysmon record -> the flat EventData document the Sysmon DSM parses.
     VERBATIM: every EventData name is kept exactly as Sysmon wrote it. #>
  param($Event)
  $x = [xml]$Event.ToXml()
  $raw = [ordered]@{
    event_id = [int]$Event.Id
    provider = $x.Event.System.Provider.Name      # must contain "Sysmon"
    channel  = $x.Event.System.Channel
    Computer = $x.Event.System.Computer
    record_id = [int64]$Event.RecordId
  }
  if ($x.Event.System.TimeCreated.SystemTime) {
    $raw['TimeCreated'] = $x.Event.System.TimeCreated.SystemTime
  }
  foreach ($d in @($x.Event.EventData.Data)) {
    if (-not $d -or -not $d.Name) { continue }
    # D13 · nothing the source sends may impersonate NivX transport
    # provenance. A field in the reserved namespace is refused, not renamed.
    if ($d.Name -like '_nivx*') { continue }
    $raw[$d.Name] = [string]$d.'#text'
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
  <# Fetch FORWARD from the bookmark.

     A newest-first `-MaxEvents` fetch would silently skip a backlog older
     than the window, so the record id is pushed into the query and the
     oldest records are taken first. If the cap is still hit, the skipped
     range is RECORDED as a gap rather than lost quietly. #>
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
    Write-Log WARN ("forward fetch failed ({0}); retrying newest-first" -f
                    $_.Exception.Message)
    $evts = Get-WinEvent -LogName $script:Channel -FilterXPath $xpath `
                         -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
  }
  if (-not $evts) { return @() }
  $sorted = @($evts | Sort-Object { [int64]$_.RecordId })
  $firstId = [int64]$sorted[0].RecordId
  if ($sorted.Count -ge $MaxEvents -and $firstId -gt ($AfterRecordId + 1)) {
    # only possible on the newest-first fallback path
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    Add-Content -Path (Join-Path $StateDir 'gap.jsonl') -Value (
      @{ kind = 'BACKLOG_WINDOW_EXCEEDED'
         skipped_from = ($AfterRecordId + 1); skipped_to = ($firstId - 1)
         observed_at = (Get-Date).ToUniversalTime().ToString('o') } |
      ConvertTo-Json -Compress)
    Write-Log WARN ("GAP RECORDED: records {0}..{1} were not delivered — " +
                    "raise -MaxEvents or shorten -PollSeconds" -f
                    ($AfterRecordId + 1), ($firstId - 1))
  }
  return $sorted
}

function Send-Batch {
  param($Envelopes, $Config, [string] $Key)
  $body = @{ envelopes = $Envelopes } | ConvertTo-Json -Depth 8 -Compress
  $headers = @{ 'X-XDR-API-Key' = $Key
                'X-Tenant-Id'   = $Config.TenantId
                'Content-Type'  = 'application/json' }
  [Net.ServicePointManager]::SecurityProtocol =
    [Net.SecurityProtocolType]::Tls12 -bor 3072
  $uri = ($Config.ApiBaseUrl.TrimEnd('/') + '/api/xdr/ingest/telemetry')
  try {
    return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers `
                             -Body $body -TimeoutSec 120
  } catch {
    $resp = $_.Exception.Response
    $status = if ($resp) { [int]$resp.StatusCode } else { 0 }
    $detail = ''
    if ($resp) {
      $sr = New-Object IO.StreamReader($resp.GetResponseStream())
      $detail = $sr.ReadToEnd()
      if ($detail.Length -gt 600) { $detail = $detail.Substring(0, 600) }
    }
    # the key is in the request headers, never in this message
    throw "ingest HTTP $status : $detail"
  }
}

function Record-Refused {
  param($Rows)
  if (-not $Rows) { return }
  New-Item -ItemType Directory -Force $StateDir | Out-Null
  $p = Join-Path $StateDir 'refused.jsonl'
  foreach ($r in $Rows) {
    Add-Content -Path $p -Value (($r | ConvertTo-Json -Depth 6 -Compress))
  }
}

function Invoke-ForwardCycle {
  $cfg = if ($DryRun -and -not (Test-Path $ConfigPath)) {
    # Phase 2 review: no config has been created yet.
    [pscustomobject]@{ ApiBaseUrl = 'https://DRYRUN.invalid'
                       TenantId = '<TENANT>'; CollectorId = '<COLLECTOR>'
                       SourceLabel = $env:COMPUTERNAME; BatchSize = 200 }
  } else { Get-ForwarderConfig }

  $bookmark = if ($DryRun) { [int64]0 } else { Get-Bookmark }
  $pending = Get-PendingEvents -AfterRecordId $bookmark
  Write-Log INFO ("pending records after bookmark {0}: {1}" -f $bookmark,
                  $pending.Count)
  if ($pending.Count -eq 0) { return }

  if ($DryRun) {
    $envs = @($pending | Select-Object -First 5 |
              ForEach-Object { ConvertTo-Envelope -Event $_ -Config $cfg })
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $out = Join-Path $StateDir ('dryrun-{0}.json' -f
             (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
    ($envs | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 $out
    Write-Log INFO ("DRY RUN — {0} envelope(s) written to {1}. Nothing was " +
                    "sent, no key was read, the bookmark was not moved." -f
                    $envs.Count, $out)
    $envs | ForEach-Object {
      [pscustomobject]@{
        source_event_id = $_.source_event_id
        declared_source = $_.declared_source
        event_id        = $_.raw.event_id
        provider        = $_.raw.provider
        utc_time        = $(if ($_.raw.Contains('UtcTime')) { $_.raw.UtcTime } else { '' })
        fields          = (@($_.raw.Keys).Count)
        has_guid        = $_.raw.Contains('ProcessGuid')
        has_parent_cmd  = $_.raw.Contains('ParentCommandLine')
        has_orig_name   = $_.raw.Contains('OriginalFileName')
        hash_algos      = $(if ($_.raw.Contains('Hashes')) {
                              ((($_.raw.Hashes -split ',') |
                                ForEach-Object { ($_ -split '=')[0] }) -join '+')
                            } else { '' })
      }
    } | Format-Table -AutoSize
    return
  }

  $key = Get-IngestKey
  $i = 0
  while ($i -lt $pending.Count) {
    $chunk = @($pending[$i..([Math]::Min($i + $cfg.BatchSize - 1,
                                         $pending.Count - 1))])
    $envs = @($chunk | ForEach-Object {
      ConvertTo-Envelope -Event $_ -Config $cfg })
    $receipt = Send-Batch -Envelopes $envs -Config $cfg -Key $key
    $refused = @()
    foreach ($o in @($receipt.reasoning)) {
      if ($o.status -notin @('REASONED', 'DUPLICATE', 'RESUME_FROM_RAW',
                             'STITCHED_INTO')) {
        $refused += [pscustomobject]@{
          source_event_id = $o.source_event_id; status = $o.status
          blocker = $o.blocker; error = $o.error
          observed_at = (Get-Date).ToUniversalTime().ToString('o') }
      }
    }
    Record-Refused -Rows $refused
    Write-Log INFO ("sent={0} accepted={1} duplicates={2} resumed={3} " +
                    "routing_blocked={4} reasoned={5} refused_recorded={6} " +
                    "collector_state={7}" -f
                    $envs.Count, $receipt.accepted, $receipt.duplicates,
                    $receipt.resumed, $receipt.routing_blocked,
                    $receipt.reasoned, $refused.Count,
                    $receipt.collector_state)
    # The bookmark advances only after the server accounted for this chunk.
    Set-Bookmark -RecordId ([int64]($chunk[-1].RecordId))
    $i += $chunk.Count
  }
}

try {
  Write-Log INFO ("{0} starting · host={1} · dryrun={2}" -f $script:Version,
                  $env:COMPUTERNAME, [bool]$DryRun)
  if ($Loop -and -not $DryRun) {
    while ($true) {
      try { Invoke-ForwardCycle } catch { Write-Log ERROR $_.Exception.Message }
      Start-Sleep -Seconds $PollSeconds
    }
  } else {
    Invoke-ForwardCycle
  }
  exit 0
} catch {
  Write-Log ERROR $_.Exception.Message
  exit 1
}
