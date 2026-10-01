# NivXForge · PRODUCTION CANONICAL CONFIRMATION (READ-ONLY)  —  run on YOUR machine
#
# Three GETs. No write, no patch, no deploy, no DB change, no endpoint action.
# Prints ONLY sanitised aggregates + one sample event's derivations.
# Never prints payload bodies, Event XML, tokens or credentials.
#
# HOW TO GET THE TOKEN (never paste it into chat):
#   1. Sign in to the console, press F12 → Console tab
#   2. Run:  localStorage.getItem('nvx_token')
#   3. Copy the value; this script asks for it with a HIDDEN prompt, so it
#      does not appear on screen or in your PowerShell history.
#
# RUN:  powershell -ExecutionPolicy Bypass -File .\prod_canonical_check.ps1

$ErrorActionPreference = 'Stop'
$api    = 'https://nivxray.nivxforge.com'
$ep     = 'ep_1989031c8c1d0085812f'
$tenant = 'ten_e759b7288598bd882e3dcac49d'

$sec = Read-Host 'Paste console bearer token (hidden)' -AsSecureString
$jwt = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
         [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$h = @{ Authorization = "Bearer $jwt"; 'X-Tenant-Id' = $tenant }

function Tally($rows, $name, $selector) {
  "  $name :"
  $rows | Group-Object $selector | Sort-Object Count -Descending |
    ForEach-Object { "      {0,-34} {1}" -f ("$($_.Name)"), $_.Count }
}

# ─── 1/3 · events for the live Windows endpoint ───────────────────────
"=== 1/3  GET /api/edr/events?endpoint_id=$ep&hours=24&limit=200"
try {
  $r = Invoke-RestMethod -Headers $h -Method GET `
        -Uri "$api/api/edr/events?endpoint_id=$ep&hours=24&limit=200"
} catch {
  "REQUEST FAILED: $($_.Exception.Message)"
  if ($_.ErrorDetails.Message) { "DETAIL: $($_.ErrorDetails.Message)" }
  exit 1
}
"  tenant_id : $($r.tenant_id)"
"  rows      : $($r.count)   has_more: $($r.has_more)"
Tally $r.events 'parser_state'      { $_.parser_state }
"  canonical_event_id present : {0} / {1}" -f `
  (@($r.events | Where-Object { $_.canonical_event_id }).Count), $r.events.Count
Tally $r.events 'detection.outcome' { $_.detection.outcome }
Tally $r.events 'activity (STAMPED?)' { $_.activity }
Tally $r.events 'operation'         { $_.operation }
Tally $r.events 'trust_state'       { $_.trust_state }
Tally $r.events 'sensor_version'    { $_.sensor_version }
Tally $r.events 'derivation_count'  { $_.derivation_count }

$sysmon = @($r.events | Where-Object {
  $_.payload_preview -like '*Microsoft-Windows-Sysmon/Operational*' })
"  rows whose preview shows Sysmon/Operational : $($sysmon.Count)"
$sample = if ($sysmon.Count) { $sysmon[0] } else { $r.events[0] }
"  SAMPLE (sanitised, no payload):"
foreach ($k in 'raw_id','ingest_time','event_time','endpoint_ref','hostname',
                'activity','operation','parser_state','canonical_event_id',
                'derivation_count','trust_state','telemetry_quality',
                'payload_sha256') {
  "      {0,-20} = {1}" -f $k, $sample.$k
}
"      detection            = $($sample.detection | ConvertTo-Json -Compress)"

# ─── 2/3 · coverage facets (this is where the UI gets its zeros) ──────
""
"=== 2/3  GET /api/edr/events/facets?hours=24"
$f = Invoke-RestMethod -Headers $h -Method GET `
      -Uri "$api/api/edr/events/facets?hours=24"
"  total_events          : $($f.total_events)"
"  activity (facet map)  : $($f.activity | ConvertTo-Json -Compress)"
"  activity_not_observed : $($f.activity_not_observed -join ', ')"
"  source_kind           : $($f.source_kind | ConvertTo-Json -Compress)"
"  trust_state           : $($f.trust_state | ConvertTo-Json -Compress)"
"  detection             : $($f.detection | ConvertTo-Json -Compress)"

# ─── 3/3 · one event in full: derivations + raw→canonical link ────────
""
"=== 3/3  GET /api/edr/events/$($sample.raw_id)"
$d = Invoke-RestMethod -Headers $h -Method GET `
      -Uri "$api/api/edr/events/$($sample.raw_id)"
$ev = $d.event
foreach ($k in 'raw_id','activity','operation','parser_state',
                'canonical_event_id','trust_state','telemetry_quality',
                'payload_sha256','derivation_count') {
  "  {0,-20} = {1}" -f $k, $ev.$k
}
"  authentication keys  = $((($ev.authentication).psobject.Properties.Name) -join ', ')"
"  DERIVATIONS (no payload):"
$i = 0
foreach ($der in @($ev.derivations)) {
  $keep = [ordered]@{}
  foreach ($k in 'replay_generation','derived_at','parser_name','parser_version',
                  'parser_state','normalizer_version','detection_content_version',
                  'event_id','evidence_ids','outcome') {
    if ($null -ne $der.$k) { $keep[$k] = $der.$k }
  }
  "   [$i] $($keep | ConvertTo-Json -Compress)"
  if ($der.parser_notes) { "        parser_notes: $($der.parser_notes -join ' | ')" }
  if ($der.reason)       { "        reason      : $($der.reason)" }
  $i++
}
""
"  winlog fields only (channel / event_id / record_id — no XML content):"
try {
  $env0 = $ev.payload | ConvertFrom-Json
  "      kind        = $($env0.kind)"
  "      channel     = $($env0.winlog.channel)"
  "      event_id    = $($env0.winlog.event_id)"
  "      record_id   = $($env0.winlog.record_id)"
  "      provider    = $($env0.winlog.provider)"
  "      computer    = $($env0.winlog.computer)"
  "      xml_present = $([bool]$env0.winlog.xml)  xml_length = $(($env0.winlog.xml).Length)"
} catch { "      (stored payload is not JSON)" }

$jwt = $null
""
"DONE — read-only. Paste the output above."
