$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'windows_snapshot.py') -Raw
$helpers=[regex]::Match($source,"(?s)HELPERS = r'''(.*?)'''").Groups[1].Value
if(-not $helpers){throw 'Collector helpers missing'}
& ([scriptblock]::Create($helpers + @'

function Profiles { 'C:\FixtureA'; 'C:\FixtureB' }
function Test-Path { param($LiteralPath) return $true }
function Get-Content { param($LiteralPath,$Tail) 'old-command'; 'new-command' }
function Get-WinEvent {
 param($ListLog,$FilterHashtable,$MaxEvents,$ErrorAction,$ErrorVariable)
 if($ListLog){return [pscustomobject]@{IsEnabled=$true}}
 1..200|ForEach-Object{[pscustomobject]@{id=$_}}
}
function PowerShellEventRow($event){[pscustomobject]@{source='event_log';record_id=$event.id;script_text=('x'*20000)}}
$rows=@(PowerShellHistory)
if(@($rows|Where-Object source -eq 'PSReadLine').Count -ne 8){throw 'Saturated event logs suppressed PSReadLine'}
if(@($rows|Where-Object source -eq 'event_log').Count -lt 2){throw 'Event logs were lost'}
if(-not $script:historyLimited){throw 'Limits not reported'}
$bytes=[Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $rows -Depth 8 -Compress))
if($bytes -gt 1966080){throw 'History exceeded category serialization budget'}
$bucket=HistoryBucket 'fixture' 500 10
$huge=@(HistoryRow ([pscustomobject]@{text=('x'*1000)}) $bucket)
$small=@(HistoryRow ([pscustomobject]@{text='retained'}) $bucket)
if($huge.Count -ne 0 -or $small.Count -ne 1 -or $bucket.omitted -ne 1){throw 'Oversized row prevented later small evidence'}
Write-Output 'PASS: independent history budgets, both shells and profiles, oversized row recovery'

$script:binary=New-Object byte[] 65536
$script:binary[65535]=123
$script:key=[pscustomobject]@{Name='FixtureRegistry'}
$script:key|Add-Member ScriptMethod GetValueNames {return ,@('AppCompatCache')}
$script:key|Add-Member ScriptMethod GetValue {param($n,$d,$o);return ,$script:binary}
$script:key|Add-Member ScriptMethod GetValueKind {param($n);return 'Binary'}
function Get-Item {param($LiteralPath);return $script:key}
$row=@(RegTree 'fixture' 0)[0]
if($row.value_truncated -or $row.original_bytes -ne 65536 -or $row.retained_bytes -ne 65536){throw 'Binary beyond old 32KB cap was truncated'}
$decoded=[Convert]::FromBase64String($row.value)
if($decoded.Length -ne 65536 -or $decoded[65535] -ne 123){throw 'Binary round trip mismatch'}
$hash=[Security.Cryptography.SHA256]::Create()
try{$expected=([BitConverter]::ToString($hash.ComputeHash($script:binary))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
if($row.original_sha256 -ne $expected){throw 'Original SHA256 mismatch'}
$script:binary=New-Object byte[] 1048577
$row=@(RegTree 'fixture' 0)[0]
if(-not $row.value_truncated -or $row.original_bytes -ne 1048577 -or $row.retained_bytes -ne 1048576){throw 'Oversize binary not bounded truthfully'}
if([Convert]::FromBase64String($row.value).Length -ne 1048576){throw 'Binary retained length mismatch'}
Write-Output 'PASS: full 64KB binary capture, SHA256, explicit 1MB truncation metadata'
'@))
