# =====================================================================
# NIVXFORGE | B5 | SYSMON XML RECOVERY HUNT | STRICTLY READ-ONLY
#
# GOAL: find the ORIGINAL C:\NivX\sysmon\nivx-w1-sysmon.xml, or any copy
# whose SHA-256 equals the hash Sysmon itself recorded:
#
#     0BAE60B361373E09C3B834EE68CA52B9412D9A9239036F25DE5A2EBC39C9A7AC
#
# This block RESTORES NOTHING. It does not copy, move, rename, write,
# delete, undelete, mount, apply, import or modify anything. It only
# lists, reads and hashes. It runs no Sysmon command, touches no service,
# and changes no configuration. The only write is the optional transcript
# in %TEMP% (delete the two Transcript lines for a zero-write run).
#
# RUN ELEVATED (shadow-copy listing and some paths need it).
# =====================================================================
$ErrorActionPreference = 'Continue'
$Target  = '0bae60b361373e09c3b834ee68ca52b9412d9a9239036f25de5a2ebc39c9a7ac'
$OutFile = Join-Path $env:TEMP ("nivxforge_xmlhunt_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
Start-Transcript -Path $OutFile -Force | Out-Null

function Test-Candidate([string]$path) {
  try {
    $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
    $verdict = if ($h -eq $Target) { '*** EXACT MATCH - THIS IS THE ORIGINAL ***' } else { 'different bytes' }
    Write-Host ("  {0}`n    sha256={1}  {2}" -f $path, $h, $verdict)
  } catch {
    Write-Host ("  {0}`n    unreadable: {1}" -f $path, $_.Exception.Message)
  }
}

Write-Host "=== 0 | TARGET ==="
Write-Host ("looking for sha256 : {0}" -f $Target)
Write-Host ("host / time UTC    : {0} / {1}" -f $env:COMPUTERNAME, (Get-Date).ToUniversalTime().ToString('o'))
Write-Host ("config still absent: {0}" -f (-not (Test-Path 'C:\NivX\sysmon\nivx-w1-sysmon.xml')))

Write-Host ""
Write-Host "=== 1 | THE SYSMON DIRECTORY AND ANY XML NEAR IT ==="
Get-ChildItem 'C:\NivX' -Recurse -File -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTimeUtc | Format-Table -AutoSize
Get-ChildItem 'C:\NivX' -Recurse -File -Include '*.xml','*.bak','*.old','*.txt' -ErrorAction SilentlyContinue |
  ForEach-Object { Test-Candidate $_.FullName }

Write-Host ""
Write-Host "=== 2 | RECYCLE BIN (listed and hashed IN PLACE, never restored) ==="
try {
  $shell = New-Object -ComObject Shell.Application
  $bin = $shell.Namespace(10)
  $found = 0
  foreach ($item in $bin.Items()) {
    if ($item.Name -match 'sysmon|nivx|\.xml$') {
      $found++
      Write-Host ("  name={0}" -f $item.Name)
      Write-Host ("    original location={0}" -f $bin.GetDetailsOf($item, 1))
      Write-Host ("    deleted={0}" -f $bin.GetDetailsOf($item, 2))
      Test-Candidate $item.Path
    }
  }
  if ($found -eq 0) { Write-Host "  no sysmon/nivx/.xml item in the Recycle Bin" }
} catch { Write-Host ("  recycle bin not enumerable: {0}" -f $_.Exception.Message) }

Write-Host ""
Write-Host "=== 3 | TEMP, DOWNLOADS, DESKTOP, DOCUMENTS, ONEDRIVE ==="
$roots = @($env:TEMP, "$env:SystemRoot\Temp", "$env:USERPROFILE\Downloads",
           "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents",
           $env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) |
         Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
foreach ($r in $roots) {
  Write-Host ("searching {0}" -f $r)
  Get-ChildItem $r -Recurse -File -Include '*sysmon*','*nivx*' -ErrorAction SilentlyContinue |
    Select-Object -First 40 | ForEach-Object { Test-Candidate $_.FullName }
}

Write-Host ""
Write-Host "=== 4 | FILE HISTORY / WINDOWS BACKUP LOCATIONS ==="
$histRoots = @("$env:USERPROFILE\AppData\Local\Microsoft\Windows\FileHistory",
               'C:\FileHistory', 'D:\FileHistory',
               "$env:SystemDrive\WindowsImageBackup") |
             Where-Object { Test-Path $_ }
if ($histRoots.Count -eq 0) { Write-Host "  no File History / Windows Backup root present" }
foreach ($r in $histRoots) {
  Write-Host ("searching {0}" -f $r)
  Get-ChildItem $r -Recurse -File -Include '*nivx-w1-sysmon*','*sysmon*.xml' -ErrorAction SilentlyContinue |
    Select-Object -First 40 | ForEach-Object { Test-Candidate $_.FullName }
}

Write-Host ""
Write-Host "=== 5 | VOLUME SHADOW COPIES (LISTED ONLY - not mounted, not read) ==="
# A shadow copy would need a mount/symlink to read, which is a WRITE.
# So this only reports whether one exists that predates the loss; the
# OWNER decides whether mounting it is worth authorising later.
& vssadmin.exe list shadows 2>&1 |
  Select-String -Pattern 'Shadow Copy Set|creation time|Original Volume' |
  ForEach-Object { Write-Host ("  {0}" -f $_.Line.Trim()) }

Write-Host ""
Write-Host "=== 6 | POWERSHELL HISTORY AND TRANSCRIPTS (matching lines only) ==="
# The config was pasted into a console, so PSReadLine may still hold it.
# ONLY lines that look like the Sysmon config are printed - history files
# can contain unrelated secrets and are never dumped wholesale.
$histFiles = @("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
               "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") +
             @(Get-ChildItem "$env:USERPROFILE\Documents" -Filter 'PowerShell_transcript*' -Recurse -ErrorAction SilentlyContinue |
                 Select-Object -ExpandProperty FullName) +
             @(Get-ChildItem $env:TEMP -Filter 'PowerShell_transcript*' -ErrorAction SilentlyContinue |
                 Select-Object -ExpandProperty FullName)
$histFiles = $histFiles | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
if ($histFiles.Count -eq 0) { Write-Host "  no PSReadLine history or transcript found" }
foreach ($f in $histFiles) {
  $hits = Select-String -LiteralPath $f -Pattern 'Sysmon schemaversion|ProcessTerminate onmatch|HashAlgorithms|nivx-w1-sysmon' -ErrorAction SilentlyContinue
  Write-Host ("{0}  ({1} matching lines)" -f $f, @($hits).Count)
  $hits | Select-Object -First 60 | ForEach-Object {
    Write-Host ("    {0}: {1}" -f $_.LineNumber, $_.Line.Trim())
  }
}

Write-Host ""
Write-Host "=== 7 | WHOLE-DRIVE NAME SWEEP (names only, then hash matches) ==="
Get-ChildItem 'C:\' -Recurse -File -Filter 'nivx-w1-sysmon*' -ErrorAction SilentlyContinue |
  Select-Object -First 25 | ForEach-Object { Test-Candidate $_.FullName }

Write-Host ""
Write-Host "=== RESULT ==="
Write-Host "If any line above says EXACT MATCH, exact rollback is recoverable and"
Write-Host "EID 5 enablement can proceed with a proven backup. If nothing matches,"
Write-Host "the original artefact is gone and EID 5 stays"
Write-Host "BLOCKED_ON_EXACT_SYSMON_ROLLBACK_ARTIFACT - which is a configuration"
Write-Host "authority gap, not a reason to weaken evidence semantics."
Write-Host ("Transcript : {0}" -f $OutFile)
Write-Host "NOTHING was restored, copied, moved, written, deleted or applied."
Stop-Transcript | Out-Null
