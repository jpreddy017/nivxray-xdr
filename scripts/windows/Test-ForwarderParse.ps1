# W1 - parse a .ps1 the way a runtime with no BOM would decode it.
# Windows PowerShell 5.1 decodes a BOM-less .ps1 using the machine's ANSI
# code page, so UTF-8 bytes become mojibake and can break quoting. This
# reproduces that deterministically: the file is decoded with the named
# encoding and the resulting TEXT is handed to the PowerShell parser.
param(
  [Parameter(Mandatory = $true)][string] $Path,
  [string] $Encoding = 'utf-8'
)

$bytes = [IO.File]::ReadAllBytes($Path)
try {
  $enc = [Text.Encoding]::GetEncoding($Encoding)
} catch {
  Write-Output "ENCODING_UNAVAILABLE $Encoding"
  exit 3
}
$text = $enc.GetString($bytes)

$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput(
  $text, [ref]$tokens, [ref]$errors)

$nonAscii = @()
for ($i = 0; $i -lt $bytes.Length; $i++) {
  if ($bytes[$i] -gt 127) { $nonAscii += $i; if ($nonAscii.Count -ge 5) { break } }
}

[pscustomobject]@{
  Path            = $Path
  DecodedAs       = $Encoding
  PSVersion       = $PSVersionTable.PSVersion.ToString()
  Bytes           = $bytes.Length
  HasBom          = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and
                     $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
  NonAsciiBytes   = $nonAscii.Count
  ParserErrors    = $errors.Count
} | Format-List

if ($errors.Count -gt 0) {
  Write-Output '--- parser errors ---'
  $errors | Select-Object -First 8 | ForEach-Object {
    Write-Output ("line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message)
  }
  exit 1
}
Write-Output 'PARSE_OK'
exit 0
