# W1 - format-string gate for the forwarder scripts.
#
# PowerShell's -f operator binds TIGHTER than +, so
#     "records {0}..{1} were not delivered - " + "raise -MaxEvents" -f $a, $b
# parses as
#     "records {0}..{1} were not delivered - " + ("raise -MaxEvents" -f $a, $b)
# The placeholders in the FIRST literal are never expanded and the arguments
# are silently swallowed. The owner's real Windows run printed
# "GAP RECORDED: records {0}..{1}" for exactly this reason - an observability
# defect precisely where dropped records are reported.
#
# This gate walks the AST of every .ps1 and fails on:
#   1. a `+` whose right operand is a format expression  (the precedence bug)
#   2. a format expression whose format string carries NO {n} placeholder
#   3. a format expression whose highest placeholder index does not match
#      the number of arguments supplied
param(
  [Parameter(Mandatory = $true)][string[]] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$findings = @()

function Get-FormatLiteral {
  # the literal text of the format string, with nested concatenation joined
  param($Ast)
  if ($Ast -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
    return $Ast.Value
  }
  if ($Ast -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
    return $Ast.Value
  }
  if ($Ast -is [System.Management.Automation.Language.ParenExpressionAst]) {
    return Get-FormatLiteral $Ast.Pipeline.PipelineElements[0].Expression
  }
  if ($Ast -is [System.Management.Automation.Language.BinaryExpressionAst] -and
      $Ast.Operator -eq 'Plus') {
    return (Get-FormatLiteral $Ast.Left) + (Get-FormatLiteral $Ast.Right)
  }
  return $null
}

foreach ($p in $Path) {
  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile(
           $p, [ref]$tokens, [ref]$errors)
  if ($errors.Count -gt 0) {
    $findings += [pscustomobject]@{ File = $p; Line = $errors[0].Extent.StartLineNumber
                                    Kind = 'PARSE_ERROR'
                                    Detail = $errors[0].Message }
    continue
  }
  $bins = $ast.FindAll({
    param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst]
  }, $true)

  foreach ($b in $bins) {
    if ($b.Operator -eq 'Plus' -and
        $b.Right -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $b.Right.Operator -eq 'Format') {
      $findings += [pscustomobject]@{
        File = $p; Line = $b.Extent.StartLineNumber
        Kind = 'FORMAT_BINDS_TO_RIGHT_OPERAND_ONLY'
        Detail = ('wrap the whole concatenation in parentheses before -f: ' +
                  $b.Extent.Text.Substring(0, [Math]::Min(70, $b.Extent.Text.Length))) }
      continue
    }
    if ($b.Operator -ne 'Format') { continue }

    $literal = Get-FormatLiteral $b.Left
    if ($null -eq $literal) { continue }     # runtime-built format string
    $indexes = @([regex]::Matches($literal, '\{(\d+)') |
                 ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique)
    if ($indexes.Count -eq 0) {
      $findings += [pscustomobject]@{
        File = $p; Line = $b.Extent.StartLineNumber
        Kind = 'FORMAT_STRING_HAS_NO_PLACEHOLDER'
        Detail = ('-f applied to a string with no {n}: ' +
                  $literal.Substring(0, [Math]::Min(60, $literal.Length))) }
      continue
    }
    $argCount = 1
    if ($b.Right -is [System.Management.Automation.Language.ArrayLiteralAst]) {
      $argCount = $b.Right.Elements.Count
    }
    $needed = ($indexes[-1] + 1)
    if ($needed -ne $argCount) {
      $findings += [pscustomobject]@{
        File = $p; Line = $b.Extent.StartLineNumber
        Kind = 'FORMAT_ARGUMENT_COUNT_MISMATCH'
        Detail = ("format string needs $needed argument(s) but $argCount " +
                  'were supplied') }
      continue
    }
    # RENDERED check: format the literal with synthetic arguments and
    # require that no {n} placeholder survives in the output.
    $probe = @(0..($needed - 1) | ForEach-Object { "<arg$_>" })
    $rendered = $literal -f $probe
    if ($rendered -match '\{\d+') {
      $findings += [pscustomobject]@{
        File = $p; Line = $b.Extent.StartLineNumber
        Kind = 'PLACEHOLDER_SURVIVES_RENDERING'
        Detail = $rendered.Substring(0, [Math]::Min(70, $rendered.Length)) }
    }
  }
}

if ($findings.Count -gt 0) {
  Write-Output ('FORMAT_FINDINGS ' + $findings.Count)
  foreach ($f in $findings) {
    Write-Output ('  {0}:{1} {2} - {3}' -f
      (Split-Path $f.File -Leaf), $f.Line, $f.Kind, $f.Detail)
  }
  exit 1
}
Write-Output 'FORMAT_OK'
exit 0
