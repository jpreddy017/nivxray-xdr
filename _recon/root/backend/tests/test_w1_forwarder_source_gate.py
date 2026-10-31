"""W1 · source gate for the Windows forwarder.

Phase 2.3 failed on the owner's real laptop before a single line executed:
Windows PowerShell 5.1 decodes a BOM-less `.ps1` with the machine ANSI code
page, so the em dashes in the comments and in two `throw` strings became
mojibake and broke quoting. The 21/21 contract test could not see it — it
validated the server-side envelope contract, not the script's own parse.

This gate closes that hole at the source level:

* the file must be **pure ASCII**, LF, no BOM — then no code page can change
  its meaning, with or without a BOM;
* it must parse with the PowerShell parser when decoded as UTF-8 **and** as
  Windows-1252 / Latin-1 / Cyrillic, which is what a 5.1 host would do;
* the security properties that make this script safe to hand an ingest key
  must still be present.

A PowerShell runtime is required for the parse assertions. This pod has
PowerShell 7 (Linux) — **not** Windows PowerShell 5.1 — so the parse result
proves syntax, and the ASCII invariant is what removes the 5.1 code-page
variable. Runtime compatibility on 5.1 itself is proven only by the owner's
`-DryRun` on the real laptop.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest

FORWARDER = "/app/scripts/windows/NivXRay-SysmonForwarder.ps1"
PARSER = "/app/scripts/windows/Test-ForwarderParse.ps1"
GENERATOR = "/app/scripts/windows/Test-ForwarderEnvelope.ps1"
FORMAT_GATE = "/app/scripts/windows/Test-ForwarderFormatStrings.ps1"
PWSH = "/opt/pwsh/pwsh"
PS_FILES = [FORWARDER, PARSER, GENERATOR, FORMAT_GATE]


def _bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


@pytest.mark.parametrize("path", PS_FILES)
def test_every_powershell_file_is_pure_ascii(path):
    raw = _bytes(path)
    offenders = [(i, raw[i]) for i in range(len(raw)) if raw[i] > 127]
    assert not offenders, (
        f"{os.path.basename(path)} carries {len(offenders)} non-ASCII byte(s), "
        f"first at offset {offenders[0][0] if offenders else '-'}. Windows "
        f"PowerShell 5.1 would decode those with the machine ANSI code page "
        f"and can break quoting — use ASCII punctuation.")


@pytest.mark.parametrize("path", PS_FILES)
def test_no_bom_and_unix_line_endings(path):
    raw = _bytes(path)
    assert not raw.startswith(b"\xef\xbb\xbf"), "a BOM would change the hash"
    assert b"\r\n" not in raw, "the canonical artifact is LF"


@pytest.mark.skipif(not os.path.exists(PWSH),
                    reason="no PowerShell runtime available in this pod")
@pytest.mark.parametrize("encoding", ["utf-8", "windows-1252", "iso-8859-1",
                                      "windows-1251"])
def test_the_forwarder_parses_under_every_plausible_code_page(encoding):
    r = subprocess.run([PWSH, "-NoProfile", "-File", PARSER,
                        "-Path", FORWARDER, "-Encoding", encoding],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, (
        f"decoded as {encoding} the forwarder does not parse:\n"
        f"{r.stdout[-1200:]}")
    assert "PARSE_OK" in r.stdout


@pytest.mark.skipif(not os.path.exists(PWSH),
                    reason="no PowerShell runtime available in this pod")
def test_the_forwarders_own_code_builds_the_contracted_envelope(tmp_path):
    out = tmp_path / "envelopes.json"
    r = subprocess.run([PWSH, "-NoProfile", "-File", GENERATOR,
                        "-ForwarderPath", FORWARDER, "-OutFile", str(out)],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr[-1200:] or r.stdout[-1200:]
    envs = json.loads(out.read_text())
    assert len(envs) == 3
    assert set(envs[0]) == {"tenant_id", "collector_id", "source_event_id",
                            "collection_method", "source", "connector_id",
                            "declared_source", "parser_version", "raw"}
    e1 = next(e for e in envs if e["raw"]["event_id"] == 1)
    assert e1["declared_source"] == "microsoft-sysmon"
    assert e1["collection_method"] == "windows_eventlog_pull"
    assert e1["source_event_id"] == \
        f"{e1['raw']['Computer']}|{e1['raw']['record_id']}"
    # EventData verbatim …
    for f in ("OriginalFileName", "ParentCommandLine", "ParentImage",
              "Hashes", "ProcessGuid", "ParentProcessGuid", "RuleName"):
        assert f in e1["raw"], f
    # … except a source field impersonating NivX transport provenance.
    assert not [k for k in e1["raw"] if k.startswith("_nivx")]


def test_the_security_properties_are_still_in_the_source():
    src = open(FORWARDER, encoding="ascii").read()
    assert src.count("Invoke-RestMethod") == 1, "exactly one egress call"
    assert "ServerCertificateValidationCallback" not in src
    assert "SkipCertificateCheck" not in src
    assert "-notmatch '^https://'" in src, "the https guard must remain"
    assert "SecurityProtocolType]::Tls12" in src
    assert "refusing to read $KeyPath" in src, "the key-file ACL check"
    assert "(Everyone|BUILTIN\\\\Users|Authenticated Users)" in src
    assert "declared_source   = $script:Declared" in src
    assert "$script:SupportedEventIds = @(1, 3, 11, 12, 13, 14, 22)" in src
    assert "Set-Bookmark -RecordId ([int64]($chunk[-1].RecordId))" in src
    # do not shadow a cmdlet name that exists on some hosts
    assert "function Write-Log" not in src
    assert "gap.jsonl" in src and "refused.jsonl" in src
    # a first run with no bookmark must not report a false gap for records
    # that had already rolled out of the channel
    assert "if ($AfterRecordId -eq 0)" in src
    assert "are NOT counted as a gap" in src
    # and a dry run must not write diagnostics state
    assert "if (-not $DryRun) {\n        New-Item -ItemType Directory " in src
    # the key must never reach a log line or an error message
    import re
    for line in src.splitlines():
        if "Write-ForwarderLog" in line or "throw" in line:
            assert not re.search(r"\$[kK]ey\b(?!Path)", line), line.strip()


@pytest.mark.skipif(not os.path.exists(PWSH),
                    reason="no PowerShell runtime available in this pod")
@pytest.mark.parametrize("path", PS_FILES)
def test_every_log_format_string_actually_renders(path):
    """`-f` binds tighter than `+`.

    `"records {0}..{1} " + "raise -MaxEvents" -f $a, $b` formats only the
    SECOND literal, so the placeholders in the first are printed verbatim
    and the arguments are swallowed. The owner's real Windows run printed
    `GAP RECORDED: records {0}..{1}` for exactly this reason. The gate walks
    the AST for that precedence pattern, for `-f` on a string with no
    placeholder, for an argument-count mismatch, and finally renders every
    format string with synthetic arguments to prove no `{n}` survives.
    """
    r = subprocess.run([PWSH, "-NoProfile", "-File", FORMAT_GATE,
                        "-Path", path],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout[-1500:]
    assert "FORMAT_OK" in r.stdout


def _analyzer_available():
    if not os.path.exists(PWSH):
        return False
    r = subprocess.run([PWSH, "-NoProfile", "-Command",
                        "[bool](Get-Module -ListAvailable PSScriptAnalyzer)"],
                       capture_output=True, text=True, timeout=180)
    return r.stdout.strip() == "True"


@pytest.mark.skipif(not _analyzer_available(),
                    reason="PSScriptAnalyzer is not installed in this pod")
@pytest.mark.parametrize("path", PS_FILES)
def test_psscriptanalyzer_reports_no_5_1_syntax_incompatibility(path):
    cmd = ("Import-Module PSScriptAnalyzer; "
           "$s = @{ IncludeRules = @('PSUseCompatibleSyntax'); "
           "Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; "
           "TargetVersions = @('5.1','7.0') } } }; "
           f"$r = @(Invoke-ScriptAnalyzer -Path '{path}' -Settings $s); "
           "if ($r.Count) { $r | ForEach-Object { 'line ' + $_.Line + ': ' "
           "+ $_.Message } } else { 'NO_FINDINGS' }")
    r = subprocess.run([PWSH, "-NoProfile", "-Command", cmd],
                       capture_output=True, text=True, timeout=240)
    assert "NO_FINDINGS" in r.stdout, r.stdout[-1500:]


def test_the_format_gate_catches_the_defect_it_exists_for():
    """A gate nobody has seen fail is not a gate."""
    if not os.path.exists(PWSH):
        pytest.skip("no PowerShell runtime available in this pod")
    broken = ('Write-Host ("records {0}..{1} were not delivered - " +\n'
              '            "raise the cap" -f $a, $b)\n')
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".ps1",
                                     delete=False) as fh:
        fh.write(broken)
        path = fh.name
    try:
        r = subprocess.run([PWSH, "-NoProfile", "-File", FORMAT_GATE,
                            "-Path", path],
                           capture_output=True, text=True, timeout=180)
        assert r.returncode == 1
        assert "FORMAT_BINDS_TO_RIGHT_OPERAND_ONLY" in r.stdout
    finally:
        os.unlink(path)


def test_powershell_5_1_pitfalls_are_avoided():
    src = open(FORWARDER, encoding="ascii").read()
    # positional Add-Member binds differently across hosts
    assert "Add-Member -NotePropertyName" in src
    assert "$cfg | Add-Member BatchSize" not in src
    # StrictMode: an optional field must be read through Get-Prop, never
    # as a bare property that throws when the server omitted it
    assert "function Get-Prop" in src
    for probe in ("$receipt.accepted", "$receipt.reasoning", "$o.status",
                  "$cfg.$f", "$state.LastRecordId"):
        assert probe not in src, f"{probe} throws under Set-StrictMode"
    # the ingest route wraps its receipt in `data`
    assert "Get-Prop $response 'data'" in src
