"""Command Intelligence · R-1 / R-2 / R-3 acceptance tests.

R-1  evidence-preserving Windows tokenization
R-2  honest decode_status + unresolved_expressions[]
R-3  artifact classes; a FRAGMENT is never decoded as a payload

These tests pin the CONTRACT, not the decoder's cleverness. R-4/R-5 (semantic
expression evaluation and dataflow reconstruction) are NOT implemented yet, so
the obfuscated fixture below must report PARTIALLY_RECOVERED — never RECOVERED.

NOTE · the obfuscated fixture is the NON-AUTHORITATIVE reconstruction from
`/app/memory/CI_DECODER_P0_RCA.md`. The owner's exact byte-for-byte sample
replaces it as the authoritative D-11 specimen when supplied.
"""
import pytest

from command_analyzer import (
    analyze_command, tokenize, tokenize_windows, first_token_span,
    ARTIFACT_FRAGMENT, DECODE_RECOVERED, DECODE_PARTIALLY_RECOVERED,
    DECODE_NOT_REQUIRED,
)

WIN_PS = (
    r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe '
    r'-ExecutionPolicy bypass -c "$EbaYA; '
    r"$BnWKB = 'ZWxlYXN' + 9 + 'lDQppcGNvbmZpZyAvcmVuZ' + 9 + "
    r"'XcNCm5ldHNoIHdpbnNvY2sgcmVzZXQNCg=='; "
    r'$EbaYA = [System.Text.Encoding]::UTF8.GetString('
    r'[Convert]::FromBase64String($BnWKB)); '
    r'Invoke-Command -ScriptBlock ([ScriptBlock]::Create($EbaYA))"'
)

# Same payload expression, but OUTSIDE any interpreter-claimed span — this is
# the shape that used to promote 40-char slices to "standalone base64".
BARE_CONCAT = (
    r"$B = 'ZWxlYXNlDQppcGNvbmZpZyAvcmVuZXcNCm5ldHNo' + 9 + "
    r"'IHdpbnNvY2sgcmVzZXQNCnN0YXJ0LXNsZWVw' + 'IC1zIDUNCg==' ; iex $B"
)


# ── R-1 · evidence preservation ──────────────────────────────────────────────
def test_r1_windows_backslashes_are_never_deleted():
    toks = tokenize_windows(r'C:\Windows\System32\cmd.exe /c whoami')
    assert toks[0] == r"C:\Windows\System32\cmd.exe"
    assert toks[1:] == ["/c", "whoami"]


def test_r1_quoted_windows_path_with_space_is_one_token():
    toks = tokenize_windows(r'"C:\Program Files\app\x.exe" -q')
    assert toks == [r"C:\Program Files\app\x.exe", "-q"]


def test_r1_first_token_span_is_a_byte_for_byte_slice():
    raw, start, end = first_token_span(WIN_PS)
    assert WIN_PS[start:end] == raw
    assert raw == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def test_r1_executable_matches_observed_evidence():
    ps = analyze_command(WIN_PS)["parsed_structure"]
    assert ps["executable"] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert ps["evidence_preserved"] is True
    assert ps["tokenizer"] == "windows-argv"
    assert WIN_PS[ps["executable_span"]["start"]:ps["executable_span"]["end"]] \
        == ps["executable_span"]["text"]


def test_r1_shell_token_count_is_named_honestly():
    ps = analyze_command(WIN_PS)["parsed_structure"]
    assert ps["shell_token_count"] == ps["token_count"]      # deprecated mirror
    assert ps["shell_token_count"] == len(tokenize(ps["pipeline_segments"][0]))


def test_r1_posix_commands_keep_posix_tokenization():
    assert tokenize("bash -c 'echo hi'") == ["bash", "-c", "echo hi"]


# ── R-2 · honest decode status ───────────────────────────────────────────────
def test_r2_obfuscated_sample_is_not_claimed_as_recovered():
    r = analyze_command(WIN_PS)
    assert r["decode_status"] == DECODE_PARTIALLY_RECOVERED
    assert r["decode_status_reason"]


def test_r2_unresolved_expressions_are_reported():
    r = analyze_command(WIN_PS)
    kinds = {u["kind"] for u in r["unresolved_expressions"]}
    assert "non-string-concat-operand" in kinds
    assert "unbound-variable" in kinds
    assert "dynamic-base64" in kinds
    assert "dynamic-scriptblock" in kinds
    for u in r["unresolved_expressions"]:
        assert u["expression"] and u["reason"] and u["found_in"]


def test_r2_recovered_is_impossible_while_anything_is_unresolved():
    r = analyze_command(WIN_PS)
    assert not (r["decode_status"] == DECODE_RECOVERED
                and r["unresolved_expressions"])


def test_r2_single_layer_base64_still_reaches_recovered():
    r = analyze_command("powershell.exe -enc aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAA=")
    assert r["decode_status"] == DECODE_RECOVERED
    assert r["unresolved_expressions"] == []


def test_r2_benign_command_is_not_required():
    r = analyze_command("ipconfig /all")
    assert r["decode_status"] == DECODE_NOT_REQUIRED


def test_r2_case_normalization_alone_is_not_a_recovery():
    r = analyze_command(r"InVOkE-eXpReSsION (Get-Content C:\x.txt)")
    assert r["ast_deobfuscation"]["applied"] is False
    assert r["ast_deobfuscation"]["semantic_transformations"] == 0
    assert r["decode_status"] != DECODE_RECOVERED


def test_r2_partial_concat_fold_is_flagged_incomplete():
    from powershell_ast import deobfuscate_ps
    d = deobfuscate_ps("$x = 'AB' + 9 + 'CD' + 'EF'")
    concat = [t for t in d["transformations"] if t["kind"] == "string-concat"]
    assert concat and concat[0]["complete"] is False
    assert "PARTIAL" in concat[0]["detail"]


def test_r2_pure_literal_fold_is_complete():
    from powershell_ast import deobfuscate_ps
    d = deobfuscate_ps("$x = 'AB' + 'CD' + 'EF'")
    concat = [t for t in d["transformations"] if t["kind"] == "string-concat"]
    assert concat and concat[0]["complete"] is True


# ── R-3 · artifact classes ───────────────────────────────────────────────────
def test_r3_concat_operand_is_a_fragment_and_is_not_decoded():
    r = analyze_command(BARE_CONCAT)
    frags = [p for p in r["identified_payloads"]
             if p["artifact_class"] == ARTIFACT_FRAGMENT]
    assert frags, "a `+`-joined literal must be classified FRAGMENT"
    for f in frags:
        assert f["auto_decoded"] is False
        assert f["fragment_of"]
    assert r["fragment_count"] == len(frags)


def test_r3_every_payload_carries_an_artifact_class():
    for cmd in (WIN_PS, BARE_CONCAT,
                "powershell.exe -enc aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAA="):
        for p in analyze_command(cmd)["identified_payloads"]:
            assert p["artifact_class"] in {
                "FRAGMENT", "CONSTRUCTED_VALUE", "ENCODED_ARTIFACT",
                "DECODED_ARTIFACT", "EXECUTABLE_ARTIFACT", "SHELLCODE_ARTIFACT",
            }


def test_r3_canonical_artifact_is_not_promoted_on_partial_recovery():
    c = analyze_command(WIN_PS)["canonical_decoded_artifact"]
    assert c["promoted"] is False
    assert c["text"] is None
    assert c["reason"]


def test_r3_canonical_artifact_is_promoted_on_full_recovery():
    c = analyze_command(
        "powershell.exe -enc aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAA="
    )["canonical_decoded_artifact"]
    assert c["promoted"] is True
    assert c["text"].strip() == "ipconfig /all"
    assert c["artifact_class"]


# ── adversarial · stronger honesty must not create false positives ──────────
@pytest.mark.parametrize("cmd", [
    "msbuild.exe /t:Build MySolution.sln",
    r'copy "C:\Program Files\app\readme.txt" D:\backup\readme.txt',
    "python3 -m pip install requests",
])
def test_benign_commands_produce_no_fragments_and_no_payload_promotion(cmd):
    r = analyze_command(cmd)
    assert r["canonical_decoded_artifact"]["promoted"] is False
    assert r["fragment_count"] == 0


def test_benign_literal_concat_is_a_fragment_not_a_payload():
    r = analyze_command("$msg = 'build' + 1 + 'done'; Write-Host $msg")
    assert r["canonical_decoded_artifact"]["promoted"] is False
    assert all(p["auto_decoded"] is False
               for p in r["identified_payloads"]
               if p["artifact_class"] == ARTIFACT_FRAGMENT)
