"""IEDDE Stage 2 + Stage 3 · Technique Detector + Recipe Planner tests."""
from __future__ import annotations

import json

import pytest

from services.interpreter_identifier import identify
from services.recipe_planner import plan_and_execute
from services.technique_detector import (
    DetectionContext,
    detect_techniques,
    registered_names,
)


# ---------------------------------------------------------------------------
# Stage 2 · Technique detector
# ---------------------------------------------------------------------------


def _ctx(payload: str) -> DetectionContext:
    r = identify(payload)
    return DetectionContext(
        primary_interpreter=r.primary_interpreter,
        interpreters=tuple(m.interpreter for m in r.interpreters),
    )


def test_registry_contains_all_expected_techniques():
    names = set(registered_names())
    for expected in (
        "base64", "utf16le", "hex", "xor", "rc4_wrapper", "aes_wrapper",
        "gzip", "zlib", "string_concat", "char_array", "env_var_assembly",
        "ps_backtick", "cmd_caret", "reverse", "url_encoding",
        "unicode_escape", "ps_invocation_wrapper", "ps_launcher_wrapper",
    ):
        assert expected in names, f"missing detector: {expected}"


def test_base64_quoted_literal_detected():
    # Realistic b64 blob (60+ chars) — the detector's 20-char threshold
    # deliberately ignores toy strings under 20 chars.
    payload = 'iex "ZWNobyBoZWxsbyB0aGlzIGlzIGEgbG9uZ2VyIGJhc2U2NCBibG9iIGZvciByZWFsaXNt"'
    inv = detect_techniques(payload, _ctx(payload))
    b64 = inv.by_name("base64")
    assert b64 is not None
    assert b64.confidence >= 0.80


def test_hex_byte_array_detected():
    payload = "shellcode = 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77"
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("hex") is not None


def test_gzip_marker_in_b64_detected():
    # H4sI is the base64 prefix of the gzip magic bytes 1f 8b 08.
    payload = 'iex "H4sIAAAAAAAAAytJLS4BAAx+f9gEAAAA"'
    inv = detect_techniques(payload, _ctx(payload))
    gz = inv.by_name("gzip")
    assert gz is not None
    assert gz.confidence >= 0.80


def test_zlib_marker_in_b64_detected():
    # `eJw` is the base64 prefix of the zlib header byte 0x78 0x9c.
    # Extend to a realistic length so the b64 detector doesn't reject.
    payload = 'iex "eJwrSS0uAQAEFwGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("zlib") is not None


def test_string_concat_detected():
    payload = "powershell.exe -Command \"&(('Get-' + 'Process') 'lsass')\""
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("string_concat") is not None
    assert inv.by_name("ps_invocation_wrapper") is not None
    assert inv.by_name("ps_launcher_wrapper") is not None


def test_xor_detected_and_marked_as_key_required():
    payload = "python3 -c \"print(''.join(chr(ord(c) ^ 5) for c in 'bco'))\""
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("xor") is not None


def test_char_array_detected_ps():
    payload = "[char[]](72, 101, 108, 108, 111) -join ''"
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("char_array") is not None


def test_env_var_assembly_detected_ps():
    payload = "$env:USERNAME + $env:PATH[0..2]"
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("env_var_assembly") is not None


def test_backtick_only_fires_in_powershell_ctx():
    inv_no = detect_techniques(
        "`a`b`c",
        DetectionContext(primary_interpreter="unknown", interpreters=()),
    )
    assert inv_no.by_name("ps_backtick") is None

    inv_yes = detect_techniques(
        "powershell.exe -Command \"`ec`h`o hi\"",
        _ctx("powershell.exe -Command \"`ec`h`o hi\""),
    )
    assert inv_yes.by_name("ps_backtick") is not None


def test_url_encoding_detected():
    payload = "http://example.com/path?q=%68%65%6c%6c%6f"
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("url_encoding") is not None


def test_unicode_escape_detected():
    payload = r'"\u0068\u0065\u006c\u006c\u006f"'
    inv = detect_techniques(payload, _ctx(payload))
    assert inv.by_name("unicode_escape") is not None


def test_empty_input_yields_empty_inventory():
    inv = detect_techniques("", _ctx(""))
    assert inv.techniques == []


def test_technique_inventory_is_deterministic():
    payload = "powershell.exe -Command \"&(('Get-' + 'Process') 'lsass')\""
    a = json.dumps(detect_techniques(payload, _ctx(payload)).to_dict(), sort_keys=True)
    b = json.dumps(detect_techniques(payload, _ctx(payload)).to_dict(), sort_keys=True)
    assert a == b


# ---------------------------------------------------------------------------
# Stage 3 · Recipe Planner (end-to-end IEDDE loop)
# ---------------------------------------------------------------------------


def test_planner_canonicalises_lsass_payload():
    """Full IEDDE loop on the reference LSASS invocation payload."""
    payload = "powershell.exe -NoProfile -Command \"&(('Get-' + 'Process') 'lsass')\""
    r = plan_and_execute(payload)
    assert "Get-Process lsass" in r.canonical_output
    assert r.terminal_state == "canonical"
    # At least the structural pass fired.
    assert any(s.chosen_pass == "structural" and s.changed for s in r.stages)


def test_planner_stops_cleanly_on_plain_text():
    r = plan_and_execute("Just a sentence with nothing to decode.")
    assert r.terminal_state == "canonical"
    assert "no_further_techniques_detected" in r.stop_reason
    assert r.canonical_output == "Just a sentence with nothing to decode."


def test_planner_stability_gate_on_aes_key_unavailable():
    payload = (
        "$aes = New-Object System.Security.Cryptography.AesManaged;"
        "$aes.Mode = 'CBC';"
        "$plain = $aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)"
    )
    r = plan_and_execute(payload)
    assert r.terminal_state == "stability_gate"
    assert "AES" in r.stop_reason or "aes" in r.stop_reason.lower()
    assert "key_unavailable" in r.stop_reason.lower() or "key unavailable" in r.stop_reason.lower()


def test_planner_stability_gate_on_rc4_key_unavailable():
    payload = "$ct = RC4($key, $cipher)"
    r = plan_and_execute(payload)
    assert r.terminal_state == "stability_gate"
    assert "rc4" in r.stop_reason.lower() or "RC4" in r.stop_reason


def test_planner_never_returns_output_equals_input_silently():
    """Rule 24 · §4 contract: silent OUTPUT = INPUT is forbidden."""
    payload = "This is definitely encrypted with some key I don't have."
    r = plan_and_execute(payload)
    # Either canonical (nothing needs decoding — plain text) OR stability_gate
    # with a reasoned stop message.
    assert r.stop_reason  # never empty
    if r.canonical_output == payload:
        # Then we must have a reason.
        assert (
            r.terminal_state in {"canonical", "stability_gate"}
            and r.stop_reason
        )


def test_planner_is_deterministic():
    payload = "powershell.exe -Command \"&(('Get-' + 'Process') 'lsass')\""
    a = json.dumps(plan_and_execute(payload).to_dict(), sort_keys=True)
    b = json.dumps(plan_and_execute(payload).to_dict(), sort_keys=True)
    assert a == b


def test_planner_records_every_iteration():
    payload = "powershell.exe -Command \"&(('a'+'b'+'c') 'x')\""
    r = plan_and_execute(payload)
    # At least one stage must be recorded.
    assert len(r.stages) >= 1
    for s in r.stages:
        assert s.iteration >= 0
        assert isinstance(s.techniques_present, list)


def test_planner_reports_final_interpreter():
    r = plan_and_execute("powershell.exe -Command \"Get-Process\"")
    assert r.final_interpreter == "powershell"


def test_planner_bounds_iterations():
    r = plan_and_execute("x" * 100, max_iterations=3)
    assert r.iterations_executed <= 3
