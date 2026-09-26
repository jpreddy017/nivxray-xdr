"""RC4.2 verification — 12 targeted /api/decode/smart flows.

Covers the review-request flows:
  1) Login
  2) powershell-hex-csv-inline
  3) powershell-xor-inline-key
  4) RC4 inline decrypt (rc4-inline-decrypt)
  5) AES-CBC crypto-hint annotator
  6) DPAPI ProtectedData annotator
  7) MachineGuid → MITRE T1082
  8) Benign PS command (not malicious)
  9) batch-envvar-substitute
 10) cmd-envvar-substring-picker
 11) powershell-reverse-string
 12) powershell-reverse-regex-swap
"""
import os
import pytest
import requests

API_URL = os.environ.get("RC42_API_URL", "http://localhost:8001")
EMAIL = "admin@nivxray.com"
PWD   = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{API_URL}/api/auth/login",
                      json={"email": EMAIL, "password": PWD}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token")
    assert tok, "no access_token in login response"
    return tok


def _smart(token, payload):
    r = requests.post(f"{API_URL}/api/decode/smart",
                      headers={"Authorization": f"Bearer {token}",
                               "Content-Type": "application/json"},
                      json={"input": payload}, timeout=60)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}"
    return r.json()


def _recipe_ops(js):
    recipe = js.get("recipe") or []
    ops = []
    for step in recipe:
        if isinstance(step, dict):
            ops.append(step.get("op") or step.get("name") or "")
        else:
            ops.append(str(step))
    return ops


def _chain_ops(js):
    """Also inspect chain / chain_analyzer entries for ops."""
    ops = list(_recipe_ops(js))
    for key in ("chain", "chain_analysis", "chain_analyzer", "stages"):
        v = js.get(key)
        if isinstance(v, list):
            for st in v:
                if isinstance(st, dict):
                    ops.append(st.get("op") or st.get("name") or st.get("stage") or "")
    return [o for o in ops if o]


# ---- Flow 1 ----
def test_login_returns_access_token(token):
    assert isinstance(token, str) and len(token) > 20


# ---- Flow 2 ----
def test_powershell_hex_csv_inline(token):
    payload = ("$h='43,61,6c,63,2e,65,78,65'; "
               "$c = $h -split ',' | ForEach-Object {[char][int]('0x'+$_)}; "
               "Invoke-Expression ($c -join '')")
    js = _smart(token, payload)
    ops = _chain_ops(js)
    assert any("powershell-hex-csv-inline" in o for o in ops), f"op missing; ops={ops}"
    assert "Calc.exe" in (js.get("output_raw") or ""), f"output_raw={js.get('output_raw')!r}"


# ---- Flow 3 ----
def test_powershell_xor_inline_key(token):
    payload = ("$k=[System.Text.Encoding]::ASCII.GetBytes('KEY'); "
               "$b=[byte[]](7,36,25,32,17,29,25,12,32,25,52,11,17,4,12); "
               "$d=-join(0..($b.Length-1)|%{[char]($b[$_] -bxor $k[$_ % $k.Length])}); IEX $d")
    js = _smart(token, payload)
    ops = _chain_ops(js)
    assert any("powershell-xor-inline-key" in o for o in ops), f"op missing; ops={ops}"


# ---- Flow 4 ----
def test_rc4_inline_decrypt(token):
    payload = (
        "$key = [System.Text.Encoding]::ASCII.GetBytes('NivXKey2026'); "
        "$cipher = [Convert]::FromBase64String('1czR7GQkGxqyMkprVmc8OtH7q4577QmQ'); "
        "$S = 0..255; $j = 0; "
        "for ($i=0; $i -lt 256; $i++) { "
        "  $j = ($j + $S[$i] + $key[$i % $key.Length]) % 256; "
        "  $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t } "
        "$i=0; $j=0; $out = New-Object byte[] $cipher.Length; "
        "for ($k=0; $k -lt $cipher.Length; $k++) { "
        "  $i = ($i+1) % 256; $j = ($j + $S[$i]) % 256; "
        "  $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t; "
        "  $out[$k] = $cipher[$k] -bxor $S[($S[$i]+$S[$j]) % 256] } "
        "Invoke-Expression ([Text.Encoding]::ASCII.GetString($out))"
    )
    js = _smart(token, payload)
    output = js.get("output_raw") or ""
    hints = js.get("crypto_hints") or []
    assert "http://c2.evil.io/beacon" in output, f"output_raw missing beacon; got={output[:300]!r}"
    match = [h for h in hints if isinstance(h, dict)
             and (h.get("algorithm") or "").upper() == "RC4"
             and (h.get("key_source") or "").lower() == "inline"]
    assert match, f"crypto_hints missing RC4/inline entry; hints={hints}"


# ---- Flow 5 ----
def test_aes_cbc_crypto_hint(token):
    payload = (
        "using (Aes aes = Aes.Create()) { aes.Mode = CipherMode.CBC; "
        "aes.Key = key; aes.IV = iv; "
        "ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV); "
        "byte[] plain = dec.TransformFinalBlock(cipher, 0, cipher.Length); }"
    )
    js = _smart(token, payload)
    hints = js.get("crypto_hints") or []
    aes = [h for h in hints if isinstance(h, dict)
           and (h.get("algorithm") or "").upper() == "AES-CBC"]
    assert aes, f"AES-CBC hint missing; hints={hints}"
    assert (aes[0].get("recovery") or "") == "runtime-required", f"recovery={aes[0].get('recovery')!r}"
    sr = js.get("static_recovery") or {}
    verdict = str(sr.get("verdict") or "")
    assert "runtime-decryption-required" in verdict, f"static_recovery.verdict={verdict!r}"


# ---- Flow 6 ----
def test_dpapi_hint(token):
    payload = ("byte[] plain = ProtectedData.Unprotect(cipher, null, "
               "DataProtectionScope.CurrentUser);")
    js = _smart(token, payload)
    hints = js.get("crypto_hints") or []
    dpapi = [h for h in hints if isinstance(h, dict)
             and (h.get("algorithm") or "").upper() == "DPAPI"
             and (h.get("key_source") or "").lower() == "dpapi"]
    assert dpapi, f"DPAPI hint missing; hints={hints}"


# ---- Flow 7 ----
def test_machineguid_mitre_t1082(token):
    payload = ("$mg = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid; "
               "$key = [System.Text.Encoding]::ASCII.GetBytes($mg.Substring(0,16));")
    js = _smart(token, payload)
    mitre = js.get("mitre") or []
    ids = []
    for m in mitre:
        if isinstance(m, dict):
            ids.append(m.get("id") or m.get("technique_id") or "")
        else:
            ids.append(str(m))
    assert any("T1082" in i for i in ids), f"T1082 missing; mitre={mitre}"


# ---- Flow 8 ----
def test_benign_not_malicious(token):
    js = _smart(token, "Get-Process | Where-Object CPU -gt 100")
    verdict = (js.get("verdict") or js.get("classification")
               or (js.get("static_recovery") or {}).get("verdict") or "")
    verdict = str(verdict).lower()
    assert "malicious" not in verdict, f"benign flagged malicious; verdict={verdict!r}"


# ---- Flow 9 ----
def test_batch_envvar_substitute(token):
    payload = 'set p=c_a_l_c_._e_x_e && start "" %p:_=%'
    js = _smart(token, payload)
    ops = _chain_ops(js)
    assert any("batch-envvar-substitute" in o for o in ops), f"op missing; ops={ops}"
    assert "calc.exe" in (js.get("output_raw") or "").lower(), f"output={js.get('output_raw')!r}"


# ---- Flow 10 ----
def test_cmd_envvar_substring_picker(token):
    js = _smart(token, "%ComSpec:~-7,3%")
    ops = _chain_ops(js)
    assert any("cmd-envvar-substring-picker" in o for o in ops), f"op missing; ops={ops}"
    assert "cmd" in (js.get("output_raw") or "").lower(), f"output={js.get('output_raw')!r}"


# ---- Flow 11 ----
def test_powershell_reverse_string(token):
    payload = "$s = 'exe.clac'; $x = -join ($s[-1..-8]); Invoke-Expression $x"
    js = _smart(token, payload)
    ops = _chain_ops(js)
    assert any("powershell-reverse-string" in o for o in ops), f"op missing; ops={ops}"


# ---- Flow 12 ----
def test_powershell_reverse_regex_swap(token):
    payload = "$s = 'exe.calc' -replace '(\\w+)\\.(\\w+)','$2.$1'; Start-Process $s"
    js = _smart(token, payload)
    ops = _chain_ops(js)
    assert any("powershell-reverse-regex-swap" in o for o in ops), f"op missing; ops={ops}"
