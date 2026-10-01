"""RC4.2 - Transformation trace + recipe attribution tests"""
import os
import json
import requests
import pytest

BASE_URL = "http://localhost:8001"
DECODE_URL = f"{BASE_URL}/api/decode/smart"

_TOKEN = None
def _token():
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    # Try cached token first
    try:
        with open("/app/.tok") as f:
            t = f.read().strip()
            if t:
                # quick validity check
                r = requests.get(f"{BASE_URL}/api/auth/me",
                                 headers={"Authorization": f"Bearer {t}"}, timeout=30)
                if r.status_code == 200:
                    _TOKEN = t
                    return _TOKEN
    except Exception:
        pass
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": "admin@nivxray.com",
                            "password": "uulVDp5cCSB3Hva99s7UUAwK"}, timeout=300)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    _TOKEN = r.json()["access_token"]
    try:
        with open("/app/.tok", "w") as f:
            f.write(_TOKEN)
    except Exception:
        pass
    return _TOKEN

def _post(payload):
    h = {"Authorization": f"Bearer {_token()}"}
    r = requests.post(DECODE_URL, json=payload, headers=h, timeout=300)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}"
    return r.json()


def _recipe_ops(result):
    return [r.get("op") for r in (result.get("recipe") or []) if isinstance(r, dict)]


# ---------- Flow 1: SET + %p:_=% ----------
def test_flow1_set_and_envvar_substitute():
    body = {"input": 'set "p=c_a_l_c_._e_x_e" && start %p:_=%'}
    res = _post(body)
    ops = _recipe_ops(res)
    trace = res.get("transformation_trace") or []
    assert "batch-envvar-substitute" in ops, f"missing op, recipe={ops}"
    steps = {t.get("step") for t in trace}
    assert "set-var" in steps, f"missing set-var, trace={trace}"
    assert "envvar-substitute" in steps, f"missing envvar-substitute, trace={trace}"
    set_details = [t["detail"] for t in trace if t["step"] == "set-var"]
    assert any("p = c_a_l_c_._e_x_e" in d for d in set_details), f"set-var detail wrong: {set_details}"
    sub_details = [t["detail"] for t in trace if t["step"] == "envvar-substitute"]
    assert any("calc.exe" in d for d in sub_details), f"envvar-substitute missing calc.exe: {sub_details}"


# ---------- Flow 2: concatenation of two SET vars ----------
def test_flow2_two_set_vars():
    body = {"input": "set p=cer && set q=tutil && start %p%%q%.exe"}
    res = _post(body)
    ops = _recipe_ops(res)
    trace = res.get("transformation_trace") or []
    assert "batch-envvar-substitute" in ops, f"missing op, recipe={ops}"
    set_details = [t["detail"] for t in trace if t.get("step") == "set-var"]
    assert any("p = cer" in d for d in set_details), f"missing p=cer, trace={trace}"
    assert any("q = tutil" in d for d in set_details), f"missing q=tutil, trace={trace}"


# ---------- Flow 3: substring picker ----------
def test_flow3_envvar_substring():
    body = {"input": "%ComSpec:~-7,3%"}
    res = _post(body)
    ops = _recipe_ops(res)
    trace = res.get("transformation_trace") or []
    assert "cmd-envvar-substring-picker" in ops, f"missing op, recipe={ops}"
    steps = {t.get("step") for t in trace}
    assert "envvar-substring" in steps, f"trace missing envvar-substring: {trace}"


# ---------- Flow 4: benign command should NOT have transformation_trace ----------
def test_flow4_benign_no_trace():
    body = {"input": "Get-Process | Where-Object CPU -gt 100"}
    res = _post(body)
    assert "transformation_trace" not in res or not res.get("transformation_trace"), \
        f"benign command should have no trace, got: {res.get('transformation_trace')}"


# ---------- Flow 5: RC4 regression ----------
def test_flow5_rc4_regression():
    rc4_payload = (
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
    res = _post({"input": rc4_payload})
    output_raw = str(res.get("output_raw") or res.get("output") or "")
    crypto = res.get("crypto_hints") or []
    algos = [(h.get("algorithm") or "").upper() for h in crypto]
    assert any("RC4" in a for a in algos), f"missing RC4 hint, got: {algos}"
    assert "http://c2.evil.io/beacon" in output_raw, f"missing decoded URL in output_raw"


# ---------- Flow 6: AES-CBC regression ----------
def test_flow6_aes_cbc_regression():
    aes_payload = (
        "$aes=[System.Security.Cryptography.Aes]::Create();"
        "$aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;"
        "$aes.Key=[System.Text.Encoding]::UTF8.GetBytes('0123456789ABCDEF0123456789ABCDEF');"
        "$aes.IV=[System.Text.Encoding]::UTF8.GetBytes('FEDCBA9876543210');"
        "$dec=$aes.CreateDecryptor();"
        "$dec.TransformFinalBlock($ct,0,$ct.Length);"
    )
    res = _post({"input": aes_payload})
    crypto = res.get("crypto_hints") or []
    assert len(crypto) > 0, "no crypto_hints returned"
    sr = res.get("static_recovery") or {}
    verdict = str(sr.get("verdict") or "")
    assert "runtime-decryption-required" in verdict, f"missing runtime-decryption-required, verdict={verdict}"


# ---------- Flow 7: benign verdict regression ----------
def test_flow7_benign_verdict():
    res = _post({"input": "Get-Process | Where-Object CPU -gt 100"})
    verdict = str(res.get("verdict") or res.get("threat_verdict") or "").lower()
    assert "malicious" not in verdict, f"benign command flagged malicious: verdict={verdict}, full={json.dumps(res)[:400]}"
