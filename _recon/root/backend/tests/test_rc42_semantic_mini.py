"""Tests for RC4.2 powershell-semantic-mini + regression on prior RC4.1/RC4.2 features."""
import os
import requests
import pytest

BASE_URL = "http://localhost:8001"
SMART = f"{BASE_URL}/api/decode/smart"


@pytest.fixture(scope="module")
def token():
    last = None
    for _ in range(3):
        try:
            r = requests.post(f"{BASE_URL}/api/auth/login", json={
                "email": "admin@nivxray.com",
                "password": "uulVDp5cCSB3Hva99s7UUAwK"
            }, timeout=90)
            if r.status_code == 200:
                return r.json().get("access_token") or r.json().get("token")
            last = f"{r.status_code} {r.text[:200]}"
        except Exception as e:
            last = str(e)
    pytest.skip(f"login failed: {last}")


@pytest.fixture()
def headers(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def _post(headers, payload):
    return requests.post(SMART, json=payload, headers=headers, timeout=60)


def test_flow1_semantic_mini_reverse_recovery(headers):
    ipt = "Invoke-Expression (('exe.clac') -join '' -replace '([a-z]+)\\.([a-z]+)','$2.$1' | ForEach-Object { $_[-1..-8] -join '' })"
    r = _post(headers, {"input": ipt})
    assert r.status_code == 200, r.text[:500]
    data = r.json()
    recipe = data.get("recipe") or []
    ops = [step.get("op") for step in recipe]
    assert "powershell-semantic-mini" in ops, f"ops={ops}"
    trace = data.get("transformation_trace") or []
    ps_steps = [t for t in trace if t.get("step") == "ps-semantic"]
    assert len(ps_steps) >= 3, f"ps-semantic steps={len(ps_steps)} trace={trace}"
    out = data.get("output_raw") or ""
    assert "Recovered command:" in out and "exe.calc" in out, f"out={out[:800]}"
    assert "Cannot prove this launches" in out, f"out={out[:800]}"


def test_flow2_semantic_mini_real_binary_verdict(headers):
    # already-reversed literal 'calc.exe' - chain reverses to 'exe.clac' effectively;
    # per spec, replacing literal to 'calc.exe' yields recovered 'calc.exe' after full chain (reverse -> exe.clac->clac.exe? -> reversed 8 chars)
    # The task requires that when recovered literal is a real Windows binary, output says LOLBAS-safe path
    # Chain math: 'clac.exe' -> replace-swap -> 'exe.clac' -> reverse first 8 -> 'calc.exe'
    # (Review spec said "literal changed to 'calc.exe' (already reversed)" - actual literal
    #  needed to recover the real binary 'calc.exe' is 'clac.exe'. Backend behavior is correct.)
    ipt = "Invoke-Expression (('clac.exe') -join '' -replace '([a-z]+)\\.([a-z]+)','$2.$1' | ForEach-Object { $_[-1..-8] -join '' })"
    r = _post(headers, {"input": ipt})
    assert r.status_code == 200
    data = r.json()
    out = data.get("output_raw") or ""
    assert "Launches calc.exe" in out and "LOLBAS-safe path recovered" in out, f"out={out[:800]}"


def test_flow3_regression_batch_envvar(headers):
    ipt = 'set "p=c_a_l_c_._e_x_e" && start %p:_=%'
    r = _post(headers, {"input": ipt})
    assert r.status_code == 200
    data = r.json()
    ops = [s.get("op") for s in (data.get("recipe") or [])]
    assert "batch-envvar-substitute" in ops, f"ops={ops}"
    trace = data.get("transformation_trace") or []
    steps = " ".join(str(t) for t in trace)
    assert "set" in steps.lower() and "envvar" in steps.lower(), f"trace={trace}"


def test_flow4_regression_rc4_inline(headers):
    ipt = (
        "$key='NivXKey2026'; $cipher='1czR7GQkGxqyMkprVmc8OtH7q4577QmQ';"
        "$S=0..255; $j=0; $kb=[Text.Encoding]::UTF8.GetBytes($key);"
        "for($i=0;$i -lt 256;$i++){ $j=($j + $S[$i] + $kb[$i % $kb.Length]) % 256; $t=$S[$i]; $S[$i]=$S[$j]; $S[$j]=$t }"
        "$c=[Convert]::FromBase64String($cipher); $i=0; $j=0; $out=@();"
        "for($k=0;$k -lt $c.Length;$k++){ $i=($i+1)%256; $j=($j+$S[$i])%256; $t=$S[$i]; $S[$i]=$S[$j]; $S[$j]=$t; $out += $c[$k] -bxor $S[($S[$i]+$S[$j])%256] }"
        "[Text.Encoding]::UTF8.GetString($out)"
    )
    r = _post(headers, {"input": ipt})
    assert r.status_code == 200
    data = r.json()
    out = data.get("output_raw") or ""
    assert "http://c2.evil.io/beacon" in out, f"out={out[:800]}"
    ch = data.get("crypto_hints") or []
    assert ch and ch[0].get("algorithm") == "RC4", f"crypto_hints={ch}"


def test_flow5_regression_aes_cbc(headers):
    ipt = "$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.CreateDecryptor()"
    r = _post(headers, {"input": ipt})
    assert r.status_code == 200
    data = r.json()
    ch = data.get("crypto_hints") or []
    assert any("AES" in (h.get("algorithm") or "") for h in ch), f"crypto_hints={ch}"
    sr = data.get("static_recovery") or {}
    verdict = sr.get("verdict", "")
    assert "runtime-decryption-required" in verdict, f"verdict={verdict} sr={sr}"


def test_flow6_regression_benign(headers):
    ipt = "Get-Process | Where-Object CPU -gt 100"
    r = _post(headers, {"input": ipt})
    assert r.status_code == 200
    data = r.json()
    verdict = (data.get("verdict") or data.get("static_recovery", {}).get("verdict") or "").lower()
    assert "malicious" not in verdict, f"verdict={verdict}"
