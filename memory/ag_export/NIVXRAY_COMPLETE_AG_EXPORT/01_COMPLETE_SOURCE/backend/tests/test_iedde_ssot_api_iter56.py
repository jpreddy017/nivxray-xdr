"""Iter-56 focused SSOT wiring API tests via public preview URL."""
import os, time, json, requests, pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # fallback: read from frontend .env
    with open("/app/frontend/.env") as f:
        for l in f:
            if l.startswith("REACT_APP_BACKEND_URL"):
                BASE_URL = l.strip().split("=", 1)[1].strip().strip('"').rstrip("/")

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

PS_ENC = "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA=="
AES_INPUT = 'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'

@pytest.fixture(scope="module")
def token():
    last = None
    for _ in range(5):
        try:
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=120)
            if r.status_code == 200:
                return r.json()["access_token"]
            last = r.text[:200]
        except Exception as e:
            last = str(e)
        time.sleep(3)
    pytest.fail(f"login failed after retries: {last}")

@pytest.fixture(scope="module")
def hdr(token):
    return {"Authorization": f"Bearer {token}"}

def _decode(hdr, payload):
    last = None
    for _ in range(5):
        try:
            r = requests.post(f"{BASE_URL}/api/decode/smart",
                              headers=hdr, json={"input": payload}, timeout=120)
            if r.status_code == 200:
                return r.json()
            last = f"{r.status_code}:{r.text[:200]}"
        except Exception as e:
            last = str(e)
        time.sleep(3)
    pytest.fail(f"decode failed: {last}")

def test_ps_encoded_iedde_canonical(hdr):
    d = _decode(hdr, PS_ENC)
    assert d.get("iedde_terminal_state") == "canonical", d
    assert d.get("canonical_confidence") == 100
    assert "canonical_reached" in (d.get("canonical_confidence_reason") or "")
    assert isinstance(d.get("iedde"), dict)
    stages = d["iedde"].get("stages")
    assert isinstance(stages, list) and len(stages) > 0
    sel = stages[0].get("decision", {}).get("selected")
    assert sel in ("utf16le", "base64"), sel
    out = d.get("output", "")
    if isinstance(out, dict):
        out = json.dumps(out)
    assert "Write-Host" in out or "tweet" in out.lower(), out[:400]

def test_whoami_canonical(hdr):
    d = _decode(hdr, "whoami")
    assert d.get("iedde_terminal_state") == "canonical"
    assert d.get("canonical_confidence") == 100

def test_aes_stability_gate(hdr):
    d = _decode(hdr, AES_INPUT)
    assert d.get("iedde_terminal_state") == "stability_gate", d
    assert (d.get("canonical_confidence") or 0) < 100
    reason = d.get("canonical_confidence_reason") or ""
    assert len(reason) > 5

def test_determinism(hdr):
    d1 = _decode(hdr, PS_ENC)
    d2 = _decode(hdr, PS_ENC)
    assert json.dumps(d1.get("iedde"), sort_keys=True) == json.dumps(d2.get("iedde"), sort_keys=True)
    assert d1.get("iedde_terminal_state") == d2.get("iedde_terminal_state")
    assert d1.get("canonical_confidence") == d2.get("canonical_confidence")
    assert d1.get("canonical_confidence_reason") == d2.get("canonical_confidence_reason")

def test_atomic_ioc_no_augment(hdr):
    d = _decode(hdr, "8.8.8.8")
    ca = d.get("canonical_artifact") or {}
    assert ca.get("terminal_state") == "atomic_ioc"
    # IEDDE fields should be null/absent for atomic IOC
    assert not d.get("iedde")
    assert d.get("iedde_terminal_state") in (None, "", "atomic_ioc")

def test_analyze_async_has_iedde_fields(hdr):
    r = requests.post(f"{BASE_URL}/api/analyze/async",
                      headers=hdr, json={"input": PS_ENC}, timeout=30)
    assert r.status_code in (200, 201, 202), r.text
    job_id = r.json().get("job_id") or r.json().get("id")
    assert job_id
    for _ in range(30):
        s = requests.get(f"{BASE_URL}/api/analyze/status/{job_id}", headers=hdr, timeout=30)
        assert s.status_code == 200, s.text
        j = s.json()
        if j.get("status") in ("done", "completed", "success", "finished"):
            break
        time.sleep(1)
    else:
        pytest.fail(f"job never completed: {j}")
    assert "iedde" in j
    assert "iedde_terminal_state" in j
    assert "canonical_confidence" in j
    assert "canonical_confidence_reason" in j
    assert j["iedde_terminal_state"] == "canonical"
    assert j["canonical_confidence"] == 100
