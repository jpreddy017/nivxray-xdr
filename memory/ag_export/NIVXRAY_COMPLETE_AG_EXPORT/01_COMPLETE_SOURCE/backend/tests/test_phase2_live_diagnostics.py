"""Phase 2 live-API tests: Broken Payload Diagnostics via /api/decode/smart and /api/analyze/async."""
import os
import time
import requests
import pytest

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE:
    # fallback: try reading frontend env
    try:
        with open("/app/frontend/.env") as fh:
            for line in fh:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE = line.split("=", 1)[1].strip().rstrip("/")
                    break
    except Exception:
        pass

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

AES_PAYLOAD = 'powershell.exe -Command "$aes = [System.Security.Cryptography.Aes]::Create()"'


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=90)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:400]}"
    return r.json()["access_token"]


@pytest.fixture
def auth(token):
    return {"Authorization": f"Bearer {token}"}


def _decode(auth, text):
    r = requests.post(f"{BASE}/api/decode/smart", json={"input": text}, headers=auth, timeout=60)
    assert r.status_code == 200, f"decode failed: {r.status_code} {r.text[:400]}"
    return r.json()


def test_aes_payload_stability_gate_with_diagnostics(auth):
    body = _decode(auth, AES_PAYLOAD)
    assert body.get("iedde_terminal_state") == "stability_gate", body.get("iedde_terminal_state")
    diags = body.get("iedde_diagnostics")
    assert isinstance(diags, list) and len(diags) > 0, f"expected non-empty diagnostics, got {diags!r}"
    for d in diags:
        for k in ("layer", "reason", "recommendation", "severity", "code"):
            assert k in d and isinstance(d[k], str) and d[k].strip(), f"bad field {k}: {d}"
        assert d["severity"] in ("medium", "high", "critical", "info"), d["severity"]
        hs = d.get("hex_snippet")
        assert hs is None or isinstance(hs, str), f"hex_snippet must be str|None: {hs!r}"


def test_whoami_canonical_no_diagnostics(auth):
    body = _decode(auth, "whoami")
    diags = body.get("iedde_diagnostics")
    assert diags == [], f"canonical recovery should have empty diagnostics, got {diags!r}"


def test_diagnostics_are_deterministic(auth):
    a = _decode(auth, AES_PAYLOAD).get("iedde_diagnostics")
    b = _decode(auth, AES_PAYLOAD).get("iedde_diagnostics")
    assert a == b, f"diagnostics not deterministic:\n{a}\n---\n{b}"


def test_pe_in_base64_binary_artifact_recovered(auth):
    # Fabricated PE-in-base64 similar to tests/test_binary_terminal_state.py
    import base64
    pe = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x64\x86" + b"\x00" * 120
    b64 = base64.b64encode(pe).decode()
    payload = f"powershell.exe -c \"[Convert]::FromBase64String('{b64}')\""
    body = _decode(auth, payload)
    ts = body.get("iedde_terminal_state")
    assert ts == "binary_artifact_recovered", f"expected binary_artifact_recovered, got {ts}"
    assert body.get("iedde_diagnostics") == [], body.get("iedde_diagnostics")


def test_analyze_async_final_job_includes_iedde_diagnostics(auth):
    r = requests.post(f"{BASE}/api/analyze/async", json={"input": AES_PAYLOAD}, headers=auth, timeout=60)
    assert r.status_code in (200, 201, 202), f"async submit failed: {r.status_code} {r.text[:300]}"
    job = r.json()
    job_id = job.get("job_id") or job.get("id")
    assert job_id, f"no job id in {job}"
    deadline = time.time() + 60
    final = None
    while time.time() < deadline:
        s = requests.get(f"{BASE}/api/analyze/status/{job_id}", headers=auth, timeout=30)
        assert s.status_code == 200, s.text[:300]
        j = s.json()
        st = j.get("status") or j.get("state")
        if st in ("completed", "done", "finished", "success"):
            final = j
            break
        if st in ("failed", "error"):
            final = j
            break
        time.sleep(1)
    assert final is not None, "async job did not finish in time"
    assert "iedde_diagnostics" in final, f"iedde_diagnostics missing at top level of job doc: keys={list(final.keys())}"
