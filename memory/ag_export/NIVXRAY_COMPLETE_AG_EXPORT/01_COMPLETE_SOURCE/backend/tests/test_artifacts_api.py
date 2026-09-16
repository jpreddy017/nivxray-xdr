"""API-level tests for /api/artifacts/{capabilities,analyze} + /decode/smart PDF routing.

Phase 3 · Cycle A · Artifact Intelligence Layer.
"""
import base64
import io
import os
import hashlib
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

SAMPLE_PE_PATH = "/root/.venv/lib/python3.11/site-packages/pip/_vendor/distlib/t32.exe"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in login response: {r.json()}"
    return tok


@pytest.fixture(scope="module")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def pdf_bytes():
    from pypdf import PdfWriter
    w = PdfWriter()
    w.add_blank_page(width=595, height=842)
    w.add_metadata({"/Title": "artifact-router-test", "/Producer": "nivx-test"})
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_capabilities_lists_pe_and_pdf(auth):
    r = requests.get(f"{BASE_URL}/api/artifacts/capabilities", headers=auth, timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    analyzers = {a["artifact_type"]: a for a in data["analyzers"]}
    assert "pe" in analyzers and analyzers["pe"]["available"] is True
    assert "pdf" in analyzers and analyzers["pdf"]["available"] is True
    assert "display_name" in analyzers["pe"] and "display_name" in analyzers["pdf"]


def test_analyze_pe_via_bytes_b64(auth):
    with open(SAMPLE_PE_PATH, "rb") as f:
        b = f.read()
    r = requests.post(f"{BASE_URL}/api/artifacts/analyze",
                      headers=auth,
                      json={"bytes_b64": base64.b64encode(b).decode()}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["artifact_type"] == "pe"
    assert d["confidence"] >= 85
    assert d["capability_available"] is True
    a = d["analysis"]
    assert a["available"] is True
    assert a["overview"]["arch"]
    assert a["sections"], "PE sections must not be empty"
    # findings sorted by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sevs = [sev_order.get(f.get("severity"), 99) for f in a.get("findings", [])]
    assert sevs == sorted(sevs), f"findings not sorted by severity: {sevs}"


def test_analyze_pdf_via_bytes_b64(auth, pdf_bytes):
    r = requests.post(f"{BASE_URL}/api/artifacts/analyze",
                      headers=auth,
                      json={"bytes_b64": base64.b64encode(pdf_bytes).decode()}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["artifact_type"] == "pdf"
    assert d["confidence"] >= 80
    assert d["capability_available"] is True
    a = d["analysis"]
    assert a["available"] is True
    assert a["overview"]["page_count"] == 1
    assert a["overview"]["producer"] == "nivx-test"


def test_analyze_plain_text_returns_unknown(auth):
    b = b"just some random text with no magic bytes anywhere here 12345678"
    r = requests.post(f"{BASE_URL}/api/artifacts/analyze",
                      headers=auth,
                      json={"bytes_b64": base64.b64encode(b).decode()}, timeout=15)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["artifact_type"] == "unknown"
    assert d["confidence"] == 0
    assert d["capability_available"] is False
    assert d["fallback_reason"] == "no_analyzer_claimed_the_payload"


def test_analyze_pdf_via_canonical_output(auth, pdf_bytes):
    r = requests.post(f"{BASE_URL}/api/artifacts/analyze",
                      headers=auth,
                      json={"canonical_output": pdf_bytes.decode("latin-1")}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["artifact_type"] == "pdf"
    assert d["analysis"]["available"] is True
    assert d["analysis"]["overview"]["page_count"] == 1


def test_analyze_pe_is_deterministic(auth):
    with open(SAMPLE_PE_PATH, "rb") as f:
        b = f.read()
    payload = {"bytes_b64": base64.b64encode(b).decode()}
    r1 = requests.post(f"{BASE_URL}/api/artifacts/analyze", headers=auth, json=payload, timeout=30)
    r2 = requests.post(f"{BASE_URL}/api/artifacts/analyze", headers=auth, json=payload, timeout=30)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json(), "AnalysisResult.to_dict() must be byte-identical"


def test_decode_smart_pdf_reaches_binary_artifact_recovered(auth, pdf_bytes):
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      headers=auth,
                      json={"input": pdf_bytes.decode("latin-1")}, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    # IEDDE terminal state
    iedde = d.get("iedde") or {}
    assert iedde.get("terminal_state") == "binary_artifact_recovered", \
        f"terminal_state={iedde.get('terminal_state')}"
    ba = iedde.get("binary_artifact") or d.get("binary_artifact") or {}
    assert ba.get("kind") == "PDF", f"binary_artifact.kind={ba.get('kind')}"
    ra = ba.get("routed_analysis") or {}
    assert ra.get("artifact_type") == "pdf"
    assert ra.get("capability_available") is True
