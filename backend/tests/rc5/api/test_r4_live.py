"""Live API tests for R4 Deterministic Investigation Report Generator."""
import os
import re
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
CASE_ID = "case_dfir_bumblebee_akira_2026"
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

EXPECTED_SECTIONS = [
    "executive_summary", "case_metadata", "verdict_rollup", "mitre_coverage",
    "process_ancestry", "top_entities", "chronological_timeline",
    "commandline_decoding", "enrichment", "signature",
]


@pytest.fixture(scope="module")
def auth_token():
    for path in ["/api/auth/login", "/api/v2/auth/login"]:
        r = requests.post(f"{BASE_URL}{path}", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
        if r.status_code == 200:
            d = r.json()
            tok = d.get("access_token") or d.get("token") or (d.get("data") or {}).get("access_token")
            if tok:
                return tok
    pytest.skip("Cannot obtain admin token")


@pytest.fixture
def headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


def test_report_json_envelope(headers):
    r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report", headers=headers, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("schema_version") == "r4.0"
    assert d.get("case_id") == CASE_ID
    assert d.get("generated_at")
    assert "generator" in d
    sections = d.get("sections") or []
    assert len(sections) == 10
    names = [s.get("name") or s.get("id") for s in sections]
    assert names == EXPECTED_SECTIONS, names
    sig = d.get("signature") or {}
    sha = sig.get("sha256") if isinstance(sig, dict) else None
    if not sha:
        # look inside sections
        for s in sections:
            if (s.get("name") or s.get("id")) == "signature":
                sha = ((s.get("body") or {}).get("sha256")) or (s.get("body") or {}).get("hash")
    assert sha and re.fullmatch(r"[0-9a-f]{64}", sha), f"bad sha256: {sha}"


def test_report_md(headers):
    r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report.md", headers=headers, timeout=30)
    assert r.status_code == 200
    assert "text/plain" in r.headers.get("content-type", "").lower()
    body = r.text
    assert "# NivXRay · Deterministic Investigation Report" in body
    assert CASE_ID in body
    assert re.search(r"[0-9a-f]{64}", body)
    for i, sec in enumerate(EXPECTED_SECTIONS, 1):
        assert re.search(rf"^##\s*{i}\.", body, re.M), f"missing section {i} heading"


def test_json_determinism(headers):
    r1 = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report", headers=headers, timeout=30)
    r2 = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report", headers=headers, timeout=30)
    assert r1.status_code == r2.status_code == 200
    def sig(d):
        s = (d.get("signature") or {}).get("sha256")
        if s: return s
        for sec in d.get("sections", []):
            if (sec.get("name") or sec.get("id")) == "signature":
                return (sec.get("body") or {}).get("sha256")
    assert sig(r1.json()) == sig(r2.json())


def test_md_determinism(headers):
    r1 = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report.md", headers=headers, timeout=30)
    r2 = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report.md", headers=headers, timeout=30)
    assert r1.content == r2.content


def test_process_name_quality(headers):
    r = requests.get(f"{BASE_URL}/api/v2/cases/{CASE_ID}/report", headers=headers, timeout=30)
    d = r.json()
    sections = {s.get("name") or s.get("id"): s for s in d["sections"]}
    exec_body = sections["executive_summary"].get("body") or {}
    dom = exec_body.get("dominant_process")
    assert dom, "no dominant_process"
    assert dom not in ("event", "unattributed")
    assert not str(dom).startswith("proc_shadow_")
    assert re.search(r"\.(exe|msi|dll|ps1|bat|cmd|sh)$", dom, re.I), f"not a real binary: {dom}"
    anc = (sections["process_ancestry"].get("body") or {})
    tops = anc.get("top_processes") or []
    for p in tops:
        name = p if isinstance(p, str) else (p.get("name") or p.get("process") or "")
        assert not name.startswith("proc_shadow_"), f"synthetic iid: {name}"


def test_empty_case(headers):
    r = requests.get(f"{BASE_URL}/api/v2/cases/__no_such_case__/report", headers=headers, timeout=30)
    assert r.status_code == 200
    d = r.json()
    sections = d.get("sections", [])
    assert len(sections) == 10
    exec_body = next((s.get("body") for s in sections if (s.get("name") or s.get("id")) == "executive_summary"), {})
    assert exec_body.get("event_total") == 0
    sig = (d.get("signature") or {}).get("sha256") or next(
        ((s.get("body") or {}).get("sha256") for s in sections if (s.get("name") or s.get("id")) == "signature"), None
    )
    assert sig and re.fullmatch(r"[0-9a-f]{64}", sig)


def test_rc5_parse_regression(headers):
    r = requests.post(f"{BASE_URL}/api/rc5/parse", headers=headers,
                      json={"input": "powershell -enc SGVsbG8="}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    # RC5 parse response schema is flexible; verify shape by presence of core keys
    assert d and (("verdict" in d) or ("data" in d) or ("api_version" in d))
