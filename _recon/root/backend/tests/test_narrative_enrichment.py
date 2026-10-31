"""Tests for narrative enrichment fix (ADR-005) — case 'Same' + cyberdefenders URL."""
import os
import json
import hashlib
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
CASE_ID = "abe701b3-a3b5-4092-8dc8-ef98ec95af40"
CYBER_URL = "https://cyberdefenders.org/blog/encoded-powershell-detection-soc-playbook/"

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    last = None
    for i in range(5):
        try:
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                              timeout=90)
            if r.status_code == 200:
                tok = r.json().get("access_token") or r.json().get("token")
                assert tok, f"no token in response: {r.json()}"
                return tok
            last = (r.status_code, r.text[:200])
        except Exception as e:
            last = ("EXC", str(e))
        import time as _t; _t.sleep(3)
    pytest.fail(f"login failed after retries: {last}")


@pytest.fixture(scope="module")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- die/investigation-results ----------
class TestInvestigationResults:
    def test_investigation_results_shape(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/die/investigation-results",
                          json={"input": CYBER_URL},
                          headers=auth_headers, timeout=180)
        assert r.status_code == 200, f"{r.status_code} {r.text[:400]}"
        payload = r.json()
        obj = payload.get("object") or payload  # canonical location per spec
        # narrative
        narr = obj.get("narrative") or {}
        assert isinstance(narr.get("executive_summary"), str) and narr["executive_summary"].strip(), \
            f"executive_summary empty: {narr.get('executive_summary')!r}"
        assert isinstance(narr.get("recommended_actions"), list)
        assert len(narr["recommended_actions"]) >= 10, f"recommended_actions len={len(narr['recommended_actions'])}"
        assert isinstance(narr.get("attack_progression"), list)
        assert len(narr["attack_progression"]) == 3, f"attack_progression len={len(narr['attack_progression'])}"
        oa = narr.get("overall_assessment")
        assert isinstance(oa, dict), f"overall_assessment type={type(oa)}"
        for k in ("risk", "primary_objective", "attack_progress_pct", "confidence"):
            assert k in oa, f"overall_assessment missing {k}: {oa}"
        assert isinstance(narr.get("behavior_summary"), list) and len(narr["behavior_summary"]) == 3
        # chain
        chain = obj.get("chain") or {}
        steps = chain.get("steps") or []
        assert len(steps) == 3, f"chain.steps len={len(steps)}"
        assert chain.get("source") == "canonical.narrative_progression", f"chain.source={chain.get('source')}"
        # lolbas
        lolbas = obj.get("lolbas") or []
        assert len(lolbas) > 0, "lolbas empty"
        l0 = lolbas[0]
        assert l0.get("legit") and l0.get("abuse") and l0.get("detection"), f"lolbas[0] not populated: {l0}"


# ---------- GET /api/cases/{id} ----------
class TestSavedCase:
    def test_saved_case_narrative(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/cases/{CASE_ID}", headers=auth_headers, timeout=60)
        assert r.status_code == 200, f"{r.status_code} {r.text[:400]}"
        data = r.json()
        ssot = data.get("ssot") or data.get("case", {}).get("ssot") or {}
        assert ssot, f"no ssot in response keys={list(data.keys())}"
        assert data.get("ssot_source") == "immutable_store" or ssot.get("ssot_source") == "immutable_store", \
            f"ssot_source={data.get('ssot_source')}"
        narr = ssot.get("analyst_narrative") or {}
        assert isinstance(narr.get("executive_summary"), str) and narr["executive_summary"].strip()
        assert len(narr.get("recommended_actions") or []) >= 10
        assert len(narr.get("attack_progression") or []) == 3
        assert len(narr.get("mitre_matrix") or []) == 5, f"mitre_matrix len={len(narr.get('mitre_matrix') or [])}"
        assert isinstance(narr.get("overall_assessment"), dict)
        assert len(narr.get("behavior_summary") or []) == 3
        assert isinstance(narr.get("likely_objective"), list)
        inv = ssot.get("investigation_object") or {}
        chain_steps = ((inv.get("chain") or {}).get("steps")) or []
        assert len(chain_steps) == 3, f"inv.chain.steps len={len(chain_steps)}"
        lolbas = inv.get("lolbas") or []
        assert lolbas and lolbas[0].get("legit") and lolbas[0].get("abuse") and lolbas[0].get("detection"), \
            f"inv.lolbas[0]={lolbas[:1]}"


# ---------- Sample1 regression ----------
class TestSample1Regression:
    def test_sample1_not_modified(self, auth_headers):
        # Find Sample1 case
        r = requests.get(f"{BASE_URL}/api/cases", headers=auth_headers, timeout=60,
                         params={"limit": 200})
        assert r.status_code == 200
        cases = r.json() if isinstance(r.json(), list) else r.json().get("cases", [])
        sample1_ids = []
        for c in cases:
            name = (c.get("name") or "").lower()
            inp = (c.get("input") or c.get("input_value") or "").lower()
            if "sample" in name or "sample.docx" in inp or "3915b712" in inp:
                sample1_ids.append(c.get("id") or c.get("_id") or c.get("case_id"))
        if not sample1_ids:
            pytest.skip("No Sample1 case found to regression-check")
        # Just verify Sample1 has narrative field but was not force-enriched with cyberdefenders content
        cid = sample1_ids[0]
        r2 = requests.get(f"{BASE_URL}/api/cases/{cid}", headers=auth_headers, timeout=60)
        assert r2.status_code == 200
        ssot = r2.json().get("ssot", {})
        narr = (ssot.get("analyst_narrative") or {})
        # Sample1 exec_summary (if any) should NOT reference cyberdefenders / encoded-powershell-detection blog URL
        es = (narr.get("executive_summary") or "").lower()
        assert "cyberdefenders" not in es and "encoded-powershell-detection-soc-playbook" not in es, \
            f"Sample1 case {cid} appears polluted with cyberdefenders content"
