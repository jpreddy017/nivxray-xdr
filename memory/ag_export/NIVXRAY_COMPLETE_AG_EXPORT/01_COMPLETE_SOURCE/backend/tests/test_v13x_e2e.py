"""v1.3.x E2E integration tests via public API only.
Tests: decode/smart shape, multi-fragment, reverse chain, AMSI mitre,
       6 gap heuristics, lab narrative endpoint + reveal enrichment,
       heatmap, corpus validate, threat-intel feed sync, batch endpoints.
"""
import os
import base64, gzip, subprocess, pytest, requests

API = os.environ.get("REACT_APP_BACKEND_URL") or subprocess.check_output(
    "grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2", shell=True
).decode().strip()
EMAIL, PW = "admin@nivxray.com", os.environ.get("ADMIN_PASSWORD", "")


@pytest.fixture(scope="module")
def h():
    r = requests.post(f"{API}/api/auth/login", json={"email": EMAIL, "password": PW}, timeout=10)
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- decode/smart top-level shape ---
def test_smart_response_shape_top_level(h):
    r = requests.post(f"{API}/api/decode/smart", headers=h,
                      json={"input": "cmd.exe /c whoami"}, timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert isinstance(d.get("chain_ids"), list), d.keys()
    assert isinstance(d.get("score"), int) and 0 <= d["score"] <= 100
    risk = d.get("risk") or {}
    assert risk.get("verdict") and risk.get("level") and isinstance(risk.get("score"), int)


# --- multi-fragment auto-split ---
_ENC = ("cgB1AG4AZABsAGwAMwAyAC4AZQB4AGUAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMA"
        "dABlAG0AMwAyAFwAYwBvAG0AcwB2AGMAcwAuAGQAbABsACwAIABgACMAKwAwADAAMAAwADIA"
        "NAAgACgARwBlAHQALQBQAHIAbwBjAGUAcwBzACAAbABzAGEAcwBzACkALgBJAGQAIABcAFcA"
        "aQBuAGQAbwB3AHMAXABUAGUAbQBwAFwATgA0AFAATQAuAGQAbwBjAHgAIABmAHUAbABsAA==")

def test_multi_fragment_br_split(h):
    payload = f"-Embedding<br>-NoP -Enc {_ENC}<br>-NoP -Enc {_ENC}<br>-NoP -Enc {_ENC}"
    r = requests.post(f"{API}/api/decode/smart", headers=h, json={"input": payload}, timeout=60)
    assert r.status_code == 200
    d = r.json()
    assert d.get("engine") == "multi-fragment", d.get("engine")
    frags = d.get("fragments") or []
    assert len(frags) >= 3


# --- reverse chain ---
def test_reverse_string_chain(h):
    pt = b"NivXray_Test_Payload_01\n"
    s = base64.b64encode(pt)
    s = gzip.compress(s)
    s = base64.b64encode(s)
    s = s.hex().encode()[::-1]
    enc = base64.b64encode(s).decode()
    r = requests.post(f"{API}/api/decode/smart", headers=h, json={"input": enc}, timeout=60)
    d = r.json()
    assert "NivXray_Test_Payload_01" in (d.get("output") or ""), d.get("output", "")[:200]


# --- AMSI mitre surfaces ---
def test_amsi_mitre_t1562_001(h):
    payload = ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
               ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    r = requests.post(f"{API}/api/decode/smart", headers=h, json={"input": payload}, timeout=30)
    d = r.json()
    ids = {(m.get("id") if isinstance(m, dict) else m) for m in (d.get("mitre") or [])}
    assert "T1562.001" in ids, ids


# --- lab reveal enrichment ---
def test_lab_reveal_enriched(h):
    ch = requests.get(f"{API}/api/lab/challenge", headers=h, timeout=10).json()
    r = requests.get(f"{API}/api/lab/reveal/{ch['challenge_id']}", headers=h, timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert "expected_mitre_enriched" in d
    if d.get("expected_mitre"):
        assert isinstance(d["expected_mitre_enriched"], list)
        for m in d["expected_mitre_enriched"]:
            assert "id" in m and "name" in m and "tactic" in m


# --- lab narrative ---
def test_lab_narrative(h):
    for _ in range(20):
        ch = requests.get(f"{API}/api/lab/challenge", headers=h, timeout=10).json()
        rv = requests.get(f"{API}/api/lab/reveal/{ch['challenge_id']}", headers=h, timeout=10).json()
        if rv.get("expected_mitre"):
            break
    r = requests.post(f"{API}/api/lab/attempt/narrative", headers=h, json={
        "challenge_id": ch["challenge_id"],
        "understanding": "PowerShell downloads and executes remote script via IEX + Net.WebClient.",
        "impact": "High severity; code execution, persistence, lateral movement risk.",
        "recommendations": "Block via ASR, monitor 4104, quarantine host.",
    }, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["max_score"] == 100
    assert 0 <= d["understanding_score"] <= 40
    assert 0 <= d["impact_score"] <= 30
    assert 0 <= d["recommendations_score"] <= 30
    assert d["score"] == d["understanding_score"] + d["impact_score"] + d["recommendations_score"]
    assert isinstance(d.get("expected_mitre_enriched"), list)


def test_lab_narrative_bad_id_404(h):
    r = requests.post(f"{API}/api/lab/attempt/narrative", headers=h, json={
        "challenge_id": "NXR-DOES-NOT-EXIST",
        "understanding": "x", "impact": "x", "recommendations": "x",
    }, timeout=10)
    assert r.status_code == 404


# --- heatmap ---
def test_heatmap_data(h):
    r = requests.get(f"{API}/api/mitre/heatmap", headers=h, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert isinstance(d, dict)
    assert d.get("total_heuristics", 0) > 0
    assert isinstance(d.get("tactics"), list) and len(d["tactics"]) > 0
    assert isinstance(d.get("matrix"), dict)
    assert isinstance(d.get("top_techniques"), list) and len(d["top_techniques"]) > 0
    sample = d["top_techniques"][0]
    assert "id" in sample and "name" in sample and "tactic" in sample and "count" in sample


# --- corpus validate ---
def test_corpus_validate(h):
    r = requests.post(f"{API}/api/corpus/validate/json", headers=h,
                      json={"payloads": [{"input": "vssadmin delete shadows /all /quiet",
                                            "expected_mitre": ["T1490"]}]}, timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()
    assert isinstance(d, dict)


# --- threat-intel feeds sync ---
def test_threat_intel_feeds_sync(h):
    r = requests.post(f"{API}/api/threat-intel/feeds/sync", headers=h, json={}, timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    assert isinstance(d, dict)


# --- batch test + runs ---
def test_batch_test_and_runs(h):
    r = requests.post(f"{API}/api/batch/test/json", headers=h, json={
        "payloads": ["whoami", "vssadmin delete shadows /all /quiet"],
        "analysis_mode": "fast",
    }, timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("total") == 2

    r2 = requests.get(f"{API}/api/batch/history", headers=h, timeout=15)
    assert r2.status_code == 200
    runs = r2.json()
    assert isinstance(runs, (list, dict))
