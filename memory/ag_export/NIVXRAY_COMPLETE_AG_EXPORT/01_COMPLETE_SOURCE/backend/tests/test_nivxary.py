"""NivXary backend API tests."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
# Read from frontend .env if empty
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


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "access_token" in data
    return data["access_token"]


@pytest.fixture(scope="session")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- Auth ----------
class TestAuth:
    def test_login_bad(self):
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": "wrong@x.com", "password": "bad"}, timeout=15)
        assert r.status_code == 401

    def test_me(self, auth):
        r = requests.get(f"{BASE_URL}/api/auth/me", headers=auth, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == ADMIN_EMAIL
        assert data.get("role") == "admin"

    def test_operations_unauth(self):
        r = requests.get(f"{BASE_URL}/api/operations", timeout=15)
        assert r.status_code in (401, 403)


# ---------- Operations & Examples ----------
class TestOps:
    def test_operations_list(self, auth):
        r = requests.get(f"{BASE_URL}/api/operations", headers=auth, timeout=15)
        assert r.status_code == 200
        ops = r.json()
        assert isinstance(ops, list)
        assert len(ops) >= 45, f"Expected at least 45 ops, got {len(ops)}"

    def test_examples(self, auth):
        r = requests.get(f"{BASE_URL}/api/examples", headers=auth, timeout=15)
        assert r.status_code == 200
        exs = r.json()
        assert len(exs) == 5
        ids = {e["id"] for e in exs}
        expected = {"powershell-encoded", "ransomware-note", "defanged-iocs",
                    "nested-base64-gzip", "url-encoded-xss"}
        assert expected.issubset(ids), f"Missing examples: {expected - ids}"

    def test_recipe_run_base64(self, auth):
        r = requests.post(f"{BASE_URL}/api/recipe/run", headers=auth, timeout=15,
                          json={"input": "SGVsbG8gV29ybGQ=",
                                "steps": [{"op": "base64-decode", "args": {}}]})
        assert r.status_code == 200
        assert r.json()["output"] == "Hello World"


# ---------- Smart Decode ----------
class TestSmartDecode:
    def _get_example(self, auth, ex_id):
        exs = requests.get(f"{BASE_URL}/api/examples", headers=auth, timeout=15).json()
        return next(e for e in exs if e["id"] == ex_id)

    @pytest.mark.parametrize("ex_id", [
        "powershell-encoded", "ransomware-note", "defanged-iocs",
        "nested-base64-gzip", "url-encoded-xss",
    ])
    def test_smart_decode_examples(self, auth, ex_id):
        ex = self._get_example(auth, ex_id)
        r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth, timeout=30,
                          json={"input": ex["input"]})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["output"], f"Empty output for {ex_id}"
        assert isinstance(data.get("recipe"), list)

    def test_powershell_content(self, auth):
        ex = self._get_example(auth, "powershell-encoded")
        r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth, timeout=30,
                          json={"input": ex["input"]}).json()
        out = r["output"]
        assert "192.168.1.1" in out
        assert "DownloadString" in out or "downloadstring" in out.lower()

    def test_xss_content(self, auth):
        ex = self._get_example(auth, "url-encoded-xss")
        r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth, timeout=30,
                          json={"input": ex["input"]}).json()
        assert "<script>" in r["output"].lower()

    def test_defanged_content(self, auth):
        ex = self._get_example(auth, "defanged-iocs")
        r = requests.post(f"{BASE_URL}/api/decode/smart", headers=auth, timeout=30,
                          json={"input": ex["input"]}).json()
        out = r["output"]
        # refanged: hxxp -> http, [.] -> .
        assert "hxxp" not in out.lower()
        assert "[.]" not in out


# ---------- Analyze ----------
class TestAnalyze:
    def test_analyze_basic(self, auth):
        payload = {
            "input": "Connect to 185.220.101.45 and http://evil.com/x md5:d41d8cd98f00b204e9800998ecf8427e",
            "output": "",
            "enrich_osint": True,
        }
        r = requests.post(f"{BASE_URL}/api/analyze", headers=auth, json=payload, timeout=60)
        assert r.status_code == 200, r.text
        data = r.json()
        for k in ("iocs", "mitre", "yara", "risk", "osint"):
            assert k in data, f"missing {k}"
        assert data["osint"] is None or "sources_used" in data["osint"] or "error" in data["osint"]


# ---------- Admin OSINT ----------
class TestAdmin:
    def test_osint_services(self, auth):
        r = requests.get(f"{BASE_URL}/api/admin/osint/services", headers=auth, timeout=15)
        assert r.status_code == 200
        svcs = r.json()
        assert len(svcs) >= 8

    def test_osint_services_unauth(self):
        r = requests.get(f"{BASE_URL}/api/admin/osint/services", timeout=15)
        assert r.status_code in (401, 403)

    def test_osint_put_and_get(self, auth):
        fake = "TEST_fake_vt_key_1234567890"
        r = requests.put(f"{BASE_URL}/api/admin/osint/settings", headers=auth, timeout=15,
                         json={"keys": {"virustotal": fake}})
        assert r.status_code == 200
        r2 = requests.get(f"{BASE_URL}/api/admin/osint/services", headers=auth, timeout=15).json()
        vt = next(s for s in r2 if s["id"] == "virustotal")
        assert vt["configured"] is True
        assert vt["masked_key"] and "•" in vt["masked_key"]
        # cleanup
        requests.put(f"{BASE_URL}/api/admin/osint/settings", headers=auth, timeout=15,
                     json={"keys": {"virustotal": ""}})

    def test_admin_stats(self, auth):
        r = requests.get(f"{BASE_URL}/api/admin/stats", headers=auth, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert "operations" in data or "users" in data or isinstance(data, dict)
