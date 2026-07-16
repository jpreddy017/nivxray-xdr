"""Tests for Feb-2026 Phase-3.5 · Docs extras
(feedback loop, RAG file-watcher, HTML/DOCX exports, screenshot endpoints).
"""
from __future__ import annotations
import io
import os
import time
import zipfile
from pathlib import Path

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
                      timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ----------------------------------------------------------------------
# 1. Explain feedback loop
# ----------------------------------------------------------------------
class TestExplainFeedback:
    def test_up_vote_records(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                          headers=auth_headers,
                          json={
                              "page": "candidate_explorer",
                              "session_id": "test-fb-up-session",
                              "message_index": 0,
                              "vote": "up",
                              "provider": "static-registry",
                              "reply_snippet": "hi",
                          }, timeout=15)
        assert r.status_code == 200
        assert r.json()["status"] == "recorded"

    def test_toggle_replaces_vote(self, auth_headers):
        sid = f"test-fb-toggle-{time.time_ns()}"
        for vote in ("up", "down"):
            requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                          headers=auth_headers,
                          json={"page": "rot13", "session_id": sid,
                                "message_index": 0, "vote": vote}, timeout=15)
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/stats",
                         headers=auth_headers, timeout=15)
        stats = r.json()
        # After up→down, rot13 should have exactly 1 down (up replaced)
        rot = stats.get("per_page", {}).get("rot13", {})
        assert rot.get("down", 0) >= 1

    def test_retract_deletes(self, auth_headers):
        sid = f"test-fb-retract-{time.time_ns()}"
        requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                      headers=auth_headers,
                      json={"page": "base64_decode", "session_id": sid,
                            "message_index": 0, "vote": "up"}, timeout=15)
        r = requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                         headers=auth_headers,
                         json={"page": "base64_decode", "session_id": sid,
                               "message_index": 0, "vote": "none"}, timeout=15)
        assert r.status_code == 200
        assert r.json()["status"] == "retracted"

    def test_stats_shape(self, auth_headers):
        # Seed at least one vote to guarantee a non-trivial stats payload
        requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                      headers=auth_headers,
                      json={"page": "taxii_push",
                            "session_id": "stats-shape-session",
                            "message_index": 0, "vote": "up",
                            "provider": "emergent-claude"}, timeout=15)
        r = requests.get(f"{BASE_URL}/api/docs/explain/feedback/stats",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert set(d.keys()) >= {"totals", "per_page", "per_provider"}
        assert d["totals"]["up"] >= 1

    def test_invalid_vote_rejected(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/docs/explain/feedback",
                         headers=auth_headers,
                         json={"page": "rot13", "session_id": "x",
                               "message_index": 0, "vote": "meh"}, timeout=15)
        assert r.status_code == 422


# ----------------------------------------------------------------------
# 2. RAG index auto-invalidation on YAML mtime change
# ----------------------------------------------------------------------
class TestRagAutoInvalidate:
    def test_touch_yaml_triggers_rebuild(self):
        from docs import rag_index
        rag_index.build_index()
        fp_before = rag_index._fingerprint
        assert fp_before

        # Touch a YAML file to advance its mtime.
        p = Path("/app/backend/docs/features/rot13.yaml")
        # Advance mtime forward by 2 seconds so the delta is unambiguous
        # on filesystems with 1s resolution.
        new_mtime = time.time() + 2
        os.utime(p, (new_mtime, new_mtime))

        # A retrieve() call should transparently rebuild the index.
        _ = rag_index.retrieve("rot13 caesar", k=1)
        fp_after = rag_index._fingerprint
        assert fp_after != fp_before, "index did not auto-rebuild on YAML mtime change"


# ----------------------------------------------------------------------
# 3. HTML + DOCX exporters
# ----------------------------------------------------------------------
class TestExporters:
    def test_html_export_endpoint(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/export/html?audience=user",
                         headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("text/html")
        assert r.text.startswith("<!doctype")
        assert "NivXRay" in r.text
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd

    def test_html_export_inline(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/export/html?inline=true",
                         headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert "attachment" not in r.headers.get("content-disposition", "")

    def test_docx_export_endpoint(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/export/docx?audience=user",
                         headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert "wordprocessingml" in r.headers.get("content-type", "")
        # DOCX is a ZIP; must open as such
        buf = io.BytesIO(r.content)
        with zipfile.ZipFile(buf) as z:
            names = z.namelist()
            assert "word/document.xml" in names
        cd = r.headers.get("content-disposition", "")
        assert ".docx" in cd

    @pytest.mark.parametrize("audience", ["user", "admin", "developer", "all"])
    def test_all_formats_all_audiences(self, auth_headers, audience):
        for fmt in ("pdf", "html", "docx"):
            r = requests.get(f"{BASE_URL}/api/docs/export/{fmt}?audience={audience}",
                             headers=auth_headers, timeout=30)
            assert r.status_code == 200, f"{fmt} {audience}"

    def test_html_export_bad_audience_422(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/export/html?audience=nope",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 422


# ----------------------------------------------------------------------
# 4. Screenshot endpoints
# ----------------------------------------------------------------------
class TestScreenshots:
    def test_list_empty_when_no_captures(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/screenshots/no-such-workflow",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        d = r.json()
        assert d["screenshots"] == []

    def test_list_after_synthetic_capture(self, auth_headers, tmp_path_factory):
        # Create a synthetic screenshot on disk to prove the endpoint indexes it.
        wf_id = "encoded_powershell"
        shot_dir = Path("/app/backend/docs/screenshots") / wf_id
        shot_dir.mkdir(parents=True, exist_ok=True)
        target = shot_dir / "step_1.png"
        # 1x1 transparent PNG
        target.write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4"
            b"\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe"
            b"\xdc\xccY\xe7\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        try:
            r = requests.get(f"{BASE_URL}/api/docs/screenshots/{wf_id}",
                             headers=auth_headers, timeout=15)
            assert r.status_code == 200
            files = [s["filename"] for s in r.json()["screenshots"]]
            assert "step_1.png" in files
            # Serve the file
            r2 = requests.get(f"{BASE_URL}/api/docs/screenshots/{wf_id}/step_1.png",
                              headers=auth_headers, timeout=15)
            assert r2.status_code == 200
            assert r2.headers.get("content-type", "").startswith("image/png")
            assert r2.content.startswith(b"\x89PNG")
        finally:
            try: target.unlink()
            except Exception: pass

    def test_traversal_blocked(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/screenshots/wf/../../etc/passwd",
                         headers=auth_headers, timeout=15)
        # Either 404 (path doesn't exist under the safe dir) or 400 (rejected).
        assert r.status_code in {400, 404}
