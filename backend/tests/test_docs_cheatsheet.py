"""Tests for per-payload / per-feature cheat-sheet exports."""
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


@pytest.mark.parametrize("doc_id,fmt,expect_bytes", [
    ("rot13", "pdf", b"%PDF"),
    ("rot13", "html", b"<!doctype"),
    ("payload_encoded_powershell_download", "pdf", b"%PDF"),
    ("payload_encoded_powershell_download", "html", b"<!doctype"),
    ("workspace_tour", "pdf", b"%PDF"),
])
def test_cheatsheet_returns_expected_format(doc_id, fmt, expect_bytes):
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/{doc_id}?fmt={fmt}",
                     timeout=30)
    assert r.status_code == 200
    assert r.content.lower().startswith(expect_bytes.lower())


def test_cheatsheet_pdf_has_attachment_header():
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/rot13?fmt=pdf", timeout=30)
    assert "attachment" in r.headers.get("content-disposition", "")
    assert "rot13" in r.headers.get("content-disposition", "")


def test_cheatsheet_html_inline_mode_omits_attachment():
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/rot13?fmt=html&inline=true", timeout=30)
    assert r.status_code == 200
    assert "attachment" not in r.headers.get("content-disposition", "")


def test_cheatsheet_unknown_doc_404():
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/no-such-doc?fmt=pdf", timeout=15)
    assert r.status_code == 404


def test_cheatsheet_bad_format_422():
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/rot13?fmt=xml", timeout=15)
    assert r.status_code == 422


def test_cheatsheet_publicly_accessible():
    # No Authorization header — should still succeed
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/rot13?fmt=pdf", timeout=15)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


def test_cheatsheet_html_contains_key_sections():
    r = requests.get(f"{BASE_URL}/api/docs/cheatsheet/payload_certutil_dropper?fmt=html",
                     timeout=30)
    body = r.text
    # Must mention key structural sections
    assert "CHEAT SHEET" in body
    assert "payload_certutil_dropper" in body.lower() or "certutil" in body.lower()
