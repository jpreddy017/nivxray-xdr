"""Tests for the auto-generated PDF User Guide.

Covers both the pure-Python generator (`create_user_guide`) and the
FastAPI endpoint (`GET /api/docs/export/pdf`).
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
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestPDFGenerator:
    """Direct unit tests for `create_user_guide`."""

    def test_returns_valid_pdf_bytes(self):
        from docs.pdf_generator import create_user_guide
        data = create_user_guide("user")
        assert isinstance(data, bytes)
        assert data[:4] == b"%PDF"
        assert len(data) > 2000  # non-trivial content

    @pytest.mark.parametrize("audience", ["user", "admin", "developer", "all"])
    def test_all_audiences_produce_pdf(self, audience):
        from docs.pdf_generator import create_user_guide
        data = create_user_guide(audience)
        assert data[:4] == b"%PDF"

    def test_invalid_audience_defaults_to_user(self):
        from docs.pdf_generator import create_user_guide
        data = create_user_guide("hacker")
        assert data[:4] == b"%PDF"

    def test_writes_to_disk_when_out_path_provided(self, tmp_path):
        from docs.pdf_generator import create_user_guide
        out = tmp_path / "guide.pdf"
        data = create_user_guide("user", out_path=out)
        assert out.exists()
        assert out.read_bytes() == data
        assert out.read_bytes()[:4] == b"%PDF"


class TestPDFEndpoint:
    """FastAPI export endpoint."""

    def test_export_pdf_returns_pdf(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/export/pdf",
                         headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("application/pdf")
        assert r.content[:4] == b"%PDF"
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert ".pdf" in cd

    @pytest.mark.parametrize("audience", ["user", "admin", "developer", "all"])
    def test_export_pdf_all_audiences(self, auth_headers, audience):
        r = requests.get(f"{BASE_URL}/api/docs/export/pdf?audience={audience}",
                         headers=auth_headers, timeout=30)
        assert r.status_code == 200
        assert r.content[:4] == b"%PDF"
        assert f"nivxray-{audience}-guide.pdf" in r.headers.get("content-disposition", "")

    def test_export_pdf_invalid_audience_422(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/docs/export/pdf?audience=hacker",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 422

    def test_export_pdf_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/docs/export/pdf", timeout=15)
        assert r.status_code in {401, 403}
