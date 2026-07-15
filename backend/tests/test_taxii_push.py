"""Tests for the TAXII 2.1 Push feature (Feb-2026 P1)."""
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
ADMIN_PASSWORD = "NivXRay#2026!"


@pytest.fixture(scope="module")
def auth_headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=30,
    )
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestTaxiiConfig:
    def test_get_config_returns_dict(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/admin/taxii/config",
                         headers=auth_headers, timeout=15)
        assert r.status_code == 200
        assert "config" in r.json()

    def test_post_config_upserts(self, auth_headers):
        payload = {
            "server_url": "https://taxii-test.example.com",
            "collection_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "auth_type": "bearer",
            "token": "sk-test-token-1234",
            "identity_name": "NivXRay-Test",
        }
        r = requests.post(f"{BASE_URL}/api/admin/taxii/config",
                          headers=auth_headers, json=payload, timeout=15)
        assert r.status_code == 200
        cfg = r.json()["config"]
        assert cfg["server_url"] == payload["server_url"]
        assert cfg["collection_id"] == payload["collection_id"]
        # Token must be REDACTED
        assert "sk-test-token" not in cfg.get("token", "")
        assert cfg["token"].endswith("1234")

    def test_config_password_redacted(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/admin/taxii/config",
            headers=auth_headers,
            json={
                "server_url": "https://x.example.com",
                "collection_id": "cc",
                "auth_type": "basic",
                "username": "user",
                "password": "SuperSecret123!",
            }, timeout=15,
        )
        assert r.status_code == 200
        cfg = r.json()["config"]
        assert "SuperSecret" not in cfg.get("password", "")


class TestTaxiiPush:
    def test_push_builds_stix_bundle(self, auth_headers):
        # Configure a fake server that will fail — we just want the STIX
        # bundle to be built and object count returned correctly.
        requests.post(
            f"{BASE_URL}/api/admin/taxii/config",
            headers=auth_headers,
            json={
                "server_url": "https://taxii-unreachable.local",
                "collection_id": "test-collection",
                "auth_type": "none",
            }, timeout=15,
        )
        payload = {
            "iocs": {
                "urls": ["http://evil.com/x.ps1"],
                "domains": ["evil.com"],
                "sha256": [
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ],
            },
            "description": "test push",
        }
        r = requests.post(f"{BASE_URL}/api/admin/taxii/push",
                          headers=auth_headers, json=payload, timeout=30)
        assert r.status_code == 200
        data = r.json()
        # Bundle built with: 1 identity + 3 indicators = 4 objects
        assert data["object_count"] == 4
        assert data["bundle_id"].startswith("bundle--")
        # Push itself must fail (fake server) — engine records it gracefully
        assert data["ok"] is False
        assert data["result"]["objects_sent"] == 4

    def test_push_empty_iocs_produces_identity_only(self, auth_headers):
        r = requests.post(
            f"{BASE_URL}/api/admin/taxii/push",
            headers=auth_headers,
            json={"iocs": {}}, timeout=15,
        )
        assert r.status_code == 200
        data = r.json()
        # Only the identity object should be present
        assert data["object_count"] == 1


class TestTaxiiHistory:
    def test_history_returns_events(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/admin/taxii/history?limit=10",
                          headers=auth_headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data["events"], list)
        # After the push test above, at least one event exists
        if data["events"]:
            e = data["events"][0]
            assert "created_at" in e
            assert "bundle_id" in e
            assert "object_count" in e


class TestTaxiiStixBundleShape:
    """Unit-test the pure-python bundle builder (no network)."""

    def test_indicator_pattern_shapes(self):
        from taxii import build_stix_bundle
        bundle = build_stix_bundle({
            "urls": ["http://evil.com/x"],
            "domains": ["evil.com"],
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
        })
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        objs = bundle["objects"]
        assert objs[0]["type"] == "identity"

        indicators = [o for o in objs if o["type"] == "indicator"]
        assert len(indicators) == 3
        patterns = {ind["pattern"] for ind in indicators}
        assert "[url:value = 'http://evil.com/x']" in patterns
        assert "[domain-name:value = 'evil.com']" in patterns
        assert "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']" in patterns

    def test_bundle_spec_version(self):
        from taxii import build_stix_bundle
        bundle = build_stix_bundle({"urls": ["http://a.com"]})
        indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert indicator["spec_version"] == "2.1"
        assert indicator["pattern_type"] == "stix"
