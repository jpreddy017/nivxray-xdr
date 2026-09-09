"""P1.10 live contract tests — bare list vs envelopes, tenant isolation, protocol catalog."""
import os
import uuid
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or "http://localhost:8001"
if not BASE.endswith("/api"):
    API = BASE + "/api"
else:
    API = BASE

TENANT = "nivx-live"
COLLECTOR = "col_6551885c766a458ab315"


def _env(tenant=TENANT, collector=COLLECTOR):
    return {
        "envelope_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "collector_id": collector,
        "collection_method": "syslog",
        "source": "syslog",
        "connector_id": "syslog-3daed23d",
        "parser_version": "cef-leef/1.0",
        "event_type": "test",
        "source_timestamp": "2026-01-01T00:00:00Z",
        "collection_timestamp": "2026-01-01T00:00:01Z",
        "canonical": {
            "raw_ref": {"line": "TEST_line"},
            "additional_fields": {"epistemic_state": {}},
        },
    }


def _hdrs(tenant=TENANT):
    return {"X-Tenant-Id": tenant, "X-Principal-Id": "test-suite", "Content-Type": "application/json"}


class TestIngestContract:
    def test_bare_list_accepted(self):
        r = requests.post(f"{API}/xdr/ingest/telemetry", json=[_env()], headers=_hdrs(), timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("accepted") is not None or "reasoned" in body or "ingested" in body

    def test_envelopes_wrapper_accepted(self):
        r = requests.post(f"{API}/xdr/ingest/telemetry", json={"envelopes": [_env()]}, headers=_hdrs(), timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "reasoning" in body or "reasoned" in body or "observations_created" in body

    def test_tenant_isolation_envelope_mismatch(self):
        # header says nivx-live but envelope says another tenant
        env = _env(tenant="some-other-tenant")
        r = requests.post(f"{API}/xdr/ingest/telemetry", json={"envelopes": [env]}, headers=_hdrs(), timeout=30)
        assert r.status_code == 403, f"expected 403, got {r.status_code}: {r.text}"
        assert "TENANT_ISOLATION_VIOLATION" in r.text

    def test_mixed_envelope_tenants(self):
        e1 = _env(tenant=TENANT)
        e2 = _env(tenant="another-tenant")
        r = requests.post(f"{API}/xdr/ingest/telemetry", json={"envelopes": [e1, e2]}, headers=_hdrs(), timeout=30)
        assert r.status_code == 403
        assert "TENANT_ISOLATION_VIOLATION" in r.text

    def test_mixed_collectors(self):
        e1 = _env(collector=COLLECTOR)
        e2 = _env(collector="col_other12345")
        r = requests.post(f"{API}/xdr/ingest/telemetry", json={"envelopes": [e1, e2]}, headers=_hdrs(), timeout=30)
        assert r.status_code == 400
        assert "MIXED_COLLECTORS" in r.text


class TestProtocolCatalog:
    def test_cef_leef_implemented(self):
        # login as admin
        login = requests.post(
            f"{API}/auth/login",
            json={"email": "admin@nivxray.com", "password": "uulVDp5cCSB3Hva99s7UUAwK"},
            timeout=30,
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        r = requests.get(
            f"{API}/xdr/collectors/protocols/catalog",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        payload = data.get("data") or data
        protocols = payload.get("protocols") or {}
        assert "cef" in protocols and "leef" in protocols
        assert protocols["cef"].get("implementation") == "IMPLEMENTED"
        assert protocols["leef"].get("implementation") == "IMPLEMENTED"
        counts = payload.get("counts") or {}
        assert counts.get("implemented") == 5
        assert counts.get("total") == 12
