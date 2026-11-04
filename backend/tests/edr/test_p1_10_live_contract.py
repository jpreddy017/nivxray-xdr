"""P1.10 live contract — telemetry ingest shape, tenant isolation, catalog.

CONTRACT CORRECTION (classified `OBSOLETE_CONTRACT`, not `STALE_TEST`):
these tests were written when `POST /api/xdr/ingest/telemetry` accepted
an `X-Tenant-Id` + `X-Principal-Id` pair with **no credential at all**.
The platform now fails closed — `require_permission("collectors.enroll")`
refuses an unauthenticated request with
`ACCESS_DENIED · collectors.enroll · unauthenticated` — so every one of
these tests was asserting a contract the product deliberately replaced
with a stronger one.

The replacement contract is proven here in BOTH directions:

  * `test_unauthenticated_ingest_is_refused` — the new authority rule
    itself, asserted first so the payload tests below can never pass by
    accidentally re-opening it;
  * the payload/isolation contracts, re-run with a principal that
    actually carries `collectors.enroll`.

Nothing was weakened to make this file green.
"""
import os
import uuid

import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or \
    "http://localhost:8001"
API = BASE if BASE.endswith("/api") else BASE + "/api"

TENANT = "nivx-live"
COLLECTOR = "col_6551885c766a458ab315"
PERMISSION = "collectors.enroll"


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


@pytest.fixture(scope="module")
def ingest_hdrs():
    """A principal that actually carries `collectors.enroll`.

    The route accepts either a machine key (`X-XDR-API-Key`) or a verified
    JWT; the suite uses the JWT because a key would have to be pasted into
    the repository."""
    r = requests.post(f"{API}/auth/login",
                      json={"email": "admin@nivxray.com",
                            "password": "uulVDp5cCSB3Hva99s7UUAwK"},
                      timeout=30)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}",
            "X-Tenant-Id": TENANT,
            "Content-Type": "application/json"}


def test_unauthenticated_ingest_is_refused():
    """THE contract that replaced the old one: presenting a tenant header
    is not authority. This must fail closed, with the permission named."""
    r = requests.post(f"{API}/xdr/ingest/telemetry", json=[_env()],
                      headers={"X-Tenant-Id": TENANT,
                               "X-Principal-Id": "test-suite",
                               "Content-Type": "application/json"},
                      timeout=30)
    assert r.status_code == 403, r.text
    body = r.json()["detail"]
    assert body["code"] == "ACCESS_DENIED"
    assert body["permission"] == PERMISSION
    assert body["reason"] == "unauthenticated"


class TestIngestContract:
    def test_bare_list_accepted(self, ingest_hdrs):
        r = requests.post(f"{API}/xdr/ingest/telemetry", json=[_env()],
                          headers=ingest_hdrs, timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("accepted") is not None or "reasoned" in body \
            or "ingested" in body

    def test_envelopes_wrapper_accepted(self, ingest_hdrs):
        r = requests.post(f"{API}/xdr/ingest/telemetry",
                          json={"envelopes": [_env()]},
                          headers=ingest_hdrs, timeout=30)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "reasoning" in body or "reasoned" in body \
            or "observations_created" in body

    def test_tenant_isolation_envelope_mismatch(self, ingest_hdrs):
        # header says nivx-live but the envelope claims another tenant
        env = _env(tenant="some-other-tenant")
        r = requests.post(f"{API}/xdr/ingest/telemetry",
                          json={"envelopes": [env]},
                          headers=ingest_hdrs, timeout=30)
        assert r.status_code == 403, f"expected 403, got {r.status_code}: {r.text}"
        assert "TENANT_ISOLATION_VIOLATION" in r.text

    def test_mixed_envelope_tenants(self, ingest_hdrs):
        e1, e2 = _env(tenant=TENANT), _env(tenant="another-tenant")
        r = requests.post(f"{API}/xdr/ingest/telemetry",
                          json={"envelopes": [e1, e2]},
                          headers=ingest_hdrs, timeout=30)
        assert r.status_code == 403, r.text
        assert "TENANT_ISOLATION_VIOLATION" in r.text

    def test_mixed_collectors(self, ingest_hdrs):
        e1, e2 = _env(collector=COLLECTOR), _env(collector="col_other12345")
        r = requests.post(f"{API}/xdr/ingest/telemetry",
                          json={"envelopes": [e1, e2]},
                          headers=ingest_hdrs, timeout=30)
        assert r.status_code == 400, r.text
        assert "MIXED_COLLECTORS" in r.text


class TestProtocolCatalog:
    def test_cef_leef_implemented(self, ingest_hdrs):
        r = requests.get(f"{API}/xdr/collectors/protocols/catalog",
                         headers={"Authorization":
                                  ingest_hdrs["Authorization"]}, timeout=30)
        assert r.status_code == 200, r.text
        payload = r.json().get("data") or r.json()
        protocols = payload.get("protocols") or {}
        assert "cef" in protocols and "leef" in protocols
        assert protocols["cef"].get("implementation") == "IMPLEMENTED"
        assert protocols["leef"].get("implementation") == "IMPLEMENTED"

        # STALE_TEST correction: this asserted `implemented == 5` and
        # `total == 12`, so implementing a sixth protocol FAILED the suite.
        # Freezing a number measures the changelog, not the contract. The
        # contract is that the counts describe the catalog exactly — no
        # protocol may be silently uncounted or double-counted.
        counts = payload.get("counts") or {}
        by_state: dict[str, int] = {}
        for entry in protocols.values():
            state = str(entry.get("implementation", "UNDECLARED")).lower()
            by_state[state] = by_state.get(state, 0) + 1
        assert counts.get("total") == len(protocols), (counts, len(protocols))
        assert counts.get("implemented") == by_state.get("implemented", 0)
        assert counts.get("scaffold") == by_state.get("scaffold", 0)
        assert counts.get("blocked") == by_state.get("blocked", 0)
        assert sum(v for k, v in counts.items() if k != "total") == \
            counts["total"], (
            "every protocol must be counted in exactly one state")
        assert "undeclared" not in by_state, (
            "a protocol in the catalog with no declared implementation "
            "state would render as a capability claim with no basis")
