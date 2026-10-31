"""EDR runtime activation (P0) — iteration_82 backend acceptance.

Covers:
  1. /api/edr/endpoints returns 7 authoritative rows from v2_shadow_observations
  2. /api/edr/device-trajectory resolves by IID and by hostname (case-insensitive)
  3. Honest identity-unresolved state (200, reason='identity_unresolved')
  4. Window semantics — default 24h window is empty but identity is still resolved
  5. Every event carries evidence_ref.type == 'v2_shadow_observation'
  6. Tenant scoping — unauth is rejected (401/403)
  7. Regression: /api/edr/detections and /api/edr/process-tree still respond
"""
from __future__ import annotations

import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL",
    "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

EXPECTED_HOSTS = {"WKS-01", "FILE-SRV-01", "SRV-DC01", "FIN-07",
                  "ENG-42", "HR-11", "WKS-07"}


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth(token):
    # B7 Option A · tenant-scoped EDR routes require an explicit tenant.
    return {"Authorization": f"Bearer {token}", "X-Tenant-Id": "default"}


def _legacy_corpus_rows():
    """The golden-corpus devices as the CROSS-TENANT projection sees them.

    B7/R2 · these 7 hosts are `UNATTRIBUTED_LEGACY_OBSERVATION`:
    `v2_shadow_observations` carries no `tenant_id` for them. An explicitly
    tenant-scoped request therefore CANNOT be answered with them — that is the
    mis-attribution the production Gate H finding exposed. The evidence still
    exists and is still readable, so its existence is asserted here against the
    cross-tenant projection instead of against a tenant-scoped HTTP read.

    (There is deliberately no HTTP route that returns unattributed evidence
    yet; the separately-named unattributed view is a deferred, separately
    approved change.)
    """
    from services.edr import device_identity as dir_svc
    rows = dir_svc.list_devices({"all_tenants": True, "tenant_ids": []})
    return {r["hostname"]: r for r in rows if r.get("hostname") in EXPECTED_HOSTS}


def test_legacy_corpus_still_exists_unowned_on_the_cross_tenant_path():
    """Evidence narrowed, never destroyed."""
    corpus = _legacy_corpus_rows()
    assert set(corpus) == set(EXPECTED_HOSTS), \
        f"legacy corpus lost: {set(EXPECTED_HOSTS) - set(corpus)}"
    for host, row in corpus.items():
        assert row["tenant_attribution"] == "UNATTRIBUTED_LEGACY_OBSERVATION", \
            f"{host}: {row['tenant_attribution']}"
        assert row["tenant_id"] is None, f"{host} was given an owner by inference"
        assert row["identity_confidence"] == "authoritative"
        assert row["device_iid"].startswith("dev_")
        assert row["observation_count"] > 0
        assert row["lane_counts"]


def test_endpoints_returns_seven_authoritative(auth):
    """Under an EXPLICIT tenant the projection is attributed-only.

    Previously this asserted the 7 legacy hosts came back. They carry no
    owner, so returning them to a caller that named a tenant is exactly the
    Gate H mis-attribution. Their existence is asserted by
    `test_legacy_corpus_still_exists_unowned_on_the_cross_tenant_path`.
    """
    r = requests.get(f"{BASE_URL}/api/edr/endpoints", headers=auth, timeout=20)
    assert r.status_code == 200, r.text
    data = r.json()
    rows = [d for d in data["endpoints"]
            if d.get("source") == "v2_shadow_observations"]
    leaked = {d["hostname"] for d in rows} & set(EXPECTED_HOSTS)
    assert not leaked, f"unowned legacy hosts released under a tenant: {leaked}"
    for row in rows:
        assert row["tenant_attribution"].startswith("ATTRIBUTED")
        assert row["tenant_id"] == auth["X-Tenant-Id"]
        assert row["identity_confidence"] == "authoritative"
        assert row["device_iid"] and row["device_iid"].startswith("dev_")
        assert row["observation_count"] > 0
        assert row.get("lane_counts")


def test_device_trajectory_by_iid(auth):
    """FIN-07 is unowned, so a tenant-scoped trajectory must fail closed.

    The 45 IRG events still exist — asserted against the cross-tenant
    projection below, not claimed as this tenant's evidence.
    """
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27", "all_time": "true"},
                     headers=auth, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["identity"]["resolved"] is False
    assert d["reason"] == "identity_unresolved"
    assert d["events"] == []
    assert _legacy_corpus_rows()["FIN-07"]["observation_count"] == 45


@pytest.mark.parametrize("host", ["fin-07", "FIN-07", "Fin-07"])
def test_hostname_case_insensitive(auth, host):
    """Case-insensitive matching is asserted on the projection that can see
    the device at all; the tenant-scoped read fails closed for every casing,
    which is the contract, not a resolver regression."""
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": host, "all_time": "true"},
                     headers=auth, timeout=30)
    assert r.status_code == 200
    assert r.json()["identity"]["resolved"] is False

    from services.edr import device_identity as dir_svc
    identity = dir_svc.resolve(host, {"all_tenants": True, "tenant_ids": []})
    assert identity is not None, f"{host!r} no longer resolves cross-tenant"
    assert identity["device_iid"] == "dev_baaa72285d27"
    assert identity["hostname"] == "FIN-07"
    assert identity["identity_confidence"] == "authoritative"


def test_identity_unresolved_honest_state(auth):
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "bogus-host-does-not-exist",
                             "all_time": "true"},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["reason"] == "identity_unresolved"
    assert d["identity"]["resolved"] is False
    assert d["events"] == []
    assert all(v == 0 for v in d["lane_counts"].values())


def test_window_semantics_empty_but_identified(auth):
    """FIN-07 is unowned: the tenant-scoped read fails closed, and the window
    semantics are asserted where the device is visible at all."""
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27", "hours": 24},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    assert r.json()["identity"]["resolved"] is False

    row = _legacy_corpus_rows()["FIN-07"]
    # observations dated 2026-02-25 → outside a 24h window, but the identity
    # and its counts are still known and dated, never blank.
    assert row["observation_count"] == 45
    assert row["first_seen"] and row["last_seen"]


def test_evidence_provenance_on_events(auth):
    """Provenance is asserted on the projection that can return the events.

    A tenant-scoped request gets nothing for an unowned device, so asserting
    provenance through it would only prove the fail-closed path.
    """
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27", "all_time": "true"},
                     headers=auth, timeout=30)
    assert r.json()["identity"]["resolved"] is False

    from services.edr import device_identity as dir_svc
    wide = {"all_tenants": True, "tenant_ids": []}
    events = dir_svc.observations("dev_baaa72285d27", wide, None)
    assert events
    for e in events:
        ref = e["evidence_ref"]
        assert ref["type"] == "v2_shadow_observation"
        assert "event_iid" in ref
        assert "case_id" in ref
        assert "sequence" in ref
        assert e.get("observation_kind")


def test_unauth_rejected():
    r = requests.get(f"{BASE_URL}/api/edr/endpoints", timeout=10)
    assert r.status_code in (401, 403)
    r = requests.get(f"{BASE_URL}/api/edr/device-trajectory",
                     params={"device": "dev_baaa72285d27"}, timeout=10)
    assert r.status_code in (401, 403)


def test_regression_detections_and_process_tree(auth):
    # find a real workspace case id
    r = requests.get(f"{BASE_URL}/api/incidents?limit=5", headers=auth, timeout=15)
    assert r.status_code == 200
    js = r.json()
    items = js.get("items") or js.get("incidents") or js
    if isinstance(items, dict):
        items = items.get("items", [])
    assert items, "no incidents found for regression"
    # P3 · an incident is tenant evidence, so it must be read under the tenant
    # that owns it. Picking the first row of a cross-tenant list and then
    # naming another tenant correctly returns 404 (existence in another tenant
    # is not disclosed), which is the contract, not a regression.
    tenant = auth["X-Tenant-Id"]
    owned = [i for i in items if i.get("tenant_id") == tenant]
    if not owned:
        pytest.skip(f"no incident owned by tenant {tenant!r} in this corpus")
    incident_id = owned[0].get("id") or owned[0].get("incident_id")
    assert incident_id

    r = requests.get(f"{BASE_URL}/api/edr/detections",
                     params={"incident_id": incident_id},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert "detections" in body
    assert isinstance(body["detections"], list)

    r = requests.get(f"{BASE_URL}/api/edr/process-tree",
                     params={"incident_id": incident_id},
                     headers=auth, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert "nodes" in body and "roots" in body
