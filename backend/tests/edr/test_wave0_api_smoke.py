"""Smoke tests for Wave 0 read-only routes via preview URL."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
EMAIL = "admin@nivxray.com"
PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=20)
    assert r.status_code == 200, r.text
    return r.json()["access_token"] if "access_token" in r.json() else r.json().get("token")


@pytest.fixture(scope="module")
def h(token):
    return {"Authorization": f"Bearer {token}"}


def test_auth_required_capabilities():
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities", timeout=20)
    assert r.status_code in (401, 403), f"unauth got {r.status_code}"
    # ensure no leak
    body = r.text.lower()
    assert "capability_id" not in body


def test_capabilities_list(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities", headers=h, timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    rows = data.get("capabilities") or data.get("rows") or data.get("items") or data
    if isinstance(data, dict) and "capabilities" in data:
        rows = data["capabilities"]
    assert isinstance(rows, list)
    assert len(rows) == 127, f"expected 127 rows got {len(rows)}"
    planes = {}
    for row in rows:
        planes[row["plane"]] = planes.get(row["plane"], 0) + 1
        for k in ["capability_id", "plane", "domain", "name", "description",
                  "declared_state", "effective_state", "gap_class"]:
            assert k in row, f"missing {k} in row {row.get('capability_id')}"
    assert planes.get("AGENT") == 31
    assert planes.get("BACKEND") == 63
    assert planes.get("EXPERIENCE") == 33


def test_capabilities_summary(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities/summary", headers=h, timeout=30)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s.get("downgraded_claims") == 0
    assert s.get("operational") == 11


def test_no_dishonest_row(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities", headers=h, timeout=30)
    data = r.json()
    rows = data["capabilities"] if isinstance(data, dict) and "capabilities" in data else data
    for row in rows:
        eff = row["effective_state"]
        tel = row.get("telemetry_status") or (row.get("components") or {}).get("telemetry")
        if eff in ("OPERATIONAL", "PRODUCTION_READY"):
            assert tel != "ABSENT", f"row {row['capability_id']} claims {eff} with telemetry ABSENT"
        if eff not in ("NOT_IMPLEMENTED", "CONTRACT_DEFINED"):
            assert row.get("evidence_reference"), f"row {row['capability_id']} lacks evidence"


def test_plane_filter(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities?plane=AGENT", headers=h, timeout=30)
    assert r.status_code == 200
    data = r.json()
    rows = data["capabilities"] if isinstance(data, dict) and "capabilities" in data else data
    assert len(rows) == 31
    assert all(r_["plane"] == "AGENT" for r_ in rows)


def test_gap_class_filter(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities?gap_class=TELEMETRY_MISSING", headers=h, timeout=30)
    assert r.status_code == 200
    data = r.json()
    rows = data["capabilities"] if isinstance(data, dict) and "capabilities" in data else data
    assert all(r_["gap_class"] == "TELEMETRY_MISSING" for r_ in rows)
    assert len(rows) == 67


def test_operational_only(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities?operational_only=true", headers=h, timeout=30)
    assert r.status_code == 200
    data = r.json()
    rows = data["capabilities"] if isinstance(data, dict) and "capabilities" in data else data
    assert len(rows) == 11


def test_get_capability_by_id(h):
    for cid in ["backend.telemetry_health", "backend.service.file_trajectory"]:
        r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities/{cid}", headers=h, timeout=20)
        assert r.status_code == 200, f"{cid} -> {r.status_code} {r.text}"
        assert r.json()["capability_id"] == cid


def test_capability_unknown_404(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/capabilities/does.not.exist", headers=h, timeout=20)
    assert r.status_code == 404
    body = r.json()
    # error code check
    txt = str(body).upper()
    assert "CAPABILITY_NOT_REGISTERED" in txt


def test_sensors_empty(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/sensors", headers=h, timeout=20)
    assert r.status_code == 200
    d = r.json()
    sensors = d.get("sensors") if isinstance(d, dict) else d
    if isinstance(d, dict):
        assert d.get("count", 0) == 0
        assert d.get("note")
    assert sensors == [] or sensors is None or len(sensors) == 0


def test_contracts_manifest(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/contracts", headers=h, timeout=20)
    assert r.status_code == 200
    d = r.json()
    manifest = d.get("manifest", d)
    names = manifest.get("contracts") or []
    expected = {"endpoint_identity", "telemetry_schema", "process_identity", "file_identity",
                "network_identity", "event_identity", "evidence_identity", "response_command",
                "response_result", "telemetry_health"}
    assert set(names) == expected, f"got {set(names)}"
    fe = manifest.get("forbidden_equivalences") or d.get("forbidden_equivalences") or []
    assert len(fe) == 6
    for item in fe:
        assert "because" in item or "reason" in item


def test_contract_schema(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/contracts/process_identity/schema", headers=h, timeout=20)
    assert r.status_code == 200
    s = r.json()
    assert "properties" in s or "$defs" in s or "type" in s


def test_contract_schema_404(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/contracts/bogus/schema", headers=h, timeout=20)
    assert r.status_code == 404
    assert "CONTRACT_NOT_DEFINED" in str(r.json()).upper()


def test_filter_taxonomy(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/filter-taxonomy", headers=h, timeout=20)
    assert r.status_code == 200
    d = r.json()
    assert d.get("complete") is False
    assert d.get("registered_item_count") == 0
    assert d.get("expected_item_count") == 43
    assert d.get("disclosure")
    assert d.get("provenance")


def test_raw_events_stats(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/raw-events/stats", headers=h, timeout=20)
    assert r.status_code == 200
    d = r.json()
    assert d.get("append_only") is True


def test_raw_events_replay(h):
    r = requests.get(f"{BASE_URL}/api/edr/wave0/raw-events/replay-candidates", headers=h, timeout=20)
    assert r.status_code == 200
    d = r.json()
    assert "candidates" in d
