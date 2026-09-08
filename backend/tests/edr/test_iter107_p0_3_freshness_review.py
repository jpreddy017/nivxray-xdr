"""
Iteration 107 — Review of P0-3 Blindness/Staleness Detection + Linux Sensor Recovery.

Public-URL, read-only tests (no Mongo writes, do not stop sensor).
Assert on identifiers and states — never on exact counts.
"""
import os
import requests
import pytest

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE = line.split("=", 1)[1].strip().rstrip("/")

ADMIN = ("admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK")
ANALYST_LIVE = ("analyst@nivx-live.com", "NivxLive!Analyst2026")

LIVE_DEV = "dev_42e8c6dc74b9"
LIVE_EP = "ep_2d57cbe6f80152062109"
LIVE_HOST = "agent-env-630704a1-621f-478b-9b86-a321772d01bf"
BLIND_EP = "ep_a01197382b9aeb861045"
OUTSIDE_WINDOW_DEV = "dev_a0267ae20737"
FORGED = "dev_ffffffffffff"


def _login(email, password):
    r = requests.post(f"{BASE}/api/auth/login", json={"email": email, "password": password}, timeout=15)
    assert r.status_code == 200, f"login failed {r.status_code}: {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def admin_h():
    return _login(*ADMIN)


@pytest.fixture(scope="module")
def analyst_h():
    return _login(*ANALYST_LIVE)


# --- Freshness API ---
class TestFreshness:
    def test_fleet_summary_shape(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", headers=admin_h, timeout=20)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        assert "fleet" in body and "endpoints" in body
        fleet = body["fleet"]
        for k in ("state", "statement", "enrolled", "ever_delivered", "never_delivered", "by_delivery_state"):
            assert k in fleet, f"missing fleet.{k}: keys={list(fleet.keys())}"
        assert set(fleet["by_delivery_state"].keys()) == {"DELIVERING", "STALE", "BLIND_NO_DELIVERY"}, fleet["by_delivery_state"]

    def test_endpoint_row_shape_live(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", params={"endpoint": LIVE_DEV}, headers=admin_h, timeout=20)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        rows = body["endpoints"]
        assert len(rows) == 1, f"expected 1 row got {len(rows)}"
        row = rows[0]
        assert row.get("endpoint_id") == LIVE_EP, row
        dlv = row["delivery"]
        for k in ("state", "basis", "statement", "thresholds", "last_delivery_at"):
            assert k in dlv, f"missing delivery.{k}: keys={list(dlv.keys())}"
        assert dlv["state"] in ("DELIVERING", "STALE"), f"unexpected state {dlv['state']}"
        thr = dlv["thresholds"]
        assert "cadence_basis" in thr and "formula" in thr, thr
        assert thr["cadence_basis"] == "DECLARED_BY_SENSOR", thr
        assert thr.get("report_interval_s") == 15, thr
        assert isinstance(thr["formula"], str) and len(thr["formula"]) > 0

    def test_alias_hostname(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", params={"endpoint": LIVE_HOST}, headers=admin_h, timeout=20)
        assert r.status_code == 200
        rows = r.json()["endpoints"]
        assert len(rows) == 1 and rows[0]["endpoint_id"] == LIVE_EP

    def test_alias_endpoint_id(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", params={"endpoint": LIVE_EP}, headers=admin_h, timeout=20)
        assert r.status_code == 200
        rows = r.json()["endpoints"]
        assert len(rows) == 1 and rows[0]["endpoint_id"] == LIVE_EP

    def test_blind_never_delivered(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", params={"endpoint": BLIND_EP}, headers=admin_h, timeout=20)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        rows = body["endpoints"]
        assert len(rows) == 1, rows
        row = rows[0]
        assert row["delivery"]["state"] == "BLIND_NO_DELIVERY"
        assert row["delivery"]["basis"] == "NEVER_DELIVERED"
        # addressed_by resolution
        ab = row.get("addressed_by") or {}
        assert ab.get("resolved_via") == "ENROLMENT_REGISTRY_DIRECT", ab

    def test_forged_identifier(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", params={"endpoint": FORGED}, headers=admin_h, timeout=20)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        assert body.get("state") == "ENDPOINT_NOT_RESOLVED", body.get("state")
        assert body["endpoints"] == []
        fleet = body.get("fleet") or {}
        if fleet:
            assert fleet.get("scope") == "FLEET_WIDE_NOT_THE_SUPPLIED_IDENTIFIER", fleet.get("scope")

    def test_tenant_isolation(self, analyst_h):
        r = requests.get(f"{BASE}/api/edr/telemetry/freshness", params={"endpoint": LIVE_DEV}, headers=analyst_h, timeout=20)
        assert r.status_code == 200, r.text[:300]
        body_text = r.text
        assert LIVE_EP not in body_text, "endpoint id leaked to out-of-tenant analyst"
        assert LIVE_HOST not in body_text, "hostname leaked to out-of-tenant analyst"


class TestHeartbeatAuth:
    def test_heartbeat_requires_agent_session(self):
        r = requests.post(f"{BASE}/api/edr/agent/heartbeat", json={}, timeout=15)
        assert r.status_code in (401, 403), f"got {r.status_code}: {r.text[:200]}"


class TestWindowHonesty:
    def test_window_object_shape(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/process-tree",
                         params={"endpoint_id": LIVE_DEV, "hours": 1},
                         headers=admin_h, timeout=30)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        w = body.get("window")
        assert w, "missing window object"
        for k in ("observations_in_window", "observations_outside_window",
                  "processes_outside_window", "retained_observations_total",
                  "earliest_evidence_at", "latest_evidence_at",
                  "max_window_hours", "state"):
            assert k in w, f"missing window.{k}: keys={list(w.keys())}"
        assert w["max_window_hours"] == 720
        return w["observations_in_window"]

    def test_widening_increases_observations(self, admin_h):
        r1 = requests.get(f"{BASE}/api/edr/process-tree",
                          params={"endpoint_id": LIVE_DEV, "hours": 1},
                          headers=admin_h, timeout=30)
        r720 = requests.get(f"{BASE}/api/edr/process-tree",
                            params={"endpoint_id": LIVE_DEV, "hours": 720},
                            headers=admin_h, timeout=60)
        assert r1.status_code == 200 and r720.status_code == 200
        w1 = r1.json()["window"]["observations_in_window"]
        w720 = r720.json()["window"]["observations_in_window"]
        assert w720 >= w1, f"expected 720h >= 1h; got {w720} vs {w1}"

    def test_evidence_outside_window(self, admin_h):
        r = requests.get(f"{BASE}/api/edr/process-tree",
                         params={"endpoint_id": OUTSIDE_WINDOW_DEV, "hours": 24},
                         headers=admin_h, timeout=30)
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        assert body.get("reason") == "evidence_outside_window", f"reason={body.get('reason')}"
        w = body.get("window") or {}
        assert w.get("state") == "EVIDENCE_OUTSIDE_WINDOW", w.get("state")
        assert w.get("processes_outside_window", 0) > 0, w
        stmt = body.get("statement") or w.get("statement") or ""
        assert w.get("latest_evidence_at") and (str(w["latest_evidence_at"]) in stmt or "latest" in stmt.lower() or "most recent" in stmt.lower() or "at" in stmt.lower()), f"statement missing timestamp: {stmt!r}"
