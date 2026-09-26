"""NivXForge EDR · Windows Device Onboarding V1.

The acceptance target of the wave: TWO independent Windows computers, the
SAME reusable installer build, no source/DB/tenant editing in between, two
distinct identities and credentials, and CONNECTED only after AUTHENTICATED
telemetry.

EVIDENCE LABELLING — TEST/SYNTHETIC: synthetic tenant, synthetic machine
attributes. No real endpoint is touched.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DB_NAME", "test_database")

from routers import edr_onboarding as onboarding                # noqa: E402
from server import app                                          # noqa: E402

WORKER = os.environ.get("PYTEST_XDIST_WORKER", "main")
RUN = f"{WORKER}{uuid.uuid4().hex[:8]}"
TENANT = f"ten_onboard_{RUN}"
PACKAGES = "/api/edr/onboarding/packages"
COMPUTERS = "/api/edr/onboarding/computers"
INSTALLER = "/app/agents/nivxforge-windows/Install-NivXForgeSensor.ps1"
SENSOR = "/app/agents/nivxforge-windows/nivxforge_sensor.py"


# ── the reusable build (static contract, no backend needed) ───────
def _installer() -> str:
    with open(INSTALLER, encoding="utf-8") as fh:
        return fh.read()


def _sensor_source() -> str:
    with open(SENSOR, encoding="utf-8") as fh:
        return fh.read()


def test_the_installer_carries_no_credential_and_no_identity():
    text = _installer() + _sensor_source()
    for shape in onboarding._SECRET_SHAPES:                  # noqa: SLF001
        assert not shape.search(text), shape.pattern
    assert not re.search(r"ten_[0-9a-f]{8,}", _installer()), (
        "a reusable build must not pin a real tenant id")


def test_the_installer_takes_its_inputs_at_install_time():
    text = _installer()
    for parameter in ("$BackendUrl", "$TenantId", "$EnrollmentToken",
                      "$ReEnroll", "$Uninstall"):
        assert parameter in text, parameter
    assert "-EnrollmentToken is required to enrol" in text
    assert "-TenantId is required to enrol" in text


def test_the_credential_directory_is_restricted_to_system_and_admins():
    text = _installer()
    assert "SetAccessRuleProtection($true, $false)" in text
    assert "NT AUTHORITY\\SYSTEM" in text
    assert "BUILTIN\\Administrators" in text
    assert "Assert-Administrator" in text


def test_reinstall_behaviour_is_deterministic_and_documented():
    text = _installer()
    assert "already enrolled" in text
    assert "keeping this computer''s existing identity and credential" in text
    assert "never creates a second Computers" in text
    assert "state directory kept at" in text        # uninstall keeps evidence


def test_the_sensor_journals_before_it_delivers():
    text = _sensor_source()
    assert "os.fsync" in text, "acquisition must be durable before delivery"
    assert text.index("def _enqueue") < text.index("def _drain")
    assert "/api/edr/agent/enroll" in text
    assert "/api/edr/agent/session" in text
    assert "/api/edr/agent/telemetry" in text
    assert "/api/edr/agent/heartbeat" in text
    assert "never proposes" in text or "platform mints" in text


def test_the_sensor_never_names_its_own_endpoint_id():
    assert not re.search(r'"endpoint_id"\s*:\s*[a-z_]+\(', _sensor_source())


# ── the Downloads surface ─────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_downloads_requires_an_authenticated_user(client):
    assert client.get(PACKAGES).status_code in (401, 403)
    assert client.get(COMPUTERS).status_code in (401, 403)


def test_the_package_catalog_reports_only_what_exists_on_disk():
    described = {p["id"]: p for p in
                 (onboarding._describe(pkg)                   # noqa: SLF001
                  for pkg in onboarding.PACKAGES.values())}
    win = described["windows-x64"]
    assert win["available"] is True and win["state"] == "AVAILABLE"
    assert win["credential_free"] is True
    assert win["sensor_version"] == "0.1.0-windows"
    with open(INSTALLER, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    entry = [f for f in win["files"] if f["name"].endswith(".ps1")][0]
    assert entry["sha256"] == digest and entry["size_bytes"] > 0
    assert win["silent_install"].startswith("powershell")
    # architectures we have NOT built must say so, with no download offered
    for missing in ("windows-arm64", "windows-x86"):
        assert described[missing]["state"] == "NOT_BUILT"
        assert described[missing]["download_available"] is False


def test_a_package_carrying_a_credential_shape_is_refused(tmp_path,
                                                          monkeypatch):
    root = tmp_path / "poisoned"
    root.mkdir()
    (root / "Install-NivXForgeSensor.ps1").write_text(
        "$Token = 'nvx_" + "a" * 48 + "'")
    (root / "nivxforge_sensor.py").write_text('SENSOR_VERSION = "9.9.9"')
    monkeypatch.setattr(onboarding, "AGENTS_ROOT", str(tmp_path))
    described = onboarding._describe({                        # noqa: SLF001
        **onboarding.PACKAGES["windows-x64"], "directory": "poisoned"})
    assert described["credential_free"] is False
    assert described["state"] == "REFUSED_EMBEDDED_CREDENTIAL"
    assert described["download_available"] is False


# ── Computers truth (pure projection, no DB needed) ───────────────
def _record(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    base = {"tenant_id": TENANT, "endpoint_id": f"ep_{RUN}",
            "hostname": "PC1", "platform": "WINDOWS",
            "sensor_version": "0.1.0-windows",
            "enrollment_state": "ENROLLED", "credential_state": "ACTIVE",
            "last_seen": now.isoformat(), "last_telemetry_at": None,
            "last_heartbeat_at": None, "event_count": 0,
            "report_interval_seconds": 30,
            "group_id": onboarding.DEFAULT_GROUP["id"],
            "policy_id": onboarding.DEFAULT_POLICY["id"]}
    base.update(overrides)
    return base


def _iso(seconds_ago: float) -> str:
    return datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() - seconds_ago,
        tz=timezone.utc).isoformat()


def test_enrolment_alone_is_never_connected():
    state = onboarding._status(_record())                     # noqa: SLF001
    assert state["status"] == "ENROLLED_NO_TELEMETRY"
    assert "never CONNECTED" in state["basis"]


def test_connected_requires_recent_authenticated_telemetry():
    state = onboarding._status(                               # noqa: SLF001
        _record(last_telemetry_at=_iso(10), event_count=12))
    assert state["status"] == "CONNECTED"
    assert "authenticated telemetry" in state["basis"]


def test_a_heartbeating_sensor_with_stale_telemetry_is_not_connected():
    state = onboarding._status(                               # noqa: SLF001
        _record(last_telemetry_at=_iso(5000), last_heartbeat_at=_iso(5),
                outbox_queue_depth=41))
    assert state["status"] == "ALIVE_NO_RECENT_TELEMETRY"
    assert "41 events are queued" in state["basis"]


def test_a_silent_sensor_is_reported_silent():
    assert onboarding._status(                                # noqa: SLF001
        _record(last_telemetry_at=_iso(9000)))["status"] == "SILENT"


def test_a_revoked_credential_outranks_any_telemetry():
    state = onboarding._status(                               # noqa: SLF001
        _record(credential_state="REVOKED", last_telemetry_at=_iso(1)))
    assert state["status"] == "REVOKED"


def test_protection_never_claims_enforcement_the_sensor_cannot_do():
    protection = onboarding._protection(                      # noqa: SLF001
        onboarding.DEFAULT_POLICY, _record())
    assert protection["state"] == "DETECT_ONLY"
    assert protection["prevention_enabled"] is False
    lifecycle = protection["policy_lifecycle"]
    assert lifecycle["configured"] is True and lifecycle["assigned"] is True
    assert lifecycle["enforced"] is False and lifecycle["verified"] is False
    assert "ransomware_prevention" in protection["not_enforced"]


def test_an_unassigned_policy_is_unavailable_not_invented():
    protection = onboarding._protection(None, _record())      # noqa: SLF001
    assert protection["state"] == "UNAVAILABLE"


# ── PC1 + PC2 on ONE build ────────────────────────────────────────
def test_two_computers_get_two_identities_from_the_same_build():
    """The platform mints the identity from durable machine attributes."""
    from edr_plane.contracts.identity import EndpointIdentity

    pc1 = EndpointIdentity.mint(tenant_id=TENANT, processor_id="cpu-aaa",
                                machine_guid="guid-aaa", device_iid=None,
                                hostname="PC1")
    pc2 = EndpointIdentity.mint(tenant_id=TENANT, processor_id="cpu-bbb",
                                machine_guid="guid-bbb", device_iid=None,
                                hostname="PC2")
    assert pc1 != pc2, "two computers must never share one identity"
    # deterministic: a reinstall on PC1 resolves to the SAME endpoint_id
    again = EndpointIdentity.mint(tenant_id=TENANT, processor_id="cpu-aaa",
                                  machine_guid="guid-aaa", device_iid=None,
                                  hostname="PC1-RENAMED")
    assert again == pc1, ("a rename or reinstall must not create a second "
                          "Computers entry for one machine")
    # and the same machine in another tenant is a different endpoint
    other = EndpointIdentity.mint(tenant_id=TENANT + "x",
                                  processor_id="cpu-aaa",
                                  machine_guid="guid-aaa", device_iid=None,
                                  hostname="PC1")
    assert other != pc1
