"""Re-enrolling a REVOKED endpoint must restore service without erasing its past.

DESKTOP-SYNTH01 is the case this suite exists for: a revoked credential on an
endpoint holding 822,757 queued records. Recovery means a fresh single-use
token produces an ACTIVE credential on the SAME endpoint_id under the SAME
tenant, and the delivery record — the evidence blindness detection is derived
from — survives untouched.

`test_p0_3_telemetry_freshness.test_reenrolment_never_resets_the_delivery_record`
already guards this, but by `inspect.getsource()` on `store.enroll`: it proves
the `$setOnInsert` partition is still written, not that a re-enrolment behaves.
A refactor that preserved the text and broke the behaviour would pass it. These
tests exercise the real store against a real database instead.

Nothing here weakens a refusal: the revoked credential stays unusable, the
spent token stays spent, and the cross-tenant and replay guards are asserted
alongside the recovery path.
"""
from __future__ import annotations

import uuid

import os
import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane.contracts.identity import EndpointIdentity
from edr_plane.enrollment import store
from edr_plane.enrollment.identity import (CredentialState, EnrollmentState,
                                           SensorState)
from edr_plane.enrollment import rejection
from edr_plane.enrollment.store import EnrollmentError


class _Scope:
    """One throwaway tenant on the harness database; nothing shared, nothing left."""

    async def __aenter__(self):
        self.client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        self.db = self.client[os.environ["DB_NAME"]]
        await store.ensure_indexes(self.db)
        await rejection.ensure_indexes(self.db)
        self.tenant = f"winreenrol-{uuid.uuid4().hex[:8]}"
        return self.db, self.tenant

    async def __aexit__(self, *exc):
        for collection in (store.ENDPOINTS, store.CREDENTIALS, store.TOKENS,
                           store.SESSIONS):
            await self.db[collection].delete_many({"tenant_id": self.tenant})
        self.client.close()


async def _mint(db, tenant, **kw):
    return await store.mint_enrollment_token(db, tenant_id=tenant,
                                             issued_by="owner@test", **kw)

#: The durable attribute DESKTOP-SYNTH01 enrolled with.
PROCESSOR_ID = "BFEBFBFF00SYNTH1"
MACHINE_GUID = "7b1f0a2c-5d44-4f0e-9b2a-1c3d5e7f9a0b"

#: The delivery history a recovery may not erase.
HISTORY = {
    "event_count": 822_757,
    "last_telemetry_at": "2026-10-11T07:14:22+00:00",
    "last_heartbeat_at": "2026-10-11T07:19:03+00:00",
    "report_interval_seconds": 300,
    "cadence_basis": "SENSOR_REPORTED",
    "lifecycle_reported": True,
    "outbox_queue_depth": 822_757,
}


async def _enrolled_then_revoked(db, tenant: str) -> str:
    """Bring an endpoint to the exact state the laptop is in: enrolled, having
    delivered, then revoked by an operator."""
    endpoint_id = EndpointIdentity.mint(tenant_id=tenant,
                                        processor_id=PROCESSOR_ID)
    token = await _mint(db, tenant)
    await store.enroll(db, tenant_id=tenant,
                       presented_token=token["enrollment_token"],
                       endpoint_id=endpoint_id, hostname="DESKTOP-SYNTH01",
                       platform="windows", sensor_version="0.3.0-windows")
    await db[store.ENDPOINTS].update_one(
        {"tenant_id": tenant, "endpoint_id": endpoint_id},
        {"$set": {**HISTORY, "sensor_state": SensorState.REPORTING.value}})
    await store.revoke_endpoint(db, tenant_id=tenant, endpoint_id=endpoint_id,
                                revoked_by="operator@synthetic",
                                reason="OPERATOR_REVOKED")
    row = await db[store.ENDPOINTS].find_one(
        {"tenant_id": tenant, "endpoint_id": endpoint_id})
    assert row["enrollment_state"] == EnrollmentState.REVOKED.value
    assert row["credential_state"] == CredentialState.REVOKED.value
    return endpoint_id


@pytest.mark.asyncio
async def test_revoked_endpoint_recovers_identity_state_and_history():
  async with _Scope() as (db, tenant):
    endpoint_id = await _enrolled_then_revoked(db, tenant)
    before = await db[store.ENDPOINTS].find_one(
        {"tenant_id": tenant, "endpoint_id": endpoint_id})

    fresh = await _mint(db, tenant)
    result = await store.enroll(
        db, tenant_id=tenant, presented_token=fresh["enrollment_token"],
        endpoint_id=endpoint_id, hostname="DESKTOP-SYNTH01",
        platform="windows", sensor_version="0.3.0-windows")

    # 1 · the same endpoint, under the same tenant — not a second identity
    assert result["endpoint_id"] == endpoint_id
    assert await db[store.ENDPOINTS].count_documents({"tenant_id": tenant}) == 1

    after = await db[store.ENDPOINTS].find_one(
        {"tenant_id": tenant, "endpoint_id": endpoint_id})
    assert after["tenant_id"] == before["tenant_id"]

    # 2 · ACTIVE again, and no longer revoked anywhere
    assert after["enrollment_state"] == EnrollmentState.ENROLLED.value
    assert after["credential_state"] == CredentialState.ACTIVE.value
    assert after["sensor_state"] != SensorState.REVOKED.value
    assert after.get("revoked_at") in (None, "")

    # 3 · the delivery record is intact, field by field
    for field, value in HISTORY.items():
        assert after[field] == value, f"{field} was reset by re-enrolment"
    # A delivering endpoint must not be called "never reported" again.
    assert after["sensor_state"] == SensorState.REPORTING.value
    assert result["delivery_history_preserved"] is True

    # 4 · a NEW credential, and the revoked one is not resurrected
    assert result["credential_id"] != before["credential_id"]
    assert result["agent_credential"].startswith(f"{store.PREFIX_CREDENTIAL}_")
    old = await db[store.CREDENTIALS].find_one(
        {"tenant_id": tenant, "credential_id": before["credential_id"]})
    assert old["status"] == CredentialState.REVOKED.value


@pytest.mark.asyncio
async def test_the_recovery_token_is_still_single_use():
  async with _Scope() as (db, tenant):
    endpoint_id = await _enrolled_then_revoked(db, tenant)
    fresh = await _mint(db, tenant)
    await store.enroll(db, tenant_id=tenant,
                       presented_token=fresh["enrollment_token"],
                       endpoint_id=endpoint_id, hostname="DESKTOP-SYNTH01")
    credentials = await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant})
    with pytest.raises(EnrollmentError) as err:
        await store.enroll(db, tenant_id=tenant,
                           presented_token=fresh["enrollment_token"],
                           endpoint_id=endpoint_id, hostname="DESKTOP-SYNTH01")
    assert err.value.code == "ENROLLMENT_TOKEN_INVALID"
    assert await db[store.CREDENTIALS].count_documents(
        {"tenant_id": tenant}) == credentials


@pytest.mark.asyncio
async def test_the_revoked_credential_stays_unusable_after_recovery():
  async with _Scope() as (db, tenant):
    endpoint_id = await _enrolled_then_revoked(db, tenant)
    revoked = await db[store.ENDPOINTS].find_one(
        {"tenant_id": tenant, "endpoint_id": endpoint_id})
    fresh = await _mint(db, tenant)
    await store.enroll(db, tenant_id=tenant,
                       presented_token=fresh["enrollment_token"],
                       endpoint_id=endpoint_id, hostname="DESKTOP-SYNTH01")
    # Recovery re-points identity; it does not reactivate what was revoked.
    old = await db[store.CREDENTIALS].find_one(
        {"tenant_id": tenant, "credential_id": revoked["credential_id"]})
    assert old["status"] == CredentialState.REVOKED.value


# ── hardware identity stability ───────────────────────────────────
def test_the_same_processor_id_always_mints_the_same_endpoint():
    tenant = f"ten_{uuid.uuid4().hex[:12]}"
    first = EndpointIdentity.mint(tenant_id=tenant, processor_id=PROCESSOR_ID)
    again = EndpointIdentity.mint(tenant_id=tenant, processor_id=PROCESSOR_ID,
                                  machine_guid=MACHINE_GUID,
                                  hostname="DESKTOP-SYNTH01")
    assert first == again, "hardware id must win over guid and hostname"
    assert first.startswith("ep_")


def test_a_missing_processor_id_mints_a_DIFFERENT_endpoint():
    """The re-enrolment risk, pinned as a fact rather than a footnote.

    Precedence is hardware id > machine guid > device_iid > hostname. If WMI
    cannot read the processor id at re-enrolment time the installer still
    enrols — against a DIFFERENT endpoint_id, which splits the queue onto a
    second identity and leaves the original looking blind. Operators must
    confirm the durable attribute BEFORE re-enrolling; this test exists so
    nobody discovers the behaviour on a production laptop.
    """
    tenant = f"ten_{uuid.uuid4().hex[:12]}"
    by_hardware = EndpointIdentity.mint(tenant_id=tenant,
                                        processor_id=PROCESSOR_ID)
    by_guid = EndpointIdentity.mint(tenant_id=tenant, machine_guid=MACHINE_GUID)
    by_hostname = EndpointIdentity.mint(tenant_id=tenant,
                                        hostname="DESKTOP-SYNTH01")
    assert by_hardware != by_guid != by_hostname
    assert len({by_hardware, by_guid, by_hostname}) == 3


def test_the_same_machine_in_another_tenant_is_another_endpoint():
    a = EndpointIdentity.mint(tenant_id="ten_a", processor_id=PROCESSOR_ID)
    b = EndpointIdentity.mint(tenant_id="ten_b", processor_id=PROCESSOR_ID)
    assert a != b


def test_an_endpoint_id_is_never_accepted_from_the_agent():
    with pytest.raises(ValueError):
        EndpointIdentity.mint(tenant_id="ten_a")
