"""Direct compatibility proof against the enrolment code the live surface fingerprints to.

Read-only with respect to production: every write here lands on the LOCAL harness
database under a throwaway tenant. Nothing is sent to nivxray.nivxforge.com, no
token is minted against production, and no production document is read or changed.
"""
import asyncio, os, uuid, json
from motor.motor_asyncio import AsyncIOMotorClient

from edr_plane.contracts.identity import EndpointIdentity
from edr_plane.enrollment import store, rejection
from edr_plane.enrollment.identity import (CredentialState, EnrollmentState,
                                           SensorState)
from edr_plane.enrollment.store import EnrollmentError

TENANT_REAL = "ten_0000000000synthetic0000"      # identity maths only, no DB write
EVENTS = 157_226                                     # the owner's verified count
PROC = "BFEBFBFF000906EA"
GUID = "7b1f0a2c-5d44-4f0e-9b2a-1c3d5e7f9a0b"
HISTORY = {"event_count": EVENTS,
           "last_telemetry_at": "2026-06-11T07:14:22+00:00",
           "last_heartbeat_at": "2026-06-11T07:19:03+00:00",
           "report_interval_seconds": 300,
           "cadence_basis": "SENSOR_REPORTED",
           "lifecycle_reported": True,
           "outbox_queue_depth": 541_233}

out = {}

async def main():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    await store.ensure_indexes(db); await rejection.ensure_indexes(db)
    tenant = f"recovery-proof-{uuid.uuid4().hex[:8]}"
    try:
        # ── 1 · identity determinism (pure function, real tenant, no DB) ──
        a = EndpointIdentity.mint(tenant_id=TENANT_REAL, processor_id=PROC)
        b = EndpointIdentity.mint(tenant_id=TENANT_REAL, processor_id=PROC,
                                  machine_guid=GUID, hostname="DESKTOP-SYNTH01")
        c = EndpointIdentity.mint(tenant_id=TENANT_REAL, processor_id=PROC,
                                  hostname="RENAMED-HOST")
        other_tenant = EndpointIdentity.mint(tenant_id="ten_other",
                                             processor_id=PROC)
        guid_only = EndpointIdentity.mint(tenant_id=TENANT_REAL, machine_guid=GUID)
        out["identity"] = {
            "stable_across_extra_attributes": a == b,
            "stable_across_hostname_change": a == c,
            "tenant_scoped": a != other_tenant,
            "hardware_beats_guid": a != guid_only,
            "shape": a.split("_")[0] + "_" + str(len(a.split("_")[1])) + "hex",
        }

        # ── 2 · the laptop's exact state: enrolled, delivered, then revoked ──
        endpoint = EndpointIdentity.mint(tenant_id=tenant, processor_id=PROC)
        tok1 = await store.mint_enrollment_token(db, tenant_id=tenant,
                                                 issued_by="owner@proof")
        first = await store.enroll(
            db, tenant_id=tenant, presented_token=tok1["enrollment_token"],
            endpoint_id=endpoint, hostname="DESKTOP-SYNTH01",
            platform="WINDOWS", sensor_version="0.2.0-windows")
        await db[store.ENDPOINTS].update_one(
            {"tenant_id": tenant, "endpoint_id": endpoint},
            {"$set": {**HISTORY,
                      "group_id": "grp_synthetic", "policy_id": "pol_synthetic",
                      "placement_basis": "DEFAULT_AT_ENROLMENT"}})
        await store.revoke_endpoint(db, tenant_id=tenant, endpoint_id=endpoint,
                                    revoked_by="owner@proof",
                                    reason="operator revoked (baseline)")
        before = await db[store.ENDPOINTS].find_one(
            {"tenant_id": tenant, "endpoint_id": endpoint}, {"_id": 0})
        out["before"] = {k: before.get(k) for k in
                         ("enrollment_state", "credential_state", "sensor_state",
                          "event_count", "last_telemetry_at", "group_id")}

        # ── 3 · recovery: a fresh single-use token ──
        tok2 = await store.mint_enrollment_token(db, tenant_id=tenant,
                                                 issued_by="owner@proof")
        after_res = await store.enroll(
            db, tenant_id=tenant, presented_token=tok2["enrollment_token"],
            endpoint_id=endpoint, hostname="DESKTOP-SYNTH01",
            platform="WINDOWS", sensor_version="0.3.0-windows")
        after = await db[store.ENDPOINTS].find_one(
            {"tenant_id": tenant, "endpoint_id": endpoint}, {"_id": 0})
        count = await db[store.ENDPOINTS].count_documents({"tenant_id": tenant})
        out["recovery"] = {
            "same_endpoint_id": after_res["endpoint_id"] == endpoint,
            "endpoint_documents": count,
            "enrollment_state": after.get("enrollment_state"),
            "credential_state": after.get("credential_state"),
            "sensor_state": after.get("sensor_state"),
            "event_count": after.get("event_count"),
            "event_count_preserved": after.get("event_count") == EVENTS,
            "last_telemetry_at_preserved":
                after.get("last_telemetry_at") == HISTORY["last_telemetry_at"],
            "every_delivery_field_preserved":
                all(after.get(k) == v for k, v in HISTORY.items()),
            "group_preserved": after.get("group_id") == "grp_synthetic",
            "policy_preserved": after.get("policy_id") == "pol_synthetic",
            "new_credential_id": after_res["credential_id"] != first["credential_id"],
            "credential_returned_once": bool(after_res.get("agent_credential")),
            "delivery_history_preserved": after_res.get("delivery_history_preserved"),
            "sensor_version_refreshed": after.get("sensor_version"),
        }

        # ── 4 · nothing was loosened ──
        old = await db[store.CREDENTIALS].find_one(
            {"tenant_id": tenant, "credential_id": first["credential_id"]},
            {"_id": 0, "status": 1})
        replay = None
        try:
            await store.enroll(db, tenant_id=tenant,
                               presented_token=tok2["enrollment_token"],
                               endpoint_id=endpoint)
        except EnrollmentError as e:
            replay = e.code
        cross = None
        try:
            await store.enroll(db, tenant_id="ten_foreign",
                               presented_token=tok2["enrollment_token"],
                               endpoint_id=endpoint)
        except EnrollmentError as e:
            cross = e.code
        out["refusals"] = {"old_credential_status": old.get("status"),
                           "token_replay": replay, "cross_tenant": cross}

        # ── 5 · the duplicate-identity risk, demonstrated ──
        tok3 = await store.mint_enrollment_token(db, tenant_id=tenant,
                                                 issued_by="owner@proof")
        fallback_id = EndpointIdentity.mint(tenant_id=tenant, machine_guid=GUID)
        await store.enroll(db, tenant_id=tenant,
                           presented_token=tok3["enrollment_token"],
                           endpoint_id=fallback_id, hostname="DESKTOP-SYNTH01",
                           platform="WINDOWS", sensor_version="0.3.0-windows")
        split = await db[store.ENDPOINTS].count_documents({"tenant_id": tenant})
        orig = await db[store.ENDPOINTS].find_one(
            {"tenant_id": tenant, "endpoint_id": endpoint}, {"_id": 0,
                                                             "event_count": 1})
        out["processor_id_fallback"] = {
            "mints_a_different_endpoint": fallback_id != endpoint,
            "endpoint_documents_after": split,
            "original_history_still_intact": orig.get("event_count") == EVENTS,
        }
    finally:
        for c in (store.ENDPOINTS, store.CREDENTIALS, store.TOKENS,
                  store.SESSIONS):
            await db[c].delete_many({"tenant_id": tenant})
        client.close()
    print(json.dumps(out, indent=2))

asyncio.run(main())
