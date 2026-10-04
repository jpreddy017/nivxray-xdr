"""STEP 34F end-to-end check through the REAL canonical writer, scratch DB only.

Drives `process_event_through_pipeline` twice — once with an authenticated
endpoint envelope, once without — and inspects the canonical row it wrote.
The only database touched is a scratch DB created and dropped here.
"""
import asyncio
import sys

from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, "/app/backend")
from detection_content.xdr_pipeline import \
    process_event_through_pipeline  # noqa: E402

SCRATCH = "nivx_34f_pipeline_scratch"
TENANT = "ten_scratch34f"
EP = "ep_a67be48d5b4e01d4d9e8"


def sensor_event(**kw):
    ev = {"activity": "PROCESS", "op": "start", "hostname": "SCRATCHHOST",
          "computer": "SCRATCHHOST", "collection_method": "PROC_POLL",
          "sensor_version": "1.4.2", "ts": "2026-06-01T00:00:00.123456Z",
          "timestamp": "2026-06-01T00:00:00.123456Z",
          "process": {"pid": 4242, "ppid": 1, "image": "C:\\x.exe",
                      "cmdline": "x.exe run", "user": "SCRATCH\\u"},
          # an event-content endpoint claim, which must carry NO authority
          "endpoint_id": EP}
    ev.update(kw)
    return ev


async def run(db, event, *, authenticated, collector_id):
    ev = dict(event)
    if authenticated:
        ev["_authenticated_ingest"] = {
            "source_kind": "REAL_SENSOR_DERIVED", "sensor_version": "1.4.2",
            "trust_state": "AUTHENTICATED", "raw_id": "raw_scratch",
            "authenticated_endpoint_id": EP}
    return await process_event_through_pipeline(
        db, ev, trace_id="trace_scratch", integration_id="scratch",
        collector_id=collector_id, tenant_id=TENANT)


async def main():
    client = AsyncIOMotorClient("mongodb://localhost:27017",
                                serverSelectionTimeoutMS=4000)
    await client.drop_database(SCRATCH)
    db = client[SCRATCH]
    try:
        for label, authenticated, collector in (
                ("AUTHENTICATED (sensor envelope)", True, EP),
                ("UNAUTHENTICATED (same event, no envelope)", False, EP),
                ("UNAUTHENTICATED third-party collector", False,
                 "collector-snort-ref")):
            await db.xdr_canonical_evidence.delete_many({})
            out = await run(db, sensor_event(), authenticated=authenticated,
                            collector_id=collector)
            doc = await db.xdr_canonical_evidence.find_one(
                {}, {"_id": 0, "additional_fields.endpoint_id": 1,
                     "provenance.endpoint_identity": 1,
                     "provenance.collector_id": 1, "host": 1,
                     "tenant_id": 1, "event_time": 1, "raw_ref": 1})
            stage = [s for s in (out.get("stages") or ())
                     if s.get("stage") == "endpoint_identity"]
            print(f"\n--- {label}")
            print("  blocker:", out.get("blocker"))
            print("  stage  :", stage)
            if not doc:
                print("  NO CANONICAL ROW WRITTEN")
                continue
            print("  af.endpoint_id        :",
                  (doc.get("additional_fields") or {}).get("endpoint_id"))
            print("  identity record       :",
                  (doc.get("provenance") or {}).get("endpoint_identity"))
            print("  tenant/event_time kept:", doc.get("tenant_id"),
                  doc.get("event_time"))
            print("  host kept             :", doc.get("host"))
            print("  collector_id kept     :",
                  (doc.get("provenance") or {}).get("collector_id"))
    finally:
        await client.drop_database(SCRATCH)
        print("\nSCRATCH DROPPED. PRODUCTION_TOUCHED = NO")


asyncio.run(main())
