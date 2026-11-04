"""TIMELINE CHECK (read-only intent) — what `xdr_canonical_evidence.event_time`
holds for a Sysmon delivery, proven on the deployed code.

PREVIEW DATABASE ONLY. Production is never contacted. This does not modify any
production record; it drives one synthetic Sysmon record shaped exactly like the
W1 five through the same pipeline the ingest route calls, then reads back the
persisted canonical evidence document and prints its temporal fields.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv  # noqa: E402

load_dotenv("/app/backend/.env")

from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

from detection_content.xdr_pipeline import process_event_through_pipeline  # noqa: E402
from services import source_routing  # noqa: E402

# The W1 sample's real times, from the owner's production read.
UTC_TIME = "2026-09-18 08:38:17.569"          # Sysmon EventData.UtcTime
TIME_CREATED = "2026-09-18T08:38:17.5694321Z"  # System.TimeCreated
NIVX_RECEIVED = "2026-09-18T10:01:43.112000+00:00"

TEN = f"timecheck-{uuid.uuid4().hex[:8]}"
COL = f"col-timecheck-{uuid.uuid4().hex[:8]}"

RAW = {
    "event_id": 1,
    "provider": "Microsoft-Windows-Sysmon",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "DESKTOP-A9HGFJJ",
    "record_id": 1696988,
    "TimeCreated": TIME_CREATED,
    "UtcTime": UTC_TIME,
    "ProcessGuid": "{a1b2c3d4-0000-0000-0000-000000000001}",
    "ProcessId": "4412",
    "Image": r"C:\Windows\System32\notepad.exe",
    "CommandLine": r"notepad.exe C:\Users\owner\notes.txt",
    "User": "DESKTOP-A9HGFJJ\\owner",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ParentCommandLine": "explorer.exe",
    "Hashes": "SHA256=3F1B2C0000000000000000000000000000000000000000000000000000000001",
}


async def main() -> int:
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    routing = {
        "routing_result": source_routing.ACCEPTED,
        "routing_authority": source_routing.DECLARED_AUTHORITY,
        "declared_source": "microsoft-sysmon",
        "declared_source_resolved": "microsoft-sysmon",
        "selected_dsm_id": "microsoft-sysmon",
        "content_compatible": True,
        "collector_authorized_sources": ["microsoft-sysmon"],
    }
    trace = f"timecheck_{uuid.uuid4().hex[:12]}"
    res = await process_event_through_pipeline(
        db, dict(RAW), trace, integration_id="timecheck",
        collector_id=COL, tenant_id=TEN,
        ingest_provenance={"nivx_received_at": {"status": "AVAILABLE",
                                                "value": NIVX_RECEIVED}},
        routing=routing)

    canon = res.get("canonical")
    if not canon:
        print("PIPELINE DID NOT PRODUCE CANONICAL EVIDENCE")
        print(json.dumps(res.get("stages"), indent=2, default=str)[:2000])
        return 1

    stored = await db["xdr_canonical_evidence"].find_one(
        {"event_id": canon.get("event_id")})
    doc = stored or canon
    src = "xdr_canonical_evidence (persisted)" if stored else "in-memory canonical"

    extra = doc.get("additional_fields") or {}
    ts = ((doc.get("provenance") or {}).get("timestamps") or {})

    print(f"read from            : {src}")
    print(f"event_id             : {doc.get('event_id')}")
    print(f"source_event_id      : {doc.get('source_event_id')!r}"
          "   <- Sysmon EventID on the evidence plane, NOT the collector id string")
    print(f"event_type           : {doc.get('event_type')}")
    print()
    print(f"raw UtcTime          : {UTC_TIME}      (activity)")
    print(f"raw TimeCreated      : {TIME_CREATED}  (ETW record write)")
    print(f"nivx_received_at     : {NIVX_RECEIVED} (NivX receive)")
    print()
    print(f"event_time           : {doc.get('event_time')}")
    print(f"ingest_time          : {doc.get('ingest_time')}")
    print(f"event_time_basis     : {extra.get('event_time_basis')}")
    print(f"event_time_source    : {extra.get('event_time_source')}")
    print(f"event_time_substituted: {extra.get('event_time_substituted')}")
    print(f"event_time_format    : {extra.get('event_time_format_state')}")
    print()
    for k in ("activity_occurred_at", "sensor_observed_at",
              "nivx_received_at", "raw_persisted_at"):
        print(f"provenance.timestamps.{k} = "
              f"{json.dumps(ts.get(k), default=str)}")

    ok = (str(doc.get("event_time")).startswith("2026-09-18 08:38:17")
          or str(doc.get("event_time")).startswith("2026-09-18T08:38:17"))
    print()
    print("VERDICT:", "event_time IS ACTIVITY TIME (08:38)" if ok
          else f"event_time IS NOT ACTIVITY TIME -> {doc.get('event_time')!r}")
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
