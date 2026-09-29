"""DT2-3c · DETERMINISTIC IOC FIXTURE.

The real clean G1 corpus contains NO authoritative compromise. That is
the correct result and it is reported as
`REAL_WINDOWS_COMPROMISE = NOT OBSERVED` — the renderer is therefore
proven against a deterministic fixture instead of by inventing a
compromise on real evidence.

The fixture is honest about itself: a separate tenant, a separate device,
observations tagged `fixture`, and a compromise built by the CONTRACT
from a DETECTION_MATCHED derivation. Two of the observations are
byte-identical in content and share `event.iid`; only the one the
authority named may be emphasised.

    python3 scripts/dt2_3c_ioc_fixture.py --apply
    python3 scripts/dt2_3c_ioc_fixture.py --remove
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

from motor.motor_asyncio import AsyncIOMotorClient               # noqa: E402

from edr_plane import compromise_store as cs                     # noqa: E402
from edr_plane.compromise_contract import (                      # noqa: E402
    from_detection_derivation,
)

ORGANIZATION_ID = "org_10b45e9746dd71655ecbb13287"
TENANT_SLUG = "dt2-3c-ioc-fixture"
FIXTURE_ID = "dt2-3c-ioc-fixture-1"
DEVICE_IID = "dev_dt23cfixture"
HOST = "DT2-3C-FIXTURE"
ENDPOINT_ID = "ep_dt23cfixture01"
T0 = datetime(2026, 9, 22, 16, 20, 0, tzinfo=timezone.utc)

#: (offset ms, kind, process, image, target, is the authority's subject)
PLAN = [
    (0, "process_create", "explorer.exe",
     "C:\\Windows\\explorer.exe", None, False),
    (1200, "process_create", "powershell.exe",
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     None, False),
    (2400, "file_create", "powershell.exe",
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "C:\\Users\\Public\\updater.exe", False),
    # the authority's subject observation
    (3600, "registry_value_set", "powershell.exe",
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
     True),
    # byte-identical TWIN of the subject: same instant, same key, same
    # image. It must NOT be emphasised.
    (3600, "registry_value_set", "powershell.exe",
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
     False),
    (4800, "network_connect", "updater.exe",
     "C:\\Users\\Public\\updater.exe", "203.0.113.24:443", False),
]


def _iso(offset_ms: int) -> str:
    return (T0 + timedelta(milliseconds=offset_ms)).isoformat()


def _observation(tenant: str, idx: int, offset_ms: int, kind: str,
                 process: str, image: str, target, subject: bool) -> dict:
    """One fixture observation, shaped exactly like a real one."""
    ts = _iso(offset_ms)
    # Content identity: deliberately NOT including the record id, so the
    # twin collides on content exactly as the real corpus does.
    content = f"{ts}|{kind}|{image}|{target or ''}"
    import hashlib
    evt_iid = "evt_" + hashlib.blake2s(content.encode(),
                                       digest_size=8).hexdigest()
    record_id = 900000 + idx
    obs_id = "obs_" + hashlib.blake2s(
        f"{tenant}|{DEVICE_IID}|{HOST}|{record_id}".encode(),
        digest_size=6).hexdigest()
    proc_iid = "proc_" + hashlib.blake2s(
        f"{HOST}:{process}".encode(), digest_size=6).hexdigest()
    return {
        "adapter": "dt2-3c-fixture", "cem_version": "v1", "case_id": None,
        "tenant_id": tenant, "captured_at": ts, "kind": kind,
        "process_iid": proc_iid, "artefacts_iids": [],
        "observation_id": obs_id,
        "observation_identity_state": "UNIQUE_BY_SOURCE_RECORD_IDENTITY",
        "observation_identity_key":
            f"{tenant}|{DEVICE_IID}|{HOST}|{record_id}",
        "ingest_job_id": FIXTURE_ID,
        "origin": "dt2-3c-fixture",
        "fixture": {"id": FIXTURE_ID, "synthetic": True,
                    "purpose": "prove the DT2-3c IOC renderer against an "
                               "authoritative contract; NOT real evidence"},
        "event": {
            "iid": evt_iid, "ts": ts, "kind": kind, "sequence": idx,
            "adapter": "dt2-3c-fixture", "adapter_version": "1.0",
            "device_iid": DEVICE_IID, "computer": HOST,
            "process": {"iid": proc_iid, "name": process, "image": image,
                        "parent_iid": None},
            "raw": {
                "computer": HOST, "image_path": image, "pid": 3000 + idx,
                "user": f"{HOST}\\analyst",
                "target": target,
                "remote_ip": target if kind == "network_connect" else None,
                "registry_key": target if kind.startswith("registry")
                else None,
                "rule_label": f"{process} · {kind}",
                "source_identity": {
                    "provider": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 13 if kind.startswith("registry") else 1,
                    "record_id": record_id, "computer": HOST,
                    "source_time": ts},
            },
            "provenance": {"origin": "dt2-3c-fixture",
                           "normalizer": "dt2-3c-fixture",
                           "source": "fixture"},
        },
        "_subject": subject,
    }


async def _tenant(db, *, apply: bool) -> str:
    row = await db["tenants"].find_one({"organization_id": ORGANIZATION_ID,
                                        "slug": TENANT_SLUG})
    if row:
        return row["id"]
    if not apply:
        return "(not created — plan only)"
    tid = "ten_" + os.urandom(13).hex()
    now = datetime.now(timezone.utc).isoformat()
    await db["tenants"].insert_one({
        "id": tid, "organization_id": ORGANIZATION_ID, "slug": TENANT_SLUG,
        "display_name": "DT2-3c IOC renderer fixture", "kind": "LAB",
        "state": "ACTIVE", "products": ["XDR", "EDR"],
        "created_at": now, "updated_at": now,
        "created_by": "dt2-3c-renderer-proof"})
    return tid


async def main(apply: bool, remove: bool) -> None:
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    obs = db["v2_shadow_observations"]
    tenant = await _tenant(db, apply=apply and not remove)

    if remove:
        a = await obs.delete_many({"ingest_job_id": FIXTURE_ID})
        b = await db[cs.COLLECTION].delete_many({"tenant_id": tenant})
        c = await db["edr_endpoints"].delete_many(
            {"endpoint_id": ENDPOINT_ID})
        print(json.dumps({"MODE": "REMOVE", "observations": a.deleted_count,
                          "compromises": b.deleted_count,
                          "endpoints": c.deleted_count}, indent=1))
        return

    docs = [_observation(tenant, i, *row)
            for i, row in enumerate(PLAN)]
    subject = next(d for d in docs if d["_subject"])
    contributors = [d["observation_id"] for d in docs
                    if d["kind"] in ("file_create", "network_connect")]
    for d in docs:
        d.pop("_subject", None)

    compromise = from_detection_derivation(
        {"outcome": "DETECTION_MATCHED",
         "derived_at": subject["captured_at"],
         "detection_content_version": "nivxray_native_sigma@1.4.0",
         "event_id": "cev_dt23c_fixture",
         "evidence_ids": contributors,
         "reason": "Run-key persistence written by PowerShell, followed by "
                   "the dropped binary beaconing out"},
        observation_iid=subject["observation_id"],
        observed_at=subject["captured_at"],
        techniques=("T1547.001", "T1059.001"))

    report = {
        "MODE": "APPLY" if apply else "PLAN",
        "TENANT": tenant, "DEVICE_IID": DEVICE_IID,
        "ENDPOINT_ID": ENDPOINT_ID, "HOST": HOST,
        "OBSERVATIONS": len(docs),
        "CONTENT_IID_COLLISIONS": len(docs) - len({d["event"]["iid"]
                                                   for d in docs}),
        "UNIQUE_OBSERVATION_IDS": len({d["observation_id"] for d in docs}),
        "COMPROMISE": compromise.to_dict(),
        "SUBJECT_OBSERVATION": subject["observation_id"],
        "TWIN_OBSERVATION": [d["observation_id"] for d in docs
                             if d["event"]["iid"]
                             == subject["event"]["iid"]
                             and d["observation_id"]
                             != subject["observation_id"]],
    }
    if apply:
        await obs.delete_many({"ingest_job_id": FIXTURE_ID})
        await db[cs.COLLECTION].delete_many({"tenant_id": tenant})
        await obs.insert_many(docs)
        await cs.persist(db, compromise, tenant_id=tenant,
                         device_iid=DEVICE_IID,
                         raised_by="dt2-3c-renderer-proof")
        await db["edr_endpoints"].update_one(
            {"endpoint_id": ENDPOINT_ID},
            {"$set": {"endpoint_id": ENDPOINT_ID, "tenant_id": tenant,
                      "device_iid": DEVICE_IID, "hostname": HOST,
                      "os_family": "windows",
                      "enrollment_state": "ENROLLED",
                      "fixture": FIXTURE_ID}}, upsert=True)
        report["WRITTEN"] = len(docs)
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--remove", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(apply=args.apply, remove=args.remove))
