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
import hashlib
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

#: Authored fixture COMMAND LINES. The fixture supplies TELEMETRY only;
#: the detection, its rule and its ATT&CK mapping are produced by the
#: engine at replay time and are NOT written here.
COMMAND_LINES = {
    "explorer.exe": "C:\\Windows\\explorer.exe",
    "powershell.exe": ("powershell.exe -nop -w hidden -enc "
                       "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
    "updater.exe": "C:\\Users\\Public\\updater.exe",
}

#: Sysmon event ids the fixture's families correspond to.
SYSMON_EVENT_ID = {"process_create": 1, "file_create": 11,
                   "registry_value_set": 13, "network_connect": 3}
CANONICAL_EVENT_TYPE = {"process_create": "process_creation",
                        "file_create": "file_event",
                        "registry_value_set": "registry_event",
                        "network_connect": "network_connection"}

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
UPDATER = "C:\\Users\\Public\\updater.exe"

#: DT2-3c REV 2 · the fixture now AUTHORS the parent-process evidence
#: explicitly, so `explorer.exe -> powershell.exe -> updater.exe` exists
#: IN EVIDENCE and the renderer may legitimately draw it. This is
#: authored fixture evidence, NOT inferred from name order, proximity or
#: PID surrogacy, and it is NOT presented as real endpoint telemetry.
#: (offset ms, kind, process, image, target, subject, parent image)
PLAN = [
    (0, "process_create", "explorer.exe", EXPLORER, None, False, None),
    (1200, "process_create", "powershell.exe", PS, None, False, EXPLORER),
    (2400, "file_create", "powershell.exe", PS, UPDATER, False, EXPLORER),
    # the authority's subject observation
    (3600, "registry_value_set", "powershell.exe", PS,
     "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
     True, EXPLORER),
    # byte-identical TWIN of the subject: same instant, same key, same
    # image. It must NOT be emphasised.
    (3600, "registry_value_set", "powershell.exe", PS,
     "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
     False, EXPLORER),
    (4800, "network_connect", "updater.exe", UPDATER,
     "203.0.113.24:443", False, PS),
]


def _iso(offset_ms: int) -> str:
    return (T0 + timedelta(milliseconds=offset_ms)).isoformat()


def _canonical_event_id(kind: str, record_id: int) -> str:
    eid = SYSMON_EVENT_ID.get(kind, 1)
    return f"sysmon-{eid}-" + hashlib.blake2s(
        f"{FIXTURE_ID}|{kind}|{record_id}".encode(),
        digest_size=16).hexdigest()


def _canonical(tenant: str, idx: int, offset_ms: int, kind: str,
               process: str, image: str, target, subject: bool,
               parent_image: str = None) -> dict:
    """The CANONICAL EVIDENCE row for one fixture observation.

    This is the shape the Sysmon normalizer produces, so the detection
    authority can evaluate it with no replay-specific translation. The
    fixture authors TELEMETRY here — process, command line, registry key,
    peer. It authors NO detection, NO rule id and NO ATT&CK technique:
    those must be produced by the engine, which is the whole point of
    reversing the fixture/engine dependency.
    """
    ts = (T0 + timedelta(milliseconds=offset_ms)).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]
    record_id = 900000 + idx
    parent_name = (str(parent_image).split("\\")[-1]
                   if parent_image else "")
    guid = "{" + hashlib.blake2s(
        f"guid|{HOST}|{process}".encode(), digest_size=8).hexdigest() + "}"
    parent_guid = ("{" + hashlib.blake2s(
        f"guid|{HOST}|{parent_name}".encode(), digest_size=8).hexdigest()
        + "}" if parent_name else "")
    reg = {}
    if kind.startswith("registry") and target:
        key = str(target)
        reg = {"hive": key.split("\\")[0],
               "key_path": key.rsplit("\\", 1)[0],
               "value_name": key.rsplit("\\", 1)[-1],
               "value_data": UPDATER, "value_type": "REG_SZ",
               "action": "set_value"}
    net = {}
    if kind == "network_connect" and target:
        host, _, port = str(target).partition(":")
        net = {"dest_ip": host, "dest_port": int(port) if port else None,
               "protocol": "tcp", "direction": "outbound"}
    fil = {}
    if kind == "file_create" and target:
        fil = {"path": str(target), "name": str(target).split("\\")[-1],
               "action": "create"}
    return {
        "event_id": _canonical_event_id(kind, record_id),
        "tenant_id": tenant,
        "source_vendor": "Microsoft", "source_product": "Sysmon",
        "source_event_id": str(SYSMON_EVENT_ID.get(kind, 1)),
        "event_type": CANONICAL_EVENT_TYPE.get(kind, "process_creation"),
        "event_time": ts,
        "ingest_time": datetime.now(timezone.utc).isoformat(),
        "host": {"hostname": HOST, "host_id": DEVICE_IID,
                 "ip_addresses": [], "os_family": "windows", "domain": ""},
        "identity": {"principal_id": f"{HOST}\\analyst",
                     "username": f"{HOST}\\analyst", "domain": "",
                     "user_sid": "", "logon_id": "", "is_privileged": False},
        "process": {"name": process, "pid": 3000 + idx,
                    "ppid": (3000 + idx - 1) if parent_name else None,
                    "parent_name": parent_name,
                    "executable_path": image,
                    "command_line": COMMAND_LINES.get(process, ""),
                    "parent_executable_path": parent_image or "",
                    "parent_command_line": "",
                    "hashes": {}, "process_guid": guid,
                    "parent_process_guid": parent_guid,
                    "attribution_state": "FIXTURE_AUTHORED_PROCESS_IDENTITY",
                    "attribution_reason": (
                        "authored fixture evidence: the child names its "
                        "parent explicitly, exactly as Sysmon would")},
        "network": net, "file": fil, "registry": reg, "security": {},
        "provenance": {"origin": "dt2-3c-fixture",
                       "collector_id": ENDPOINT_ID,
                       "integration_id": FIXTURE_ID,
                       "dsm_id": "microsoft-sysmon",
                       "normalizer_id": "dt2-3c-fixture",
                       "source_record_id": record_id},
        "fixture": {"id": FIXTURE_ID, "synthetic": True,
                    "purpose": ("prove the DETECTION ENGINE against "
                                "authored telemetry; NOT real evidence")},
        "ingest_job_id": FIXTURE_ID,
    }


def _observation(tenant: str, idx: int, offset_ms: int, kind: str,
                 process: str, image: str, target, subject: bool,
                 parent_image: str = None) -> dict:
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
    # Authored parent-process evidence. The parent's identity is derived
    # from the PARENT'S OWN image, exactly as the child observation would
    # have reported it, and a root process names no parent at all.
    parent_name = (str(parent_image).split("\\")[-1]
                   if parent_image else None)
    parent_iid = ("proc_" + hashlib.blake2s(
        f"{HOST}:{parent_name}".encode(), digest_size=6).hexdigest()
        if parent_name else None)
    guid = "{" + hashlib.blake2s(
        f"guid|{HOST}|{process}".encode(), digest_size=8).hexdigest() + "}"
    parent_guid = ("{" + hashlib.blake2s(
        f"guid|{HOST}|{parent_name}".encode(), digest_size=8).hexdigest()
        + "}" if parent_name else None)
    return {
        "adapter": "dt2-3c-fixture", "cem_version": "v1", "case_id": None,
        "tenant_id": tenant, "captured_at": ts, "kind": kind,
        "process_iid": proc_iid, "artefacts_iids": [],
        "observation_id": obs_id,
        "observation_identity_state": "UNIQUE_BY_SOURCE_RECORD_IDENTITY",
        "observation_identity_key":
            f"{tenant}|{DEVICE_IID}|{HOST}|{record_id}",
        "ingest_job_id": FIXTURE_ID,
        "canonical_event_id": _canonical_event_id(kind, record_id),
        "origin": "dt2-3c-fixture",
        "fixture": {"id": FIXTURE_ID, "synthetic": True,
                    "purpose": "prove the DT2-3c IOC renderer against an "
                               "authoritative contract; NOT real evidence"},
        "event": {
            "iid": evt_iid, "ts": ts, "kind": kind, "sequence": idx,
            "adapter": "dt2-3c-fixture", "adapter_version": "1.0",
            "device_iid": DEVICE_IID, "computer": HOST,
            "process": {"iid": proc_iid, "name": process, "image": image,
                        "guid": guid,
                        "parent_iid": parent_iid,
                        "parent_name": parent_name,
                        "parent_image": parent_image,
                        "parent_guid": parent_guid},
            "raw": {
                "computer": HOST, "image_path": image, "pid": 3000 + idx,
                "user": f"{HOST}\\analyst",
                "target": target,
                "command_line": COMMAND_LINES.get(process, ""),
                "process_guid": guid,
                "parent_process_guid": parent_guid,
                "parent_image": parent_image,
                "ppid": (3000 + idx - 1) if parent_name else None,
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

    canon = db["xdr_canonical_evidence"]

    if remove:
        a = await obs.delete_many({"ingest_job_id": FIXTURE_ID})
        b = await db[cs.COLLECTION].delete_many({"tenant_id": tenant})
        c = await db["edr_endpoints"].delete_many(
            {"endpoint_id": ENDPOINT_ID})
        d = await canon.delete_many({"ingest_job_id": FIXTURE_ID})
        e = await db["edr_finding_evaluations"].delete_many(
            {"tenant_id": tenant})
        f = await db["edr_findings"].delete_many({"tenant_id": tenant})
        print(json.dumps({"MODE": "REMOVE", "observations": a.deleted_count,
                          "compromises": b.deleted_count,
                          "endpoints": c.deleted_count,
                          "canonical_evidence": d.deleted_count,
                          "evaluations": e.deleted_count,
                          "findings": f.deleted_count}, indent=1))
        return

    docs = [_observation(tenant, i, *row)
            for i, row in enumerate(PLAN)]
    canonicals = [_canonical(tenant, i, *row)
                  for i, row in enumerate(PLAN)]
    subject = next(d for d in docs if d["_subject"])
    for d in docs:
        d.pop("_subject", None)

    report = {
        "MODE": "APPLY" if apply else "PLAN",
        "TENANT": tenant, "DEVICE_IID": DEVICE_IID,
        "ENDPOINT_ID": ENDPOINT_ID, "HOST": HOST,
        "OBSERVATIONS": len(docs),
        "CANONICAL_EVIDENCE": len(canonicals),
        "DETECTION_SOURCE": ("produced by the engine at replay time; the "
                             "fixture authors telemetry only"),
        "CONTENT_IID_COLLISIONS": len(docs) - len({d["event"]["iid"]
                                                   for d in docs}),
        "UNIQUE_OBSERVATION_IDS": len({d["observation_id"] for d in docs}),
        "COMPROMISE_SOURCE": (
            "derived from the REAL detection the engine produced at replay "
            "time — rule ids, ATT&CK techniques and contributors all come "
            "from the matched findings. The fixture no longer authors a "
            "detection derivation or a technique list."),
        "SUBJECT_OBSERVATION": subject["observation_id"],
        "TWIN_OBSERVATION": [d["observation_id"] for d in docs
                             if d["event"]["iid"]
                             == subject["event"]["iid"]
                             and d["observation_id"]
                             != subject["observation_id"]],
    }
    if apply:
        await obs.delete_many({"ingest_job_id": FIXTURE_ID})
        await canon.delete_many({"ingest_job_id": FIXTURE_ID})
        await db[cs.COLLECTION].delete_many({"tenant_id": tenant})
        await db["edr_finding_evaluations"].delete_many(
            {"tenant_id": tenant})
        await db["edr_findings"].delete_many({"tenant_id": tenant})
        await obs.insert_many(docs)
        await canon.insert_many(canonicals)
        await db["edr_endpoints"].update_one(
            {"endpoint_id": ENDPOINT_ID},
            {"$set": {"endpoint_id": ENDPOINT_ID, "tenant_id": tenant,
                      "device_iid": DEVICE_IID, "hostname": HOST,
                      "os_family": "windows",
                      "enrollment_state": "ENROLLED",
                      "fixture": FIXTURE_ID}}, upsert=True)
        report["WRITTEN"] = len(docs)
        # E3 · the fixture no longer hand-writes the detection. The real
        # detection authority is run over the authored canonical evidence
        # and whatever it produces is what the console will show.
        from edr_plane.detection_replay import replay_endpoint
        rp = await replay_endpoint(db, tenant_id=tenant,
                                   refs=[ENDPOINT_ID, HOST, DEVICE_IID],
                                   apply=True)
        report["DETECTION_REPLAY"] = {
            k: rp[k] for k in ("evaluated", "matched", "no_match", "failed",
                              "persisted_findings", "rules_fired",
                              "rule_set")}

        # E7 (minimal, honest form) · the compromise is now built from the
        # detection the ENGINE produced. Its techniques are the ones the
        # matched rules declared, and its contributors are the exact
        # observations those rules cited — never an observation chosen by
        # proximity, and never a technique the fixture picked.
        by_canonical = {d["canonical_event_id"]: d for d in docs}
        fnds = [f async for f in db["edr_findings"].find(
            {"tenant_id": tenant}, {"_id": 0})]
        cited = [f for f in fnds if f.get("rule_id")]
        if not cited:
            report["COMPROMISE"] = ("NO_AUTHORITATIVE_COMPROMISE — the "
                                    "engine produced no detection")
        else:
            techniques = tuple(sorted({t for f in cited
                                       for t in (f.get("attck") or [])}))
            contributor_obs = sorted({
                by_canonical[r]["observation_id"]
                for f in cited for r in (f.get("evidence_refs") or [])
                if r in by_canonical})
            # The subject is the LATEST cited observation: the instant by
            # which the authority had all of its evidence. No timestamp is
            # altered to produce it.
            subj = max((by_canonical[r] for f in cited
                        for r in (f.get("evidence_refs") or [])
                        if r in by_canonical),
                       key=lambda d: d["captured_at"])
            top = max(cited, key=lambda f: len(f.get("attck") or []))
            compromise = from_detection_derivation(
                {"outcome": "DETECTION_MATCHED",
                 "derived_at": top.get("evaluation_time"),
                 "detection_content_version": top.get("analyzer_version"),
                 "event_id": top.get("finding_id"),
                 "evidence_ids": contributor_obs,
                 "reason": ("rules: " + ", ".join(sorted(
                     {f["rule_id"] for f in cited})))},
                observation_iid=subj["observation_id"],
                observed_at=subj["captured_at"],
                techniques=techniques)
            await cs.persist(db, compromise, tenant_id=tenant,
                             device_iid=DEVICE_IID,
                             raised_by="nivxforge::e3::detection_replay")
            report["COMPROMISE"] = compromise.to_dict()
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--remove", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(apply=args.apply, remove=args.remove))
