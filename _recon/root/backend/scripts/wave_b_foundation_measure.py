"""WAVE B · read-only measurement of the foundation over REAL evidence.

    python3 scripts/wave_b_foundation_measure.py [--tenant T]

Runs B1 (preservation), B2 (process identity), B3 (file identity) and B4
(observable extraction) over `xdr_canonical_evidence` and prints what is
MEASURED. It writes nothing — no collection is modified, no evidence is
rewritten, no reputation provider is queried.
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import os
import sys

sys.path.insert(0, "/app/backend")

from dotenv import load_dotenv                                  # noqa: E402

load_dotenv("/app/backend/.env")

from edr_plane import file_identity as fi                       # noqa: E402
from edr_plane import process_identity as pi                    # noqa: E402
from edr_plane.reputation import extract                        # noqa: E402
from v2.ingestion.canonical import HASH_OBSERVED                # noqa: E402
from v2.ingestion.telemetry_bridge import observation_doc       # noqa: E402

REAL_TENANT = "ten_f1a5479243e901cf159e230fa0"
CANONICAL = "xdr_canonical_evidence"

#: B1 · fields whose LOSS would be a security-semantic loss. Measured as
#: "present in canonical evidence" vs "present in the projection".
PRESERVED = {
    "process.process_guid": (
        lambda c: (c.get("process") or {}).get("process_guid"),
        lambda r: r.get("process_guid")),
    "process.command_line": (
        lambda c: (c.get("process") or {}).get("command_line"),
        lambda r: r.get("command_line")),
    "process.original_file_name": (
        lambda c: (c.get("process") or {}).get("original_file_name"),
        lambda r: r.get("original_file_name")),
    "process.hashes.sha256": (
        lambda c: ((c.get("process") or {}).get("hashes") or {}).get("sha256"),
        lambda r: (r.get("process_image_hashes") or {}).get("sha256")),
    "process.hashes.md5": (
        lambda c: ((c.get("process") or {}).get("hashes") or {}).get("md5"),
        lambda r: (r.get("process_image_hashes") or {}).get("md5")),
    "process.parent_process_guid": (
        lambda c: (c.get("process") or {}).get("parent_process_guid"),
        lambda r: r.get("parent_process_guid")),
    "process.parent_command_line": (
        lambda c: (c.get("process") or {}).get("parent_command_line"),
        lambda r: r.get("parent_command_line")),
    "process.parent_executable_path": (
        lambda c: (c.get("process") or {}).get("parent_executable_path"),
        lambda r: r.get("parent_image_path")),
    "process.ppid": (
        lambda c: ((c.get("process") or {}).get("parent_pid")
                   or (c.get("process") or {}).get("ppid")),
        lambda r: r.get("ppid")),
    "process.field_provenance": (
        lambda c: (c.get("process") or {}).get("field_provenance"),
        lambda r: r.get("field_provenance")),
    "file.path": (
        lambda c: (c.get("file") or {}).get("path"),
        lambda r: (r.get("file") or {}).get("path")),
    "file.hashes.sha256": (
        lambda c: ((c.get("file") or {}).get("hashes") or {}).get("sha256"),
        lambda r: ((r.get("file") or {}).get("hashes") or {}).get("sha256")),
    "file.field_provenance": (
        lambda c: (c.get("file") or {}).get("field_provenance"),
        lambda r: r.get("field_provenance")),
}

ENVELOPE = {"source": "measurement", "connector_id": "measure",
            "collector_id": "measure", "collection_method": "READ_ONLY",
            "parser_version": "0", "source_event_id": "measure",
            "collection_timestamp": ""}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", default=REAL_TENANT)
    args = ap.parse_args()

    from motor.motor_asyncio import AsyncIOMotorClient
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    present = collections.Counter()
    preserved = collections.Counter()
    lost: dict[str, list[str]] = collections.defaultdict(list)
    views: list[pi.ProcessView] = []
    files: list[fi.FileObservation] = []
    image_hash_states = collections.Counter()
    observables = collections.Counter()
    kinds = collections.Counter()

    total = 0
    async for c in db[CANONICAL].find({"tenant_id": args.tenant},
                                      {"_id": 0}):
        total += 1
        endpoint = ((c.get("additional_fields") or {}).get("endpoint_id")
                    or (c.get("host") or {}).get("host_id") or "")
        doc = observation_doc(c, envelope={**ENVELOPE,
                                           "connector_id": endpoint,
                                           "collector_id": endpoint},
                              tenant_id=args.tenant)
        raw = doc["event"]["raw"]
        kinds[doc["event"]["kind"]] += 1
        for name, (read_c, read_r) in PRESERVED.items():
            if read_c(c) in (None, "", {}, []):
                continue
            present[name] += 1
            if read_r(raw) in (None, "", {}, []):
                lost[name].append(str(c.get("event_id"))[:40])
            else:
                preserved[name] += 1
        views.append(pi.from_canonical(c, tenant_id=args.tenant,
                                       endpoint_id=endpoint))
        f = fi.from_canonical(c, tenant_id=args.tenant,
                              endpoint_id=endpoint)
        if f:
            files.append(f)
        image_hash_states[fi.process_image_identity(c)["hash_state"]] += 1
        for o in extract(c, tenant_id=args.tenant, endpoint_id=endpoint):
            observables[f"{o.type}:{o.subject}"] += 1

    identity = pi.build(views)
    authorities = collections.Counter(
        p["identity_authority"] for p in identity["processes"])
    lifetimes = collections.Counter(
        p["lifecycle"]["lifetime_state"] for p in identity["processes"])
    parent_bases = collections.Counter(
        e["basis"] for e in identity["relationships"])

    print(json.dumps({
        "tenant": args.tenant,
        "canonical_observations": total,
        "kinds": dict(kinds.most_common()),
        "B1_preservation": {
            name: {"present_in_canonical": present[name],
                   "preserved_in_projection": preserved[name],
                   "lost": present[name] - preserved[name],
                   "example_lost_event_ids": lost[name][:3]}
            for name in sorted(present)
        },
        "B1_fields_still_lost": {n: present[n] - preserved[n]
                                 for n in sorted(present)
                                 if present[n] != preserved[n]},
        "B2_process_identity": {
            "processes": identity["counts"]["processes"],
            "identity_authorities": dict(authorities),
            "lifetime_states": dict(lifetimes),
            "relationship_bases": dict(parent_bases),
            "unattributed_observations":
                identity["counts"]["unattributed_observations"],
            "pid_reuse_cases": len(identity["pid_reuse"]),
        },
        "B3_file_identity": {
            **fi.coverage(files),
            "process_image_hash_states": dict(image_hash_states),
        },
        "B4_observables": dict(observables.most_common()),
    }, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
