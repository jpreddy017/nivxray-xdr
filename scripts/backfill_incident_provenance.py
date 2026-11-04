#!/usr/bin/env python3
"""Backfill incident provenance from EVIDENCE ONLY.

Owner directive (2026-06): **never guess historical provenance.**

Every incident is classified by tracing a concrete artefact. An incident
whose origin cannot be established becomes `PROVENANCE_UNKNOWN` — it is
NOT filed as seeded, because inventing an answer is precisely the
failure this field exists to prevent.

    python3 scripts/backfill_incident_provenance.py --dry-run
    python3 scripts/backfill_incident_provenance.py --apply

`--relabel-unknown` re-runs the SAME evidence classification over
incidents already labelled `PROVENANCE_UNKNOWN`. It exists because P0-3
found a real defect — the canonical layer dropped the authenticated
sensor attribution, so incidents created from live sensor evidence were
born `PROVENANCE_UNKNOWN` while their own raw event proved otherwise.
Re-classification may only ever move an incident OFF unknown, never onto
it and never off any other label, and the previous label is recorded.
"""
from __future__ import annotations

import collections
import os
import sys

sys.path.insert(0, "/app/backend")
os.chdir("/app/backend")

from dotenv import load_dotenv                                # noqa: E402
load_dotenv("/app/backend/.env")

from pymongo import MongoClient                               # noqa: E402
from services import incident_provenance as prov              # noqa: E402


def main() -> int:
    apply = "--apply" in sys.argv
    if not apply and "--dry-run" not in sys.argv:
        print(__doc__)
        return 2

    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    col = db[prov.INCIDENTS]

    counts = collections.Counter()
    by_basis = collections.Counter()
    skipped = 0
    total = col.count_documents({})

    for doc in col.find({}, {"_id": 1, "id": 1, "doc_type": 1,
                             "xdr_pipeline": 1, "user_email": 1,
                             "provenance": 1}):
        existing = doc.get("provenance")
        if existing in prov.PROVENANCE_VALUES:
            relabel = ("--relabel-unknown" in sys.argv
                       and existing == prov.PROVENANCE_UNKNOWN)
            if not relabel:
                skipped += 1
                counts[f"already::{existing}"] += 1
                continue
            block = prov.classify_from_evidence(db, doc)
            if block["provenance"] == prov.PROVENANCE_UNKNOWN:
                skipped += 1
                counts["still_unknown_after_reclassification"] += 1
                continue
            block["provenance_previous"] = existing
            block["provenance_basis"] = (
                f"re-classified from {existing} on the same evidence rule "
                f"after the P0-3 canonical-attribution fix · "
                + block["provenance_basis"])
            counts[f"relabelled::{block['provenance']}"] += 1
            if apply:
                col.update_one({"_id": doc["_id"]}, {"$set": block})
            continue
        block = prov.classify_from_evidence(db, doc)
        counts[block["provenance"]] += 1
        by_basis[(doc.get("doc_type"), block["provenance"],
                  block["provenance_basis"][:70])] += 1
        if apply:
            col.update_one({"_id": doc["_id"]}, {"$set": block})

    print(f"\n{'APPLIED' if apply else 'DRY RUN'} · {total} documents in "
          f"{prov.INCIDENTS}\n")
    print("Classification:")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {v:6d}  {k}")
    print(f"  {skipped:6d}  already labelled (untouched)")

    print("\nRules that fired (doc_type · class · basis):")
    for (dt, cls, basis), v in by_basis.most_common(12):
        print(f"  {v:6d}  {dt} · {cls}\n          {basis}…")

    real = counts[prov.REAL_SENSOR_DERIVED]
    unknown = counts[prov.PROVENANCE_UNKNOWN]
    print(f"\n{'='*70}")
    print(f"REAL_SENSOR_DERIVED : {real}")
    print(f"PROVENANCE_UNKNOWN  : {unknown}   "
          f"(origin not establishable — NOT a claim of fabrication)")
    print(f"{'='*70}")
    if not apply:
        print("\nNothing written. Re-run with --apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
