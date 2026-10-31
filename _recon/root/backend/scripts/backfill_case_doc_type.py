"""P0-1 · Deterministic `doc_type` backfill for `workspace_cases`.

Owner constraints (2026-09-05), enforced by this script:
  * NO migration between stores.  This writes a single additive field.
  * NO deletion, NO merging, NO re-keying.  `id` namespace untouched.
  * Ambiguous documents are NOT blindly backfilled.  By default they are
    left completely untouched and reported.  Marking them explicitly as
    `unclassified` requires the separate `--mark-unclassified` flag.
  * Idempotent: re-running changes nothing once applied.

Usage:
    python3 -m scripts.backfill_case_doc_type                      # dry run
    python3 -m scripts.backfill_case_doc_type --apply              # write
    python3 -m scripts.backfill_case_doc_type --apply --mark-unclassified
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402
from pymongo import MongoClient  # noqa: E402

from case_doc_type import (  # noqa: E402
    DOC_TYPE_FIELD,
    DOC_TYPE_REASON_FIELD,
    DOC_TYPE_UNCLASSIFIED,
    classify,
)

COLLECTION = "workspace_cases"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="write changes (default is dry-run)")
    ap.add_argument("--mark-unclassified", action="store_true",
                    help="also stamp ambiguous docs as doc_type=unclassified "
                         "with an explicit reason (opt-in)")
    args = ap.parse_args()

    load_dotenv(os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))), ".env"))
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    col = db[COLLECTION]

    report: dict = {
        "collection": COLLECTION,
        "mode": "APPLY" if args.apply else "DRY_RUN",
        "mark_unclassified": args.mark_unclassified,
        "before": {
            "total": col.count_documents({}),
            "with_doc_type": col.count_documents(
                {DOC_TYPE_FIELD: {"$exists": True}}),
        },
        "classification": {},
        "by_rule": {},
        "ambiguous_ids": [],
        "written": 0,
        "skipped_already_correct": 0,
        "skipped_ambiguous": 0,
        "conflicts": [],
    }

    types = Counter()
    rules = Counter()

    for doc in col.find({}, {"_id": 1, "id": 1, "xdr_pipeline": 1,
                             "ssot": 1, "input": 1, DOC_TYPE_FIELD: 1}):
        doc_type, rule = classify(doc)
        types[doc_type] += 1
        rules[rule] += 1

        if doc_type == DOC_TYPE_UNCLASSIFIED:
            report["ambiguous_ids"].append(doc.get("id"))
            if not args.mark_unclassified:
                report["skipped_ambiguous"] += 1
                continue

        existing = doc.get(DOC_TYPE_FIELD)
        if existing == doc_type:
            report["skipped_already_correct"] += 1
            continue
        if existing and existing != doc_type:
            report["conflicts"].append(
                {"id": doc.get("id"), "existing": existing,
                 "computed": doc_type, "rule": rule})
            continue

        if args.apply:
            update = {DOC_TYPE_FIELD: doc_type}
            if doc_type == DOC_TYPE_UNCLASSIFIED:
                update[DOC_TYPE_REASON_FIELD] = (
                    "no discriminating field (xdr_pipeline / ssot / input) — "
                    "classification withheld, not guessed")
            col.update_one({"_id": doc["_id"]}, {"$set": update})
        report["written"] += 1

    report["classification"] = dict(types)
    report["by_rule"] = dict(rules)
    report["after"] = {
        "total": col.count_documents({}),
        "with_doc_type": col.count_documents(
            {DOC_TYPE_FIELD: {"$exists": True}}),
        "xdr_incident": col.count_documents({DOC_TYPE_FIELD: "xdr_incident"}),
        "analysis_case": col.count_documents({DOC_TYPE_FIELD: "analysis_case"}),
        "unclassified": col.count_documents(
            {DOC_TYPE_FIELD: DOC_TYPE_UNCLASSIFIED}),
        "without_doc_type": col.count_documents(
            {DOC_TYPE_FIELD: {"$exists": False}}),
    }
    report["invariants"] = {
        "sum_matches_total":
            sum(types.values()) == report["before"]["total"],
        "id_namespace_untouched": True,
        "no_documents_deleted":
            report["after"]["total"] == report["before"]["total"],
    }

    json.dump(report, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
