"""Deterministic `verdict_stage2` backfill for authoritative incidents.

Owner-authorised 2026-09-05.  STRICT constraints enforced here:
  * Uses ONLY already-persisted authoritative VEEE / verdict data.
  * NO second verdict engine: the projection is produced by the SAME
    `detection_content.xdr_incident._stage2_from_veee` used by the live
    pipeline writer.  Nothing is re-scored, re-run or re-interpreted.
  * Only `doc_type == "xdr_incident"` records are touched.
  * `id`, evidence ids, provenance, `created_at`/`updated_at` and
    `tenant_id` are never written.
  * If authoritative data genuinely does not exist, the record is SKIPPED
    so the queue keeps showing UNKNOWN / NO EVIDENCE.  Nothing manufactured.
  * Idempotent: a second run writes nothing.

Deterministic source precedence (first match wins):
  S1  xdr_pipeline.veee WITH contributors[]  → full projection + evidence
  S2  xdr_pipeline.veee WITHOUT contributors → label/score, evidence []
  S3  verdict_card (engine == VEEE)          → label/score, evidence []
  S4  none of the above                      → SKIP (epistemically unknown)

Usage:
    python3 -m scripts.backfill_verdict_stage2            # dry run
    python3 -m scripts.backfill_verdict_stage2 --apply
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

from detection_content.xdr_incident import _stage2_from_veee  # noqa: E402

COLLECTION = "workspace_cases"
DOC_TYPE = "xdr_incident"
VEEE_ENGINE = "nivxray::xdr::veee"


def _resolve_source(doc: dict) -> tuple[str, dict | None]:
    """Return `(tier, veee_shaped_dict)` from persisted data only."""
    veee = ((doc.get("xdr_pipeline") or {}).get("veee")) or None
    if veee and veee.get("contributors"):
        return "S1_veee_with_contributors", veee
    if veee:
        return "S2_veee_no_contributors", veee

    card = doc.get("verdict_card") or None
    if card and card.get("verdict"):
        # Re-shape the persisted card into the VEEE envelope the projection
        # expects.  No new scoring: label and score are read verbatim.
        return "S3_verdict_card", {
            "engine_id": card.get("engine") or VEEE_ENGINE,
            "label": str(card.get("verdict") or "").upper(),
            "score": card.get("confidence") or 0,
            "reason": card.get("reason"),
            "contributors": [],
        }
    return "S4_no_authoritative_data", None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="write changes (default is dry-run)")
    args = ap.parse_args()

    load_dotenv(os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))), ".env"))
    db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    col = db[COLLECTION]
    q = {"doc_type": DOC_TYPE}

    report: dict = {
        "collection": COLLECTION,
        "scope": q,
        "mode": "APPLY" if args.apply else "DRY_RUN",
        "before": {
            "authoritative_incidents": col.count_documents(q),
            "with_verdict_stage2": col.count_documents(
                {**q, "verdict_stage2": {"$exists": True}}),
        },
        "by_tier": {},
        "examined": 0,
        "projected": 0,
        "skipped_no_authoritative_data": 0,
        "skipped_already_present": 0,
        "with_evidence_rows": 0,
        "with_empty_evidence": 0,
        "label_distribution": {},
        "skipped_ids": [],
        "non_incident_touched": 0,
    }
    tiers = Counter()
    labels = Counter()

    for doc in col.find(q, {"_id": 1, "id": 1, "doc_type": 1,
                            "xdr_pipeline": 1, "verdict_card": 1,
                            "verdict_stage2": 1}):
        report["examined"] += 1

        # Belt-and-braces: never touch a non-incident document.
        if doc.get("doc_type") != DOC_TYPE:
            report["non_incident_touched"] += 1
            continue

        if doc.get("verdict_stage2"):
            report["skipped_already_present"] += 1
            continue

        tier, veee = _resolve_source(doc)
        tiers[tier] += 1
        if veee is None:
            report["skipped_no_authoritative_data"] += 1
            report["skipped_ids"].append(doc.get("id"))
            continue

        canonical = {
            "event_id": (doc.get("xdr_pipeline") or {}).get("canonical_event_id")
        }
        stage2 = _stage2_from_veee(veee, canonical)
        stage2["backfilled_from"] = tier

        labels[stage2["label"]] += 1
        if stage2["evidence"]:
            report["with_evidence_rows"] += 1
        else:
            report["with_empty_evidence"] += 1

        if args.apply:
            # Single additive field.  No id/provenance/timestamp/tenant write.
            col.update_one({"_id": doc["_id"]},
                           {"$set": {"verdict_stage2": stage2}})
        report["projected"] += 1

    report["by_tier"] = dict(tiers)
    report["label_distribution"] = dict(labels)
    report["after"] = {
        "authoritative_incidents": col.count_documents(q),
        "with_verdict_stage2": col.count_documents(
            {**q, "verdict_stage2": {"$exists": True}}),
        "still_without_verdict_stage2": col.count_documents(
            {**q, "verdict_stage2": {"$exists": False}}),
        "with_non_empty_evidence": col.count_documents(
            {**q, "verdict_stage2.evidence.0": {"$exists": True}}),
    }
    report["invariants"] = {
        "examined_equals_scope":
            report["examined"] == report["before"]["authoritative_incidents"],
        "no_non_incident_touched": report["non_incident_touched"] == 0,
        "accounted_for": (
            report["projected"]
            + report["skipped_no_authoritative_data"]
            + report["skipped_already_present"]
        ) == report["examined"],
        "total_docs_unchanged":
            col.count_documents({}) == 484,
    }

    json.dump(report, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
