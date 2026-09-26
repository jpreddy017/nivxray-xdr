"""One-shot backfill: for every workspace_case where the flat `confidence`
field is 0 (or missing) but `verdict_card.confidence` holds a real value,
sync the flat field to match the card. Purely additive — never lowers a
confidence, never overwrites when the card is absent.

Run once against Preview / Production:

    cd /app/backend && set -a && source .env && set +a && \
      python /app/scripts/rc454_backfill_case_confidence.py

Exits 0 on success. Idempotent.
"""
from __future__ import annotations
import os
import sys
from datetime import datetime, timezone

from pymongo import MongoClient


def main() -> int:
    mongo_url = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")
    if not mongo_url or not db_name:
        print("ERROR: MONGO_URL and DB_NAME must be set in the environment.")
        return 1

    client = MongoClient(mongo_url)
    col = client[db_name].workspace_cases

    total = col.count_documents({})
    scanned = 0
    updated = 0
    skipped = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for doc in col.find({}, {"id": 1, "confidence": 1, "verdict_card": 1, "name": 1}):
        scanned += 1
        flat = doc.get("confidence")
        card = (doc.get("verdict_card") or {}).get("confidence")

        # Only backfill when the card has a real numeric value AND
        # the flat field is 0/None/missing (never overwrite a real value).
        if card is None:
            skipped += 1
            continue
        try:
            card_num = float(card)
        except (TypeError, ValueError):
            skipped += 1
            continue

        flat_num = 0.0
        if flat is not None:
            try:
                flat_num = float(flat)
            except (TypeError, ValueError):
                flat_num = 0.0

        # Skip cases where flat >= card (nothing to do, or card is stale)
        if flat_num >= card_num:
            skipped += 1
            continue

        col.update_one(
            {"id": doc["id"]},
            {"$set": {"confidence": card_num, "confidence_backfilled_at": now_iso}},
        )
        updated += 1
        print(f"  · {doc.get('name'):40s}  {flat_num:>6.1f}  →  {card_num:>6.1f}")

    print(f"\nScanned:  {scanned}/{total}")
    print(f"Updated:  {updated}")
    print(f"Skipped:  {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
