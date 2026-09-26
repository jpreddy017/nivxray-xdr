#!/usr/bin/env python3
"""Seed a second EDR operator so exclusion APPROVAL can be exercised.

An exclusion may not be approved by the operator who created it (Gate 7,
`SELF_APPROVAL_REFUSED`), so proving the approval path requires two
principals. Idempotent.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, "/app/backend")
from dotenv import load_dotenv  # noqa: E402

load_dotenv("/app/backend/.env")
from pymongo import MongoClient  # noqa: E402
from deps import hash_password  # noqa: E402

EMAIL = "approver@nivxray.com"
PASSWORD = os.environ.get("NIVX_APPROVER_PASSWORD", "AppRoVe-Excl-2026-nvx")

db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
res = db.users.update_one(
    {"email": EMAIL},
    {"$setOnInsert": {"email": EMAIL, "password": hash_password(PASSWORD),
                      "role": "admin",
                      "created_at": datetime.now(timezone.utc).isoformat()}},
    upsert=True)
print(f"{EMAIL}: {'created' if res.upserted_id else 'already present'}")
