#!/usr/bin/env python3
"""Sample1 sanity check — READ-ONLY governance gate before Phase 5.1.

Usage (on the Sample1-hosting pod ONLY):
    python /app/backend/tools/sample1_sanity_check.py

Owner directive 2026-08-10:
  - Runs only against the pod that hosts the frozen Sample1 case row.
  - Verifies:
      1. Sample1 case row exists (workspace_cases.id == expected).
      2. Frozen fingerprint matches
         5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d.
      3. verdict_shadow_observations count == 2 (Wave 1 baseline).
      4. Absolutely NO writes are performed.

Exit code:
    0 → GREEN     · all invariants hold; Phase 5.1 A4.2 gate satisfied
    1 → DRIFT     · Sample1 row present but at least one invariant failed
    2 → SKIP      · Sample1 row absent — this is not the Sample1-hosting pod
    3 → ERROR     · MONGO_URL / DB_NAME unset, or connection failure
"""
from __future__ import annotations

import json
import hashlib
import os
import sys


EXPECTED_CASE_ID     = "3db79c4a-088b-4df7-b65a-f68b367b7677"
EXPECTED_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"
EXPECTED_WAVE1_COUNT = 2


GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
RST   = "\033[0m"


def _load_env_if_needed() -> None:
    if os.environ.get("MONGO_URL") and os.environ.get("DB_NAME"):
        return
    try:
        from dotenv import load_dotenv
        for candidate in ("/app/backend/.env", "/app/.env"):
            if os.path.exists(candidate):
                load_dotenv(candidate)
    except ImportError:
        pass


def main() -> int:
    _load_env_if_needed()
    mongo_url = os.environ.get("MONGO_URL")
    db_name   = os.environ.get("DB_NAME")
    if not mongo_url or not db_name:
        print(f"{RED}ERROR{RST} · MONGO_URL / DB_NAME unset")
        return 3

    try:
        from pymongo import MongoClient
    except ImportError:
        print(f"{RED}ERROR{RST} · pymongo not available in this Python env")
        return 3

    try:
        # Read-only client is enforced by CONVENTION here — we call ONLY
        # find_one() and count_documents(). No writes. The connection is
        # closed immediately after the reads finish.
        client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
        db     = client[db_name]
    except Exception as exc:                                          # noqa: BLE001
        print(f"{RED}ERROR{RST} · MongoDB connection failed: {exc}")
        return 3

    # ── Read #1 · Sample1 case row ────────────────────────────────────
    case = db.workspace_cases.find_one({"id": EXPECTED_CASE_ID})
    if case is None:
        print(f"{YEL}SKIP{RST}  · Sample1 case {EXPECTED_CASE_ID!r} not "
              f"present in this pod's database ({db_name!r})")
        print(f"        This pod is not the Sample1-hosting pod. No action "
              f"taken. Exit=2.")
        client.close()
        return 2

    # ── Read #2 · Fingerprint (deterministic canonical-JSON sha256) ───
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                      ensure_ascii=False).encode()
    fingerprint = hashlib.sha256(blob).hexdigest()

    # ── Read #3 · Wave 1 count ────────────────────────────────────────
    wave1_count = db.verdict_shadow_observations.count_documents({})
    client.close()

    # ── Report ────────────────────────────────────────────────────────
    checks = []
    checks.append(("Sample1 row exists",           True))
    checks.append(("Frozen fingerprint matches",   fingerprint == EXPECTED_FINGERPRINT))
    checks.append(("Wave 1 record count == 2",     wave1_count == EXPECTED_WAVE1_COUNT))

    print("─" * 66)
    print(f"Sample1 sanity check · READ-ONLY · pod DB = {db_name!r}")
    print("─" * 66)
    print(f"  Case id        : {EXPECTED_CASE_ID}")
    print(f"  Expected fp    : {EXPECTED_FINGERPRINT}")
    print(f"  Observed fp    : {fingerprint}")
    print(f"  Wave 1 count   : {wave1_count} (expected {EXPECTED_WAVE1_COUNT})")
    print("─" * 66)
    for label, ok in checks:
        mark = f"{GREEN}✓{RST}" if ok else f"{RED}✗{RST}"
        print(f"  {mark}  {label}")
    print("─" * 66)

    all_green = all(ok for _label, ok in checks)
    if all_green:
        print(f"{GREEN}GREEN{RST} · A4.2 gate satisfied · Phase 5.1 authorised "
              f"pending owner sign-off")
        return 0
    print(f"{RED}DRIFT{RST} · Sample1 invariant broken · HALT · do NOT "
          f"authorise Phase 5.1")
    return 1


if __name__ == "__main__":
    sys.exit(main())
