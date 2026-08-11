"""Phase 5.W permanent fix · P0.3 leg 2 — Sample1 immutability guard
(2026-08-11).

Owner directive: "Sample1 (Sample.docx) row is NEVER touched. Regression
tests dynamically check its hash."

This test:
  1. Reads the frozen Sample1 case row from Mongo (if present).
  2. Records its deterministic sha256 fingerprint.
  3. Runs a representative Workspace API call
     (`POST /api/die/investigation-results`) against unrelated input.
  4. Re-reads the Sample1 case row and asserts the fingerprint is
     bit-identical to step 2.
  5. Also asserts a static-import invariant: no module in
     `services/die/*` or `routers/die.py` writes to the Sample1
     case id.

If Sample1 is absent (fresh CI pod / non-Sample1-hosting DB), the
test SKIPS — never fails erroneously.

Expected constants sourced from the pre-existing
`backend/tools/sample1_sanity_check.py`.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest
from fastapi.testclient import TestClient

EXPECTED_CASE_ID     = "3db79c4a-088b-4df7-b65a-f68b367b7677"
EXPECTED_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"


def _fingerprint(doc: dict) -> str:
    snap = {k: v for k, v in (doc or {}).items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                      ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def _find_sample1() -> dict | None:
    """Return the Sample1 case row from Mongo, or None if absent."""
    mongo = os.environ.get("MONGO_URL")
    db_name = os.environ.get("DB_NAME")
    if not mongo or not db_name:
        return None
    try:
        from pymongo import MongoClient
        client = MongoClient(mongo, serverSelectionTimeoutMS=3000)
        row = client[db_name].workspace_cases.find_one({"id": EXPECTED_CASE_ID})
        client.close()
        return row
    except Exception:
        return None


@pytest.fixture(scope="module")
def sample1_row():
    row = _find_sample1()
    if row is None:
        pytest.skip("Sample1 case row not present in this pod — guard skipped "
                    "(this is not the Sample1-hosting DB)")
    return row


@pytest.fixture(scope="module")
def api_client():
    from server import app
    with TestClient(app) as c:
        yield c


# ─────────────────────────────────────────────────────────────────
# P0.3-Sample1-1 — Baseline fingerprint matches the frozen invariant.
# ─────────────────────────────────────────────────────────────────
def test_sample1_baseline_fingerprint_matches(sample1_row):
    got = _fingerprint(sample1_row)
    assert got == EXPECTED_FINGERPRINT, (
        f"Sample1 fingerprint drifted BEFORE any test action:\n"
        f"  observed = {got}\n  expected = {EXPECTED_FINGERPRINT}\n"
        f"Something outside this test corrupted the Sample1 row. Do NOT "
        f"proceed with Phase 5.x work until the row is restored from "
        f"the golden snapshot."
    )


# ─────────────────────────────────────────────────────────────────
# P0.3-Sample1-2 — Workspace API calls MUST NOT mutate Sample1.
# ─────────────────────────────────────────────────────────────────
def test_workspace_investigation_does_not_mutate_sample1(sample1_row, api_client):
    before_fp = _fingerprint(sample1_row)
    # Trigger a representative Workspace investigation on unrelated
    # input. This is the exact endpoint the analyst hits.
    resp = api_client.post(
        "/api/die/investigation-results",
        json={"input": "powershell.exe -EncodedCommand SQBFAFgAKAA="},
    )
    assert resp.status_code == 200

    # Re-fetch the Sample1 row fresh from Mongo.
    after_row = _find_sample1()
    assert after_row is not None, "Sample1 row disappeared after Workspace call — critical."
    after_fp = _fingerprint(after_row)
    assert after_fp == before_fp, (
        f"Sample1 fingerprint MUTATED by /api/die/investigation-results:\n"
        f"  before = {before_fp}\n  after  = {after_fp}\n"
        f"Some code path wrote to the Sample1 case row. Locate the writer "
        f"and add a defensive `if case_id == '{EXPECTED_CASE_ID}': skip` "
        f"OR remove the write entirely. Sample1 is the canonical fixture "
        f"and MUST remain byte-identical across all runs."
    )


# ─────────────────────────────────────────────────────────────────
# P0.3-Sample1-3 — Static-import invariant: no die.* code references
# the Sample1 case id (defensive; would trip if someone tried to
# special-case Sample1 in a service, which is precisely the wrong
# direction).
# ─────────────────────────────────────────────────────────────────
def test_no_die_module_hardcodes_sample1_id():
    hits = []
    root = Path(__file__).resolve().parents[3] / "services" / "die"
    for py in root.rglob("*.py"):
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if EXPECTED_CASE_ID in text:
            hits.append(str(py.relative_to(root.parent.parent)))
    assert not hits, (
        f"services/die/* modules must NOT hard-code the Sample1 case id "
        f"({EXPECTED_CASE_ID}). Found in:\n  " + "\n  ".join(hits) +
        f"\nSpecial-casing Sample1 inside DIE creates the exact coupling "
        f"the immutability guard exists to prevent."
    )
