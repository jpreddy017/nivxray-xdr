"""Idempotent Sample1 golden-case seeder.

The frozen Sample1 case (id ``3db79c4a-088b-4df7-b65a-f68b367b7677``) is
the architectural canary for the canonical investigation lifecycle.  Its
byte-identical fingerprint (sha256 of persisted doc, `_id` excluded) is
locked in three canonical tests:

  - tests/canonical/iue/test_composer_sample_acceptance.py::test_a1_2
  - tests/canonical/ssot/test_ssot_sample_acceptance.py::test_a2_3
  - tests/canonical/executor/test_executor_all.py::test_a3_3

A snapshot of the raw MongoDB document lives at
``/app/memory/GOLDEN_CASE_SAMPLE1.snapshot.json`` (79 903 bytes,
committed).  This module loads that snapshot into MongoDB on startup
whenever the case is absent — idempotent, deterministic, byte-for-byte.

Guardrails (owner-locked):
  - NEVER overwrite an existing Sample1 case.
  - NEVER mutate the persisted document after insert.
  - NEVER seed if the snapshot file has been tampered (fingerprint
    verification is a HARD REQUIREMENT before insert).
  - Zero side effects when the case is already present.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

SAMPLE1_CASE_ID = "3db79c4a-088b-4df7-b65a-f68b367b7677"
SAMPLE1_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"
SAMPLE1_SNAPSHOT_PATH = "/app/memory/GOLDEN_CASE_SAMPLE1.snapshot.json"


def _fingerprint(doc: dict) -> str:
    """Compute the canonical fingerprint used by the acceptance tests."""
    snap = {k: v for k, v in doc.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                       ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def _load_snapshot() -> Optional[dict]:
    """Load and fingerprint-verify the on-disk snapshot.

    Returns the parsed document only if its fingerprint matches the
    locked golden value.  Any drift returns None and logs a warning —
    seeding is refused rather than corrupting the golden canary.
    """
    p = Path(SAMPLE1_SNAPSHOT_PATH)
    if not p.exists():
        log.warning("Sample1 snapshot not found at %s — seed skipped",
                     SAMPLE1_SNAPSHOT_PATH)
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        log.warning("Sample1 snapshot unreadable (%s) — seed skipped", e)
        return None
    if not isinstance(doc, dict) or doc.get("id") != SAMPLE1_CASE_ID:
        log.warning("Sample1 snapshot id mismatch — seed skipped")
        return None
    fp = _fingerprint(doc)
    if fp != SAMPLE1_FINGERPRINT:
        log.warning(
            "Sample1 snapshot fingerprint drift: %s != %s — seed refused",
            fp, SAMPLE1_FINGERPRINT,
        )
        return None
    return doc


def seed_sample1_if_missing(db) -> str:
    """Seed the Sample1 golden case into ``workspace_cases`` when it is
    absent.  Returns one of {"absent_snapshot", "already_present",
    "seeded", "verify_failed"}.  Never raises.
    """
    try:
        existing = db.workspace_cases.find_one({"id": SAMPLE1_CASE_ID})
    except Exception as e:
        log.warning("Sample1 seed: mongo query failed (%s)", e)
        return "verify_failed"
    if existing is not None:
        return "already_present"
    doc = _load_snapshot()
    if doc is None:
        return "absent_snapshot"
    try:
        db.workspace_cases.insert_one(doc)
    except Exception as e:
        log.warning("Sample1 seed: insert failed (%s)", e)
        return "verify_failed"
    log.info("Sample1 golden case seeded (fingerprint=%s)", SAMPLE1_FINGERPRINT)
    return "seeded"


__all__ = ["seed_sample1_if_missing", "SAMPLE1_CASE_ID",
             "SAMPLE1_FINGERPRINT", "SAMPLE1_SNAPSHOT_PATH"]
