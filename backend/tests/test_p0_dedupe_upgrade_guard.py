"""Upgrade guard: claims written by the pre-hardening version stay terminal.

The first dedupe implementation marked success as `status="PROCESSED"` and had
no `lease_expires_at` / `retention_at` fields.  After the hardening rewrite
such a record must NOT be re-claimable (a retry would duplicate the chain) and
must NOT be immortal (it would never be TTL'd).
"""
from __future__ import annotations

import os
import uuid

from pymongo import MongoClient

os.environ.setdefault("DB_NAME", "test_database")

from services import ingest_idempotency as idem  # noqa: E402

_claims = MongoClient(os.environ["MONGO_URL"])[
    os.environ["DB_NAME"]][idem.COLLECTION]


def _legacy(**over):
    ident = idem.event_identity("legacy-tenant", "col_legacy", "fw",
                                f"legacy-{uuid.uuid4().hex[:8]}", {"a": 1})
    doc = {**ident, "status": "PROCESSED", "delivery_count": 1,
           "trace_id": "live_legacy", "incident_id": "inc_legacy",
           "canonical_event_id": "cev_legacy"}
    doc.update(over)
    _claims.insert_one(dict(doc))
    return ident


def test_legacy_processed_claim_is_treated_as_a_duplicate():
    ident = _legacy()
    try:
        state, rec = idem.claim(ident)
        assert state == "DUPLICATE", (
            "a pre-hardening completed claim became re-claimable — a retry "
            "would duplicate the chain")
        assert rec["incident_id"] == "inc_legacy"
    finally:
        _claims.delete_one({"key": ident["key"]})


def test_legacy_claim_gets_retention_armed_on_first_contact():
    ident = _legacy()
    try:
        assert _claims.find_one({"key": ident["key"]}).get("retention_at") is None
        idem.claim(ident)
        assert _claims.find_one({"key": ident["key"]})["retention_at"] is not None
    finally:
        _claims.delete_one({"key": ident["key"]})


def test_non_terminal_claim_without_a_lease_cannot_deadlock_in_flight():
    """A malformed/legacy in-progress record must be recoverable rather than
    permanently reported as IN_FLIGHT."""
    ident = _legacy(status="CLAIMED", stage="NONE")
    try:
        state, _ = idem.claim(ident)
        assert state == "RESUME_FULL"
    finally:
        _claims.delete_one({"key": ident["key"]})


def test_terminal_states_include_the_legacy_marker():
    assert "PROCESSED" in idem.TERMINAL
    assert "COMPLETED" in idem.TERMINAL
    assert "NEEDS_REVIEW" in idem.TERMINAL
