"""Durable delivery receipts · the permanent end of R5/R6-style recovery.

WHY THIS EXISTS
    HTTP success/failure alone cannot establish whether an endpoint event was
    durably committed and evidenced by the authoritative backend. R5 and R6
    proved that the expensive way: 3,334 identities had to be reconciled and
    accounted by hand because a 2xx (or a lost response) was the only thing
    the endpoint had ever recorded.

THE INVARIANT
    No delivery is DELIVERED until an authoritative backend disposition is
    durably evidenced AND locally verified.

This module owns three things and nothing else:

    1. the STABLE delivery identity (identical to the backend's
       `services.ingest_idempotency.event_identity`, so the endpoint can
       compute the key the server already claimed under, and a transport
       retry, a restart or a reconciliation never changes it);
    2. the RECEIPT contract — what an authoritative disposition must contain
       before it may be believed;
    3. VERIFICATION — tenant, collector and delivery identity must match the
       local row, and each authoritative disposition maps to exactly one
       local action. An unverifiable or ambiguous receipt never becomes
       success.

B4 TRUTH IS PRESERVED: `DELIVERED_CANONICAL` and `DELIVERED_RETAINED_RAW` are
both durable, and they are NOT the same fact. Retained raw is never collapsed
into canonical evidence.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

RECEIPT_CONTRACT = "nivx.delivery.receipt/1"

_IDENTITY_SEPARATOR = "\x1f"
_NO_SOURCE_EVENT_ID = "__no_source_event_id__"

# ── authoritative dispositions (server vocabulary) ───────────────────
DISPOSITION_CANONICAL = "DELIVERED_CANONICAL"
DISPOSITION_RETAINED = "DELIVERED_RETAINED_RAW"
DISPOSITION_TERMINAL_REFUSED = "TERMINAL_REFUSED"
DISPOSITION_TERMINAL_REVIEW = "TERMINAL_NEEDS_REVIEW"
DISPOSITION_IN_PROGRESS = "SERVER_IN_PROGRESS"
DISPOSITION_NO_EVIDENCE = "ACCOUNTED_WITHOUT_EVIDENCE"
DISPOSITION_NOT_FOUND = "NOT_FOUND"

# ── accounting buckets (identical to the server's) ───────────────────
BUCKET_CANONICAL = "DELIVERED_CANONICAL"
BUCKET_RETAINED = "DELIVERED_RETAINED_RAW"
BUCKET_OPEN = "RETRYABLE_STILL_QUEUED"
BUCKET_TERMINAL = "TERMINAL_ACCOUNTED"
BUCKET_UNEXPLAINED = "UNEXPLAINED"

# ── local actions a verified receipt authorises ──────────────────────
ACTION_DELIVERED = "DELIVERED"
ACTION_RETRYABLE = "RETRYABLE"
ACTION_TERMINAL = "TERMINAL_ACCOUNTED"
ACTION_UNKNOWN = "UNKNOWN_COMMIT_STATE"

#: What the endpoint knows about whether the backend may have committed.
COMMIT_NOT_SENT = "NOT_SENT"
COMMIT_CLAIMED = "COMMIT_CLAIMED"
COMMIT_UNKNOWN = "UNKNOWN"
COMMIT_TERMINAL_CLAIMED = "TERMINAL_CLAIMED"

BASIS_RECONCILIATION = "AUTHORITATIVE_RECONCILIATION"


class ReceiptVerificationError(Exception):
    """The disposition could not be proven to belong to this delivery.

    Raised instead of returning a result, because a receipt that cannot be
    bound to the expected tenant, collector and delivery identity must never
    be able to advance a local row.
    """


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def payload_digest(raw: Any) -> str:
    """The semantic event only — never the volatile transport fields."""
    return hashlib.sha256(
        json.dumps(raw if raw is not None else {}, sort_keys=True,
                   default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def delivery_key(*, tenant_id: str, collector_id: str, source: Optional[str],
                 source_event_id: Optional[str], raw: Any) -> str:
    """The stable delivery identity, byte-identical to the server's claim key.

    Deliberately derived only from what the endpoint already holds, so it
    survives a timeout, a retry, a process restart and a reconciliation
    without ever being re-issued.
    """
    material = _IDENTITY_SEPARATOR.join([
        str(tenant_id or ""), str(collector_id or ""), str(source or ""),
        str(source_event_id if source_event_id else _NO_SOURCE_EVENT_ID),
        payload_digest(raw),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def delivery_key_for_envelope(envelope: Any) -> str:
    """The identity of the delivery as it will actually be sent."""
    return delivery_key(tenant_id=envelope.tenant_id,
                        collector_id=envelope.collector_id,
                        source=envelope.source,
                        source_event_id=envelope.source_event_id,
                        raw=envelope.raw)


def identity_for(row: Any, key: str, *, collector_id: str) -> Dict[str, Any]:
    """The reconciliation identity of ONE local row."""
    return {
        "ref": row.id,
        "delivery_key": key,
        "source_event_id": row.source_event_id,
        "collector_id": collector_id,
        "connector_id": row.connector_id,
        "payload_digest": payload_digest(row.raw),
        "endpoint_outcome": row.status,
    }


def _action_for(disposition: str, evidence_ref: Optional[str],
                retained_raw_id: Optional[str]) -> tuple[str, str]:
    """(local action, why). Never guesses DELIVERED."""
    if disposition == DISPOSITION_CANONICAL:
        if not evidence_ref:
            return ACTION_UNKNOWN, ("the claim is terminal-successful but no "
                                    "canonical evidence reference resolved")
        return ACTION_DELIVERED, ("authoritative canonical evidence exists "
                                  "for this delivery identity")
    if disposition == DISPOSITION_RETAINED:
        if not retained_raw_id:
            return ACTION_UNKNOWN, ("a retained-raw disposition with no "
                                    "retained raw reference proves nothing")
        return ACTION_DELIVERED, ("refused before interpretation and retained "
                                  "verbatim under B4; durable, and NOT "
                                  "canonical evidence")
    if disposition in (DISPOSITION_TERMINAL_REFUSED,
                       DISPOSITION_TERMINAL_REVIEW):
        return ACTION_TERMINAL, ("the authoritative boundary refused or "
                                 "quarantined this delivery and kept the "
                                 "refusal as evidence")
    if disposition == DISPOSITION_NOT_FOUND:
        return ACTION_RETRYABLE, ("the authoritative plane holds no claim, no "
                                  "retained raw and no refusal for this "
                                  "identity: proven absence, so a retry "
                                  "cannot duplicate evidence")
    if disposition == DISPOSITION_IN_PROGRESS:
        return ACTION_UNKNOWN, ("the authoritative plane holds a live, "
                                "non-terminal claim; retrying it now would "
                                "race the commit it is waiting for")
    if disposition == DISPOSITION_NO_EVIDENCE:
        return ACTION_UNKNOWN, ("accounted without resolvable evidence; this "
                                "is exactly the UNEXPLAINED case that may "
                                "never be called delivered")
    return ACTION_UNKNOWN, (f"unrecognised authoritative disposition "
                            f"{disposition!r}")


def verify(*, row: Any, key: str, expected_collector: str,
           authority: Dict[str, Any], server_row: Dict[str, Any],
           surface: Optional[str] = None) -> Dict[str, Any]:
    """Bind one authoritative disposition to one local delivery, or refuse.

    Every mismatch is a hard failure: a receipt for another tenant, another
    collector or another delivery identity is never converted into success.
    """
    if not isinstance(server_row, dict):
        raise ReceiptVerificationError("the disposition is not an object")
    auth_tenant = (authority or {}).get("tenant_id")
    auth_collector = (authority or {}).get("collector_id")
    if auth_tenant != row.tenant_id:
        raise ReceiptVerificationError(
            f"receipt tenant {auth_tenant!r} is not this delivery's tenant "
            f"{row.tenant_id!r}")
    if auth_collector != expected_collector:
        raise ReceiptVerificationError(
            f"receipt collector {auth_collector!r} is not this endpoint's "
            f"collector {expected_collector!r}")
    if server_row.get("ref") != row.id:
        raise ReceiptVerificationError(
            f"receipt ref {server_row.get('ref')!r} is not local row "
            f"{row.id!r}")
    if server_row.get("delivery_key") != key:
        raise ReceiptVerificationError(
            "receipt delivery_key does not match the identity this delivery "
            "was sent under")
    row_collector = server_row.get("collector_id")
    if row_collector and row_collector != expected_collector:
        raise ReceiptVerificationError(
            f"receipt row collector {row_collector!r} is not "
            f"{expected_collector!r}")
    row_sei = server_row.get("source_event_id")
    if row_sei and row.source_event_id and row_sei != row.source_event_id:
        raise ReceiptVerificationError(
            "receipt source_event_id does not match the local row")

    disposition = str(server_row.get("disposition") or "")
    bucket = str(server_row.get("bucket") or "")
    if bucket and bucket not in (BUCKET_CANONICAL, BUCKET_RETAINED,
                                 BUCKET_OPEN, BUCKET_TERMINAL,
                                 BUCKET_UNEXPLAINED):
        raise ReceiptVerificationError(f"unknown accounting bucket {bucket!r}")

    claim = server_row.get("claim") or {}
    evidence_ref = server_row.get("evidence_ref")
    retained_raw_id = server_row.get("retained_raw_id")
    action, why = _action_for(disposition, evidence_ref, retained_raw_id)

    return {
        "contract": RECEIPT_CONTRACT,
        "basis": BASIS_RECONCILIATION,
        "authority": {
            "surface": surface,
            "tenant_id": auth_tenant,
            "collector_id": auth_collector,
            "at": (authority or {}).get("at"),
            "read_only": True,
        },
        "delivery_key": key,
        "ref": row.id,
        "source_event_id": row.source_event_id,
        "connector_id": row.connector_id,
        "disposition": disposition,
        "bucket": bucket,
        "bucket_basis": server_row.get("bucket_basis"),
        "matched_by": server_row.get("matched_by"),
        #: B4 · durable does NOT mean canonical.
        "canonical": disposition == DISPOSITION_CANONICAL,
        "retained_raw": disposition == DISPOSITION_RETAINED,
        "evidence_ref": evidence_ref,
        "canonical_event_id": claim.get("canonical_event_id"),
        "retained_raw_id": retained_raw_id,
        "retained_raw_reason": server_row.get("retained_raw_reason"),
        "claim": {
            "status": claim.get("status"),
            "stage": claim.get("stage"),
            "trace_id": claim.get("trace_id"),
            "delivery_count": claim.get("delivery_count"),
            "duplicate_count": claim.get("duplicate_count"),
            "raw_row_id": claim.get("raw_row_id"),
            "review_reason": claim.get("review_reason"),
        },
        "routing_block": server_row.get("routing_block"),
        "local_action": action,
        "local_action_basis": why,
        "verified_at": _now(),
    }


def load(raw_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw_json:
        return None
    try:
        doc = json.loads(raw_json)
    except (TypeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def is_verified_delivery(receipt: Optional[Dict[str, Any]]) -> bool:
    """A local `delivered` is only legitimate with one of these behind it."""
    if not isinstance(receipt, dict):
        return False
    return (receipt.get("contract") == RECEIPT_CONTRACT
            and receipt.get("local_action") == ACTION_DELIVERED
            and receipt.get("disposition") in (DISPOSITION_CANONICAL,
                                               DISPOSITION_RETAINED)
            and bool(receipt.get("delivery_key")))


def dispositions(receipts: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {BUCKET_CANONICAL: 0, BUCKET_RETAINED: 0, BUCKET_OPEN: 0,
           BUCKET_TERMINAL: 0, BUCKET_UNEXPLAINED: 0}
    for receipt in receipts:
        bucket = receipt.get("bucket")
        if bucket in out:
            out[bucket] += 1
    return out
