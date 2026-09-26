"""G1-R5 · Delivery reconciliation — server-side accounting for a drained delivery.

The collector can only ever prove that the destination answered HTTP 2xx for a
batch. That is NOT proof that the authoritative plane accounted for the
envelope: inside one accepted batch an individual delivery can still be
refused by routing (D15), retained as raw forensic evidence (B4), suppressed as
a duplicate, or left mid-flight by an incomplete reasoning pass. Treating HTTP
acceptance as canonical ingestion is exactly the class of silent loss the G1
arc exists to end.

This module answers ONE question per delivery, from records that already exist:

    for this collector delivery identity, what did the authoritative plane
    actually do with it?

It is strictly READ-ONLY. It creates no authority, writes nothing, and
recomputes no decision. Every fact comes from a store the ingest boundary
already wrote:

    xdr_ingest_dedupe          the per-delivery idempotency claim (authority on
                               whether the delivery was processed at all)
    xdr_canonical_events       the raw row a processed delivery produced
    xdr_canonical_evidence     the canonical evidence a processed delivery
                               produced
    xdr_ingest_routing_blocks  the refusal record of a blocked delivery
    xdr_ingest_raw_retained    B4 raw forensic retention for an authorized
                               delivery refused before interpretation

Identity: the claim key is `services.ingest_idempotency.event_identity`, which
is derived only from fields the collector itself holds
(`tenant_id | collector_id | source | source_event_id | sha256(raw)`), so the
endpoint can compute the same key without this service handing one out. When a
caller cannot supply the key, the claim is still located by the identity TUPLE
(`collector_id + source_event_id [+ payload_digest]`) it was written with, and
the response states which basis matched — never a guess.

Tenant authority is the CALLER's, passed in as an explicit scope. A record
outside that scope is reported as not found; it is never described, counted or
leaked.
"""
from __future__ import annotations

from typing import Any

DEDUPE_COLLECTION = "xdr_ingest_dedupe"
RAW_COLLECTION = "xdr_canonical_events"
EVIDENCE_COLLECTION = "xdr_canonical_evidence"
BLOCKS_COLLECTION = "xdr_ingest_routing_blocks"
RETAINED_COLLECTION = "xdr_ingest_raw_retained"

#: One bounded request. A reconciliation is per-batch evidence, not a bulk
#: export surface.
MAX_IDENTITIES = 500

#: The owner-declared accounting buckets. Every attempted delivery lands in
#: exactly one of them, and `UNEXPLAINED` must be zero for a PASS.
BUCKET_CANONICAL = "DELIVERED_CANONICAL"
BUCKET_RETAINED = "DELIVERED_RETAINED_RAW"
BUCKET_OPEN = "RETRYABLE_STILL_QUEUED"
BUCKET_TERMINAL = "TERMINAL_ACCOUNTED"
BUCKET_UNEXPLAINED = "UNEXPLAINED"

BUCKETS = (BUCKET_CANONICAL, BUCKET_RETAINED, BUCKET_OPEN,
           BUCKET_TERMINAL, BUCKET_UNEXPLAINED)

#: Endpoint-side dispositions that assert the destination accepted the row.
_ENDPOINT_CLAIMS_SUCCESS = ("delivered",)
#: Endpoint-side dispositions that are still in the retry/queue machinery.
#: `unknown_commit_state` belongs here: the endpoint dispatched the delivery
#: and never learned the outcome, so if the authoritative plane holds no
#: claim, no retained raw and no refusal for the identity, the delivery
#: genuinely never landed and a retry cannot duplicate evidence. Calling that
#: UNEXPLAINED would mislabel the one case the durable receipt protocol exists
#: to resolve.
_ENDPOINT_STILL_OPEN = ("queued", "retrying", "delivering", "received",
                        "unknown_commit_state")

_TERMINAL_CLAIM_OK = ("COMPLETED", "PROCESSED")

_READ_ONLY_NOTE = (
    "read-only reconciliation over records written by the authenticated "
    "ingest boundary; this surface writes nothing and re-decides nothing")

_INDEXED = False


def ensure_indexes(db) -> None:
    """Indexes reconciliation depends on to stay a bounded-cost read.

    Without `event_id` on the evidence collection, resolving one delivery
    costs a full collection scan (measured: 195,666 documents examined,
    182 ms per lookup), so a 450-identity batch took 35 s and was cut off by
    the server timeout. These indexes are what make the same answer cheap;
    none of them changes a result.
    """
    global _INDEXED
    if _INDEXED:
        return
    db[EVIDENCE_COLLECTION].create_index([("event_id", 1)])
    db[EVIDENCE_COLLECTION].create_index([("tenant_id", 1), ("event_id", 1)])
    db[DEDUPE_COLLECTION].create_index(
        [("tenant_id", 1), ("source_event_id", 1), ("collector_id", 1)])
    db[RETAINED_COLLECTION].create_index(
        [("tenant_id", 1), ("retained_identity_key", 1)])
    db[BLOCKS_COLLECTION].create_index(
        [("tenant_id", 1), ("source_event_id", 1)])
    _INDEXED = True


class ReconciliationRequestInvalid(ValueError):
    """The reconciliation request cannot be answered as asked."""


def _scope_query(tenant_ids: list[str] | None) -> dict[str, Any]:
    """`None` means an explicit cross-tenant scope; a list is fail-closed."""
    if tenant_ids is None:
        return {}
    if not tenant_ids:
        return {"tenant_id": {"$in": []}}
    return {"tenant_id": {"$in": list(tenant_ids)}}


def _norm_endpoint_outcome(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text or "unknown"


def _evidence_ref(event_id: Any) -> str | None:
    return f"{EVIDENCE_COLLECTION}/{event_id}" if event_id else None


def _load_claims(db, scope: dict[str, Any], identities: list[dict[str, Any]]
                 ) -> tuple[dict[str, Any], dict[Any, Any]]:
    """One query by delivery key, one for the tuple fallback."""
    keys = {i["delivery_key"] for i in identities if i.get("delivery_key")}
    by_key: dict[str, Any] = {}
    if keys:
        for doc in db[DEDUPE_COLLECTION].find({**scope,
                                               "key": {"$in": list(keys)}}):
            by_key[doc.get("key")] = doc

    fallback = [i for i in identities
                if i.get("source_event_id") and i.get("collector_id")
                and not by_key.get(i.get("delivery_key"))]
    by_tuple: dict[Any, Any] = {}
    if fallback:
        seis = {i["source_event_id"] for i in fallback}
        cids = {i["collector_id"] for i in fallback}
        for doc in db[DEDUPE_COLLECTION].find(
                {**scope, "source_event_id": {"$in": list(seis)},
                 "collector_id": {"$in": list(cids)}}):
            cid, sei = doc.get("collector_id"), doc.get("source_event_id")
            by_tuple.setdefault((cid, sei, doc.get("payload_digest")), doc)
            by_tuple.setdefault((cid, sei, None), doc)
    return by_key, by_tuple


def _load_retained(db, scope: dict[str, Any], identities: list[dict[str, Any]]
                   ) -> tuple[dict[str, Any], dict[Any, Any]]:
    keys = {i["delivery_key"] for i in identities if i.get("delivery_key")}
    by_key: dict[str, Any] = {}
    if keys:
        for doc in db[RETAINED_COLLECTION].find(
                {**scope, "retained_identity_key": {"$in": list(keys)}}):
            by_key[doc.get("retained_identity_key")] = doc
    seis = {i["source_event_id"] for i in identities
            if i.get("source_event_id")}
    by_sei: dict[Any, Any] = {}
    if seis:
        for doc in db[RETAINED_COLLECTION].find(
                {**scope, "source_event_id": {"$in": list(seis)}}):
            sei = doc.get("source_event_id")
            by_sei.setdefault((doc.get("collector_id"), sei), doc)
            by_sei.setdefault((None, sei), doc)
    return by_key, by_sei


def _load_blocks(db, scope: dict[str, Any], identities: list[dict[str, Any]]
                 ) -> dict[Any, Any]:
    """Latest refusal per (collector, source_event_id) — one query, one sort."""
    seis = {i["source_event_id"] for i in identities
            if i.get("source_event_id")}
    by_sei: dict[Any, Any] = {}
    if not seis:
        return by_sei
    cursor = db[BLOCKS_COLLECTION].find(
        {**scope, "source_event_id": {"$in": list(seis)}}).sort("at", -1)
    for doc in cursor:
        sei = doc.get("source_event_id")
        by_sei.setdefault((doc.get("collector_id"), sei), doc)
        by_sei.setdefault((None, sei), doc)
    return by_sei


def _load_evidence(db, scope: dict[str, Any], claims: list[dict[str, Any]]
                   ) -> dict[Any, Any]:
    event_ids = {c.get("canonical_event_id") for c in claims
                 if c.get("canonical_event_id")}
    out: dict[Any, Any] = {}
    if not event_ids:
        return out
    for doc in db[EVIDENCE_COLLECTION].find(
            {**scope, "event_id": {"$in": list(event_ids)}},
            {"event_id": 1, "tenant_id": 1, "ingest_time": 1,
             "source_event_id": 1}):
        out.setdefault(doc.get("event_id"), doc)
    return out


def _load_raw_rows(db, claims: list[dict[str, Any]]) -> set[str]:
    from bson import ObjectId
    oids, seen = [], set()
    for claim in claims:
        raw_row_id = claim.get("raw_row_id")
        if not raw_row_id or raw_row_id in seen:
            continue
        seen.add(raw_row_id)
        try:
            oids.append(ObjectId(str(raw_row_id)))
        except Exception:                                    # noqa: BLE001
            continue
    if not oids:
        return set()
    return {str(d["_id"]) for d in
            db[RAW_COLLECTION].find({"_id": {"$in": oids}}, {"_id": 1})}


def _claim_for(ident: dict[str, Any], by_key: dict[str, Any],
               by_tuple: dict[Any, Any]) -> tuple[dict[str, Any] | None, str]:
    key = ident.get("delivery_key")
    if key and by_key.get(key):
        return by_key[key], "DELIVERY_KEY"
    sei, cid = ident.get("source_event_id"), ident.get("collector_id")
    if sei and cid:
        digest = ident.get("payload_digest")
        doc = by_tuple.get((cid, sei, digest)) if digest else None
        if doc is None and not digest:
            doc = by_tuple.get((cid, sei, None))
        if doc is not None:
            return doc, "IDENTITY_TUPLE"
    return None, "NONE"


def _retained_for(ident: dict[str, Any], by_key: dict[str, Any],
                  by_sei: dict[Any, Any]
                  ) -> tuple[dict[str, Any] | None, str]:
    key = ident.get("delivery_key")
    if key and by_key.get(key):
        return by_key[key], "RETAINED_IDENTITY_KEY"
    sei = ident.get("source_event_id")
    if sei:
        cid = ident.get("collector_id")
        doc = by_sei.get((cid, sei)) if cid else by_sei.get((None, sei))
        if doc is not None:
            return doc, "RETAINED_SOURCE_EVENT_ID"
    return None, "NONE"


def _bucket(disposition: str, endpoint_outcome: str) -> tuple[str, str]:
    """(bucket, why) — the mapping is explicit so nothing is silently hidden."""
    if disposition == "DELIVERED_CANONICAL":
        return BUCKET_CANONICAL, ("the delivery claim is terminal-successful "
                                  "and its canonical evidence row resolves")
    if disposition == "DELIVERED_RETAINED_RAW":
        return BUCKET_RETAINED, ("refused before interpretation and retained "
                                 "verbatim under B4; NOT canonical evidence "
                                 "and NOT evaluated")
    if disposition == "TERMINAL_REFUSED":
        return BUCKET_TERMINAL, ("the authoritative boundary refused this "
                                 "delivery and kept the refusal as evidence")
    if disposition == "TERMINAL_NEEDS_REVIEW":
        return BUCKET_TERMINAL, ("evidence was persisted but reasoning did "
                                 "not complete; the claim is flagged for "
                                 "operator review and auto-retry is refused")
    if disposition == "SERVER_IN_PROGRESS":
        return BUCKET_OPEN, ("the authoritative plane holds a live, "
                             "non-terminal claim for this delivery")
    if disposition == "ACCOUNTED_WITHOUT_EVIDENCE":
        return BUCKET_UNEXPLAINED, ("the claim is terminal-successful but no "
                                    "canonical evidence row could be "
                                    "resolved for it")
    # NOT_FOUND
    if endpoint_outcome in _ENDPOINT_CLAIMS_SUCCESS:
        return BUCKET_UNEXPLAINED, ("the endpoint reports this row as "
                                    "DELIVERED and the authoritative plane "
                                    "holds no record of it")
    if endpoint_outcome in _ENDPOINT_STILL_OPEN:
        return BUCKET_OPEN, ("never accepted by the destination and still in "
                             "the endpoint queue/retry machinery, so the "
                             "authoritative plane is not expected to know it")
    return BUCKET_UNEXPLAINED, (
        f"endpoint outcome {endpoint_outcome!r} has no authoritative "
        "server-side accounting")


def _resolve(ident: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    """One delivery identity → what the authoritative plane did with it.

    Pure: every fact comes from the pre-loaded batch context, so the answer is
    identical to the per-identity form it replaces but costs no extra query.
    """
    endpoint_outcome = _norm_endpoint_outcome(ident.get("endpoint_outcome"))

    claim, claim_basis = _claim_for(ident, ctx["claims_by_key"],
                                    ctx["claims_by_tuple"])
    retained, retained_basis = _retained_for(ident, ctx["retained_by_key"],
                                             ctx["retained_by_sei"])
    sei, cid = ident.get("source_event_id"), ident.get("collector_id")
    block = None
    if sei:
        block = (ctx["blocks_by_sei"].get((cid, sei)) if cid
                 else ctx["blocks_by_sei"].get((None, sei)))

    evidence = None
    raw_present: bool | None = None
    claim_status = None
    if claim:
        claim_status = str(claim.get("status") or "")
        evidence = ctx["evidence_by_event_id"].get(
            claim.get("canonical_event_id"))
        raw_row_id = claim.get("raw_row_id")
        if raw_row_id:
            raw_present = str(raw_row_id) in ctx["raw_rows_present"]

    if claim and claim_status in _TERMINAL_CLAIM_OK:
        disposition = ("DELIVERED_CANONICAL" if evidence
                       else "ACCOUNTED_WITHOUT_EVIDENCE")
        matched_by = claim_basis
    elif claim and claim_status == "NEEDS_REVIEW":
        disposition, matched_by = "TERMINAL_NEEDS_REVIEW", claim_basis
    elif claim:
        disposition, matched_by = "SERVER_IN_PROGRESS", claim_basis
    elif retained:
        disposition, matched_by = "DELIVERED_RETAINED_RAW", retained_basis
    elif block:
        disposition, matched_by = "TERMINAL_REFUSED", "SOURCE_EVENT_ID_BLOCK"
    else:
        disposition, matched_by = "NOT_FOUND", "NONE"

    bucket, why = _bucket(disposition, endpoint_outcome)

    return {
        "ref": ident.get("ref"),
        "source_event_id": ident.get("source_event_id"),
        "collector_id": ident.get("collector_id"),
        "connector_id": ident.get("connector_id"),
        "delivery_key": ident.get("delivery_key"),
        "endpoint_outcome": endpoint_outcome,
        "disposition": disposition,
        "bucket": bucket,
        "bucket_basis": why,
        "matched_by": matched_by,
        "claim": None if not claim else {
            "status": claim_status,
            "stage": claim.get("stage"),
            "delivery_count": claim.get("delivery_count"),
            "duplicate_count": claim.get("duplicate_count"),
            "trace_id": claim.get("trace_id"),
            "canonical_event_id": claim.get("canonical_event_id"),
            "incident_id": claim.get("incident_id"),
            "raw_row_id": claim.get("raw_row_id"),
            "raw_row_present": raw_present,
            "review_reason": claim.get("review_reason"),
        },
        "evidence_ref": _evidence_ref((evidence or {}).get("event_id")),
        "retained_raw_id": (retained or {}).get("id"),
        "retained_raw_reason": ((retained or {}).get("disposition") or {}
                                ).get("mismatch_reason"),
        "routing_block": None if not block else {
            "trace_id": block.get("trace_id"),
            "routing_result": (block.get("routing") or {}).get(
                "routing_result"),
            "mismatch_reason": (block.get("routing") or {}).get(
                "mismatch_reason"),
            "declared_source_resolved": (block.get("routing") or {}).get(
                "declared_source_resolved"),
            "retained_raw_id": block.get("retained_raw_id"),
            "at": block.get("at"),
        },
    }


def _reconcile_rows(db, tenant_ids: list[str] | None,
                    identities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Load the whole batch in a fixed number of indexed queries, then resolve.

    Seven queries for any batch size, instead of up to five per identity. The
    resolution logic below is unchanged — only the cost of getting the facts
    is.
    """
    ensure_indexes(db)
    scope = _scope_query(tenant_ids)
    claims_by_key, claims_by_tuple = _load_claims(db, scope, identities)
    retained_by_key, retained_by_sei = _load_retained(db, scope, identities)
    matched_claims = list(claims_by_key.values()) + [
        doc for key, doc in claims_by_tuple.items() if key[2] is None]
    ctx = {
        "claims_by_key": claims_by_key,
        "claims_by_tuple": claims_by_tuple,
        "retained_by_key": retained_by_key,
        "retained_by_sei": retained_by_sei,
        "blocks_by_sei": _load_blocks(db, scope, identities),
        "evidence_by_event_id": _load_evidence(db, scope, matched_claims),
        "raw_rows_present": _load_raw_rows(db, matched_claims),
    }
    return [_resolve(ident, ctx) for ident in identities]


def reconcile(db, tenant_ids: list[str] | None,
              identities: list[dict[str, Any]]) -> dict[str, Any]:
    """Bounded reconciliation of one attempted delivery population."""
    if not isinstance(identities, list) or not identities:
        raise ReconciliationRequestInvalid(
            "at least one delivery identity is required")
    if len(identities) > MAX_IDENTITIES:
        raise ReconciliationRequestInvalid(
            f"at most {MAX_IDENTITIES} identities per request; "
            f"{len(identities)} were supplied")
    for ident in identities:
        if not isinstance(ident, dict):
            raise ReconciliationRequestInvalid(
                "each identity must be an object")
        if not (ident.get("delivery_key") or ident.get("source_event_id")):
            raise ReconciliationRequestInvalid(
                "each identity needs a delivery_key or a source_event_id; "
                "an unidentifiable delivery cannot be reconciled and is "
                "never assumed to have landed")

    rows = _reconcile_rows(db, tenant_ids, identities)
    counts = {bucket: 0 for bucket in BUCKETS}
    for row in rows:
        counts[row["bucket"]] += 1

    attempted = len(rows)
    accounted = attempted - counts[BUCKET_UNEXPLAINED]
    unexplained_rows = [r for r in rows if r["bucket"] == BUCKET_UNEXPLAINED]

    return {
        "attempted": attempted,
        "accounted": accounted,
        "buckets": counts,
        "accounting_identity": {
            "equation": ("attempted = DELIVERED_CANONICAL + "
                         "DELIVERED_RETAINED_RAW + RETRYABLE_STILL_QUEUED + "
                         "TERMINAL_ACCOUNTED + UNEXPLAINED"),
            "holds": attempted == sum(counts.values()),
        },
        "unexplained": len(unexplained_rows),
        "unexplained_rows": unexplained_rows[:50],
        "pass": counts[BUCKET_UNEXPLAINED] == 0 and
                attempted == sum(counts.values()),
        "rows": rows,
        "sources": {
            "claim": DEDUPE_COLLECTION,
            "raw": RAW_COLLECTION,
            "evidence": EVIDENCE_COLLECTION,
            "refusal": BLOCKS_COLLECTION,
            "retained_raw": RETAINED_COLLECTION,
        },
        "read_only_note": _READ_ONLY_NOTE,
    }
