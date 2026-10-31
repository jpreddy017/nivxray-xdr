"""G1-R5 · Server-side delivery reconciliation.

The collector can prove one thing about a delivery: the destination answered
HTTP 2xx. It cannot prove the authoritative plane ACCOUNTED for the envelope,
because inside one accepted batch a delivery can still be refused by routing,
retained verbatim under B4, suppressed as a duplicate, or left mid-flight.

These tests hold the accounting contract that makes a real drain provable:

    attempted = DELIVERED_CANONICAL + DELIVERED_RETAINED_RAW
              + RETRYABLE_STILL_QUEUED + TERMINAL_ACCOUNTED + UNEXPLAINED

and the rule that gives it teeth: an endpoint success with no server-side
accounting is UNEXPLAINED, never assumed to have landed.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. Synthetic tenants, synthetic
collector, synthetic claims. No endpoint state and no production data.
"""
from __future__ import annotations

import os
import time
import uuid

import pytest
from pymongo import MongoClient

from services import delivery_reconciliation as recon
from services import ingest_idempotency as idem

TEN = f"ten_r5_{uuid.uuid4().hex[:8]}"
OTHER_TEN = f"ten_r5_other_{uuid.uuid4().hex[:8]}"
COL = "col-r5-synthetic"


@pytest.fixture(scope="module")
def db():
    url = os.environ.get("MONGO_URL")
    if not url:
        pytest.skip("MONGO_URL is not bound")
    client = MongoClient(url)
    database = client[os.environ.get("DB_NAME") or "test_database"]
    yield database
    for coll in (recon.DEDUPE_COLLECTION, recon.EVIDENCE_COLLECTION,
                 recon.BLOCKS_COLLECTION, recon.RETAINED_COLLECTION):
        database[coll].delete_many({"tenant_id": {"$in": [TEN, OTHER_TEN]}})


def _identity(sei: str, raw: dict, tenant: str = TEN) -> dict:
    return idem.event_identity(tenant, COL, "windows-security-evd", sei, raw)


def _ident_input(ident: dict, *, outcome: str = "delivered",
                 ref: str | None = None) -> dict:
    return {"ref": ref or ident["source_event_id"],
            "delivery_key": ident["key"],
            "source_event_id": ident["source_event_id"],
            "collector_id": COL,
            "payload_digest": ident["payload_digest"],
            "endpoint_outcome": outcome}


def _seed_completed(db, sei: str, *, tenant: str = TEN,
                    with_evidence: bool = True) -> dict:
    ident = _identity(sei, {"xml": f"<Event>{sei}</Event>"}, tenant)
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    db[recon.DEDUPE_COLLECTION].insert_one({
        **ident, "status": "COMPLETED", "stage": "COMPLETED",
        "delivery_count": 1, "duplicate_count": 0,
        "trace_id": f"tr_{sei}", "canonical_event_id": event_id,
        "raw_row_id": None})
    if with_evidence:
        db[recon.EVIDENCE_COLLECTION].insert_one({
            "event_id": event_id, "tenant_id": tenant,
            "ingest_time": "2026-06-01T00:00:00+00:00",
            "source_event_id": "4624"})
    return ident


def test_a_processed_delivery_with_evidence_is_delivered_canonical(db):
    ident = _seed_completed(db, "r5-ok-1")
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "DELIVERED_CANONICAL"
    assert row["bucket"] == recon.BUCKET_CANONICAL
    assert row["matched_by"] == "DELIVERY_KEY"
    assert row["evidence_ref"].startswith(f"{recon.EVIDENCE_COLLECTION}/")
    assert out["pass"] is True
    assert out["unexplained"] == 0


def test_a_completed_claim_without_resolvable_evidence_is_unexplained(db):
    ident = _seed_completed(db, "r5-noevidence-1", with_evidence=False)
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "ACCOUNTED_WITHOUT_EVIDENCE"
    assert row["bucket"] == recon.BUCKET_UNEXPLAINED
    assert out["pass"] is False


def test_b4_retained_raw_is_its_own_bucket_and_not_canonical(db):
    sei = "r5-retained-1"
    ident = _identity(sei, {"xml": f"<Event>{sei}</Event>"})
    db[recon.RETAINED_COLLECTION].insert_one({
        "id": "rr_synthetic_r5_1", "tenant_id": TEN, "collector_id": COL,
        "retained_identity_key": ident["key"], "source_event_id": sei,
        "disposition": {"state": "RAW_RETAINED_NOT_EVALUATED",
                        "mismatch_reason": "SOURCE_RECORD_NOT_SUPPORTED",
                        "canonical_evidence_created": False}})
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "DELIVERED_RETAINED_RAW"
    assert row["bucket"] == recon.BUCKET_RETAINED
    assert row["retained_raw_id"] == "rr_synthetic_r5_1"
    assert row["retained_raw_reason"] == "SOURCE_RECORD_NOT_SUPPORTED"
    assert row["evidence_ref"] is None
    assert out["pass"] is True


def test_a_routing_refusal_is_terminal_accounted(db):
    sei = "r5-blocked-1"
    ident = _identity(sei, {"line": "not windows"})
    db[recon.BLOCKS_COLLECTION].insert_one({
        "tenant_id": TEN, "collector_id": COL, "source_event_id": sei,
        "trace_id": "blocked_r5_1", "at": "2026-06-01T00:00:00+00:00",
        "routing": {"routing_result": "BLOCKED",
                    "mismatch_reason": "SOURCE_FORMAT_MISMATCH",
                    "declared_source_resolved": "windows-security-evd"},
        "retained_raw_id": None})
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "TERMINAL_REFUSED"
    assert row["bucket"] == recon.BUCKET_TERMINAL
    assert row["routing_block"]["mismatch_reason"] == "SOURCE_FORMAT_MISMATCH"
    assert out["pass"] is True


def test_a_live_claim_is_still_open_not_delivered(db):
    sei = "r5-inflight-1"
    ident = _identity(sei, {"xml": "<Event/>"})
    db[recon.DEDUPE_COLLECTION].insert_one({
        **ident, "status": "RAW_PERSISTED", "stage": "RAW_PERSISTED",
        "delivery_count": 1, "raw_row_id": None})
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "SERVER_IN_PROGRESS"
    assert row["bucket"] == recon.BUCKET_OPEN


def test_needs_review_is_accounted_and_flagged(db):
    sei = "r5-review-1"
    ident = _identity(sei, {"xml": "<Event/>"})
    db[recon.DEDUPE_COLLECTION].insert_one({
        **ident, "status": "NEEDS_REVIEW", "stage": "REASONING_INCOMPLETE",
        "review_reason": "reasoning did not complete", "delivery_count": 1})
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "TERMINAL_NEEDS_REVIEW"
    assert row["bucket"] == recon.BUCKET_TERMINAL
    assert row["claim"]["review_reason"] == "reasoning did not complete"


def test_endpoint_success_with_no_server_record_is_unexplained(db):
    ident = _identity("r5-ghost-1", {"xml": "<Event/>"})
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "NOT_FOUND"
    assert row["bucket"] == recon.BUCKET_UNEXPLAINED
    assert out["pass"] is False
    assert out["unexplained_rows"][0]["ref"] == "r5-ghost-1"


def test_a_row_still_queued_on_the_endpoint_is_not_a_loss(db):
    ident = _identity("r5-queued-1", {"xml": "<Event/>"})
    out = recon.reconcile(db, [TEN],
                          [_ident_input(ident, outcome="queued")])

    row = out["rows"][0]
    assert row["bucket"] == recon.BUCKET_OPEN
    assert out["pass"] is True


def test_an_endpoint_dead_letter_without_server_accounting_is_unexplained(db):
    ident = _identity("r5-dead-1", {"xml": "<Event/>"})
    out = recon.reconcile(db, [TEN],
                          [_ident_input(ident, outcome="dead_letter")])

    assert out["rows"][0]["bucket"] == recon.BUCKET_UNEXPLAINED
    assert out["pass"] is False


# ── tenant authority · fail closed ───────────────────────────────
def test_another_tenants_delivery_is_never_described_or_counted(db):
    ident = _seed_completed(db, "r5-crosstenant-1", tenant=OTHER_TEN)
    out = recon.reconcile(db, [TEN], [_ident_input(ident)])

    row = out["rows"][0]
    assert row["disposition"] == "NOT_FOUND"
    assert row["claim"] is None
    assert row["evidence_ref"] is None
    assert row["bucket"] == recon.BUCKET_UNEXPLAINED


def test_an_empty_scope_can_see_nothing(db):
    ident = _seed_completed(db, "r5-emptyscope-1")
    out = recon.reconcile(db, [], [_ident_input(ident)])
    assert out["rows"][0]["disposition"] == "NOT_FOUND"


def test_a_cross_tenant_scope_sees_the_record(db):
    ident = _seed_completed(db, "r5-crossrole-1", tenant=OTHER_TEN)
    out = recon.reconcile(db, None, [_ident_input(ident)])
    assert out["rows"][0]["disposition"] == "DELIVERED_CANONICAL"


# ── the accounting identity itself ───────────────────────────────
def test_the_population_is_partitioned_with_no_double_counting(db):
    ok = _seed_completed(db, "r5-mix-ok")
    sei_r = "r5-mix-retained"
    retained = _identity(sei_r, {"xml": "<Event/>"})
    db[recon.RETAINED_COLLECTION].insert_one({
        "id": "rr_synthetic_r5_mix", "tenant_id": TEN, "collector_id": COL,
        "retained_identity_key": retained["key"], "source_event_id": sei_r,
        "disposition": {"mismatch_reason": "SOURCE_RECORD_NOT_SUPPORTED"}})
    sei_b = "r5-mix-blocked"
    blocked = _identity(sei_b, {"line": "x"})
    db[recon.BLOCKS_COLLECTION].insert_one({
        "tenant_id": TEN, "collector_id": COL, "source_event_id": sei_b,
        "at": "2026-06-01T00:00:00+00:00",
        "routing": {"routing_result": "BLOCKED",
                    "mismatch_reason": "SOURCE_FORMAT_MISMATCH"}})
    ghost = _identity("r5-mix-ghost", {"xml": "<Event/>"})

    out = recon.reconcile(db, [TEN], [
        _ident_input(ok), _ident_input(retained), _ident_input(blocked),
        _ident_input(ghost, outcome="queued")])

    assert out["attempted"] == 4
    assert out["buckets"] == {
        recon.BUCKET_CANONICAL: 1, recon.BUCKET_RETAINED: 1,
        recon.BUCKET_TERMINAL: 1, recon.BUCKET_OPEN: 1,
        recon.BUCKET_UNEXPLAINED: 0}
    assert out["accounting_identity"]["holds"] is True
    assert out["accounted"] == 4
    assert out["pass"] is True


def test_identity_tuple_resolves_a_claim_without_the_delivery_key(db):
    ident = _seed_completed(db, "r5-tuple-1")
    out = recon.reconcile(db, [TEN], [{
        "ref": "r5-tuple-1", "source_event_id": ident["source_event_id"],
        "collector_id": COL, "payload_digest": ident["payload_digest"],
        "endpoint_outcome": "delivered"}])

    row = out["rows"][0]
    assert row["matched_by"] == "IDENTITY_TUPLE"
    assert row["disposition"] == "DELIVERED_CANONICAL"


# ── request boundaries ───────────────────────────────────────────
def test_an_unidentifiable_delivery_is_refused_not_assumed_landed(db):
    with pytest.raises(recon.ReconciliationRequestInvalid):
        recon.reconcile(db, [TEN], [{"endpoint_outcome": "delivered"}])


def test_the_request_is_bounded(db):
    ident = _identity("r5-bound-1", {"xml": "<Event/>"})
    payload = [_ident_input(ident)] * (recon.MAX_IDENTITIES + 1)
    with pytest.raises(recon.ReconciliationRequestInvalid):
        recon.reconcile(db, [TEN], payload)
    with pytest.raises(recon.ReconciliationRequestInvalid):
        recon.reconcile(db, [TEN], [])


# ── cost · a batch must not become N+1 ───────────────────────────
class _CountingDb:
    """Counts the queries the service issues, without changing answers."""

    def __init__(self, real):
        self._real = real
        self.queries = 0

    def __getitem__(self, name):
        return _CountingCollection(self._real[name], self)


class _CountingCollection:
    def __init__(self, real, counter):
        self._real = real
        self._counter = counter

    def find(self, *a, **kw):
        self._counter.queries += 1
        return self._real.find(*a, **kw)

    def find_one(self, *a, **kw):
        self._counter.queries += 1
        return self._real.find_one(*a, **kw)

    def create_index(self, *a, **kw):
        return self._real.create_index(*a, **kw)


@pytest.fixture(scope="module")
def bulk_population(db):
    """500 processed deliveries with resolvable canonical evidence."""
    recon.ensure_indexes(db)
    idents, claims, evidence = [], [], []
    for i in range(500):
        sei = f"r5-bulk-{i}"
        ident = _identity(sei, {"xml": f"<Event>{i}</Event>"})
        event_id = f"evt_bulk_{i}_{uuid.uuid4().hex[:8]}"
        claims.append({**ident, "status": "COMPLETED", "stage": "COMPLETED",
                       "delivery_count": 1, "canonical_event_id": event_id})
        evidence.append({"event_id": event_id, "tenant_id": TEN,
                         "ingest_time": "2026-06-01T00:00:00+00:00"})
        idents.append(_ident_input(ident, ref=sei))
    db[recon.DEDUPE_COLLECTION].insert_many(claims)
    db[recon.EVIDENCE_COLLECTION].insert_many(evidence)
    return idents


@pytest.mark.parametrize("size", [1, 50, 450, 500])
def test_batch_sizes_resolve_completely_and_cheaply(db, bulk_population, size):
    """1 / 50 / 450 / 500 identities, all accounted, well under the gateway.

    The 450-identity call previously took 35 s and was cut off by the server
    timeout: resolving one delivery scanned the whole evidence collection.
    """
    counting = _CountingDb(db)
    started = time.monotonic()
    out = recon.reconcile(counting, [TEN], bulk_population[:size])
    elapsed = time.monotonic() - started

    assert out["attempted"] == size
    assert out["buckets"][recon.BUCKET_CANONICAL] == size
    assert out["unexplained"] == 0
    assert out["accounting_identity"]["holds"] is True
    assert out["pass"] is True
    # A fixed number of queries for ANY batch size - never per identity.
    assert counting.queries <= 10, (
        f"{counting.queries} queries for {size} identities looks like N+1")
    assert elapsed < 5.0, f"{size} identities took {elapsed:.1f}s"


def test_the_full_batch_is_far_below_the_gateway_timeout(db, bulk_population):
    started = time.monotonic()
    out = recon.reconcile(db, [TEN], bulk_population)
    elapsed = time.monotonic() - started
    assert out["pass"] is True
    # The preview gateway cuts at 30 s; keep an order of magnitude of margin.
    assert elapsed < 3.0, f"500 identities took {elapsed:.1f}s"


def test_a_mixed_batch_partitions_every_bucket_at_scale(db, bulk_population):
    """Canonical + retained raw + terminal + still-queued + unexplained."""
    sei_r = "r5-mixbig-retained"
    retained = _identity(sei_r, {"xml": "<Event/>"})
    db[recon.RETAINED_COLLECTION].insert_one({
        "id": "rr_synthetic_r5_mixbig", "tenant_id": TEN, "collector_id": COL,
        "retained_identity_key": retained["key"], "source_event_id": sei_r,
        "disposition": {"mismatch_reason": "SOURCE_RECORD_NOT_SUPPORTED"}})
    sei_b = "r5-mixbig-blocked"
    blocked = _identity(sei_b, {"line": "x"})
    db[recon.BLOCKS_COLLECTION].insert_one({
        "tenant_id": TEN, "collector_id": COL, "source_event_id": sei_b,
        "at": "2026-06-01T00:00:00+00:00",
        "routing": {"routing_result": "BLOCKED",
                    "mismatch_reason": "SOURCE_FORMAT_MISMATCH"}})
    ghost_open = _identity("r5-mixbig-open", {"xml": "<Event/>"})
    ghost_lost = _identity("r5-mixbig-lost", {"xml": "<Event/>"})

    batch = (bulk_population[:100]
             + [_ident_input(retained), _ident_input(blocked),
                _ident_input(ghost_open, outcome="queued"),
                _ident_input(ghost_lost, outcome="delivered")])
    out = recon.reconcile(db, [TEN], batch)

    assert out["attempted"] == 104
    assert out["buckets"] == {
        recon.BUCKET_CANONICAL: 100, recon.BUCKET_RETAINED: 1,
        recon.BUCKET_TERMINAL: 1, recon.BUCKET_OPEN: 1,
        recon.BUCKET_UNEXPLAINED: 1}
    assert out["accounting_identity"]["holds"] is True
    assert out["pass"] is False
    assert out["unexplained_rows"][0]["ref"] == "r5-mixbig-lost"


def test_tenant_isolation_holds_at_batch_scale(db, bulk_population):
    """A 500-strong batch reconciled under a foreign scope reveals nothing."""
    out = recon.reconcile(db, [OTHER_TEN], bulk_population)
    assert out["buckets"][recon.BUCKET_CANONICAL] == 0
    assert out["buckets"][recon.BUCKET_UNEXPLAINED] == 500
    assert all(r["claim"] is None and r["evidence_ref"] is None
               for r in out["rows"])


def test_identity_tuple_fallback_works_in_a_batch(db, bulk_population):
    """Mixed key-matched and key-less identities in one batch."""
    keyless = [{"ref": i["ref"], "source_event_id": i["source_event_id"],
                "collector_id": i["collector_id"],
                "payload_digest": i["payload_digest"],
                "endpoint_outcome": "delivered"}
               for i in bulk_population[:20]]
    out = recon.reconcile(db, [TEN], keyless + bulk_population[20:60])

    assert out["attempted"] == 60
    assert out["buckets"][recon.BUCKET_CANONICAL] == 60
    bases = {r["matched_by"] for r in out["rows"]}
    assert bases == {"IDENTITY_TUPLE", "DELIVERY_KEY"}
    assert out["pass"] is True


# ── the endpoint and the server must agree on the identity ───────
def test_the_collector_derives_the_same_delivery_identity():
    """The drain driver's key must equal the authoritative claim key.

    If these ever drift, reconciliation would silently fall back to the
    tuple lookup — so the drift is caught here instead of in production.
    """
    import importlib.util
    import sys

    collector_root = "/app/apps/nivxray-xdr-collector"
    if not os.path.isdir(collector_root):
        pytest.skip("collector app is not present in this checkout")
    if collector_root not in sys.path:
        sys.path.insert(0, collector_root)
    spec = importlib.util.spec_from_file_location(
        "g1_r5_delivery_drain_for_backend_test",
        os.path.join(collector_root, "scripts", "g1_r5_delivery_drain.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    raw = {"xml": "<Event><System><EventID>4624</EventID></System></Event>"}
    endpoint_key = module.delivery_key(
        tenant_id=TEN, collector_id=COL, source="windows-security-evd",
        source_event_id="r5-parity-1", raw=raw)
    server_key = idem.event_identity(TEN, COL, "windows-security-evd",
                                     "r5-parity-1", raw)["key"]
    assert endpoint_key == server_key

    # ... and the no-source-event-id case is the same convention too.
    assert module.delivery_key(
        tenant_id=TEN, collector_id=COL, source="windows-security-evd",
        source_event_id=None, raw=raw) == idem.event_identity(
            TEN, COL, "windows-security-evd", None, raw)["key"]
