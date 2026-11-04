"""Durable delivery receipts · the permanent correctness gate.

THE INVARIANT UNDER TEST THROUGHOUT
    No delivery is DELIVERED until an authoritative backend disposition is
    durably evidenced AND locally verified. HTTP 2xx is never enough, an
    ambiguous outcome is never retried blindly, and a mismatched receipt is
    never converted into success.

EVIDENCE LABELLING — TEST/SYNTHETIC. Synthetic tenant, synthetic collector,
in-temp-dir SQLite. No endpoint state, no production data, no real network.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

os.environ.setdefault("NIVX_COLLECTOR_ID", "col-durable-test")

from framework import receipts                                 # noqa: E402
from framework.base import Envelope                            # noqa: E402
from framework.delivery import (CommitState,                   # noqa: E402
                                DeliveryClassification,
                                IngestOutcome)
from framework.durable_delivery import DurableDeliveryWorker    # noqa: E402
from framework.health_gate import DeliveryHealthGate, GateState  # noqa: E402
from framework.outbox import (Outbox, OutboxStatus,            # noqa: E402
                              RestartRecovery)
from framework.receipt_client import ReceiptUnavailable        # noqa: E402

TENANT = "ten_durable_test"
COLLECTOR = "col-durable-test"
CONNECTOR = "conn-windows-security"
SOURCE = "windows-security-evd"
SURFACE = "https://authority.invalid/api/xdr/ingest/delivery/receipts"


# ── harness ───────────────────────────────────────────────────────────
def _envelope(index: int) -> Envelope:
    return Envelope(
        tenant_id=TENANT, source=SOURCE,
        source_event_id=f"sei-{index:05d}", connector_id=CONNECTOR,
        collector_id=COLLECTOR, collection_method="windows-eventlog",
        parser_version="1.0.0", source_timestamp="2026-06-01T00:00:00+00:00",
        collection_timestamp="2026-06-01T00:00:01+00:00",
        event_type="process_creation",
        raw={"EventID": 4688, "RecordId": 1000 + index},
        canonical={"event": "process_creation"},
        declared_source=SOURCE)


class FakeIngest:
    """Stands in for IngestClient; records every wire attempt."""

    def __init__(self, results=None):
        self.calls = []
        self.results = list(results or [])
        self.url = "https://authority.invalid/api/xdr/ingest/telemetry"
        self.auth_mode = "api_key"
        self.token = "nvx_" + "0123456789abcdef" * 3
        self.timeout = 30.0

    def configured(self):
        return True

    async def deliver(self, envelopes):
        envelopes = list(envelopes)
        self.calls.append([e.source_event_id for e in envelopes])
        if self.results:
            return self.results.pop(0)
        return {"outcome": IngestOutcome.OK, "delivered": len(envelopes),
                "classification": DeliveryClassification.ACCEPTED,
                "commit_state": CommitState.CLAIMED, "status_code": 202}


def _accepted():
    return {"outcome": IngestOutcome.OK, "delivered": 1,
            "classification": DeliveryClassification.ACCEPTED,
            "commit_state": CommitState.CLAIMED, "status_code": 202}


def _lost_response():
    return {"outcome": IngestOutcome.RETRYABLE, "delivered": 0,
            "classification": DeliveryClassification.RETRYABLE,
            "commit_state": CommitState.UNKNOWN,
            "reason": "ReadTimeout: response never arrived"}


def _never_sent():
    return {"outcome": IngestOutcome.RETRYABLE, "delivered": 0,
            "classification": DeliveryClassification.RETRYABLE,
            "commit_state": CommitState.NOT_SENT,
            "reason": "ConnectError: destination unreachable"}


def _refused():
    return {"outcome": IngestOutcome.FATAL, "delivered": 0, "status_code": 403,
            "classification": DeliveryClassification.AUTHORITATIVE_TERMINAL,
            "commit_state": CommitState.TERMINAL_CLAIMED,
            "app_attributed": True, "reason": "HTTP 403 | refused"}


class FakeAuthority:
    """The authoritative plane's receipt surface, programmable per identity."""

    def __init__(self, dispositions=None, *, unavailable=False,
                 tenant=TENANT, collector=COLLECTOR, omit=(),
                 mangle_key=False):
        self.dispositions = dict(dispositions or {})
        self.default = None
        self.unavailable = unavailable
        self.tenant = tenant
        self.collector = collector
        self.omit = set(omit)
        self.mangle_key = mangle_key
        self.requests = []
        self.url = SURFACE

    def status(self):
        return {"configured": True, "requests": len(self.requests)}

    def set(self, sei, disposition):
        self.dispositions[sei] = disposition

    async def fetch(self, *, tenant_id, identities, collector=None):
        self.requests.append({"tenant_id": tenant_id,
                              "identities": list(identities),
                              "collector": collector})
        if self.unavailable:
            raise ReceiptUnavailable("receipt surface unreachable (test)")
        rows = []
        for ident in identities:
            sei = ident.get("source_event_id")
            if sei in self.omit:
                continue
            disposition = self.dispositions.get(sei, self.default
                                                or receipts.DISPOSITION_NOT_FOUND)
            rows.append(_server_row(ident, disposition,
                                    mangle_key=self.mangle_key))
        return {"contract": receipts.RECEIPT_CONTRACT,
                "authority": {"tenant_id": self.tenant,
                              "collector_id": self.collector,
                              "at": "2026-06-01T00:00:02+00:00",
                              "read_only": True},
                "rows": rows}


def _server_row(ident, disposition, *, mangle_key=False):
    sei = ident.get("source_event_id")
    row = {
        "ref": ident.get("ref"),
        "delivery_key": (ident.get("delivery_key") + "-tampered"
                         if mangle_key else ident.get("delivery_key")),
        "source_event_id": sei,
        "collector_id": ident.get("collector_id"),
        "connector_id": ident.get("connector_id"),
        "endpoint_outcome": ident.get("endpoint_outcome"),
        "disposition": disposition,
        "bucket": receipts.BUCKET_UNEXPLAINED,
        "bucket_basis": "test",
        "matched_by": "DELIVERY_KEY",
        "claim": None,
        "evidence_ref": None,
        "retained_raw_id": None,
        "retained_raw_reason": None,
        "routing_block": None,
    }
    if disposition == receipts.DISPOSITION_CANONICAL:
        row["bucket"] = receipts.BUCKET_CANONICAL
        row["claim"] = {"status": "COMPLETED", "stage": "COMPLETED",
                        "trace_id": f"tr_{sei}", "delivery_count": 1,
                        "duplicate_count": 0,
                        "canonical_event_id": f"evt_{sei}"}
        row["evidence_ref"] = f"xdr_canonical_evidence/evt_{sei}"
    elif disposition == receipts.DISPOSITION_RETAINED:
        row["bucket"] = receipts.BUCKET_RETAINED
        row["retained_raw_id"] = f"raw_{sei}"
        row["retained_raw_reason"] = "SOURCE_RECORD_NOT_SUPPORTED"
    elif disposition == receipts.DISPOSITION_TERMINAL_REFUSED:
        row["bucket"] = receipts.BUCKET_TERMINAL
        row["routing_block"] = {"routing_result": "REFUSED",
                                "mismatch_reason": "DECLARATION_MISMATCH"}
    elif disposition == receipts.DISPOSITION_TERMINAL_REVIEW:
        row["bucket"] = receipts.BUCKET_TERMINAL
        row["claim"] = {"status": "NEEDS_REVIEW",
                        "review_reason": "reasoning incomplete"}
    elif disposition == receipts.DISPOSITION_IN_PROGRESS:
        row["bucket"] = receipts.BUCKET_OPEN
        row["claim"] = {"status": "CLAIMED", "stage": "NONE"}
    elif disposition == receipts.DISPOSITION_NO_EVIDENCE:
        row["claim"] = {"status": "COMPLETED", "canonical_event_id": None}
    elif disposition == receipts.DISPOSITION_NOT_FOUND:
        row["bucket"] = receipts.BUCKET_OPEN
    return row


class OpenGate:
    state = GateState.OPEN
    state_load_error = None

    def allow_delivery(self):
        return False

    def seconds_until_probe(self):
        return 42.0

    def probe_limit(self):
        return None

    def status(self):
        return {"state": self.state}

    def snapshot(self):
        return {"state": self.state}


def _outbox(tmp_path, *, recovery=RestartRecovery.RECONCILE):
    return Outbox(path=str(tmp_path), restart_recovery=recovery)


def _worker(outbox, ingest, authority, **kwargs):
    kwargs.setdefault("collector", COLLECTOR)
    kwargs.setdefault("health_gate",
                      DeliveryHealthGate(store=outbox,
                                         destination_key="test-destination"))
    return DurableDeliveryWorker(outbox, ingest, authority, **kwargs)


def _seed(outbox, count=1, start=1):
    return [outbox.record(_envelope(i))[0]
            for i in range(start, start + count)]


def _run(coro):
    return asyncio.run(coro)


# ── 1 · the lifecycle ─────────────────────────────────────────────────
def test_normal_canonical_delivery_is_verified_before_it_is_delivered(
        tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    ingest = FakeIngest([_accepted()])
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    summary = _run(_worker(outbox, ingest, authority).dispatch_once())

    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.DELIVERED
    assert summary[receipts.ACTION_DELIVERED] == 1
    assert summary["canonical"] == 1
    assert receipts.is_verified_delivery(row.receipt)
    assert row.receipt["evidence_ref"] == "xdr_canonical_evidence/evt_sei-00001"
    assert row.receipt["canonical"] is True
    assert row.receipt_basis == receipts.BASIS_RECONCILIATION
    assert row.receipt_verified_at
    # the receipt was asked for AFTER the dispatch and under the same identity
    assert authority.requests[0]["identities"][0]["delivery_key"] == \
        row.delivery_key


def test_http_2xx_alone_never_marks_a_row_delivered(tmp_path):
    """The exact R5/R6 correctness gap, closed."""
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    ingest = FakeIngest([_accepted()])
    authority = FakeAuthority(unavailable=True)
    summary = _run(_worker(outbox, ingest, authority).dispatch_once())

    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.UNKNOWN_COMMIT_STATE
    assert row.receipt is None
    assert summary[receipts.ACTION_DELIVERED] == 0
    assert summary[receipts.ACTION_UNKNOWN] == 1


def test_a_b4_retained_raw_disposition_is_durable_but_not_canonical(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_RETAINED})
    summary = _run(_worker(outbox, FakeIngest([_accepted()]),
                           authority).dispatch_once())

    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.DELIVERED
    assert summary["retained_raw"] == 1 and summary["canonical"] == 0
    assert row.receipt["canonical"] is False
    assert row.receipt["retained_raw"] is True
    assert row.receipt["retained_raw_id"] == "raw_sei-00001"
    assert row.receipt["evidence_ref"] is None, (
        "retained raw is NOT canonical evidence and must never claim to be")


def test_an_authoritative_refusal_is_terminal_and_keeps_its_evidence(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority(
        {"sei-00001": receipts.DISPOSITION_TERMINAL_REFUSED})
    summary = _run(_worker(outbox, FakeIngest([_refused()]),
                           authority).dispatch_once())

    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.DEAD_LETTER
    assert summary[receipts.ACTION_TERMINAL] == 1
    assert row.receipt["disposition"] == receipts.DISPOSITION_TERMINAL_REFUSED
    assert row.receipt["routing_block"]["mismatch_reason"] == \
        "DECLARATION_MISMATCH"


def test_a_needs_review_claim_is_terminal_accounted_not_retried(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority(
        {"sei-00001": receipts.DISPOSITION_TERMINAL_REVIEW})
    _run(_worker(outbox, FakeIngest([_accepted()]), authority).dispatch_once())
    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.DEAD_LETTER
    assert row.receipt["claim"]["review_reason"] == "reasoning incomplete"


def test_a_live_server_claim_is_never_retried_and_never_delivered(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_IN_PROGRESS})
    _run(_worker(outbox, FakeIngest([_lost_response()]),
                 authority).dispatch_once())
    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.UNKNOWN_COMMIT_STATE
    assert row.attempts == 0, "a live claim must not consume retry budget"


def test_accounted_without_evidence_is_never_called_delivered(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_NO_EVIDENCE})
    _run(_worker(outbox, FakeIngest([_accepted()]), authority).dispatch_once())
    assert outbox.by_id(rid).status == OutboxStatus.UNKNOWN_COMMIT_STATE


# ── 2 · unknown commit state ──────────────────────────────────────────
def test_a_lost_response_over_a_committed_delivery_is_never_resent(tmp_path):
    """THE critical case: backend committed, endpoint lost the answer."""
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    ingest = FakeIngest([_lost_response()])
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    _run(_worker(outbox, ingest, authority).dispatch_once())

    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.DELIVERED
    assert row.receipt["canonical_event_id"] == "evt_sei-00001"
    assert len(ingest.calls) == 1, (
        "exactly one transmission: the receipt resolved it, not a re-send")
    assert row.attempts == 0, "no retry budget was spent on a committed row"


def test_a_timeout_before_commit_is_proven_absent_and_retried(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_NOT_FOUND})
    summary = _run(_worker(outbox, FakeIngest([_lost_response()]),
                           authority).dispatch_once())
    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.RETRYING
    assert row.attempts == 1
    assert summary[receipts.ACTION_RETRYABLE] == 1
    assert "authoritative absence" in (row.last_error or "")


def test_a_request_that_was_never_sent_asks_for_no_receipt(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority()
    summary = _run(_worker(outbox, FakeIngest([_never_sent()]),
                           authority).dispatch_once())
    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.RETRYING
    assert row.attempts == 1
    assert summary["not_sent"] == 1
    assert authority.requests == [], (
        "a request that provably never left cannot have been committed")


def test_a_receipt_that_is_silent_about_a_delivery_leaves_it_unknown(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL},
                              omit=("sei-00001",))
    _run(_worker(outbox, FakeIngest([_accepted()]), authority).dispatch_once())
    assert outbox.by_id(rid).status == OutboxStatus.UNKNOWN_COMMIT_STATE


# ── 3 · restart correctness ───────────────────────────────────────────
def test_restart_moves_an_unresolved_dispatch_to_unknown_commit_state(
        tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_delivering([rid])          # crash while DISPATCHING
    outbox.close()

    reopened = _outbox(tmp_path)
    row = reopened.by_id(rid)
    assert row.status == OutboxStatus.UNKNOWN_COMMIT_STATE
    assert row.unknown_since
    assert reopened.restart_recovery_result["rows_moved"] == 1
    assert reopened.restart_recovery_result["moved_to"] == \
        OutboxStatus.UNKNOWN_COMMIT_STATE


def test_restart_with_unknown_commit_state_is_reconciled_automatically(
        tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_delivering([rid])
    outbox.close()

    reopened = _outbox(tmp_path)
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    ingest = FakeIngest()
    result = _run(_worker(reopened, ingest, authority).reconcile_once())

    row = reopened.by_id(rid)
    assert row.status == OutboxStatus.DELIVERED
    assert result[receipts.ACTION_DELIVERED] == 1
    assert ingest.calls == [], "reconciliation never retransmits"
    assert row.reconcile_attempts == 1


def test_a_stale_dispatching_row_is_reconciled_without_a_restart(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_delivering([rid])
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_RETAINED})
    worker = _worker(outbox, FakeIngest(), authority,
                     dispatch_lease_seconds=0)
    result = _run(worker.reconcile_once())
    assert result["stale_dispatching"] == 1
    assert outbox.by_id(rid).status == OutboxStatus.DELIVERED


def test_reconciliation_unavailable_changes_nothing(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_unknown_commit(rid, "lost response")
    before = outbox.by_id(rid)
    result = _run(_worker(outbox, FakeIngest(),
                          FakeAuthority(unavailable=True)).reconcile_once())
    after = outbox.by_id(rid)
    assert after.status == OutboxStatus.UNKNOWN_COMMIT_STATE
    assert after.attempts == before.attempts
    assert result["receipt_error"]
    assert result[receipts.ACTION_UNKNOWN] == 1


def test_duplicate_reconciliation_is_idempotent(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_unknown_commit(rid, "lost response")
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    worker = _worker(outbox, FakeIngest(), authority)
    _run(worker.reconcile_once())
    first = outbox.by_id(rid)
    second = _run(worker.reconcile_once())
    again = outbox.by_id(rid)
    assert first.status == again.status == OutboxStatus.DELIVERED
    assert first.receipt_verified_at == again.receipt_verified_at
    assert second["asked"] == 0, "a delivered row is not re-reconciled"


def test_a_delivered_row_can_never_be_reopened_by_a_receipt(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_unknown_commit(rid, "lost response")
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    worker = _worker(outbox, FakeIngest(), authority)
    _run(worker.reconcile_once())
    row = outbox.by_id(rid)
    # a late, contradictory disposition must not resurrect it
    assert outbox.mark_receipt_verified(rid, row.receipt) is False


# ── 4 · stable identity ───────────────────────────────────────────────
def test_the_delivery_identity_is_stable_across_retry_and_restart(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_NOT_FOUND})
    _run(_worker(outbox, FakeIngest([_lost_response()]),
                 authority).dispatch_once())
    first_key = outbox.by_id(rid).delivery_key
    assert first_key

    # a retry, then a restart, then a reconciliation
    outbox.mark_delivering([rid])
    outbox.close()
    reopened = _outbox(tmp_path)
    authority.set("sei-00001", receipts.DISPOSITION_CANONICAL)
    _run(_worker(reopened, FakeIngest(), authority).reconcile_once())
    row = reopened.by_id(rid)
    assert row.delivery_key == first_key, (
        "a transport retry or a restart must never re-issue the identity")
    assert row.receipt["delivery_key"] == first_key


def test_the_identity_matches_the_servers_claim_key():
    """Byte-identical to `services.ingest_idempotency.event_identity`."""
    import hashlib
    raw = {"EventID": 4688, "RecordId": 1001}
    digest = hashlib.sha256(json.dumps(raw, sort_keys=True, default=str,
                                       separators=(",", ":")).encode()
                            ).hexdigest()
    material = "\x1f".join([TENANT, COLLECTOR, SOURCE, "sei-00001", digest])
    assert receipts.delivery_key(
        tenant_id=TENANT, collector_id=COLLECTOR, source=SOURCE,
        source_event_id="sei-00001", raw=raw
    ) == hashlib.sha256(material.encode()).hexdigest()


def test_a_duplicate_delivery_cannot_create_a_second_local_row(tmp_path):
    outbox = _outbox(tmp_path)
    first, status = outbox.record(_envelope(1))
    again, again_status = outbox.record(_envelope(1))
    assert first == again and again_status == status
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    ingest = FakeIngest([_accepted()])
    _run(_worker(outbox, ingest, authority).dispatch_once())
    # the row is delivered and is no longer eligible for dispatch
    assert outbox.by_id(first).status == OutboxStatus.DELIVERED
    _run(_worker(outbox, ingest, authority).dispatch_once())
    assert len(ingest.calls) == 1


# ── 5 · authority isolation ───────────────────────────────────────────
@pytest.mark.parametrize("kwargs,why", [
    ({"tenant": "ten_someone_else"}, "tenant mismatch"),
    ({"collector": "col-not-ours"}, "collector mismatch"),
    ({"mangle_key": True}, "delivery-key mismatch"),
])
def test_a_receipt_from_the_wrong_authority_is_refused(tmp_path, kwargs, why):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL},
                              **kwargs)
    worker = _worker(outbox, FakeIngest([_accepted()]), authority)
    summary = _run(worker.dispatch_once())
    row = outbox.by_id(rid)
    assert row.status == OutboxStatus.UNKNOWN_COMMIT_STATE, why
    assert row.receipt is None
    assert summary["verification_failures"] == 1
    assert worker.verification_failures[0]["ref"] == rid


def test_a_receipt_for_another_row_is_refused(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    row = outbox.by_id(rid)
    with pytest.raises(receipts.ReceiptVerificationError):
        receipts.verify(row=row, key="k", expected_collector=COLLECTOR,
                        authority={"tenant_id": TENANT,
                                   "collector_id": COLLECTOR},
                        server_row={"ref": "some-other-row",
                                    "delivery_key": "k",
                                    "disposition":
                                        receipts.DISPOSITION_CANONICAL})


def test_an_unknown_bucket_is_refused(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    row = outbox.by_id(rid)
    with pytest.raises(receipts.ReceiptVerificationError):
        receipts.verify(row=row, key="k", expected_collector=COLLECTOR,
                        authority={"tenant_id": TENANT,
                                   "collector_id": COLLECTOR},
                        server_row={"ref": rid, "delivery_key": "k",
                                    "bucket": "MADE_UP",
                                    "disposition":
                                        receipts.DISPOSITION_CANONICAL})


# ── 6 · R3.1 delivery-health gate ─────────────────────────────────────
def test_an_open_gate_claims_nothing_and_asks_for_no_receipt(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    ingest = FakeIngest()
    authority = FakeAuthority()
    summary = _run(_worker(outbox, ingest, authority,
                           health_gate=OpenGate()).dispatch_once())
    assert summary["gate_skipped"] is True
    assert ingest.calls == [] and authority.requests == []
    assert outbox.by_id(rid).status == OutboxStatus.QUEUED


def test_reconciliation_still_runs_while_the_gate_is_open(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_unknown_commit(rid, "lost response")
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    result = _run(_worker(outbox, FakeIngest(), authority,
                          health_gate=OpenGate()).reconcile_once())
    assert result[receipts.ACTION_DELIVERED] == 1
    assert outbox.by_id(rid).status == OutboxStatus.DELIVERED


def test_a_gate_that_opens_mid_batch_releases_the_unclaimed_rows(tmp_path):
    outbox = _outbox(tmp_path)
    ids = _seed(outbox, count=4)
    gate = DeliveryHealthGate(store=outbox, failure_threshold=1,
                              destination_key="test-destination")
    ingest = FakeIngest([_never_sent()] * 4)
    worker = _worker(outbox, ingest, FakeAuthority(), health_gate=gate)
    summary = _run(worker.dispatch_once())
    assert summary.get("stopped_on_open_gate") is True
    assert gate.state == GateState.OPEN
    counts = outbox.counts()
    assert counts[OutboxStatus.DELIVERING] == 0, "nothing may stay claimed"
    assert counts[OutboxStatus.QUEUED] == 3
    assert outbox.by_id(ids[0]).status == OutboxStatus.RETRYING


def test_a_verified_delivery_closes_the_gate_again(tmp_path):
    outbox = _outbox(tmp_path)
    _seed(outbox)
    gate = DeliveryHealthGate(store=outbox, failure_threshold=2,
                              destination_key="test-destination")
    gate.record_destination_failure("outage")
    assert gate.state == GateState.SUSPECT
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    _run(_worker(outbox, FakeIngest([_accepted()]), authority,
                 health_gate=gate).dispatch_once())
    assert gate.state == GateState.CLOSED


# ── 7 · durability and hostile state ──────────────────────────────────
def test_a_corrupt_persisted_receipt_is_not_a_delivery(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox._conn.execute(                                    # noqa: SLF001
        "UPDATE envelopes SET receipt_json='{not json' WHERE id=?", (rid,))
    row = outbox.by_id(rid)
    assert row.receipt is None
    assert receipts.load("{not json") is None
    assert receipts.is_verified_delivery(None) is False
    assert receipts.is_verified_delivery({"local_action": "DELIVERED"}) is False


@pytest.mark.parametrize("receipt", [
    None, {}, {"contract": "something/else", "local_action": "DELIVERED"},
    {"contract": receipts.RECEIPT_CONTRACT, "local_action": "RETRYABLE"},
    {"contract": receipts.RECEIPT_CONTRACT, "local_action": "DELIVERED",
     "disposition": "NOT_FOUND", "delivery_key": "k"},
])
def test_marking_delivered_without_a_verified_receipt_is_refused(tmp_path,
                                                                 receipt):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    with pytest.raises(ValueError):
        outbox.mark_receipt_verified(rid, receipt)
    assert outbox.by_id(rid).status == OutboxStatus.QUEUED


def test_a_local_failure_while_applying_a_receipt_never_reports_success(
        tmp_path, monkeypatch):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL})
    worker = _worker(outbox, FakeIngest([_accepted()]), authority)

    def boom(*_a, **_k):
        raise RuntimeError("sqlite write failed")

    monkeypatch.setattr(outbox, "mark_receipt_verified", boom)
    with pytest.raises(RuntimeError):
        _run(worker.dispatch_once())
    row = outbox.by_id(rid)
    assert row.status != OutboxStatus.DELIVERED
    assert row.status == OutboxStatus.UNKNOWN_COMMIT_STATE
    assert row.receipt is None


def test_acquisition_is_not_advanced_by_an_unresolved_delivery(tmp_path):
    """Invariant 5: only a receipt-verified DELIVERED may advance a bookmark."""
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_unknown_commit(rid, "lost response")
    statuses = outbox.statuses_for(TENANT, CONNECTOR, ["sei-00001"])
    assert statuses["sei-00001"] == OutboxStatus.UNKNOWN_COMMIT_STATE
    assert statuses["sei-00001"] != OutboxStatus.DELIVERED


# ── 8 · the constructor hazard is contained ───────────────────────────
def test_the_restart_policy_is_explicit_and_legacy_behaviour_is_preserved(
        tmp_path):
    legacy = Outbox(path=str(tmp_path),
                    restart_recovery=RestartRecovery.RESET_TO_QUEUED)
    rid = _seed(legacy)[0]
    legacy.mark_delivering([rid])
    legacy.close()
    reopened = Outbox(path=str(tmp_path),
                      restart_recovery=RestartRecovery.RESET_TO_QUEUED)
    assert reopened.by_id(rid).status == OutboxStatus.QUEUED
    assert reopened.restart_recovery_result["moved_to"] == \
        OutboxStatus.QUEUED
    reopened.close()


def test_the_none_policy_mutates_nothing_on_open(tmp_path):
    outbox = _outbox(tmp_path)
    rid = _seed(outbox)[0]
    outbox.mark_delivering([rid])
    outbox.close()
    inert = Outbox(path=str(tmp_path), restart_recovery=RestartRecovery.NONE)
    assert inert.by_id(rid).status == OutboxStatus.DELIVERING
    assert inert.restart_recovery_result["rows_moved"] == 0
    inert.close()


def test_an_unknown_restart_policy_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Outbox(path=str(tmp_path), restart_recovery="do_whatever")


# ── 9 · the whole protocol, end to end ────────────────────────────────
def test_tick_reconciles_before_it_dispatches(tmp_path):
    outbox = _outbox(tmp_path)
    stranded = _seed(outbox, count=1, start=1)[0]
    fresh = _seed(outbox, count=1, start=2)[0]
    outbox.mark_unknown_commit(stranded, "lost response")
    authority = FakeAuthority({"sei-00001": receipts.DISPOSITION_CANONICAL,
                               "sei-00002": receipts.DISPOSITION_RETAINED})
    result = _run(_worker(outbox, FakeIngest([_accepted()]),
                          authority).tick_once())
    assert result["reconciled"][receipts.ACTION_DELIVERED] == 1
    assert result["dispatched"][receipts.ACTION_DELIVERED] == 1
    assert outbox.by_id(stranded).receipt["canonical"] is True
    assert outbox.by_id(fresh).receipt["retained_raw"] is True


def test_the_accounting_equation_holds_over_a_mixed_population(tmp_path):
    outbox = _outbox(tmp_path)
    ids = _seed(outbox, count=5)
    authority = FakeAuthority({
        "sei-00001": receipts.DISPOSITION_CANONICAL,
        "sei-00002": receipts.DISPOSITION_RETAINED,
        "sei-00003": receipts.DISPOSITION_NOT_FOUND,
        "sei-00004": receipts.DISPOSITION_TERMINAL_REFUSED,
        "sei-00005": receipts.DISPOSITION_IN_PROGRESS,
    })
    summary = _run(_worker(outbox, FakeIngest([_accepted()] * 5),
                           authority).dispatch_once())
    assert summary["dispatched"] == 5
    assert summary[receipts.ACTION_DELIVERED] == 2
    assert summary[receipts.ACTION_RETRYABLE] == 1
    assert summary[receipts.ACTION_TERMINAL] == 1
    assert summary[receipts.ACTION_UNKNOWN] == 1
    statuses = [outbox.by_id(i).status for i in ids]
    assert statuses == [OutboxStatus.DELIVERED, OutboxStatus.DELIVERED,
                        OutboxStatus.RETRYING, OutboxStatus.DEAD_LETTER,
                        OutboxStatus.UNKNOWN_COMMIT_STATE]
    delivered = [outbox.by_id(i).receipt for i in ids[:2]]
    assert [r["canonical"] for r in delivered] == [True, False]


def test_status_reports_the_protocol_and_the_invariant(tmp_path):
    outbox = _outbox(tmp_path)
    status = _worker(outbox, FakeIngest(), FakeAuthority()).status()
    assert status["protocol"] == "durable-delivery-receipt/1"
    assert "authoritative" in status["invariant"]
    assert status["collector_id"] == COLLECTOR


# ── 10 · deployment wiring ────────────────────────────────────────────
@pytest.mark.parametrize("value,durable", [
    (None, False), ("", False), ("0", False), ("1", True), ("true", True),
    ("YES", True),
])
def test_the_runtime_selects_the_protocol_by_deployment(tmp_path, monkeypatch,
                                                        value, durable):
    from framework.delivery_worker import DeliveryWorker
    from framework.runtime import CollectorRuntime

    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    if value is None:
        monkeypatch.delenv(CollectorRuntime.DURABLE_ENV, raising=False)
    else:
        monkeypatch.setenv(CollectorRuntime.DURABLE_ENV, value)
    runtime = CollectorRuntime()
    try:
        assert runtime.durable_delivery is durable
        assert isinstance(runtime.worker, DurableDeliveryWorker
                          if durable else DeliveryWorker)
        assert runtime.outbox.restart_recovery == (
            RestartRecovery.RECONCILE if durable
            else RestartRecovery.RESET_TO_QUEUED)
    finally:
        runtime.outbox.close()


def test_the_durable_worker_loop_starts_and_stops(tmp_path):
    outbox = _outbox(tmp_path)
    worker = _worker(outbox, FakeIngest(), FakeAuthority())

    async def drive():
        assert worker.running() is False
        await worker.start()
        assert worker.running() is True
        await asyncio.sleep(0)
        await worker.stop()
        assert worker.running() is False

    _run(drive())
    assert worker.status()["protocol"] == "durable-delivery-receipt/1"
