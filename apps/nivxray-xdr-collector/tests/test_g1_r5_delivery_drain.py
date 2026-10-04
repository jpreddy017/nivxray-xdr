"""G1-R5 · Bounded delivery-only drain.

R4 requeued 14,868 dead letters. Delivering them is a separate phase, and the
danger in that phase is not delivery — it is everything that normally starts
ALONGSIDE delivery. These tests hold the boundaries that make a first real
drain safe to run on a production endpoint:

  * the row ceiling is EXACT, not best-effort;
  * `--max-ticks` / `--max-seconds` are real secondary ceilings;
  * R3.1 restart recovery (delivering → queued) is MEASURED and reported,
    never absorbed into queue depth;
  * a health gate that OPENS is a hard stop with evidence — no cooldown, no
    HALF_OPEN probe, no automatic recovery that would hide the first failure;
  * no acquisition surface is touched: the Windows connector module is never
    imported, and the bookmark/acquisition tables are byte-identical after;
  * every attempted row yields the delivery identity the authoritative plane
    uses, so HTTP acceptance is never mistaken for canonical ingestion.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. No endpoint state, no
production database, no live destination.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import sqlite3
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from framework.base import Envelope                          # noqa: E402
from framework.delivery import (DeliveryClassification,       # noqa: E402
                                IngestOutcome)
from framework.outbox import Outbox, OutboxStatus             # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "g1_r5_delivery_drain",
    os.path.join(_ROOT, "scripts", "g1_r5_delivery_drain.py"))
drain = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(drain)


TEN = "ten_r5_synthetic"
CONN = "conn-r5-synthetic"
COLLECTOR = "col-r5-synthetic"
os.environ.setdefault("NIVX_COLLECTOR_ID", COLLECTOR)


class _FakeIngest:
    """A destination whose answer is declared by the test, not guessed."""

    def __init__(self, outcome: str = IngestOutcome.OK,
                 classification: str = DeliveryClassification.ACCEPTED,
                 reason: str = "synthetic") -> None:
        self.outcome = outcome
        self.classification = classification
        self.reason = reason
        self.calls = 0

    def configured(self) -> bool:
        return True

    def status(self) -> dict:
        return {"configured": True, "calls": self.calls}

    async def deliver(self, envelopes):
        self.calls += 1
        if self.outcome == IngestOutcome.OK:
            return {"outcome": IngestOutcome.OK, "delivered": 1,
                    "classification": DeliveryClassification.ACCEPTED}
        return {"outcome": self.outcome, "delivered": 0,
                "classification": self.classification,
                "reason": self.reason,
                "failure_detail": {"classification": self.classification,
                                   "status_code": 503}}


def _envelope(i: int) -> Envelope:
    return Envelope(
        tenant_id=TEN, source="windows-security-evd",
        source_event_id=f"r5-synthetic-{i}", connector_id=CONN,
        collector_id="col-r5-synthetic", collection_method="eventlog",
        parser_version="test.r5.1", source_timestamp=None,
        collection_timestamp="2026-06-01T00:00:00+00:00",
        event_type="windows_event", raw={"xml": f"<Event>{i}</Event>"},
        canonical={}, declared_source="windows-security-evd")


def _seed(state_dir: str, count: int) -> None:
    ob = Outbox(path=state_dir)
    for i in range(count):
        ob.record(_envelope(i))
    ob.close()


def _histogram(state_dir: str) -> dict:
    conn = sqlite3.connect(os.path.join(state_dir, "outbox.db"))
    conn.row_factory = sqlite3.Row
    try:
        out = {s: 0 for s in OutboxStatus.ALL}
        for r in conn.execute("SELECT status, COUNT(*) n FROM envelopes "
                              "GROUP BY status"):
            out[r["status"]] = int(r["n"])
        return out
    finally:
        conn.close()


def _run(state_dir: str, **kw):
    # `windows_connector_never_imported` inspects sys.modules, which in a
    # shared pytest process can be polluted by unrelated acquisition suites.
    # The real drain runs in its own process; drop the module here so the
    # invariant measures THIS driver and not the test session.
    sys.modules.pop("framework.windows_eventlog", None)
    params = {"state_dir": state_dir, "max_rows": 10, "max_ticks": 50,
              "max_seconds": 60.0, "batch_size": 5, "execute": True,
              "ingest_client": _FakeIngest()}
    params.update(kw)
    return asyncio.run(drain.run_drain(**params))


# ── the ceiling is exact ──────────────────────────────────────────
def test_row_ceiling_is_exact_not_best_effort(tmp_path):
    state = str(tmp_path)
    _seed(state, 120)
    report = _run(state, max_rows=50, batch_size=50)

    assert report["attempted"] == 50
    assert report["stop_reason"] == "MAX_ROWS_REACHED"
    assert report["invariants"]["row_ceiling_respected"]["holds"] is True
    hist = _histogram(state)
    assert hist[OutboxStatus.DELIVERED] == 50
    assert hist[OutboxStatus.QUEUED] == 70


def test_ceiling_below_batch_size_still_attempts_exactly_the_ceiling(tmp_path):
    state = str(tmp_path)
    _seed(state, 100)
    report = _run(state, max_rows=7, batch_size=50)

    assert report["attempted"] == 7
    assert _histogram(state)[OutboxStatus.DELIVERED] == 7


def test_queue_empty_is_a_clean_stop(tmp_path):
    state = str(tmp_path)
    _seed(state, 12)
    report = _run(state, max_rows=500, batch_size=5)

    assert report["attempted"] == 12
    assert report["stop_reason"] == "QUEUE_EMPTY"
    assert report["pass"] is True


def test_tick_ceiling_stops_the_run(tmp_path):
    state = str(tmp_path)
    _seed(state, 100)
    report = _run(state, max_rows=100, batch_size=5, max_ticks=3)

    assert report["stop_reason"] == "MAX_TICKS_REACHED"
    assert report["attempted"] == 15
    # A secondary ceiling is a bounded halt, not a success.
    assert report["pass"] is False


# ── dry run attempts nothing ──────────────────────────────────────
def test_dry_run_sends_nothing_and_mutates_no_status(tmp_path):
    state = str(tmp_path)
    _seed(state, 30)
    client = _FakeIngest()
    report = _run(state, max_rows=10, execute=False, ingest_client=client)

    assert report["mode"] == "DRY_RUN"
    assert report["attempted"] == 0
    assert client.calls == 0
    assert report["stop_reason"] == "DRY_RUN"
    assert _histogram(state)[OutboxStatus.QUEUED] == 30
    assert report["identities_count"] == 5  # default batch_size window


def test_dry_run_does_not_perform_r31_restart_recovery(tmp_path):
    """A dry run must not write — not even the recovery that --execute does."""
    state = str(tmp_path)
    _seed(state, 20)
    conn = sqlite3.connect(os.path.join(state, "outbox.db"))
    conn.execute("UPDATE envelopes SET status='delivering' WHERE id IN "
                 "(SELECT id FROM envelopes LIMIT 4)")
    conn.commit()
    conn.close()

    report = _run(state, max_rows=10, execute=False)
    recovery = report["invariants"]["restart_recovery_accounted"]

    assert recovery["state"] == "NOT_APPLIED_IN_DRY_RUN"
    assert recovery["would_reset_to_queued"] == 4
    assert recovery["delivering_reset_to_queued"] == 0
    assert _histogram(state)[OutboxStatus.DELIVERING] == 4
    assert _histogram(state)[OutboxStatus.QUEUED] == 16


def test_dry_run_and_execute_agree_on_the_delivery_identity(tmp_path):
    state = str(tmp_path)
    _seed(state, 4)
    dry = _run(state, max_rows=4, batch_size=4, execute=False)
    live = _run(state, max_rows=4, batch_size=4, execute=True)

    dry_keys = sorted(i["delivery_key"] for i in dry["identities"])
    live_keys = sorted(i["delivery_key"] for i in live["identities"])
    assert dry_keys == live_keys


# ── R3.1 restart recovery is measured, not hidden ─────────────────
def test_stranded_delivering_rows_are_measured_as_restart_recovery(tmp_path):
    state = str(tmp_path)
    _seed(state, 20)
    db = os.path.join(state, "outbox.db")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE envelopes SET status='delivering' WHERE id IN "
                 "(SELECT id FROM envelopes LIMIT 6)")
    conn.commit()
    conn.close()

    report = _run(state, max_rows=1, batch_size=1)
    recovery = report["invariants"]["restart_recovery_accounted"]

    assert recovery["delivering_before"] == 6
    assert recovery["delivering_after"] == 0
    assert recovery["delivering_reset_to_queued"] == 6
    assert recovery["queued_delta"] == 6
    assert recovery["consistent"] is True


# ── a gate that opens is a hard stop with evidence ────────────────
def test_gate_open_is_a_hard_stop_with_no_automatic_recovery(tmp_path):
    state = str(tmp_path)
    _seed(state, 200)
    client = _FakeIngest(outcome=IngestOutcome.RETRYABLE,
                         classification=DeliveryClassification.RETRYABLE,
                         reason="HTTP 503")
    report = _run(state, max_rows=200, batch_size=10, ingest_client=client)

    assert report["gate_opened"] is True
    assert report["stop_reason"] in ("GATE_OPENED_DURING_DRAIN",
                                     "GATE_BLOCKED_DELIVERY")
    assert report["pass"] is False
    assert report["gate"]["state"] == "OPEN"
    # The gate state is durable, so the operator decision is made against the
    # same outage the next process would inherit.
    conn = sqlite3.connect(os.path.join(state, "outbox.db"))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM delivery_health_gate").fetchone()
    conn.close()
    assert row is not None and row["state"] == "OPEN"
    # Nothing was delivered and nothing was lost.
    hist = _histogram(state)
    assert hist[OutboxStatus.DELIVERED] == 0
    assert hist[OutboxStatus.DELIVERING] == 0
    assert (hist[OutboxStatus.QUEUED] + hist[OutboxStatus.RETRYING]
            + hist[OutboxStatus.DEAD_LETTER]) == 200


# ── no acquisition surface ────────────────────────────────────────
def test_acquisition_tables_are_byte_identical_and_connector_never_loaded(
        tmp_path):
    state = str(tmp_path)
    _seed(state, 20)
    db = os.path.join(state, "outbox.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE windows_channel_state (channel TEXT PRIMARY "
                 "KEY, bookmark_xml TEXT, updated_at TEXT)")
    conn.execute("INSERT INTO windows_channel_state VALUES "
                 "('Security', '<BookmarkList/>', '2026-06-01T00:00:00Z')")
    conn.commit()
    conn.close()

    sys.modules.pop("framework.windows_eventlog", None)
    report = _run(state, max_rows=10, batch_size=10)

    assert report["invariants"]["no_acquisition"]["unchanged"] is True
    assert report["invariants"]["no_acquisition"]["changed_tables"] == []
    assert report["invariants"][
        "windows_connector_never_imported"]["holds"] is True
    assert report["invariants"]["total_rows_unchanged"]["holds"] is True


# ── identities are reconcilable ───────────────────────────────────
def test_every_attempted_row_yields_a_reconcilable_delivery_identity(tmp_path):
    state = str(tmp_path)
    _seed(state, 8)
    params = {"state_dir": state, "max_rows": 8, "max_ticks": 10,
              "max_seconds": 60.0, "batch_size": 4, "execute": True,
              "ingest_client": _FakeIngest()}
    sys.modules.pop("framework.windows_eventlog", None)
    report = asyncio.run(drain.run_drain(**params))

    assert report["identities_count"] == 8
    keys = set()
    for ident in report["identities"]:
        assert ident["delivery_key"] and len(ident["delivery_key"]) == 64
        assert ident["payload_digest"] and len(ident["payload_digest"]) == 64
        assert ident["tenant_id"] == TEN
        assert ident["source_event_id"].startswith("r5-synthetic-")
        assert ident["endpoint_outcome"] == OutboxStatus.DELIVERED
        keys.add(ident["delivery_key"])
    assert len(keys) == 8, "one delivery identity per distinct delivery"
    assert report["honesty_note"].startswith("HTTP 2xx is acceptance")


def test_delivery_key_is_stable_for_the_same_delivery():
    a = drain.delivery_key(tenant_id=TEN, collector_id="c1",
                           source="windows-security-evd",
                           source_event_id="e1", raw={"b": 2, "a": 1})
    b = drain.delivery_key(tenant_id=TEN, collector_id="c1",
                           source="windows-security-evd",
                           source_event_id="e1", raw={"a": 1, "b": 2})
    c = drain.delivery_key(tenant_id=TEN, collector_id="c1",
                           source="windows-security-evd",
                           source_event_id="e2", raw={"a": 1, "b": 2})
    assert a == b, "key order in the payload is not a different delivery"
    assert a != c, "a new source_event_id IS a different delivery"


def test_missing_outbox_refuses_to_run(tmp_path):
    with pytest.raises(SystemExit):
        _run(str(tmp_path / "nowhere"))


def test_an_unset_collector_identity_refuses_to_deliver(tmp_path, monkeypatch):
    """The delivery identity depends on NIVX_COLLECTOR_ID.

    Delivering under the `collector-local` fallback would produce a delivery
    the authoritative plane cannot be asked about, so the drain refuses.
    """
    state = str(tmp_path)
    _seed(state, 5)
    monkeypatch.delenv("NIVX_COLLECTOR_ID", raising=False)
    with pytest.raises(SystemExit):
        _run(state, max_rows=1)
    assert _histogram(state)[OutboxStatus.QUEUED] == 5


def test_a_collector_identity_mismatch_refuses_to_deliver(tmp_path):
    state = str(tmp_path)
    _seed(state, 5)
    with pytest.raises(SystemExit):
        _run(state, max_rows=1, expect_collector_id="some-other-collector")
    assert _histogram(state)[OutboxStatus.QUEUED] == 5
