"""Terminal record policy — a permanently rejected record must not freeze
acquisition, and must never be laundered into success.

The invariant:

    TERMINAL  !=  ACCEPTED  !=  CANONICAL EVIDENCE  !=  SUCCESSFUL DELIVERY

A terminal record may well have been ATTEMPTED against the authoritative
boundary and refused — that attempt is preserved rather than described as
though delivery never happened. The batch it belongs to completes into its
own state, `completed_with_terminal_records`, which is never `committed`.

History is append-only: a replay appends an event and leaves the original
terminal decision intact. A replay REQUEST is not proof of recovery; only a
fresh acceptance by the authoritative ingest can produce evidence.
"""
from __future__ import annotations

import pytest

from framework.acquisition_state import (COMMITTED,
                                         COMPLETED_WITH_TERMINAL_RECORDS,
                                         AcquisitionState)
from framework.base import Envelope
from framework.outbox import Outbox, OutboxStatus

CT = "Audit.Exchange"
BATCH = "c1"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_STATE_DIR", str(tmp_path))
    outbox = Outbox(path=str(tmp_path))
    state = AcquisitionState(connection=outbox._conn, owner="runner-a")
    return outbox, state, str(tmp_path)


def _env(key, tenant="acme", connector="m365-1"):
    return Envelope(
        tenant_id=tenant, source="m365", source_event_id=key,
        connector_id=connector, collector_id="col",
        collection_method="rest-poll", parser_version="v1",
        source_timestamp=None, collection_timestamp="2026-06-04T09:00:00Z",
        event_type="cloud_audit", raw={"Id": key},
        declared_source="m365-unified-audit")


def _batch(state, keys, tenant="acme", connector="m365-1", batch=BATCH):
    state.claim_batch(tenant, connector, CT, batch,
                      window_end="2026-06-04T10:00:00+00:00",
                      reference="https://manage.example.test/blob/c1")
    state.set_pending_window(tenant, connector, CT,
                             pending_until="2026-06-04T10:00:00+00:00")
    state.record_batch_keys(tenant, connector, CT, batch, keys)


def _queue(outbox, keys, tenant="acme", connector="m365-1"):
    return {k: outbox.record(_env(k, tenant, connector))[0] for k in keys}


# ── the two completion paths must stay distinguishable ────────────
def test_all_accepted_commits(store):
    outbox, state, _ = store
    _batch(state, ["r1", "r2"])
    ids = _queue(outbox, ["r1", "r2"])
    outbox.mark_delivering(ids.values())
    outbox.mark_delivered(ids.values())
    out = state.reconcile(outbox)
    assert out["committed_batches"] == [BATCH]
    assert out["completed_with_terminal_records"] == []
    assert out["terminal_records_quarantined"] == 0
    assert state.terminal_records("acme", "m365-1") == []


def test_accepted_plus_terminal_completes_into_its_own_state(store):
    outbox, state, _ = store
    _batch(state, ["r1", "r2"])
    ids = _queue(outbox, ["r1", "r2"])
    outbox.mark_delivering([ids["r1"]])
    outbox.mark_delivered([ids["r1"]])
    outbox.mark_dead(ids["r2"], "422 unparseable record")
    out = state.reconcile(outbox)
    assert out["committed_batches"] == []
    done = out["completed_with_terminal_records"][0]
    assert done["state"] == COMPLETED_WITH_TERMINAL_RECORDS
    assert done["accepted_records"] == 1 and done["terminal_records"] == 1
    assert "NOT committed" in done["basis"]
    # the three buckets stay separate at batch level
    st = state.status("acme", "m365-1")
    assert st["batch_terminal_records"] == [
        {"stream": CT, "batch_id": BATCH, "terminal_records": 1}]
    assert {b["state"] for b in st["batches"]} == {
        COMPLETED_WITH_TERMINAL_RECORDS}
    assert COMMITTED not in {b["state"] for b in st["batches"]}


def test_a_terminal_record_never_counts_as_accepted_or_evidence(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    # the outbox still says dead_letter — nothing was laundered
    assert outbox.statuses_for("acme", "m365-1", ["r1"]) == {
        "r1": OutboxStatus.DEAD_LETTER}
    st = state.status("acme", "m365-1")
    assert "TERMINAL != ACCEPTED != CANONICAL EVIDENCE" in st["states"]
    assert "SUCCESSFUL DELIVERY" in st["states"]


def test_the_attempt_against_the_boundary_is_preserved(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_retry(ids["r1"], "503 from ingest")
    outbox.mark_dead(ids["r1"], "400 rejected by ingest")
    state.reconcile(outbox)
    t = state.terminal_records("acme", "m365-1")[0]
    # it WAS attempted and refused; that is not "never delivered"
    assert t["rejection_code"] == "INGEST_REJECTED_PERMANENTLY"
    assert t["rejection_reason"] == "400 rejected by ingest"
    assert t["attempts"] >= 1
    assert t["acquisition_ref"].endswith("/blob/c1")
    assert t["batch_id"] == BATCH and t["stream"] == CT


def test_completion_waits_while_other_records_are_still_in_flight(store):
    outbox, state, _ = store
    _batch(state, ["r1", "r2"])
    ids = _queue(outbox, ["r1", "r2"])
    outbox.mark_dead(ids["r1"], "permanent")
    out = state.reconcile(outbox)
    assert out["completed_with_terminal_records"] == []
    assert out["waiting"][0]["terminal_records"] == 1
    assert out["waiting"][0]["not_yet_accepted"] == 1
    assert state.window("acme", "m365-1", CT)["committed_until"] is None


def test_the_same_rejection_is_not_quarantined_twice(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    first = state.reconcile(outbox)
    second = state.reconcile(outbox)
    assert first["terminal_records_quarantined"] == 1
    assert second["terminal_records_quarantined"] == 0
    assert len(state.terminal_records("acme", "m365-1")) == 1


# ── recovery ──────────────────────────────────────────────────────
def test_replay_retains_history_and_reopens_the_batch(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    out = state.replay_terminal_record(outbox, "acme", "m365-1", CT, BATCH,
                                       "r1", requested_by="owner@nivxray")
    assert out["outcome"] == "REPLAY_REQUESTED"
    assert "not proof of recovery" not in out["note"]  # phrased on the event
    hist = state.terminal_records("acme", "m365-1")
    kinds = [h["event_kind"] for h in hist]
    assert kinds == ["quarantined", "replay_requested"]
    # the ORIGINAL decision is untouched
    assert hist[0]["decision"] == "TERMINAL_QUARANTINED"
    assert hist[1]["decided_by"] == "owner@nivxray"
    assert "retained as history" in hist[1]["decision_basis"]
    # the record must pass the boundary again
    assert outbox.statuses_for("acme", "m365-1", ["r1"])["r1"] == \
        OutboxStatus.QUEUED
    st = state.status("acme", "m365-1")
    assert {b["state"] for b in st["batches"]} == {"acquired"}


def test_a_replayed_record_rejected_again_keeps_both_histories(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent 1")
    state.reconcile(outbox)
    state.replay_terminal_record(outbox, "acme", "m365-1", CT, BATCH, "r1")
    outbox.mark_dead(ids["r1"], "permanent 2")
    out = state.reconcile(outbox)
    # a second quarantine event is appended; nothing is rewritten
    hist = state.terminal_records("acme", "m365-1")
    assert [h["event_kind"] for h in hist] == [
        "quarantined", "replay_requested", "quarantined"]
    assert hist[0]["rejection_reason"] == "permanent 1"
    assert hist[2]["rejection_reason"] == "permanent 2"
    assert out["completed_with_terminal_records"][0]["terminal_records"] == 1


def test_a_replayed_record_that_is_accepted_commits_normally(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    state.replay_terminal_record(outbox, "acme", "m365-1", CT, BATCH, "r1")
    outbox.mark_delivering([ids["r1"]])
    outbox.mark_delivered([ids["r1"]])
    out = state.reconcile(outbox)
    assert out["committed_batches"] == [BATCH]
    # the terminal history survives the successful recovery
    assert [h["event_kind"] for h in
            state.terminal_records("acme", "m365-1")] == [
        "quarantined", "replay_requested"]


def test_a_replay_request_alone_proves_nothing(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    out = state.replay_terminal_record(outbox, "acme", "m365-1", CT, BATCH,
                                       "r1")
    assert "must pass the authoritative ingest again" in out["note"]
    # nothing is committed merely because a replay was requested
    assert state.reconcile(outbox)["committed_batches"] == []


def test_concurrent_collectors_cannot_both_release_one_record(store):
    outbox, state, _ = store
    other = AcquisitionState(connection=outbox._conn, owner="runner-b")
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    first = state.replay_terminal_record(outbox, "acme", "m365-1", CT, BATCH,
                                         "r1")
    second = other.replay_terminal_record(outbox, "acme", "m365-1", CT,
                                          BATCH, "r1")
    assert first["outcome"] == "REPLAY_REQUESTED"
    assert second["outcome"] == "REPLAY_NOT_POSSIBLE"
    assert "already released" in second["reason"]


def test_cross_tenant_replay_is_impossible(store):
    outbox, state, _ = store
    _batch(state, ["r1"], tenant="tenant-a")
    ids = _queue(outbox, ["r1"], tenant="tenant-a")
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox, tenant_id="tenant-a")
    out = state.replay_terminal_record(outbox, "tenant-b", "m365-1", CT,
                                       BATCH, "r1")
    assert out["outcome"] == "NOT_FOUND_IN_THIS_SCOPE"
    # tenant B cannot even see the terminal history
    assert state.terminal_records("tenant-b", "m365-1") == []
    assert len(state.terminal_records("tenant-a", "m365-1")) == 1
    # and the record was NOT released
    assert outbox.statuses_for("tenant-a", "m365-1", ["r1"])["r1"] == \
        OutboxStatus.DEAD_LETTER


# ── restart ───────────────────────────────────────────────────────
def test_a_restart_cannot_turn_terminal_into_accepted(store, monkeypatch):
    outbox, state, path = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    outbox.close()

    # ——— restart ———
    outbox2 = Outbox(path=path)
    state2 = AcquisitionState(connection=outbox2._conn, owner="runner-a")
    assert outbox2.statuses_for("acme", "m365-1", ["r1"])["r1"] == \
        OutboxStatus.DEAD_LETTER
    hist = state2.terminal_records("acme", "m365-1")
    assert len(hist) == 1 and hist[0]["decision"] == "TERMINAL_QUARANTINED"
    st = state2.status("acme", "m365-1")
    assert {b["state"] for b in st["batches"]} == {
        COMPLETED_WITH_TERMINAL_RECORDS}
    # reconciling again does not promote it
    assert state2.reconcile(outbox2)["committed_batches"] == []


def test_a_completed_terminal_batch_is_not_reacquired(store):
    outbox, state, _ = store
    _batch(state, ["r1"])
    ids = _queue(outbox, ["r1"])
    outbox.mark_dead(ids["r1"], "permanent")
    state.reconcile(outbox)
    assert state.claim_batch("acme", "m365-1", CT, BATCH) == \
        "ALREADY_COMMITTED"


# ── the mechanism is generic ───────────────────────────────────────
def test_a_dns_connector_gets_the_same_terminal_semantics(store):
    outbox, state, _ = store
    state.claim_batch("acme", "dns-1", "zone-transfer-logs", "export-1",
                      window_end="2026-06-04T10:00:00+00:00")
    state.set_pending_window("acme", "dns-1", "zone-transfer-logs",
                             pending_until="2026-06-04T10:00:00+00:00")
    state.record_batch_keys("acme", "dns-1", "zone-transfer-logs",
                            "export-1", ["q1"])
    rid, _ = outbox.record(Envelope(
        tenant_id="acme", source="dns", source_event_id="q1",
        connector_id="dns-1", collector_id="col",
        collection_method="rest-poll", parser_version="v1",
        source_timestamp=None, collection_timestamp="x",
        event_type="dns_query", raw={}, declared_source="dns-query-log"))
    outbox.mark_dead(rid, "malformed export row")
    out = state.reconcile(outbox)
    assert out["completed_with_terminal_records"][0]["batch_id"] == "export-1"
    assert state.terminal_records("acme", "dns-1")[0]["stream"] == \
        "zone-transfer-logs"
    assert state.window("acme", "dns-1", "zone-transfer-logs")[
        "committed_until"] == "2026-06-04T10:00:00+00:00"
