"""G1-R6 Phase A · local accounting repair.

R5 proved which of the 50 stranded `delivering` rows the authoritative plane
already holds (22 canonical) and which it does not (28 retryable). The danger
in repairing the first group is doing too much: marking all 50 delivered,
redelivering events that already landed, or letting R3.1 restart recovery
quietly requeue the 28 as a side effect of opening the Outbox.

These tests hold that line:

  * only rows the SERVER proved canonical are repaired;
  * the 28 retryable rows stay exactly as they are;
  * a row whose local delivery identity does not match the identity the
    server answered about is refused, so a stale proof cannot mark the wrong
    row delivered;
  * a proof row without canonical evidence is refused;
  * a wrong population count refuses everything, atomically;
  * the repair is transactional, idempotent-safe on re-run, and leaves the
    row total and the bookmarks untouched;
  * no network client is imported at all.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from framework.base import Envelope                          # noqa: E402
from framework.outbox import Outbox                          # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "g1_r6_local_accounting_repair",
    os.path.join(_ROOT, "scripts", "g1_r6_local_accounting_repair.py"))
repair = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(repair)

TEN = "ten_r6_synthetic"
COL = "col-r6-synthetic"
os.environ.setdefault("NIVX_COLLECTOR_ID", COL)


def _seed(state_dir: str, count: int) -> list:
    ob = Outbox(path=state_dir)
    ids = []
    for i in range(count):
        env = Envelope(
            tenant_id=TEN, source="sysmon", source_event_id=f"r6-{i}",
            connector_id="conn-r6", collector_id=COL,
            collection_method="eventlog", parser_version="test.r6.1",
            source_timestamp=None,
            collection_timestamp="2026-06-01T00:00:00+00:00",
            event_type="windows_event", raw={"xml": f"<E>{i}</E>"},
            canonical={}, declared_source="sysmon")
        recorded = ob.record(env)
        ids.append(recorded[0] if isinstance(recorded, tuple) else recorded)
    ob.close()
    return ids


def _set_status(state_dir: str, ids, status: str) -> None:
    conn = sqlite3.connect(os.path.join(state_dir, "outbox.db"))
    conn.executemany("UPDATE envelopes SET status=? WHERE id=?",
                     [(status, i) for i in ids])
    conn.commit()
    conn.close()


def _histogram(state_dir: str) -> dict:
    conn = sqlite3.connect(os.path.join(state_dir, "outbox.db"))
    try:
        return {r[0]: r[1] for r in conn.execute(
            "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
    finally:
        conn.close()


def _key_for(state_dir: str, rid: str) -> str:
    conn = sqlite3.connect(os.path.join(state_dir, "outbox.db"))
    conn.row_factory = sqlite3.Row
    try:
        r = conn.execute("SELECT * FROM envelopes WHERE id=?",
                         (rid,)).fetchone()
        return repair.delivery_key(
            tenant_id=r["tenant_id"], collector_id=COL, source=r["source"],
            source_event_id=r["source_event_id"],
            raw=json.loads(r["raw_json"]))
    finally:
        conn.close()


def _proof(state_dir: str, canonical_ids, retryable_ids, tmp_path,
           name: str = "proof.json", drop_evidence: bool = False,
           corrupt_key_for: str | None = None) -> str:
    rows = []
    for rid in canonical_ids:
        key = _key_for(state_dir, rid)
        if corrupt_key_for == rid:
            key = ("0" if key[0] != "0" else "1") + key[1:]
        rows.append({
            "ref": rid, "delivery_key": key, "endpoint_outcome": "delivering",
            "disposition": "DELIVERED_CANONICAL",
            "bucket": repair.CANONICAL, "matched_by": "DELIVERY_KEY",
            "evidence_ref": None if drop_evidence
            else f"xdr_canonical_evidence/evt_{rid}",
            "claim": {"status": "COMPLETED",
                      "canonical_event_id": None if drop_evidence
                      else f"evt_{rid}"}})
    for rid in retryable_ids:
        rows.append({
            "ref": rid, "delivery_key": _key_for(state_dir, rid),
            "endpoint_outcome": "delivering", "disposition": "NOT_FOUND",
            "bucket": repair.RETRYABLE, "matched_by": "NONE",
            "evidence_ref": None, "claim": None})
    path = str(tmp_path / name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"attempted": len(rows), "rows": rows}, fh)
    return path


@pytest.fixture()
def fixture(tmp_path):
    state = str(tmp_path / "state")
    os.makedirs(state, exist_ok=True)
    ids = _seed(state, 60)
    canonical, retryable, delivered = ids[:22], ids[22:50], ids[50:]
    _set_status(state, canonical + retryable, repair.DELIVERING)
    _set_status(state, delivered, repair.DELIVERED)
    return {"state": state, "canonical": canonical, "retryable": retryable,
            "delivered": delivered,
            "proof": _proof(state, canonical, retryable, tmp_path)}


def _run(fx, **kw):
    params = {"state_dir": fx["state"], "proof_path": fx["proof"],
              "expect_canonical": 22, "expect_retryable": 28,
              "collector_id": COL, "apply_changes": False}
    params.update(kw)
    return repair.run(**params)


def test_dry_run_plans_the_22_and_changes_nothing(fixture):
    before = _histogram(fixture["state"])
    report = _run(fixture)

    assert report["mode"] == "DRY_RUN"
    assert len(report["planned"]) == 22
    assert report["refused"] == []
    assert len(report["retryable_untouched"]) == 28
    assert report["repair"] is None
    assert _histogram(fixture["state"]) == before
    assert report["pass"] is True


def test_apply_repairs_exactly_the_22_and_leaves_the_28(fixture):
    report = _run(fixture, apply_changes=True, allow_schema_add=True)

    assert report["mode"] == "APPLY"
    assert len(report["repair"]["updated"]) == 22
    hist = _histogram(fixture["state"])
    assert hist[repair.DELIVERED] == 32       # 10 pre-existing + 22 repaired
    assert hist[repair.DELIVERING] == 28
    inv = report["invariants"]
    assert inv["delivered_delta_exact"]["actual"] == 22
    assert inv["delivering_delta_exact"]["actual"] == -22
    assert inv["total_rows_unchanged"]["holds"] is True
    assert inv["bookmarks_unchanged"]["holds"] is True
    assert inv["retryable_left_untouched"]["holds"] is True
    assert inv["no_other_status_changed"]["holds"] is True
    assert report["pass"] is True


def test_the_repaired_rows_are_marked_as_repaired_not_as_worker_deliveries(
        fixture):
    _run(fixture, apply_changes=True, allow_schema_add=True)
    conn = sqlite3.connect(os.path.join(fixture["state"], "outbox.db"))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                       (fixture["canonical"][0],)).fetchone()
    conn.close()
    marker = json.loads(row["recovery_json"])
    assert marker["phase"] == "G1-R6-A"
    assert marker["network_delivery_performed"] is False
    assert marker["from_status"] == repair.DELIVERING
    assert marker["to_status"] == repair.DELIVERED
    assert row["last_error"] is None


def test_the_28_retryable_rows_keep_their_attempt_budget(fixture):
    _run(fixture, apply_changes=True, allow_schema_add=True)
    conn = sqlite3.connect(os.path.join(fixture["state"], "outbox.db"))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT status, attempts, recovery_json FROM envelopes "
        " WHERE id IN (%s)" % ",".join("?" * 28),
        fixture["retryable"]).fetchall()
    conn.close()
    assert {r["status"] for r in rows} == {repair.DELIVERING}
    assert {r["attempts"] for r in rows} == {0}
    assert all(r["recovery_json"] is None for r in rows)


def test_a_second_apply_refuses_instead_of_double_counting(fixture):
    _run(fixture, apply_changes=True, allow_schema_add=True)
    with pytest.raises(SystemExit):
        _run(fixture, apply_changes=True, allow_schema_add=True)
    hist = _histogram(fixture["state"])
    assert hist[repair.DELIVERED] == 32
    assert hist[repair.DELIVERING] == 28


def test_an_identity_mismatch_refuses_the_whole_repair(fixture, tmp_path):
    bad = _proof(fixture["state"], fixture["canonical"], fixture["retryable"],
                 tmp_path, name="bad-key.json",
                 corrupt_key_for=fixture["canonical"][3])
    with pytest.raises(SystemExit):
        _run(fixture, proof_path=bad, apply_changes=True)
    assert _histogram(fixture["state"])[repair.DELIVERING] == 50


def test_a_proof_without_canonical_evidence_is_refused(fixture, tmp_path):
    bad = _proof(fixture["state"], fixture["canonical"], fixture["retryable"],
                 tmp_path, name="no-evidence.json", drop_evidence=True)
    with pytest.raises(SystemExit):
        _run(fixture, proof_path=bad, apply_changes=True)
    assert _histogram(fixture["state"])[repair.DELIVERING] == 50


def test_a_wrong_population_count_refuses_everything(fixture, tmp_path):
    short = _proof(fixture["state"], fixture["canonical"][:21],
                   fixture["retryable"], tmp_path, name="short.json")
    with pytest.raises(SystemExit):
        _run(fixture, proof_path=short, apply_changes=True)
    with pytest.raises(SystemExit):
        _run(fixture, expect_retryable=27, apply_changes=True)
    assert _histogram(fixture["state"])[repair.DELIVERING] == 50


def test_a_row_that_is_no_longer_delivering_is_refused(fixture):
    _set_status(fixture["state"], [fixture["canonical"][5]], "queued")
    with pytest.raises(SystemExit):
        _run(fixture, apply_changes=True)
    hist = _histogram(fixture["state"])
    assert hist[repair.DELIVERING] == 49
    assert hist["queued"] == 1


def test_a_missing_collector_identity_is_refused(fixture):
    with pytest.raises(SystemExit):
        _run(fixture, collector_id="", apply_changes=True)
    assert _histogram(fixture["state"])[repair.DELIVERING] == 50


def test_without_an_audit_column_the_repair_refuses_to_run(fixture):
    """A repair that cannot be recorded on the row is not performed."""
    with pytest.raises(SystemExit):
        _run(fixture, apply_changes=True)
    assert _histogram(fixture["state"])[repair.DELIVERING] == 50


def test_the_repair_never_imports_a_delivery_client():
    """Local bookkeeping has no destination, so it must have no client."""
    source = open(os.path.join(_ROOT, "scripts",
                               "g1_r6_local_accounting_repair.py"),
                  encoding="utf-8").read()
    for forbidden in ("IngestClient", "httpx", "requests", "DeliveryWorker",
                      "Outbox(", "windows_eventlog"):
        assert forbidden not in source, f"{forbidden} must not appear"
