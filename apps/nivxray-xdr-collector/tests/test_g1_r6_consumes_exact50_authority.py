"""R6 Phase A must consume the EXACT-50 authority file as actually written.

The Phase A repair was authored before `r5-inflight-50-server-reconciliation.json`
existed, so this rehearsal proves the two halves fit: a document in the exact
shape `g1_r5_inflight50_reconcile.py` writes (whose `rows` are verbatim
`services/delivery_reconciliation._resolve()` output) drives the repair to the
owner's contract, on an outbox carrying the real frozen population.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(_HERE, os.pardir, "scripts")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


r6 = _load("g1_r6_repair",
           os.path.join(_SCRIPTS, "g1_r6_local_accounting_repair.py"))
r5 = _load("g1_r5_exact50",
           os.path.join(_SCRIPTS, "g1_r5_inflight50_reconcile.py"))

COLLECTOR = "col_d6b0b9e8172246f29be9"
TENANT = "ten_f1a5479243e901cf159e230fa0"
SOURCE = "windows-security-evd"

# The frozen endpoint population the owner is holding.
FROZEN = {"delivered": 3284, "delivering": 50, "queued": 121993,
          "retrying": 125, "dead_letter": 0}
#: a status with zero rows simply does not appear in a GROUP BY histogram
FROZEN_HIST = {k: v for k, v in FROZEN.items() if v}
TOTAL = 125452
CANONICAL_N, RETRYABLE_N = 22, 28


def _raw(index: int) -> dict:
    return {"EventID": 4624, "RecordId": 900000 + index,
            "Channel": "Security"}


@pytest.fixture(scope="module")
def frozen_outbox(tmp_path_factory):
    """An outbox with exactly the endpoint's frozen histogram."""
    directory = str(tmp_path_factory.mktemp("frozen"))
    path = os.path.join(directory, "outbox.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE envelopes (id TEXT PRIMARY KEY, tenant_id TEXT, "
        "connector_id TEXT, source TEXT, source_event_id TEXT, raw_json TEXT, "
        "status TEXT, attempts INTEGER, next_attempt_at TEXT, "
        "last_error TEXT, updated_at TEXT, recovery_json TEXT)")
    conn.execute("CREATE TABLE windows_channel_state (channel TEXT, "
                 "bookmark TEXT)")
    conn.execute("INSERT INTO windows_channel_state VALUES "
                 "('Security', 'bm-frozen')")

    inflight, cursor = [], 0
    rows = []
    for status, count in FROZEN.items():
        for _ in range(count):
            ref = f"env-{cursor:06d}"
            attempts = 3 if status in ("delivering", "retrying") else 1
            rows.append((ref, TENANT, "conn-g1", SOURCE, f"sei-{cursor:06d}",
                         json.dumps(_raw(cursor)), status, attempts,
                         "2026-09-24T06:00:00+00:00" if status == "retrying"
                         else None,
                         "timeout" if status == "retrying" else None,
                         "2026-09-24T06:34:36+00:00", None))
            if status == "delivering":
                inflight.append((ref, cursor))
            cursor += 1
    conn.executemany("INSERT INTO envelopes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     rows)
    conn.commit()
    conn.close()
    return directory, path, inflight


def _authority_document(inflight, canonical_n=CANONICAL_N,
                        retryable_n=RETRYABLE_N, *, strip_evidence=False):
    """Exactly what g1_r5_inflight50_reconcile writes on PASS."""
    server_rows = []
    for position, (ref, index) in enumerate(inflight):
        canonical = position < canonical_n
        key = r5.delivery_key(tenant_id=TENANT, collector_id=COLLECTOR,
                              source=SOURCE,
                              source_event_id=f"sei-{index:06d}",
                              raw=_raw(index))
        event_id = f"evt_{index:06d}"
        server_rows.append({
            "ref": ref,
            "source_event_id": f"sei-{index:06d}",
            "collector_id": COLLECTOR,
            "connector_id": "conn-g1",
            "delivery_key": key,
            # the service lowercases the endpoint outcome
            "endpoint_outcome": "delivering",
            "disposition": "DELIVERED_CANONICAL" if canonical else "NOT_FOUND",
            "bucket": r5.CANONICAL if canonical else r5.RETRYABLE,
            "bucket_basis": "ENDPOINT_STILL_OPEN",
            "matched_by": "DELIVERY_KEY" if canonical else "NONE",
            "claim": ({"status": "COMPLETED", "stage": "canonical",
                       "delivery_count": 1, "duplicate_count": 0,
                       "trace_id": f"tr_{index}",
                       "canonical_event_id": event_id,
                       "incident_id": None, "raw_row_id": f"raw_{index}",
                       "raw_row_present": True, "review_reason": None}
                      if canonical else None),
            "evidence_ref": (None if (not canonical or strip_evidence)
                             else f"xdr_canonical_events/{event_id}"),
            "retained_raw_id": None,
        })
    canonical_refs = sorted(r["ref"] for r in server_rows
                            if r["bucket"] == r5.CANONICAL)
    retryable_refs = sorted(r["ref"] for r in server_rows
                            if r["bucket"] == r5.RETRYABLE)
    return {
        "phase": "G1-R5 evidence recovery · exact-50 in-flight reconciliation",
        "mode": "READ_ONLY_RECONCILE",
        "collector_id": COLLECTOR,
        "identities_requested": len(server_rows),
        "reconciliation_requests_issued": 1,
        "negative_control_issued": False,
        "buckets_local_recount": {r5.CANONICAL: len(canonical_refs),
                                  r5.RETRYABLE: len(retryable_refs)},
        "canonical_refs": canonical_refs,
        "retryable_refs": retryable_refs,
        "pass": True,
        "rows": server_rows,
    }


def _write(directory, document, name="r5-inflight-50-server-reconciliation.json"):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
    return path


def _run(directory, proof, apply_changes, **kwargs):
    return r6.run(state_dir=directory, proof_path=proof,
                  expect_canonical=CANONICAL_N, expect_retryable=RETRYABLE_N,
                  collector_id=COLLECTOR, apply_changes=apply_changes,
                  expect_total=TOTAL, **kwargs)


def test_dry_run_reads_the_exact50_authority_and_changes_nothing(
        frozen_outbox):
    directory, db_path, inflight = frozen_outbox
    proof = _write(directory, _authority_document(inflight))
    before = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    baseline = {r[0]: r[1] for r in before.execute(
        "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
    before.close()
    assert baseline == FROZEN_HIST

    report = _run(directory, proof, False)

    assert report["mode"] == "DRY_RUN"
    assert report["pass"] is True
    assert report["proof_counts"] == {"inflight": 50, "canonical": 22,
                                      "retryable": 28, "other": 0}
    assert len(report["planned"]) == 22
    assert report["refused"] == []
    assert len(report["retryable_untouched"]) == 28
    assert report["post_snapshot"]["status_histogram"] == FROZEN_HIST
    for name in ("database_file_unchanged", "bookmarks_unchanged",
                 "total_rows_unchanged", "retryable_rows_untouched_exactly",
                 "canonical_rows_untouched_in_dry_run",
                 "delivering_set_matches_the_proof", "expected_total_rows",
                 "no_network_delivery", "no_delivery_surface_loaded"):
        assert report["invariants"][name]["holds"] is True, name
    # every planned row is justified by per-row server proof
    for entry in report["planned"]:
        assert entry["canonical_event_id"]
        assert entry["evidence_ref"].startswith("xdr_canonical_events/")
        assert entry["local_status"] == "delivering"


def test_apply_reaches_the_contracted_post_state(frozen_outbox, tmp_path):
    """delivered 3284 -> 3306, delivering 50 -> 28, everything else frozen."""
    source_dir, source_db, inflight = frozen_outbox
    directory = str(tmp_path)
    with open(source_db, "rb") as src, \
            open(os.path.join(directory, "outbox.db"), "wb") as dst:
        dst.write(src.read())
    proof = _write(directory, _authority_document(inflight))

    report = _run(directory, proof, True)

    assert report["mode"] == "APPLY"
    assert report["pass"] is True
    assert len(report["repair"]["updated"]) == 22
    assert report["post_snapshot"]["status_histogram"] == {
        "delivered": 3306, "delivering": 28, "queued": 121993,
        "retrying": 125}
    assert report["post_snapshot"]["total"] == TOTAL
    assert report["invariants"]["bookmarks_unchanged"]["holds"] is True
    assert report["invariants"]["no_other_status_changed"]["holds"] is True
    assert report["invariants"]["retryable_rows_untouched_exactly"][
        "holds"] is True
    assert report["invariants"]["delivered_delta_exact"]["actual"] == 22
    assert report["invariants"]["delivering_delta_exact"]["actual"] == -22

    conn = sqlite3.connect(os.path.join(directory, "outbox.db"))
    conn.row_factory = sqlite3.Row
    # the 22 carry accounting provenance, NOT a worker delivery
    for ref in report["repair"]["updated"]:
        row = conn.execute("SELECT * FROM envelopes WHERE id=?",
                           (ref,)).fetchone()
        assert row["status"] == "delivered"
        marker = json.loads(row["recovery_json"])
        assert marker["phase"] == "G1-R6-A"
        assert marker["action"] == "local_accounting_repair"
        assert marker["network_delivery_performed"] is False
        assert marker["from_status"] == "delivering"
        assert marker["to_status"] == "delivered"
        assert "server reconciliation" in marker["basis"]
    # the 28 keep status, attempt budget and retry metadata, and carry no marker
    still = conn.execute("SELECT * FROM envelopes WHERE status='delivering'"
                         ).fetchall()
    assert len(still) == 28
    for row in still:
        assert row["attempts"] == 3
        assert row["recovery_json"] is None
    conn.close()


def test_a_second_apply_cannot_double_count(frozen_outbox, tmp_path):
    source_dir, source_db, inflight = frozen_outbox
    directory = str(tmp_path)
    with open(source_db, "rb") as src, \
            open(os.path.join(directory, "outbox.db"), "wb") as dst:
        dst.write(src.read())
    proof = _write(directory, _authority_document(inflight))
    _run(directory, proof, True)
    with pytest.raises(SystemExit) as ex:
        _run(directory, proof, True)
    assert "Nothing was changed" in str(ex.value)


def test_an_authority_file_missing_canonical_evidence_is_refused(
        frozen_outbox, tmp_path):
    source_dir, source_db, inflight = frozen_outbox
    directory = str(tmp_path)
    with open(source_db, "rb") as src, \
            open(os.path.join(directory, "outbox.db"), "wb") as dst:
        dst.write(src.read())
    proof = _write(directory,
                   _authority_document(inflight, strip_evidence=True))
    with pytest.raises(SystemExit) as ex:
        _run(directory, proof, True)
    assert "evidence_ref" in str(ex.value)


@pytest.mark.parametrize("canonical_n,retryable_n", [(21, 29), (23, 27)])
def test_any_split_other_than_22_28_is_refused(frozen_outbox, tmp_path,
                                               canonical_n, retryable_n):
    source_dir, source_db, inflight = frozen_outbox
    directory = str(tmp_path)
    with open(source_db, "rb") as src, \
            open(os.path.join(directory, "outbox.db"), "wb") as dst:
        dst.write(src.read())
    proof = _write(directory, _authority_document(
        inflight, canonical_n=canonical_n, retryable_n=retryable_n))
    with pytest.raises(SystemExit) as ex:
        _run(directory, proof, True)
    assert "expected exactly" in str(ex.value)


def test_an_untrusted_failed_authority_file_is_not_consumable(frozen_outbox,
                                                              tmp_path):
    """The FAILED-UNTRUSTED sibling has no top-level `rows`, by design."""
    source_dir, source_db, inflight = frozen_outbox
    directory = str(tmp_path)
    with open(source_db, "rb") as src, \
            open(os.path.join(directory, "outbox.db"), "wb") as dst:
        dst.write(src.read())
    untrusted = {"VERDICT": r5.UNTRUSTED_BANNER,
                 "failed_checks": ["canonical_exactly"],
                 "report": {"pass": False},
                 "raw_server_response": _authority_document(inflight)}
    proof = _write(directory, untrusted,
                   name="r5-inflight-50-server-reconciliation.json"
                        ".FAILED-UNTRUSTED.json")
    with pytest.raises(SystemExit) as ex:
        _run(directory, proof, True)
    assert "no reconciliation rows" in str(ex.value)
