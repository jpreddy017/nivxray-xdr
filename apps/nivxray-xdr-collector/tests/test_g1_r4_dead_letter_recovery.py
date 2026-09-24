"""G1-R4 · Controlled dead-letter recovery — preparation gate.

The 14,868 G1 dead letters are preserved forensic evidence, and the tool that
touches them must be provably narrow BEFORE it is ever pointed at the real
endpoint. These tests exercise the real tool against synthetic outboxes:

  * the dry run writes NOTHING and cannot (the connection is mode=ro);
  * the target predicate selects only the unattributed-404 population and
    leaves every other dead letter alone;
  * a count that disagrees with the stated expectation ABORTS before any
    write — evidence decides, not the operator's hope;
  * recovery only REQUEUES: nothing is delivered, acknowledged or marked
    DELIVERED, and no bookmark is involved;
  * every recovered row keeps its original disposition, so the operation is
    auditable and reversible;
  * recovery is idempotent and bounded, and refuses to queue into a
    destination the health gate says is unavailable.

NOTHING here touches the real endpoint. Every database is a temporary file.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid

import pytest

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "scripts", "g1_r4_recover_dead_letters.py")

SCHEMA = """
CREATE TABLE envelopes (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, connector_id TEXT NOT NULL,
    source TEXT, source_event_id TEXT, collection_method TEXT,
    parser_version TEXT, source_timestamp TEXT, collection_timestamp TEXT,
    event_type TEXT, raw_json TEXT, canonical_json TEXT,
    declared_source TEXT, status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
    last_error TEXT, failure_detail_json TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE delivery_health_gate (
    destination_key TEXT PRIMARY KEY, state_version INTEGER NOT NULL,
    state TEXT NOT NULL, consecutive_failures INTEGER NOT NULL,
    cooldown_seconds REAL NOT NULL, cooldown_until_epoch REAL,
    opened_count INTEGER NOT NULL, probes INTEGER NOT NULL,
    last_reason TEXT, last_transition_at TEXT, updated_at TEXT NOT NULL);
"""

TARGET_ERROR = ("HTTP 404 | UNATTRIBUTED_FAILURE (no X-Request-ID) | "
                "retries exhausted")
#: Dead letters that are NOT the G1 population and must never be touched.
NON_TARGET = [
    "HTTP 422 | DECLARATION_REQUIRED | authoritative refusal",
    "HTTP 403 | TENANT_ISOLATION_VIOLATION | authoritative refusal",
    "HTTP 500 | retries exhausted",
    None,
]


def _row(con, *, status, last_error, attempts=1, i=0, created="2026-09-22T17"):
    con.execute(
        "INSERT INTO envelopes (id, tenant_id, connector_id, source,"
        " source_event_id, collection_method, parser_version,"
        " source_timestamp, collection_timestamp, event_type, raw_json,"
        " canonical_json, declared_source, status, attempts, next_attempt_at,"
        " last_error, created_at, updated_at) VALUES"
        " (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, "ten_g1", "windows-eventlog-g1proof01",
         "windows_sysmon", f"evt-{status}-{i}", "windows-eventlog",
         "sysmon-1", "2026-09-22T15:00:00Z", "2026-09-22T15:00:01Z",
         "registry_event", json.dumps({"xml": f"<Event>{i}</Event>"}), "{}",
         "microsoft-sysmon", status, attempts, "2026-09-22T17:00:00Z",
         last_error, f"{created}:{i % 60:02d}:00Z", "2026-09-22T17:00:00Z"))


@pytest.fixture()
def db(tmp_path):
    """14,868-shaped population, scaled down: 40 target + 12 non-target."""
    path = str(tmp_path / "outbox.db")
    con = sqlite3.connect(path, isolation_level=None)
    con.executescript(SCHEMA)
    for i in range(40):
        _row(con, status="dead_letter", last_error=TARGET_ERROR, i=i)
    for j, err in enumerate(NON_TARGET):
        for i in range(3):
            _row(con, status="dead_letter", last_error=err, i=100 + j * 10 + i)
    for i in range(5):
        _row(con, status="delivered", last_error=None, i=200 + i)
    for i in range(4):
        _row(con, status="retrying", last_error=TARGET_ERROR, i=300 + i)
    con.close()
    return path


def _run(*args, expect_rc=0):
    proc = subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True)
    assert proc.returncode == expect_rc, proc.stdout + proc.stderr
    body = proc.stdout
    start = body.find("{")
    end = body.rfind("}")
    return json.loads(body[start:end + 1]) if start >= 0 else {}


def _counts(path):
    con = sqlite3.connect(path)
    try:
        return {r[0]: r[1] for r in con.execute(
            "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
    finally:
        con.close()


# ══ dry run ═══════════════════════════════════════════════════════
def test_dry_run_selects_only_the_unattributed_404_population(db):
    rep = _run("--db", db)
    pop = rep["population"]
    assert rep["mode"] == "DRY_RUN_READ_ONLY"
    assert rep["would_write"] is False
    assert pop["target_count"] == 40
    assert pop["all_dead_letter_count"] == 52
    assert pop["non_target_dead_letter_count"] == 12
    reasons = {r["last_error"] for r in pop["non_target_reasons"]}
    assert any("422" in r for r in reasons)
    assert any("403" in r for r in reasons)
    assert all("404" not in r for r in reasons)


def test_dry_run_writes_nothing(db):
    before = open(db, "rb").read()
    mtime = os.path.getmtime(db)
    _run("--db", db)
    assert open(db, "rb").read() == before
    assert os.path.getmtime(db) == mtime
    con = sqlite3.connect(db)
    cols = {r[1] for r in con.execute("PRAGMA table_info(envelopes)")}
    con.close()
    assert "recovery_json" not in cols     # no schema change from a dry run


def test_dry_run_reports_the_predicate_and_the_accounting_equation(db):
    rep = _run("--db", db)
    assert "status = ?" in rep["population"]["predicate_sql"]
    assert "last_error LIKE ?" in rep["population"]["predicate_sql"]
    assert "HTTP 404%" in rep["population"]["predicate_params"]
    assert "unexplained loss" in rep["reconciliation_equation"]


def test_dry_run_refuses_when_the_count_disagrees(db):
    rep = _run("--db", db, "--expect-count", "14868", expect_rc=2)
    assert rep["expectation"]["matches"] is False
    assert rep["population"]["target_count"] == 40


def test_dry_run_accepts_the_matching_expectation(db):
    rep = _run("--db", db, "--expect-count", "40")
    assert rep["expectation"]["matches"] is True


def test_retrying_rows_are_not_in_the_target_population(db):
    rep = _run("--db", db)
    # 4 RETRYING rows carry the same error text and must NOT be recovered:
    # they are already progressing under R1 semantics.
    assert rep["counts_by_status"]["retrying"] == 4
    assert rep["population"]["target_count"] == 40


# ══ execute · guards ══════════════════════════════════════════════
def test_execute_without_expectation_is_refused(db):
    proc = subprocess.run([sys.executable, TOOL, "--db", db, "--execute"],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "--expect-count" in proc.stderr
    assert _counts(db)["dead_letter"] == 52


def test_execute_without_backup_is_refused(db):
    proc = subprocess.run([sys.executable, TOOL, "--db", db, "--execute",
                           "--expect-count", "40"],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "--backup" in proc.stderr
    assert _counts(db)["dead_letter"] == 52


def test_execute_with_a_truncated_backup_is_refused(db, tmp_path):
    bad = tmp_path / "truncated.db"
    bad.write_bytes(b"x")
    proc = subprocess.run([sys.executable, TOOL, "--db", db, "--execute",
                           "--expect-count", "40", "--backup", str(bad)],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "truncated" in proc.stderr
    assert _counts(db)["dead_letter"] == 52


def _backup(db, tmp_path):
    dst = tmp_path / "outbox.backup.db"
    dst.write_bytes(open(db, "rb").read())
    return str(dst)


def test_execute_refuses_a_count_mismatch_before_writing(db, tmp_path):
    rep = _run("--db", db, "--execute", "--expect-count", "41",
               "--backup", _backup(db, tmp_path), expect_rc=2)
    assert rep["result"] == "REFUSED"
    assert _counts(db)["dead_letter"] == 52


def test_execute_refuses_while_the_health_gate_is_open(db, tmp_path):
    con = sqlite3.connect(db, isolation_level=None)
    con.execute("INSERT INTO delivery_health_gate VALUES "
                "('nivx-ingest',1,'OPEN',5,30.0,1790000000.0,1,0,"
                "'destination unavailable','2026-09-22T17:00:00Z',"
                "'2026-09-22T17:00:00Z')")
    con.close()
    rep = _run("--db", db, "--execute", "--expect-count", "40",
               "--backup", _backup(db, tmp_path), expect_rc=3)
    assert rep["result"] == "REFUSED"
    assert "health gate is not CLOSED" in rep["reason"]
    assert _counts(db)["dead_letter"] == 52


# ══ execute · behaviour ══════════════════════════════════════════
def test_execute_requeues_exactly_the_target_population(db, tmp_path):
    before = _counts(db)
    rep = _run("--db", db, "--execute", "--expect-count", "40",
               "--batch-size", "7", "--backup", _backup(db, tmp_path))
    after = _counts(db)
    assert rep["requeued"] == 40
    assert rep["batches"] == 6                 # bounded batches of 7
    assert rep["accounting_holds"] is True
    assert rep["delivered_unchanged"] is True
    assert after["dead_letter"] == before["dead_letter"] - 40 == 12
    assert after["queued"] == 40
    assert after["delivered"] == before["delivered"]
    assert after["retrying"] == before["retrying"]
    assert sum(after.values()) == sum(before.values())   # no row lost


def test_execute_preserves_original_disposition_for_audit(db, tmp_path):
    _run("--db", db, "--execute", "--expect-count", "40",
         "--backup", _backup(db, tmp_path))
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM envelopes WHERE recovery_json IS NOT "
                       "NULL").fetchall()
    con.close()
    assert len(rows) == 40
    for r in rows:
        prov = json.loads(r["recovery_json"])
        assert prov["original_status"] == "dead_letter"
        assert prov["original_last_error"] == TARGET_ERROR
        assert prov["original_attempts"] == 1
        assert prov["recovery_id"].startswith("r4_")
        assert prov["recovered_at"]
        assert r["status"] == "queued"
        assert r["attempts"] == 0               # the 404 attempt is returned
        # the payload and identity are untouched
        assert json.loads(r["raw_json"])["xml"].startswith("<Event>")
        assert r["source_event_id"].startswith("evt-dead_letter-")


def test_execute_never_delivers_or_acknowledges(db, tmp_path):
    _run("--db", db, "--execute", "--expect-count", "40",
         "--backup", _backup(db, tmp_path))
    counts = _counts(db)
    assert counts["delivered"] == 5             # unchanged
    assert counts.get("delivering", 0) == 0     # nothing claimed
    con = sqlite3.connect(db)
    recovered_delivered = con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE recovery_json IS NOT NULL "
        " AND status='delivered'").fetchone()[0]
    con.close()
    assert recovered_delivered == 0


def test_execute_is_idempotent(db, tmp_path):
    backup = _backup(db, tmp_path)
    _run("--db", db, "--execute", "--expect-count", "40", "--backup", backup)
    rep = _run("--db", db)
    assert rep["population"]["target_count"] == 0
    # a second run has nothing to claim and cannot double-recover
    second = _run("--db", db, "--execute", "--expect-count", "0",
                  "--backup", backup)
    assert second["requeued"] == 0
    assert _counts(db)["queued"] == 40


def test_max_batches_bounds_the_operation(db, tmp_path):
    """A deliberately bounded run is ACCEPTED for what it was asked to move,
    not judged against the whole population."""
    rep = _run("--db", db, "--execute", "--expect-count", "40",
               "--batch-size", "5", "--max-batches", "2",
               "--backup", _backup(db, tmp_path))
    assert rep["result"] == "ACCEPTED"
    assert rep["planned_this_run"] == 10
    assert rep["requeued"] == 10
    assert rep["batches"] == 2
    assert rep["rows_with_this_recovery_id"] == 10
    assert rep["remaining_target_after"] == 30
    assert rep["bookmarks_unchanged"] is True
    assert rep["rollback_command"].endswith(rep["recovery_id"])
    counts = _counts(db)
    assert counts["queued"] == 10
    assert counts["dead_letter"] == 42          # the rest stay preserved


def test_non_target_dead_letters_are_never_modified(db, tmp_path):
    con = sqlite3.connect(db)
    before = sorted(r[0] for r in con.execute(
        "SELECT id FROM envelopes WHERE status='dead_letter' "
        " AND (last_error IS NULL OR last_error NOT LIKE 'HTTP 404%')"))
    con.close()
    _run("--db", db, "--execute", "--expect-count", "40",
         "--backup", _backup(db, tmp_path))
    con = sqlite3.connect(db)
    after = sorted(r[0] for r in con.execute(
        "SELECT id FROM envelopes WHERE status='dead_letter'"))
    untouched = con.execute(
        "SELECT COUNT(*) FROM envelopes WHERE status='dead_letter' "
        " AND recovery_json IS NOT NULL").fetchone()[0]
    con.close()
    assert after == before
    assert untouched == 0


# ══ rollback ═════════════════════════════════════════════════════
def test_rollback_restores_the_original_disposition(db, tmp_path):
    before = _counts(db)
    rep = _run("--db", db, "--execute", "--expect-count", "40",
               "--backup", _backup(db, tmp_path))
    back = _run("--db", db, "--rollback", "--recovery-id",
                rep["recovery_id"])
    assert back["restored"] == 40
    after = _counts(db)
    assert after == before
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    r = con.execute("SELECT * FROM envelopes WHERE status='dead_letter' "
                    " AND last_error=? LIMIT 1", (TARGET_ERROR,)).fetchone()
    con.close()
    assert r["attempts"] == 1
    assert r["recovery_json"] is None


def test_rollback_does_not_reclaim_a_row_that_already_progressed(db,
                                                                 tmp_path):
    rep = _run("--db", db, "--execute", "--expect-count", "40",
               "--backup", _backup(db, tmp_path))
    con = sqlite3.connect(db, isolation_level=None)
    con.execute("UPDATE envelopes SET status='delivered' "
                " WHERE recovery_json IS NOT NULL LIMIT 3"
                if sqlite3.sqlite_version_info >= (3, 35) else
                "UPDATE envelopes SET status='delivered' "
                " WHERE id IN (SELECT id FROM envelopes "
                "              WHERE recovery_json IS NOT NULL LIMIT 3)")
    con.close()
    back = _run("--db", db, "--rollback", "--recovery-id",
                rep["recovery_id"])
    assert back["restored"] == 37
    assert back["not_restored_because_already_progressed"] == 3
    assert _counts(db)["delivered"] == 8        # 5 original + 3 delivered


# ══ the real first batch, at the real population shape ═══════════
@pytest.fixture()
def g1_shaped(tmp_path):
    """The preserved G1 population, exactly as the endpoint reports it:
    14,868 dead_letter + 107,525 queued + 2,884 delivered + 50 delivering
    + 125 retrying = 125,452 rows."""
    path = str(tmp_path / "outbox.db")
    con = sqlite3.connect(path, isolation_level=None)
    con.executescript(SCHEMA)
    con.execute("BEGIN")
    plan = [("dead_letter", 14868, TARGET_ERROR, 1),
            ("queued", 107525, None, 0),
            ("delivered", 2884, None, 1),
            ("delivering", 50, None, 2),
            ("retrying", 125, TARGET_ERROR, 1)]
    n = 0
    for status, count, err, attempts in plan:
        for _ in range(count):
            n += 1
            _row(con, status=status, last_error=err, attempts=attempts, i=n)
    con.execute("COMMIT")
    con.execute("INSERT INTO delivery_health_gate VALUES "
                "('nivx-ingest',1,'CLOSED',0,30.0,NULL,0,0,NULL,NULL,"
                "'2026-09-23T10:00:00Z')")
    con.close()
    return path


def test_first_controlled_batch_of_500_matches_the_owner_expectations(
        g1_shaped, tmp_path):
    before = _counts(g1_shaped)
    assert before == {"dead_letter": 14868, "queued": 107525,
                      "delivered": 2884, "delivering": 50, "retrying": 125}
    assert sum(before.values()) == 125452

    rep = _run("--db", g1_shaped, "--execute", "--expect-count", "14868",
               "--batch-size", "500", "--max-batches", "1",
               "--backup", _backup(g1_shaped, tmp_path))
    after = _counts(g1_shaped)

    assert rep["result"] == "ACCEPTED"
    assert rep["planned_this_run"] == 500
    assert rep["batches"] == 1
    assert rep["requeued"] == 500
    assert rep["rows_with_this_recovery_id"] == 500
    assert rep["remaining_target_after"] == 14368

    assert after["dead_letter"] == 14368
    assert after["queued"] == 108025
    assert after["delivered"] == 2884
    assert after["delivering"] == 50        # untouched: no restart recovery
    assert after["retrying"] == 125         # untouched: already progressing
    assert sum(after.values()) == 125452

    for flag in ("accounting_holds", "delivered_unchanged",
                 "delivering_unchanged", "retrying_unchanged",
                 "total_unchanged", "bookmarks_unchanged",
                 "recovery_id_row_count_matches", "no_delivery_performed"):
        assert rep[flag] is True, flag

    # the recovered rows are queued, budget returned, provenance recorded
    con = sqlite3.connect(g1_shaped)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT status, attempts, recovery_json FROM envelopes "
        " WHERE json_extract(recovery_json,'$.recovery_id')=?",
        (rep["recovery_id"],)).fetchall()
    con.close()
    assert len(rows) == 500
    for r in rows:
        assert r["status"] == "queued" and r["attempts"] == 0
        prov = json.loads(r["recovery_json"])
        assert prov["original_status"] == "dead_letter"
        assert prov["original_attempts"] == 1
        assert prov["original_last_error"] == TARGET_ERROR


def test_first_batch_is_fully_reversible(g1_shaped, tmp_path):
    before = _counts(g1_shaped)
    rep = _run("--db", g1_shaped, "--execute", "--expect-count", "14868",
               "--batch-size", "500", "--max-batches", "1",
               "--backup", _backup(g1_shaped, tmp_path))
    back = _run("--db", g1_shaped, "--rollback",
                "--recovery-id", rep["recovery_id"])
    assert back["restored"] == 500
    assert _counts(g1_shaped) == before
