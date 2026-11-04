"""G1-R4 · R3.1 health-gate prerequisite on a PRESERVED outbox.

The historical G1 endbox predates R3.1, so it has no `delivery_health_gate`
table at all. Two questions follow, and both must be answered honestly rather
than conveniently:

1.  is an ABSENT gate an outage? No. R3.1's contract is that a gate with no
    persisted state has OBSERVED NOTHING, and CLOSED is the truthful
    first-boot default. So absence must not block recovery — and equally, a
    fabricated `CLOSED` row must never be written, because a gate that has
    observed nothing may not claim to have observed health.
2.  can the table be created without disturbing 125,452 preserved rows? Yes,
    and it must be proven: schema-only, under a verified backup, with a
    before/after fingerprint of every envelope row and every bookmark.

These tests hold both answers, plus the one case that DOES block recovery: a
persisted row that says the destination is unavailable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import uuid

import pytest

from framework.outbox import Outbox

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "scripts", "g1_r4_recover_dead_letters.py")

#: The historical endpoint schema: envelopes + bookmarks, NO gate table,
#: NO failure_detail_json (that arrived with R2), NO recovery_json.
LEGACY_SCHEMA = """
CREATE TABLE envelopes (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, connector_id TEXT NOT NULL,
    source TEXT, source_event_id TEXT, collection_method TEXT,
    parser_version TEXT, source_timestamp TEXT, collection_timestamp TEXT,
    event_type TEXT, raw_json TEXT, canonical_json TEXT,
    declared_source TEXT, status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
    last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE windows_channel_state (
    tenant_id TEXT NOT NULL, collector_id TEXT NOT NULL, channel TEXT NOT NULL,
    bookmark_xml TEXT, last_record_id INTEGER, origin_computer TEXT,
    profile_id TEXT, updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, collector_id, channel));
"""

TARGET_ERROR = ("HTTP 404 | UNATTRIBUTED_FAILURE (no X-Request-ID) | "
                "retries exhausted")


def _insert(con, *, status, last_error, attempts, i):
    con.execute(
        "INSERT INTO envelopes (id, tenant_id, connector_id, source,"
        " source_event_id, collection_method, parser_version,"
        " source_timestamp, collection_timestamp, event_type, raw_json,"
        " canonical_json, declared_source, status, attempts, next_attempt_at,"
        " last_error, created_at, updated_at) VALUES"
        " (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"env-{status}-{i}", "ten_g1", "windows-eventlog-g1proof01",
         "windows_security", f"ten_g1|DESKTOP-A9HGFJJ|Security|{239000 + i}",
         "windows-eventlog", "wel/1", "2026-09-22T15:00:00Z",
         "2026-09-22T15:00:01Z", "logon_success",
         json.dumps({"xml": f"<Event>{i}</Event>", "channel": "Security"}),
         "{}", "windows_security", status, attempts,
         "2026-09-22T17:00:00Z", last_error, "2026-09-22T17:40:00Z",
         "2026-09-22T17:41:00Z"))


@pytest.fixture()
def legacy(tmp_path):
    """A pre-R3.1 outbox: dead letters, live rows and real bookmarks."""
    path = str(tmp_path / "outbox.db")
    con = sqlite3.connect(path, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(LEGACY_SCHEMA)
    for i in range(30):
        _insert(con, status="dead_letter", last_error=TARGET_ERROR,
                attempts=1, i=i)
    for i in range(10):
        _insert(con, status="queued", last_error=None, attempts=0, i=100 + i)
    for i in range(4):
        _insert(con, status="delivering", last_error=None, attempts=2,
                i=200 + i)
    for i in range(6):
        _insert(con, status="delivered", last_error=None, attempts=1,
                i=300 + i)
    for ch, rec in (("Security", 239192), ("Microsoft-Windows-Sysmon/"
                                           "Operational", 3286059)):
        con.execute("INSERT INTO windows_channel_state VALUES "
                    "(?,?,?,?,?,?,?,?)",
                    ("ten_g1", "col_d6b0b9e8172246f29be9", ch,
                     "<BookmarkList/>", rec, "DESKTOP-A9HGFJJ", "g1",
                     "2026-09-22T17:41:00Z"))
    con.close()
    return path


def _backup(db, tmp_path, name="outbox.backup.db"):
    dst = tmp_path / name
    dst.write_bytes(open(db, "rb").read())
    return str(dst)


def _run(*args, expect_rc=0):
    proc = subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True)
    assert proc.returncode == expect_rc, proc.stdout + proc.stderr
    start, end = proc.stdout.find("{"), proc.stdout.rfind("}")
    return json.loads(proc.stdout[start:end + 1])


def _fingerprint(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        h = hashlib.sha256()
        for r in con.execute("SELECT id, status, attempts, last_error, "
                             " next_attempt_at, updated_at FROM envelopes "
                             " ORDER BY id"):
            h.update(str(tuple(r)).encode())
        b = hashlib.sha256()
        for r in con.execute("SELECT * FROM windows_channel_state "
                             " ORDER BY rowid"):
            b.update(str(tuple(r)).encode())
        counts = {r[0]: r[1] for r in con.execute(
            "SELECT status, COUNT(*) FROM envelopes GROUP BY status")}
        return {"envelopes": h.hexdigest(), "bookmarks": b.hexdigest(),
                "counts": counts}
    finally:
        con.close()


def _tables(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()


# ══ the diagnosis ═════════════════════════════════════════════════
def test_a_legacy_outbox_reports_the_gate_as_absent_not_as_an_outage(legacy):
    rep = _run("--db", legacy)
    pre = rep["health_gate_prerequisite"]
    assert rep["schema"]["delivery_health_gate_table_present"] is False
    assert rep["schema"]["delivery_health_gate_row_present"] is False
    assert rep["persisted_health_gate"] is None
    assert pre["table_present"] is False
    assert pre["persisted_state"] is None
    assert pre["effective_state"] == "CLOSED"
    assert pre["satisfied"] is True          # absence is not an outage
    assert "first-boot" in pre["basis"]
    assert "must not claim" in pre["basis"]
    assert pre["durability"].startswith("ABSENT")


def test_a_legacy_outbox_also_lacks_the_r2_and_r4_columns(legacy):
    rep = _run("--db", legacy)
    assert rep["schema"]["failure_detail_json"] is False
    assert rep["schema"]["recovery_json"] is False


# ══ the initialization ═══════════════════════════════════════════
def test_b_init_requires_a_backup(legacy):
    proc = subprocess.run([sys.executable, TOOL, "--db", legacy,
                           "--init-health-gate"],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "--backup" in proc.stderr
    assert "delivery_health_gate" not in _tables(legacy)


def test_b_init_rejects_a_truncated_backup(legacy, tmp_path):
    bad = tmp_path / "trunc.db"
    bad.write_bytes(b"x")
    proc = subprocess.run([sys.executable, TOOL, "--db", legacy,
                           "--init-health-gate", "--backup", str(bad)],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "truncated" in proc.stderr
    assert "delivery_health_gate" not in _tables(legacy)


def test_b_init_creates_only_the_gate_table(legacy, tmp_path):
    before = _fingerprint(legacy)
    rep = _run("--db", legacy, "--init-health-gate",
               "--backup", _backup(legacy, tmp_path))
    after = _fingerprint(legacy)
    assert rep["result"] == "ACCEPTED"
    assert rep["rows_written"] == 0
    assert all(rep["proof"].values()), rep["proof"]
    assert sorted(_tables(legacy) - set(rep["integrity_before"]["tables"])) \
        == ["delivery_health_gate"]
    assert after == before               # every row and bookmark identical


def test_b_init_leaves_statuses_and_counts_untouched(legacy, tmp_path):
    rep = _run("--db", legacy, "--init-health-gate",
               "--backup", _backup(legacy, tmp_path))
    b, a = rep["integrity_before"], rep["integrity_after"]
    assert b["counts_by_status"] == a["counts_by_status"]
    assert b["counts_by_status"]["dead_letter"] == 30
    assert b["counts_by_status"]["delivering"] == 4   # NOT reset by init
    assert b["total_envelopes"] == a["total_envelopes"] == 50
    assert b["envelope_state_sha256"] == a["envelope_state_sha256"]
    assert b["max_updated_at"] == a["max_updated_at"]


def test_b_init_leaves_bookmarks_and_acquisition_state_untouched(legacy,
                                                                 tmp_path):
    rep = _run("--db", legacy, "--init-health-gate",
               "--backup", _backup(legacy, tmp_path))
    assert rep["integrity_before"]["bookmarks"] == \
        rep["integrity_after"]["bookmarks"]
    assert rep["integrity_before"]["bookmarks"]["rows"] == 2
    con = sqlite3.connect(legacy)
    rows = con.execute("SELECT channel, last_record_id, bookmark_xml, "
                       " updated_at FROM windows_channel_state "
                       " ORDER BY channel").fetchall()
    con.close()
    assert rows == [("Microsoft-Windows-Sysmon/Operational", 3286059,
                     "<BookmarkList/>", "2026-09-22T17:41:00Z"),
                    ("Security", 239192, "<BookmarkList/>",
                     "2026-09-22T17:41:00Z")]


def test_b_init_writes_no_gate_row_and_fabricates_no_observation(legacy,
                                                                 tmp_path):
    rep = _run("--db", legacy, "--init-health-gate",
               "--backup", _backup(legacy, tmp_path))
    assert rep["proof"]["no_gate_row_written"] is True
    con = sqlite3.connect(legacy)
    assert con.execute("SELECT COUNT(*) FROM delivery_health_gate"
                       ).fetchone()[0] == 0
    con.close()
    pre = rep["prerequisite"]
    assert pre["table_present"] is True
    assert pre["persisted_state"] is None
    assert pre["effective_state"] == "CLOSED"
    assert pre["satisfied"] is True
    assert pre["durability"] == "PRESENT"


def test_b_init_makes_table_presence_true_while_row_presence_stays_false(
        legacy, tmp_path):
    """The field the operator reads must say what it means: the table is
    present, and the ABSENCE of a row is the truthful first-boot state."""
    _run("--db", legacy, "--init-health-gate",
         "--backup", _backup(legacy, tmp_path))
    rep = _run("--db", legacy)
    assert rep["schema"]["delivery_health_gate_table_present"] is True
    assert rep["schema"]["delivery_health_gate_row_present"] is False
    assert rep["persisted_health_gate"] is None
    assert rep["health_gate_prerequisite"]["durability"] == "PRESENT"
    assert rep["health_gate_prerequisite"]["satisfied"] is True


def test_b_init_is_idempotent(legacy, tmp_path):
    backup = _backup(legacy, tmp_path)
    _run("--db", legacy, "--init-health-gate", "--backup", backup)
    before = _fingerprint(legacy)
    again = _run("--db", legacy, "--init-health-gate", "--backup", backup)
    assert again["result"] == "ALREADY_PRESENT"
    assert again["note"] == "no change was made"
    assert _fingerprint(legacy) == before


def test_b_init_ddl_matches_the_published_schema():
    """The DDL is repeated in the tool so a preserved database can be
    prepared without constructing an Outbox; it must not drift."""
    import importlib.util

    from framework import outbox as ob
    spec = importlib.util.spec_from_file_location("r4tool", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def norm(sql: str) -> str:
        sql = re.search(r"CREATE TABLE IF NOT EXISTS delivery_health_gate"
                        r".*?\);", sql, re.S).group(0)
        return re.sub(r"\s+", " ", sql).strip()

    assert norm(mod.GATE_DDL) == norm(ob.Outbox._SCHEMA)


def test_b_initialized_database_is_what_the_r31_gate_expects(legacy,
                                                             tmp_path):
    """After initialization the real R3.1 gate persists into that table —
    proving the prepared schema is the one the published code uses."""
    _run("--db", legacy, "--init-health-gate",
         "--backup", _backup(legacy, tmp_path))
    from framework.health_gate import (DEFAULT_DESTINATION_KEY,
                                       DeliveryHealthGate, GateState)
    store = Outbox(path=os.path.dirname(legacy))
    try:
        gate = DeliveryHealthGate(store=store, failure_threshold=2,
                                  cooldown_seconds=5.0)
        assert gate.state == GateState.CLOSED
        assert store.load_health_gate(DEFAULT_DESTINATION_KEY) is None
        gate.record_destination_failure("connection refused")
        gate.record_destination_failure("connection refused")
        row = store.load_health_gate(DEFAULT_DESTINATION_KEY)
        assert row["state"] == GateState.OPEN
        # and the revived gate reads it back
        revived = DeliveryHealthGate(store=store, failure_threshold=2,
                                     cooldown_seconds=5.0)
        assert revived.state == GateState.OPEN
    finally:
        store.close()


def test_opening_the_outbox_would_also_reset_delivering_rows(legacy):
    """Why a dedicated init exists: the published constructor creates the
    same table, but it ALSO runs restart recovery. On preserved evidence the
    smallest change is the DDL alone."""
    before = _fingerprint(legacy)
    store = Outbox(path=os.path.dirname(legacy))
    store.close()
    after = _fingerprint(legacy)
    assert "delivery_health_gate" in _tables(legacy)
    assert before["counts"]["delivering"] == 4
    assert after["counts"].get("delivering", 0) == 0     # reset to queued
    assert after["counts"]["queued"] == before["counts"]["queued"] + 4
    assert after["envelopes"] != before["envelopes"]
    # dead letters are still untouched by that path
    assert after["counts"]["dead_letter"] == before["counts"]["dead_letter"]


# ══ the case that DOES block recovery ════════════════════════════
def test_c_a_persisted_open_gate_blocks_recovery(legacy, tmp_path):
    backup = _backup(legacy, tmp_path)
    _run("--db", legacy, "--init-health-gate", "--backup", backup)
    con = sqlite3.connect(legacy, isolation_level=None)
    con.execute("INSERT INTO delivery_health_gate VALUES "
                "('nivx-ingest',1,'OPEN',5,30.0,1790000000.0,1,0,"
                "'destination unavailable','2026-09-23T10:00:00Z',"
                "'2026-09-23T10:00:00Z')")
    con.close()
    rep = _run("--db", legacy, expect_rc=0)
    assert rep["health_gate_prerequisite"]["satisfied"] is False
    refused = _run("--db", legacy, "--execute", "--expect-count", "30",
                   "--backup", backup, expect_rc=3)
    assert refused["result"] == "REFUSED"
    assert _fingerprint(legacy)["counts"]["dead_letter"] == 30


def test_c_a_persisted_closed_gate_satisfies_the_prerequisite(legacy,
                                                              tmp_path):
    backup = _backup(legacy, tmp_path)
    _run("--db", legacy, "--init-health-gate", "--backup", backup)
    con = sqlite3.connect(legacy, isolation_level=None)
    con.execute("INSERT INTO delivery_health_gate VALUES "
                "('nivx-ingest',1,'CLOSED',0,30.0,NULL,0,1,"
                "'destination acknowledged a delivery',"
                "'2026-09-23T10:00:00Z','2026-09-23T10:00:00Z')")
    con.close()
    rep = _run("--db", legacy)
    pre = rep["health_gate_prerequisite"]
    assert pre["persisted_state"] == "CLOSED"
    assert pre["satisfied"] is True


def test_c_strict_mode_cannot_be_satisfied_without_fabrication(legacy,
                                                               tmp_path):
    backup = _backup(legacy, tmp_path)
    _run("--db", legacy, "--init-health-gate", "--backup", backup)
    refused = _run("--db", legacy, "--execute", "--expect-count", "30",
                   "--require-persisted-gate", "--backup", backup,
                   expect_rc=3)
    assert "fabricating an observation" in refused["reason"]
    assert _fingerprint(legacy)["counts"]["dead_letter"] == 30


def test_c_absent_gate_does_not_block_a_dry_run_or_execution(legacy,
                                                             tmp_path):
    """The prerequisite is satisfied by truth, not by a written row."""
    rep = _run("--db", legacy, "--expect-count", "30")
    assert rep["expectation"]["matches"] is True
    assert rep["health_gate_prerequisite"]["satisfied"] is True
    assert rep["would_write"] is False
