#!/usr/bin/env python3
"""G1-R4 · Controlled dead-letter recovery — DRY-RUN BY DEFAULT.

The G1 outage dead-lettered 14,868 events for one reason only: an
infrastructure HTTP 404 with no application attribution was treated as a
terminal refusal on the FIRST attempt. R1 corrected the classification, R2
made every failure self-explaining, R3/R3.1 stopped a dead destination from
consuming retry budget across restarts, and B4 means a recovered event whose
record type has no coverage is RETAINED rather than lost.

This tool recovers exactly that population and nothing else. It is not a
dead-letter replay utility:

  * the target predicate is explicit, narrow and printed;
  * the operator must state the expected count, and a mismatch ABORTS before
    any write — the population is evidence, and a selection that does not
    match the evidence is a selection that must not run;
  * every recovered row keeps its original disposition under
    `recovery_json`, so recovery is auditable and reversible;
  * recovery only REQUEUES. It never delivers, never marks DELIVERED, never
    acknowledges and never touches a bookmark — delivery stays with the
    worker, under R1/R2/R3/R3.1 semantics;
  * `attempts` is reset for the recovered rows ONLY, because their recorded
    attempt was spent on an infrastructure fault that R1 now classifies as
    retryable; the reset value is recorded so the original accounting is not
    lost;
  * it refuses to run while a collector process holds the database, and
    refuses to write without a verified backup.

Modes
-----
    (default)    read-only dry run: population analysis + reconciliation plan
    --execute    bounded requeue, requires --expect-count and --backup
    --rollback   restore recovered rows to their recorded original state

Nothing in dry-run mode opens the database for writing: the connection is
`mode=ro`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

#: The authoritative G1 population: dead-lettered by an UNATTRIBUTED HTTP 404.
DEFAULT_ERROR_LIKE = "HTTP 404%"
TARGET_STATUS = "dead_letter"
RECOVERY_COLUMN = "recovery_json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(path: str, *, write: bool) -> sqlite3.Connection:
    if write:
        con = sqlite3.connect(path, isolation_level=None)
        con.row_factory = sqlite3.Row
        return con
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                              isolation_level=None)
        con.execute("SELECT COUNT(*) FROM envelopes").fetchone()
    except sqlite3.DatabaseError as exc:
        # A read-only open of a WAL database needs the -shm; when that is
        # impossible the WAL is bypassed instead, and the report SAYS SO —
        # silently reading a stale snapshot of an evidence population would
        # be worse than refusing.
        print(json.dumps({"warning": "READ_ONLY_WAL_FALLBACK",
                          "detail": f"{type(exc).__name__}: {exc}",
                          "effect": ("opened with immutable=1; rows still in "
                                     "an uncheckpointed -wal are NOT visible, "
                                     "so treat the counts as a lower bound")}),
              file=sys.stderr)
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True,
                              isolation_level=None)
    con.row_factory = sqlite3.Row
    return con


def _sha256(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _has_column(con: sqlite3.Connection, table: str, column: str) -> bool:
    return column in {r["name"] for r in
                      con.execute(f"PRAGMA table_info({table})")}


def _predicate(args) -> tuple[str, list]:
    """The target predicate, as SQL. Narrow, explicit, and printed."""
    clauses = ["status = ?", "last_error LIKE ?"]
    params: list = [TARGET_STATUS, args.error_like]
    if args.created_after:
        clauses.append("created_at >= ?")
        params.append(args.created_after)
    if args.created_before:
        clauses.append("created_at <= ?")
        params.append(args.created_before)
    if args.connector_id:
        clauses.append("connector_id = ?")
        params.append(args.connector_id)
    if args.tenant_id:
        clauses.append("tenant_id = ?")
        params.append(args.tenant_id)
    return " AND ".join(clauses), params


def _counts(con: sqlite3.Connection) -> dict:
    return {r["status"]: r["n"] for r in con.execute(
        "SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status")}


def _population(con: sqlite3.Connection, args) -> dict:
    where, params = _predicate(args)
    recovered_clause = ""
    if _has_column(con, "envelopes", RECOVERY_COLUMN):
        recovered_clause = f" AND {RECOVERY_COLUMN} IS NULL"
    target = con.execute(
        f"SELECT COUNT(*) AS n FROM envelopes WHERE {where}{recovered_clause}",
        params).fetchone()["n"]
    all_dead = con.execute(
        "SELECT COUNT(*) AS n FROM envelopes WHERE status=?",
        (TARGET_STATUS,)).fetchone()["n"]
    excluded = con.execute(
        "SELECT COALESCE(last_error,'<null>') AS e, COUNT(*) AS n "
        "  FROM envelopes WHERE status=? AND NOT (last_error LIKE ?) "
        " GROUP BY e ORDER BY n DESC LIMIT 20",
        (TARGET_STATUS, args.error_like)).fetchall()
    by_connector = con.execute(
        f"SELECT connector_id, COUNT(*) AS n FROM envelopes "
        f" WHERE {where}{recovered_clause} GROUP BY connector_id "
        f" ORDER BY n DESC", params).fetchall()
    by_source = con.execute(
        f"SELECT COALESCE(declared_source, source, '<null>') AS s, "
        f"       COUNT(*) AS n FROM envelopes "
        f" WHERE {where}{recovered_clause} GROUP BY s ORDER BY n DESC",
        params).fetchall()
    attempts = con.execute(
        f"SELECT attempts, COUNT(*) AS n FROM envelopes "
        f" WHERE {where}{recovered_clause} GROUP BY attempts "
        f" ORDER BY attempts", params).fetchall()
    window = con.execute(
        f"SELECT MIN(created_at) AS lo, MAX(created_at) AS hi FROM envelopes "
        f" WHERE {where}{recovered_clause}", params).fetchone()
    return {
        "predicate_sql": f"WHERE {where}{recovered_clause}",
        "predicate_params": params,
        "target_count": target,
        "all_dead_letter_count": all_dead,
        "non_target_dead_letter_count": all_dead - target,
        "non_target_reasons": [{"last_error": r["e"][:160], "rows": r["n"]}
                               for r in excluded],
        "target_by_connector": [{"connector_id": r["connector_id"],
                                 "rows": r["n"]} for r in by_connector],
        "target_by_source": [{"source": r["s"], "rows": r["n"]}
                             for r in by_source],
        "target_by_attempts": [{"attempts": r["attempts"], "rows": r["n"]}
                               for r in attempts],
        "target_created_window": {"first": window["lo"], "last": window["hi"]},
    }


def _health_gate(con: sqlite3.Connection) -> dict | None:
    try:
        row = con.execute(
            "SELECT * FROM delivery_health_gate LIMIT 1").fetchone()
    except sqlite3.DatabaseError:
        return None
    return {k: row[k] for k in row.keys()} if row else None


def dry_run(args) -> int:
    con = _connect(args.db, write=False)
    try:
        report = {
            "mode": "DRY_RUN_READ_ONLY",
            "opened": f"file:{args.db}?mode=ro",
            "at": _now(),
            "counts_by_status": _counts(con),
            "total_rows": con.execute(
                "SELECT COUNT(*) FROM envelopes").fetchone()[0],
            "population": _population(con, args),
            "schema": {
                "failure_detail_json": _has_column(con, "envelopes",
                                                   "failure_detail_json"),
                "recovery_json": _has_column(con, "envelopes",
                                             RECOVERY_COLUMN),
                "delivery_health_gate_table_present": _health_gate(
                    con) is not None,
            },
            "persisted_health_gate": _health_gate(con),
        }
        target = report["population"]["target_count"]
        report["expectation"] = {
            "expected_count": args.expect_count,
            "matches": (args.expect_count is None
                        or target == args.expect_count),
        }
        report["reconciliation_equation"] = (
            "TARGET = DELIVERED + (QUEUED|RETRYING) + RETAINED_UNSUPPORTED "
            "+ TERMINAL_ACCOUNTED ; any residual is unexplained loss and "
            "fails the gate")
        report["would_write"] = False
        print(json.dumps(report, indent=2, default=str))
        if args.expect_count is not None and target != args.expect_count:
            print(f"\nG1_R4_DRYRUN = REFUSED · target {target} != expected "
                  f"{args.expect_count}", file=sys.stderr)
            return 2
        print(f"\nG1_R4_DRYRUN = READY · {target} rows would be requeued "
              f"(nothing was written)")
        return 0
    finally:
        con.close()


def _guard_execute(args) -> None:
    if args.expect_count is None:
        raise SystemExit("--execute requires --expect-count (the population "
                         "is evidence; an unstated expectation must not run)")
    if not args.backup:
        raise SystemExit("--execute requires --backup <path to the verified "
                         "pre-recovery copy of outbox.db>")
    if not os.path.exists(args.backup):
        raise SystemExit(f"backup not found: {args.backup}")
    live_size = os.path.getsize(args.db)
    backup_size = os.path.getsize(args.backup)
    if backup_size < live_size * 0.5:
        raise SystemExit(f"backup looks truncated: {backup_size} bytes vs "
                         f"live {live_size} bytes")


def execute(args) -> int:
    _guard_execute(args)
    recovery_id = f"r4_{uuid.uuid4().hex[:16]}"
    con = _connect(args.db, write=True)
    try:
        before = _counts(con)
        pop = _population(con, args)
        if pop["target_count"] != args.expect_count:
            print(json.dumps({"result": "REFUSED",
                              "reason": "target count does not match the "
                                        "stated expectation",
                              "target_count": pop["target_count"],
                              "expected": args.expect_count}, indent=2))
            return 2
        gate = _health_gate(con)
        if gate and gate.get("state") not in (None, "CLOSED"):
            print(json.dumps({"result": "REFUSED",
                              "reason": "the destination health gate is not "
                                        "CLOSED; recovery must not queue into "
                                        "a known-unavailable destination",
                              "health_gate": gate}, indent=2))
            return 3

        if not _has_column(con, "envelopes", RECOVERY_COLUMN):
            con.execute(f"ALTER TABLE envelopes ADD COLUMN "
                        f"{RECOVERY_COLUMN} TEXT")

        where, params = _predicate(args)
        moved = 0
        batches = 0
        while moved < args.expect_count:
            rows = con.execute(
                f"SELECT id, status, attempts, last_error FROM envelopes "
                f" WHERE {where} AND {RECOVERY_COLUMN} IS NULL "
                f" ORDER BY created_at ASC LIMIT ?",
                (*params, args.batch_size)).fetchall()
            if not rows:
                break
            batches += 1
            now = _now()
            con.execute("BEGIN IMMEDIATE")
            try:
                for r in rows:
                    provenance = json.dumps({
                        "recovery_id": recovery_id,
                        "recovered_at": now,
                        "batch": batches,
                        "original_status": r["status"],
                        "original_attempts": int(r["attempts"]),
                        "original_last_error": r["last_error"],
                        "reason": ("G1-R4: dead-lettered by an unattributed "
                                   "infrastructure HTTP 404 that R1 now "
                                   "classifies as retryable"),
                    })
                    cur = con.execute(
                        f"UPDATE envelopes "
                        f"   SET status='queued', attempts=0, "
                        f"       next_attempt_at=?, updated_at=?, "
                        f"       {RECOVERY_COLUMN}=? "
                        f" WHERE id=? AND status=? "
                        f"   AND {RECOVERY_COLUMN} IS NULL",
                        (now, now, provenance, r["id"], TARGET_STATUS))
                    moved += cur.rowcount or 0
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
            if args.max_batches and batches >= args.max_batches:
                break

        after = _counts(con)
        report = {
            "mode": "EXECUTE",
            "recovery_id": recovery_id,
            "at": _now(),
            "batch_size": args.batch_size,
            "batches": batches,
            "requeued": moved,
            "counts_before": before,
            "counts_after": after,
            "delta_dead_letter": (after.get(TARGET_STATUS, 0)
                                  - before.get(TARGET_STATUS, 0)),
            "delta_queued": (after.get("queued", 0)
                             - before.get("queued", 0)),
            "accounting_holds": (
                before.get(TARGET_STATUS, 0) - after.get(TARGET_STATUS, 0)
                == moved
                and after.get("queued", 0) - before.get("queued", 0) == moved),
            "delivered_unchanged": (after.get("delivered", 0)
                                    == before.get("delivered", 0)),
            "note": ("requeue only — nothing was delivered, acknowledged or "
                     "marked DELIVERED by this tool"),
        }
        print(json.dumps(report, indent=2, default=str))
        ok = (report["accounting_holds"] and report["delivered_unchanged"]
              and moved == args.expect_count)
        print(f"\nG1_R4_RECOVERY = {'ACCEPTED' if ok else 'REVIEW'} · "
              f"{moved} requeued in {batches} batches")
        return 0 if ok else 4
    finally:
        con.close()


def rollback(args) -> int:
    con = _connect(args.db, write=True)
    try:
        if not _has_column(con, "envelopes", RECOVERY_COLUMN):
            print(json.dumps({"result": "NOTHING_TO_ROLLBACK",
                              "reason": "no recovery column exists"}))
            return 0
        q = f"SELECT id, {RECOVERY_COLUMN} FROM envelopes " \
            f" WHERE {RECOVERY_COLUMN} IS NOT NULL"
        params: tuple = ()
        if args.recovery_id:
            q += f" AND json_extract({RECOVERY_COLUMN}, '$.recovery_id')=?"
            params = (args.recovery_id,)
        rows = con.execute(q, params).fetchall()
        restored = 0
        now = _now()
        con.execute("BEGIN IMMEDIATE")
        try:
            for r in rows:
                prov = json.loads(r[RECOVERY_COLUMN])
                cur = con.execute(
                    f"UPDATE envelopes SET status=?, attempts=?, "
                    f"       last_error=?, updated_at=?, "
                    f"       {RECOVERY_COLUMN}=NULL "
                    f" WHERE id=? AND status='queued'",
                    (prov["original_status"], prov["original_attempts"],
                     prov["original_last_error"], now, r["id"]))
                restored += cur.rowcount or 0
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise
        print(json.dumps({"mode": "ROLLBACK", "candidates": len(rows),
                          "restored": restored,
                          "not_restored_because_already_progressed":
                              len(rows) - restored,
                          "counts": _counts(con)}, indent=2))
        return 0
    finally:
        con.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="path to outbox.db")
    ap.add_argument("--error-like", default=DEFAULT_ERROR_LIKE)
    ap.add_argument("--expect-count", type=int, default=None)
    ap.add_argument("--batch-size", type=int, default=500)
    ap.add_argument("--max-batches", type=int, default=0)
    ap.add_argument("--created-after", default=None)
    ap.add_argument("--created-before", default=None)
    ap.add_argument("--connector-id", default=None)
    ap.add_argument("--tenant-id", default=None)
    ap.add_argument("--backup", default=None)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--recovery-id", default=None)
    args = ap.parse_args()
    if args.rollback:
        return rollback(args)
    if args.execute:
        return execute(args)
    return dry_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
