"""Durable acquisition state — a GENERIC collector primitive.

Microsoft 365 is its first consumer, not its reason for existing. Any
polling connector that pulls vendor-side *batches* (content blobs, export
files, paged windows) can use it: DNS, firewall, cloud, SaaS.

The invariant this exists to protect:

    A collector restart must neither silently skip an uncollected window
    nor produce uncontrolled duplicate evidence.

To keep that provable, four states are kept distinct and never conflated:

    ACQUIRED   the vendor handed us the batch (we read it)
    QUEUED     its records are in the durable outbox
    DELIVERED  the authoritative NivX ingest returned 2xx per record
    COMMITTED  every record of the batch is DELIVERED — only now may the
               collection window advance past it

"Microsoft returned it" is therefore never treated as "NivX accepted it".
An ACQUIRED-but-not-COMMITTED batch is re-acquired after a restart (no
silent skip); the outbox's unique `(tenant, connector, source_event_id)`
key absorbs the re-delivery (no uncontrolled duplication).

Storage reuses the EXISTING durable mechanism — the same SQLite database as
the outbox (`${XDR_STATE_DIR}/outbox.db`) — so acquisition state and
delivery acknowledgement share one durability boundary. No second database
is introduced.

Scoping is always `(tenant_id, connector_id, stream)`. One collector cannot
read, claim or advance another tenant's or another connector's state.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from framework.identity import collector_id
from framework.outbox import OutboxStatus

#: A claim is a lease, so a crashed collector's batch becomes re-claimable
#: instead of being stranded forever.
DEFAULT_LEASE_SECONDS = 600

ACQUIRED = "acquired"
COMMITTED = "committed"
#: A batch whose non-accepted records are all quarantined with immutable
#: failure evidence. It is DONE, but it is NOT `committed`: the two must
#: never be conflated, because this one produced fewer pieces of evidence
#: than it acquired.
COMPLETED_WITH_TERMINAL_RECORDS = "completed_with_terminal_records"

#: Terminal-record event kinds. The table is append-only: a replay adds a
#: new event, it never rewrites the original terminal decision.
EVENT_QUARANTINED = "quarantined"
EVENT_REPLAY_REQUESTED = "replay_requested"

#: claim_batch outcomes
CLAIMED = "CLAIMED"
ALREADY_COMMITTED = "ALREADY_COMMITTED"
CLAIMED_ELSEWHERE = "CLAIMED_ELSEWHERE"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class AcquisitionState:
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS acquisition_batch (
        tenant_id        TEXT NOT NULL,
        connector_id     TEXT NOT NULL,
        stream           TEXT NOT NULL,
        batch_id         TEXT NOT NULL,
        declared_source  TEXT,
        state            TEXT NOT NULL,
        claim_owner      TEXT,
        claim_expires_at TEXT,
        reference        TEXT,
        batch_created    TEXT,
        batch_expires    TEXT,
        record_keys_json TEXT,
        window_end       TEXT,
        blocked_reason   TEXT,
        first_seen_at    TEXT NOT NULL,
        committed_at     TEXT,
        PRIMARY KEY (tenant_id, connector_id, stream, batch_id)
    );
    CREATE INDEX IF NOT EXISTS ix_acq_batch_state
        ON acquisition_batch(tenant_id, connector_id, stream, state);
    CREATE TABLE IF NOT EXISTS acquisition_window (
        tenant_id       TEXT NOT NULL,
        connector_id    TEXT NOT NULL,
        stream          TEXT NOT NULL,
        declared_source TEXT,
        committed_until TEXT,
        pending_until   TEXT,
        next_page_ref   TEXT,
        updated_at      TEXT,
        PRIMARY KEY (tenant_id, connector_id, stream)
    );
    -- Append-only terminal/quarantine history. Rows are never UPDATEd:
    -- a recovery attempt appends a new event so the original terminal
    -- decision survives as proof.
    CREATE TABLE IF NOT EXISTS acquisition_terminal_record (
        id               TEXT PRIMARY KEY,
        event_kind       TEXT NOT NULL,
        tenant_id        TEXT NOT NULL,
        connector_id     TEXT NOT NULL,
        stream           TEXT NOT NULL,
        batch_id         TEXT NOT NULL,
        record_key       TEXT NOT NULL,
        acquisition_ref  TEXT,
        outbox_row_id    TEXT,
        rejection_code   TEXT,
        rejection_reason TEXT,
        attempts         INTEGER,
        first_attempt_at TEXT,
        last_attempt_at  TEXT,
        decision         TEXT,
        decision_basis   TEXT,
        decided_by       TEXT,
        decided_at       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_acq_terminal_scope
        ON acquisition_terminal_record(tenant_id, connector_id, stream,
                                       batch_id, record_key);
    """

    def __init__(self, path: Optional[str] = None, *,
                 lease_seconds: int = DEFAULT_LEASE_SECONDS,
                 owner: Optional[str] = None,
                 connection: Optional[sqlite3.Connection] = None) -> None:
        self.lease_seconds = lease_seconds
        self.owner = owner or collector_id()
        self._lock = threading.RLock()
        if connection is not None:
            # Share the outbox's own connection when one is handed in.
            self._conn = connection
            self._db_path = "shared"
        else:
            state_dir = path or os.environ.get("XDR_STATE_DIR")
            self._db_path = ":memory:" if not state_dir else os.path.join(
                state_dir, "outbox.db")
            if state_dir:
                os.makedirs(state_dir, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path,
                                         check_same_thread=False,
                                         isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(self._SCHEMA)

    # ── windows ──────────────────────────────────────────────────
    def window(self, tenant_id: str, connector_id_: str,
               stream: str) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute("""
                SELECT * FROM acquisition_window
                 WHERE tenant_id=? AND connector_id=? AND stream=?
            """, (tenant_id, connector_id_, stream)).fetchone()
        if not row:
            return {"committed_until": None, "pending_until": None,
                    "next_page_ref": None}
        return {"committed_until": row["committed_until"],
                "pending_until": row["pending_until"],
                "next_page_ref": row["next_page_ref"]}

    def set_pending_window(self, tenant_id: str, connector_id_: str,
                           stream: str, *, pending_until: Optional[str],
                           next_page_ref: Optional[str] = None,
                           declared_source: Optional[str] = None) -> None:
        """Record where acquisition has REACHED. Never where it committed."""
        with self._lock:
            self._conn.execute("""
                INSERT INTO acquisition_window
                    (tenant_id, connector_id, stream, declared_source,
                     committed_until, pending_until, next_page_ref,
                     updated_at)
                VALUES (?,?,?,?,NULL,?,?,?)
                ON CONFLICT(tenant_id, connector_id, stream) DO UPDATE SET
                    pending_until=excluded.pending_until,
                    next_page_ref=excluded.next_page_ref,
                    declared_source=COALESCE(excluded.declared_source,
                                             acquisition_window.declared_source),
                    updated_at=excluded.updated_at
            """, (tenant_id, connector_id_, stream, declared_source,
                  pending_until, next_page_ref, _iso(_utcnow())))

    # ── batches ──────────────────────────────────────────────────
    def claim_batch(self, tenant_id: str, connector_id_: str, stream: str,
                    batch_id: str, *, reference: Optional[str] = None,
                    batch_created: Optional[str] = None,
                    batch_expires: Optional[str] = None,
                    declared_source: Optional[str] = None,
                    window_end: Optional[str] = None) -> str:
        """Take ownership of one vendor batch, or explain why we cannot."""
        now = _utcnow()
        lease = _iso(now + timedelta(seconds=self.lease_seconds))
        with self._lock:
            row = self._conn.execute("""
                SELECT state, claim_owner, claim_expires_at
                  FROM acquisition_batch
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (tenant_id, connector_id_, stream, batch_id)).fetchone()
            if row:
                if row["state"] == COMMITTED:
                    return ALREADY_COMMITTED
                if row["state"] == COMPLETED_WITH_TERMINAL_RECORDS:
                    return ALREADY_COMMITTED
                held_by_other = (row["claim_owner"] or "") != self.owner
                lease_live = bool(row["claim_expires_at"]) and \
                    row["claim_expires_at"] > _iso(now)
                if held_by_other and lease_live:
                    return CLAIMED_ELSEWHERE
                self._conn.execute("""
                    UPDATE acquisition_batch
                       SET claim_owner=?, claim_expires_at=?, window_end=?
                     WHERE tenant_id=? AND connector_id=? AND stream=?
                       AND batch_id=?
                """, (self.owner, lease, window_end, tenant_id,
                      connector_id_, stream, batch_id))
                return CLAIMED
            self._conn.execute("""
                INSERT INTO acquisition_batch
                    (tenant_id, connector_id, stream, batch_id,
                     declared_source, state, claim_owner, claim_expires_at,
                     reference, batch_created, batch_expires,
                     record_keys_json, window_end, blocked_reason,
                     first_seen_at, committed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,?,NULL,?,NULL)
            """, (tenant_id, connector_id_, stream, batch_id,
                  declared_source, ACQUIRED, self.owner, lease, reference,
                  batch_created, batch_expires, window_end, _iso(now)))
            return CLAIMED

    def record_batch_keys(self, tenant_id: str, connector_id_: str,
                          stream: str, batch_id: str,
                          record_keys: List[str]) -> None:
        """The idempotency keys whose acceptance this batch waits on."""
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch SET record_keys_json=?
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (json.dumps(list(record_keys)), tenant_id, connector_id_,
                  stream, batch_id))

    def release_batch(self, tenant_id: str, connector_id_: str, stream: str,
                      batch_id: str, *, reason: str) -> None:
        """A batch we could not read is un-claimed so it is retried, and the
        reason is kept — never dropped silently."""
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch
                   SET claim_owner=NULL, claim_expires_at=NULL,
                       blocked_reason=?
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=? AND state=?
            """, (reason, tenant_id, connector_id_, stream, batch_id,
                  ACQUIRED))

    def forget_batch(self, tenant_id: str, connector_id_: str, stream: str,
                     batch_id: str) -> None:
        """Only for a batch the vendor can no longer serve at all."""
        with self._lock:
            self._conn.execute("""
                DELETE FROM acquisition_batch
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=? AND state=?
            """, (tenant_id, connector_id_, stream, batch_id, ACQUIRED))

    # ── reconciliation ───────────────────────────────────────────
    def reconcile(self, outbox: Any, *, tenant_id: Optional[str] = None,
                  connector_id_: Optional[str] = None) -> Dict[str, Any]:
        """Promote ACQUIRED→COMMITTED and advance windows.

        A batch commits only when EVERY one of its record keys is
        `delivered` in the outbox. A window advances only when no
        uncommitted batch remains inside it.
        """
        where = ["state=?"]
        args: List[Any] = [ACQUIRED]
        if tenant_id:
            where.append("tenant_id=?")
            args.append(tenant_id)
        if connector_id_:
            where.append("connector_id=?")
            args.append(connector_id_)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM acquisition_batch WHERE {' AND '.join(where)}",
                args).fetchall()

        committed, waiting, blocked = [], [], []
        terminal_completed: List[Dict[str, Any]] = []
        terminal_total = 0
        for row in rows:
            keys = json.loads(row["record_keys_json"] or "[]")
            if not keys:
                waiting.append({"batch_id": row["batch_id"],
                                "reason": "NO_RECORD_KEYS_RECORDED_YET"})
                continue
            statuses = outbox.statuses_for(row["tenant_id"],
                                           row["connector_id"], keys)
            missing = [k for k in keys if k not in statuses]
            dead = [k for k, s in statuses.items()
                    if s == OutboxStatus.DEAD_LETTER]
            undelivered = [k for k, s in statuses.items()
                           if s != OutboxStatus.DELIVERED]
            if dead:
                # A permanent rejection is established. Quarantine each
                # rejected record with immutable failure evidence, then let
                # the batch complete into its OWN state — acquisition must
                # not freeze, and this is not `committed`.
                quarantined = 0
                for key in dead:
                    if self._quarantine(outbox, row, key):
                        quarantined += 1
                terminal_total += quarantined
                still_open = [k for k, s in statuses.items()
                              if s != OutboxStatus.DELIVERED
                              and s != OutboxStatus.DEAD_LETTER]
                if missing or still_open:
                    # Other records are still in flight: completion waits.
                    self._set_blocked(row, "AWAITING_REMAINING_RECORDS")
                    waiting.append({"batch_id": row["batch_id"],
                                    "terminal_records": len(dead),
                                    "not_yet_accepted": len(missing)
                                    + len(still_open)})
                    continue
                accepted = [k for k, s in statuses.items()
                            if s == OutboxStatus.DELIVERED]
                self._complete_with_terminal(row, terminal=len(dead))
                terminal_completed.append({
                    "batch_id": row["batch_id"],
                    "accepted_records": len(accepted),
                    "terminal_records": len(dead),
                    "state": COMPLETED_WITH_TERMINAL_RECORDS,
                    "basis": ("every non-accepted record has an immutable "
                              "terminal record; this batch is NOT committed")})
                continue
            if missing or undelivered:
                self._set_blocked(row, None)
                waiting.append({"batch_id": row["batch_id"],
                                "not_yet_accepted": len(missing)
                                + len(undelivered)})
                continue
            self._commit_batch(row)
            committed.append(row["batch_id"])

        advanced = self._advance_windows(tenant_id, connector_id_)
        return {"committed_batches": committed,
                "completed_with_terminal_records": terminal_completed,
                "terminal_records_quarantined": terminal_total,
                "waiting": waiting,
                "blocked": blocked, "windows_advanced": advanced,
                "note": ("a window advances only when every batch inside it "
                         "is either committed or completed with immutable "
                         "terminal records; TERMINAL != ACCEPTED != "
                         "CANONICAL EVIDENCE")}

    def _set_blocked(self, row: sqlite3.Row, reason: Optional[str]) -> None:
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch SET blocked_reason=?
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (reason, row["tenant_id"], row["connector_id"],
                  row["stream"], row["batch_id"]))

    # ── terminal records ─────────────────────────────────────────
    def _quarantine(self, outbox: Any, row: sqlite3.Row,
                    record_key: str) -> bool:
        """Write the immutable terminal record for one rejected record.

        Returns False when it is already quarantined — the history is
        append-only, but the same rejection is not recorded twice.
        """
        with self._lock:
            latest = self._conn.execute("""
                SELECT event_kind FROM acquisition_terminal_record
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=? AND record_key=?
                 ORDER BY decided_at DESC, rowid DESC LIMIT 1
            """, (row["tenant_id"], row["connector_id"], row["stream"],
                  row["batch_id"], record_key)).fetchone()
        # Skip only when the LATEST event is already a quarantine. A record
        # that was replayed and then rejected again is a new, truthful
        # rejection and must be recorded as one.
        if latest and latest["event_kind"] == EVENT_QUARANTINED:
            return False
        ob = outbox.row_for_key(row["tenant_id"], row["connector_id"],
                                record_key)
        self._append_terminal_event(
            EVENT_QUARANTINED, row, record_key,
            outbox_row_id=getattr(ob, "id", None),
            rejection_code=("INGEST_REJECTED_PERMANENTLY" if ob
                            else "OUTBOX_ROW_MISSING"),
            rejection_reason=(getattr(ob, "last_error", None)
                              or "no error text was recorded"),
            attempts=int(getattr(ob, "attempts", 0) or 0),
            first_attempt_at=getattr(ob, "created_at", None),
            last_attempt_at=getattr(ob, "updated_at", None),
            decision="TERMINAL_QUARANTINED",
            decision_basis=(
                "delivery attempts were exhausted or permanently refused by "
                "the authoritative ingest; the record is preserved here and "
                "is NOT accepted, NOT canonical evidence and NOT a "
                "successful delivery"),
            decided_by=self.owner)
        return True

    def _append_terminal_event(self, event_kind: str, row: sqlite3.Row,
                               record_key: str, **f: Any) -> None:
        import uuid
        with self._lock:
            self._conn.execute("""
                INSERT INTO acquisition_terminal_record
                    (id, event_kind, tenant_id, connector_id, stream,
                     batch_id, record_key, acquisition_ref, outbox_row_id,
                     rejection_code, rejection_reason, attempts,
                     first_attempt_at, last_attempt_at, decision,
                     decision_basis, decided_by, decided_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (uuid.uuid4().hex, event_kind, row["tenant_id"],
                  row["connector_id"], row["stream"], row["batch_id"],
                  record_key, row["reference"], f.get("outbox_row_id"),
                  f.get("rejection_code"), f.get("rejection_reason"),
                  f.get("attempts"), f.get("first_attempt_at"),
                  f.get("last_attempt_at"), f.get("decision"),
                  f.get("decision_basis"), f.get("decided_by"),
                  _iso(_utcnow())))

    def _complete_with_terminal(self, row: sqlite3.Row,
                                terminal: int) -> None:
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch
                   SET state=?, committed_at=?, claim_owner=NULL,
                       claim_expires_at=NULL,
                       blocked_reason=?
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (COMPLETED_WITH_TERMINAL_RECORDS, _iso(_utcnow()),
                  f"TERMINAL_RECORDS:{terminal}", row["tenant_id"],
                  row["connector_id"], row["stream"], row["batch_id"]))

    def terminal_records(self, tenant_id: str, connector_id_: str, *,
                         stream: Optional[str] = None,
                         batch_id: Optional[str] = None
                         ) -> List[Dict[str, Any]]:
        """The append-only terminal history, scoped to one tenant."""
        where = ["tenant_id=?", "connector_id=?"]
        args: List[Any] = [tenant_id, connector_id_]
        if stream:
            where.append("stream=?")
            args.append(stream)
        if batch_id:
            where.append("batch_id=?")
            args.append(batch_id)
        with self._lock:
            rows = self._conn.execute(f"""
                SELECT * FROM acquisition_terminal_record
                 WHERE {' AND '.join(where)}
                 ORDER BY decided_at ASC, rowid ASC
            """, args).fetchall()
        return [dict(r) for r in rows]

    def replay_terminal_record(self, outbox: Any, tenant_id: str,
                               connector_id_: str, stream: str,
                               batch_id: str, record_key: str, *,
                               requested_by: str = "operator"
                               ) -> Dict[str, Any]:
        """Re-admit a quarantined record for another authoritative attempt.

        The original terminal decision is NEVER erased or rewritten: this
        appends a replay event. A replay request is not proof of recovery —
        only a fresh acceptance by the authoritative ingest can produce
        canonical evidence.
        """
        with self._lock:
            batch = self._conn.execute("""
                SELECT * FROM acquisition_batch
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (tenant_id, connector_id_, stream, batch_id)).fetchone()
            terminal = self._conn.execute("""
                SELECT * FROM acquisition_terminal_record
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=? AND record_key=? AND event_kind=?
                 ORDER BY decided_at DESC LIMIT 1
            """, (tenant_id, connector_id_, stream, batch_id, record_key,
                  EVENT_QUARANTINED)).fetchone()
        if not batch or not terminal:
            # Includes the cross-tenant case: another tenant's terminal
            # record is simply not visible here, so it cannot be released.
            return {"outcome": "NOT_FOUND_IN_THIS_SCOPE",
                    "tenant_id": tenant_id, "record_key": record_key}
        if not outbox.replay_dead(terminal["outbox_row_id"] or ""):
            return {"outcome": "REPLAY_NOT_POSSIBLE",
                    "reason": ("the outbox row is not in dead_letter — it "
                               "was already released, replayed, or never "
                               "reached the boundary"),
                    "record_key": record_key}
        self._append_terminal_event(
            EVENT_REPLAY_REQUESTED, batch, record_key,
            outbox_row_id=terminal["outbox_row_id"],
            rejection_code=terminal["rejection_code"],
            rejection_reason=terminal["rejection_reason"],
            attempts=terminal["attempts"],
            first_attempt_at=terminal["first_attempt_at"],
            last_attempt_at=terminal["last_attempt_at"],
            decision="REPLAY_REQUESTED",
            decision_basis=("re-queued for another authoritative attempt; "
                            "the original terminal decision above is "
                            "retained as history and this request is not "
                            "proof of recovery"),
            decided_by=requested_by)
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch
                   SET state=?, committed_at=NULL, blocked_reason=?
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=? AND state=?
            """, (ACQUIRED, "REOPENED_AFTER_TERMINAL_REPLAY", tenant_id,
                  connector_id_, stream, batch_id,
                  COMPLETED_WITH_TERMINAL_RECORDS))
        return {"outcome": "REPLAY_REQUESTED", "record_key": record_key,
                "batch_state": ACQUIRED,
                "note": ("the record must pass the authoritative ingest "
                         "again; only that acceptance can produce canonical "
                         "evidence")}

    def _commit_batch(self, row: sqlite3.Row) -> None:
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch
                   SET state=?, committed_at=?, claim_owner=NULL,
                       claim_expires_at=NULL, blocked_reason=NULL
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (COMMITTED, _iso(_utcnow()), row["tenant_id"],
                  row["connector_id"], row["stream"], row["batch_id"]))

    def _advance_windows(self, tenant_id: Optional[str],
                         connector_id_: Optional[str]) -> List[Dict[str, Any]]:
        where, args = [], []
        if tenant_id:
            where.append("tenant_id=?")
            args.append(tenant_id)
        if connector_id_:
            where.append("connector_id=?")
            args.append(connector_id_)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            windows = self._conn.execute(
                f"SELECT * FROM acquisition_window {clause}", args).fetchall()
        advanced = []
        for w in windows:
            pending = w["pending_until"]
            if not pending or pending == w["committed_until"]:
                continue
            if w["next_page_ref"]:
                # Pagination is unfinished: the window is not fully read.
                continue
            with self._lock:
                stuck = self._conn.execute("""
                    SELECT COUNT(*) AS n FROM acquisition_batch
                     WHERE tenant_id=? AND connector_id=? AND stream=?
                       AND state=?
                """, (w["tenant_id"], w["connector_id"], w["stream"],
                      ACQUIRED)).fetchone()["n"]
                if stuck:
                    continue
                self._conn.execute("""
                    UPDATE acquisition_window
                       SET committed_until=?, updated_at=?
                     WHERE tenant_id=? AND connector_id=? AND stream=?
                """, (pending, _iso(_utcnow()), w["tenant_id"],
                      w["connector_id"], w["stream"]))
            advanced.append({"tenant_id": w["tenant_id"],
                             "connector_id": w["connector_id"],
                             "stream": w["stream"],
                             "committed_until": pending})
        return advanced

    # ── introspection ────────────────────────────────────────────
    def status(self, tenant_id: str, connector_id_: str) -> Dict[str, Any]:
        with self._lock:
            batches = self._conn.execute("""
                SELECT stream, state, COUNT(*) AS n FROM acquisition_batch
                 WHERE tenant_id=? AND connector_id=?
                 GROUP BY stream, state
            """, (tenant_id, connector_id_)).fetchall()
            blocked = self._conn.execute("""
                SELECT batch_id, stream, blocked_reason
                  FROM acquisition_batch
                 WHERE tenant_id=? AND connector_id=?
                   AND blocked_reason IS NOT NULL
            """, (tenant_id, connector_id_)).fetchall()
            windows = self._conn.execute("""
                SELECT * FROM acquisition_window
                 WHERE tenant_id=? AND connector_id=?
            """, (tenant_id, connector_id_)).fetchall()
            terminal = self._conn.execute("""
                SELECT stream, batch_id, record_key, rejection_code,
                       attempts, decided_at
                  FROM acquisition_terminal_record
                 WHERE tenant_id=? AND connector_id=? AND event_kind=?
                 ORDER BY decided_at DESC LIMIT 100
            """, (tenant_id, connector_id_, EVENT_QUARANTINED)).fetchall()
            per_batch = self._conn.execute("""
                SELECT stream, batch_id, COUNT(*) AS n
                  FROM acquisition_terminal_record
                 WHERE tenant_id=? AND connector_id=? AND event_kind=?
                 GROUP BY stream, batch_id
            """, (tenant_id, connector_id_, EVENT_QUARANTINED)).fetchall()
        return {
            "owner": self.owner,
            "batches": [{"stream": r["stream"], "state": r["state"],
                         "count": r["n"]} for r in batches],
            "batch_terminal_records": [
                {"stream": r["stream"], "batch_id": r["batch_id"],
                 "terminal_records": r["n"]} for r in per_batch],
            "terminal_records": [
                {"stream": r["stream"], "batch_id": r["batch_id"],
                 "record_key": r["record_key"],
                 "rejection_code": r["rejection_code"],
                 "attempts": r["attempts"], "decided_at": r["decided_at"]}
                for r in terminal],
            "blocked": [{"batch_id": r["batch_id"], "stream": r["stream"],
                         "reason": r["blocked_reason"]} for r in blocked],
            "windows": [{"stream": r["stream"],
                         "committed_until": r["committed_until"],
                         "pending_until": r["pending_until"],
                         "next_page_ref": r["next_page_ref"]}
                        for r in windows],
            "states": ("ACQUIRED != QUEUED != DELIVERED != COMMITTED; a "
                       "window advances only on COMMITTED or "
                       "COMPLETED_WITH_TERMINAL_RECORDS, and TERMINAL != "
                       "ACCEPTED != CANONICAL EVIDENCE != SUCCESSFUL "
                       "DELIVERY — a terminal record may well have been "
                       "attempted against the boundary and refused"),
        }

    def prune_committed(self, older_than_days: int = 30) -> int:
        cutoff = _iso(_utcnow() - timedelta(days=older_than_days))
        with self._lock:
            cur = self._conn.execute("""
                DELETE FROM acquisition_batch
                 WHERE state=? AND committed_at IS NOT NULL
                   AND committed_at < ?
            """, (COMMITTED, cutoff))
            return cur.rowcount or 0
