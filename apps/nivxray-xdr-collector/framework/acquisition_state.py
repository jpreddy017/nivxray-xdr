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
                # Explicitly reported: a permanently rejected record holds
                # this batch, and therefore this window, open. This gate
                # does NOT invent a dead-letter release policy.
                self._set_blocked(
                    row, f"BLOCKED_BY_DEAD_LETTER_RECORDS:{len(dead)}")
                blocked.append({"batch_id": row["batch_id"],
                                "dead_records": len(dead),
                                "reason": "BLOCKED_BY_DEAD_LETTER_RECORDS"})
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
        return {"committed_batches": committed, "waiting": waiting,
                "blocked": blocked, "windows_advanced": advanced,
                "note": ("a window advances only when every batch inside it "
                         "has been accepted by the authoritative ingest")}

    def _set_blocked(self, row: sqlite3.Row, reason: Optional[str]) -> None:
        with self._lock:
            self._conn.execute("""
                UPDATE acquisition_batch SET blocked_reason=?
                 WHERE tenant_id=? AND connector_id=? AND stream=?
                   AND batch_id=?
            """, (reason, row["tenant_id"], row["connector_id"],
                  row["stream"], row["batch_id"]))

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
        return {
            "owner": self.owner,
            "batches": [{"stream": r["stream"], "state": r["state"],
                         "count": r["n"]} for r in batches],
            "blocked": [{"batch_id": r["batch_id"], "stream": r["stream"],
                         "reason": r["blocked_reason"]} for r in blocked],
            "windows": [{"stream": r["stream"],
                         "committed_until": r["committed_until"],
                         "pending_until": r["pending_until"],
                         "next_page_ref": r["next_page_ref"]}
                        for r in windows],
            "states": ("ACQUIRED != QUEUED != DELIVERED != COMMITTED; a "
                       "window advances only on COMMITTED"),
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
