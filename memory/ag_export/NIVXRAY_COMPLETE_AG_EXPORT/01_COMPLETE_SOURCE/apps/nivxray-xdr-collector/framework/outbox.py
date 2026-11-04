"""
Durable outbox for canonical envelopes · Phase B.5.

Every envelope produced by a transport passes through this outbox
BEFORE it can be reported as delivered.  The outbox is SQLite-backed
at `${XDR_STATE_DIR}/outbox.db` (or in-memory `:memory:` for tests).

Status lifecycle (owner-locked):
    RECEIVED   → row inserted by transport
    QUEUED     → ready for delivery worker
    DELIVERING → in-flight to NivXRay ingest
    DELIVERED  → 2xx acknowledged by ingest
    RETRYING   → retryable failure; next_attempt_at set with backoff
    DEAD_LETTER→ non-retryable OR max_attempts exceeded

Idempotency: unique constraint on
`(tenant_id, connector_id, source_event_id)` when `source_event_id`
is non-null.  Re-recording an existing (tenant, connector, event_id)
returns the prior row untouched.

Restart recovery: DELIVERING rows are reset to QUEUED on Outbox
initialisation.  This is safe — the ingest endpoint is expected to
be idempotent on `(tenant_id, connector_id, source_event_id)`.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime    import datetime, timezone
from typing      import Any, Dict, Iterable, List, Optional, Tuple

from framework.base import Envelope


# ── Status enum ────────────────────────────────────────────────────
class OutboxStatus:
    RECEIVED     = "received"
    QUEUED       = "queued"
    DELIVERING   = "delivering"
    DELIVERED    = "delivered"
    RETRYING     = "retrying"
    DEAD_LETTER  = "dead_letter"

    ALL = ("received", "queued", "delivering", "delivered",
             "retrying", "dead_letter")


# ── Retry policy ───────────────────────────────────────────────────
DEFAULT_BACKOFF_SECONDS: Tuple[int, ...] = (30, 60, 120, 300, 600, 1200, 1800, 3600)
DEFAULT_MAX_ATTEMPTS = len(DEFAULT_BACKOFF_SECONDS)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass
class OutboxRow:
    id:                  str
    tenant_id:           str
    connector_id:        str
    source:              str
    source_event_id:     Optional[str]
    collection_method:   str
    parser_version:      str
    source_timestamp:    Optional[str]
    collection_timestamp: str
    event_type:          str
    raw:                 Dict[str, Any]
    canonical:           Dict[str, Any]
    status:              str
    attempts:            int
    next_attempt_at:     str
    last_error:          Optional[str]
    created_at:          str
    updated_at:          str

    def to_envelope(self) -> Envelope:
        return Envelope(
            tenant_id            = self.tenant_id,
            source               = self.source,
            source_event_id      = self.source_event_id,
            connector_id         = self.connector_id,
            collector_id         = "collector-local",
            collection_method    = self.collection_method,
            parser_version       = self.parser_version,
            source_timestamp     = self.source_timestamp,
            collection_timestamp = self.collection_timestamp,
            event_type           = self.event_type,
            raw                  = self.raw,
            canonical            = self.canonical,
        )


class Outbox:
    """SQLite-backed durable outbox.  Thread-safe.

    Callers use asyncio.to_thread for concurrency (all sqlite3 calls
    are synchronous under the hood).
    """
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS envelopes (
        id                   TEXT PRIMARY KEY,
        tenant_id            TEXT NOT NULL,
        connector_id         TEXT NOT NULL,
        source               TEXT,
        source_event_id      TEXT,
        collection_method    TEXT,
        parser_version       TEXT,
        source_timestamp     TEXT,
        collection_timestamp TEXT,
        event_type           TEXT,
        raw_json             TEXT,
        canonical_json       TEXT,
        status               TEXT NOT NULL,
        attempts             INTEGER NOT NULL DEFAULT 0,
        next_attempt_at      TEXT NOT NULL,
        last_error           TEXT,
        created_at           TEXT NOT NULL,
        updated_at           TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_env_status_next
        ON envelopes(status, next_attempt_at);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_env_event_id
        ON envelopes(tenant_id, connector_id, source_event_id)
        WHERE source_event_id IS NOT NULL;
    """

    def __init__(self, path: Optional[str] = None,
                    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                    backoff_seconds: Tuple[int, ...] = DEFAULT_BACKOFF_SECONDS) -> None:
        self._path = path or os.environ.get("XDR_STATE_DIR")
        self._db_path = ":memory:" if self._path is None \
                          else os.path.join(self._path, "outbox.db")
        if self._path:
            os.makedirs(self._path, exist_ok=True)
        # `check_same_thread=False` — we serialise with a lock so any
        # thread can use the connection.
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False,
                                          isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._lock  = threading.RLock()
        self._max_attempts = max_attempts
        self._backoff = backoff_seconds
        self._init_schema()
        self._reset_stuck_delivering()

    # ── setup ─────────────────────────────────────────────────
    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(self._SCHEMA)

    def _reset_stuck_delivering(self) -> None:
        """Restart-recovery: anything left in DELIVERING is put back
        into QUEUED for immediate re-attempt.  Idempotency at the
        ingest endpoint prevents double-writes."""
        with self._lock:
            now = _iso(_utcnow())
            self._conn.execute("""
                UPDATE envelopes
                   SET status=?, updated_at=?
                 WHERE status=?
            """, (OutboxStatus.QUEUED, now, OutboxStatus.DELIVERING))

    # ── CRUD ──────────────────────────────────────────────────
    def record(self, env: Envelope) -> Tuple[str, str]:
        """Insert an envelope in RECEIVED→QUEUED status.  Returns
        `(outbox_id, effective_status)`.  If a duplicate exists
        (same tenant + connector + source_event_id) returns the
        existing id + its current status without inserting."""
        with self._lock:
            # Idempotency check
            if env.source_event_id:
                row = self._conn.execute("""
                    SELECT id, status FROM envelopes
                     WHERE tenant_id=? AND connector_id=? AND source_event_id=?
                    LIMIT 1
                """, (env.tenant_id, env.connector_id, env.source_event_id)
                ).fetchone()
                if row:
                    return row["id"], row["status"]
            rid = uuid.uuid4().hex
            now = _iso(_utcnow())
            self._conn.execute("""
                INSERT INTO envelopes
                (id, tenant_id, connector_id, source, source_event_id,
                    collection_method, parser_version, source_timestamp,
                    collection_timestamp, event_type, raw_json, canonical_json,
                    status, attempts, next_attempt_at, last_error,
                    created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (rid, env.tenant_id, env.connector_id, env.source,
                    env.source_event_id, env.collection_method,
                    env.parser_version, env.source_timestamp,
                    env.collection_timestamp, env.event_type,
                    json.dumps(env.raw, default=str),
                    json.dumps(env.canonical or {}, default=str),
                    OutboxStatus.QUEUED, 0, now, None, now, now))
            return rid, OutboxStatus.QUEUED

    def by_id(self, rid: str) -> Optional[OutboxRow]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM envelopes WHERE id=?",
                                        (rid,)).fetchone()
        return self._row(r) if r else None

    def next_batch(self, limit: int = 50) -> List[OutboxRow]:
        """Pull the next batch of QUEUED or RETRYING rows whose
        `next_attempt_at` is in the past."""
        now = _iso(_utcnow())
        with self._lock:
            rows = self._conn.execute("""
                SELECT * FROM envelopes
                 WHERE status IN (?, ?)
                    AND next_attempt_at <= ?
                 ORDER BY next_attempt_at ASC, created_at ASC
                 LIMIT ?
            """, (OutboxStatus.QUEUED, OutboxStatus.RETRYING, now, limit)
            ).fetchall()
        return [self._row(r) for r in rows]

    def mark_delivering(self, ids: Iterable[str]) -> None:
        ids = list(ids)
        if not ids:
            return
        now = _iso(_utcnow())
        with self._lock:
            qmarks = ",".join("?" * len(ids))
            self._conn.execute(
                f"UPDATE envelopes SET status=?, updated_at=? WHERE id IN ({qmarks})",
                [OutboxStatus.DELIVERING, now, *ids])

    def mark_delivered(self, ids: Iterable[str]) -> None:
        ids = list(ids)
        if not ids:
            return
        now = _iso(_utcnow())
        with self._lock:
            qmarks = ",".join("?" * len(ids))
            self._conn.execute(
                f"UPDATE envelopes SET status=?, updated_at=?, last_error=NULL "
                f" WHERE id IN ({qmarks})",
                [OutboxStatus.DELIVERED, now, *ids])

    def mark_retry(self, rid: str, error: str) -> str:
        """Advance one row into RETRYING with backoff, or DEAD_LETTER
        if attempts are exhausted.  Returns the new status."""
        now = _utcnow()
        with self._lock:
            row = self._conn.execute(
                "SELECT attempts FROM envelopes WHERE id=?", (rid,)).fetchone()
            if not row:
                return "not_found"
            attempts  = int(row["attempts"]) + 1
            if attempts >= self._max_attempts:
                self._conn.execute(
                    "UPDATE envelopes SET status=?, attempts=?, last_error=?, updated_at=? "
                    " WHERE id=?",
                    (OutboxStatus.DEAD_LETTER, attempts, error, _iso(now), rid))
                return OutboxStatus.DEAD_LETTER
            idx = min(attempts - 1, len(self._backoff) - 1)
            next_at = now.timestamp() + self._backoff[idx]
            next_iso = _iso(datetime.fromtimestamp(next_at, tz=timezone.utc))
            self._conn.execute(
                "UPDATE envelopes "
                "   SET status=?, attempts=?, next_attempt_at=?, last_error=?, updated_at=? "
                " WHERE id=?",
                (OutboxStatus.RETRYING, attempts, next_iso, error, _iso(now), rid))
            return OutboxStatus.RETRYING

    def mark_dead(self, rid: str, error: str) -> None:
        now = _iso(_utcnow())
        with self._lock:
            self._conn.execute(
                "UPDATE envelopes SET status=?, last_error=?, updated_at=? WHERE id=?",
                (OutboxStatus.DEAD_LETTER, error, now, rid))

    def replay_dead(self, rid: str) -> bool:
        """Requeue a dead-letter row for another delivery attempt."""
        now = _iso(_utcnow())
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM envelopes WHERE id=? AND status=?",
                (rid, OutboxStatus.DEAD_LETTER)).fetchone()
            if not row:
                return False
            self._conn.execute(
                "UPDATE envelopes SET status=?, attempts=0, next_attempt_at=?, "
                "                       last_error=NULL, updated_at=? "
                " WHERE id=?",
                (OutboxStatus.QUEUED, now, now, rid))
            return True

    # ── metrics / list ────────────────────────────────────────
    def counts(self, connector_id: Optional[str] = None) -> Dict[str, int]:
        with self._lock:
            if connector_id:
                rows = self._conn.execute(
                    "SELECT status, COUNT(*) AS n FROM envelopes "
                    " WHERE connector_id=? GROUP BY status",
                    (connector_id,)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status"
                ).fetchall()
        out = {s: 0 for s in OutboxStatus.ALL}
        for r in rows: out[r["status"]] = int(r["n"])
        return out

    def metrics(self, connector_id: Optional[str] = None) -> Dict[str, Any]:
        c = self.counts(connector_id)
        with self._lock:
            where = "WHERE connector_id=?" if connector_id else ""
            params = (connector_id,) if connector_id else ()
            oldest = self._conn.execute(
                f"SELECT MIN(created_at) AS x FROM envelopes "
                f" {where} {'AND' if where else 'WHERE'} status IN (?, ?)",
                (*params, OutboxStatus.QUEUED, OutboxStatus.RETRYING)
            ).fetchone()["x"]
            last_ok = self._conn.execute(
                f"SELECT MAX(updated_at) AS x FROM envelopes "
                f" {where} {'AND' if where else 'WHERE'} status=?",
                (*params, OutboxStatus.DELIVERED)).fetchone()["x"]
            last_err = self._conn.execute(
                f"SELECT last_error FROM envelopes "
                f" {where} {'AND' if where else 'WHERE'} last_error IS NOT NULL "
                f" ORDER BY updated_at DESC LIMIT 1",
                params).fetchone()
        depth = c[OutboxStatus.QUEUED] + c[OutboxStatus.RETRYING]
        return {
            "counts":                c,
            "queue_depth":           depth,
            "oldest_queued_at":      oldest,
            "last_successful_at":    last_ok,
            "last_error":            last_err["last_error"] if last_err else None,
            "max_attempts":          self._max_attempts,
            "backoff_seconds":       list(self._backoff),
        }

    def list(self, status: Optional[str] = None,
                connector_id: Optional[str] = None,
                limit: int = 100) -> List[OutboxRow]:
        with self._lock:
            clauses, params = [], []
            if status:
                clauses.append("status=?"); params.append(status)
            if connector_id:
                clauses.append("connector_id=?"); params.append(connector_id)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            rows = self._conn.execute(
                f"SELECT * FROM envelopes {where} "
                f" ORDER BY updated_at DESC LIMIT ?",
                (*params, limit)).fetchall()
        return [self._row(r) for r in rows]

    # ── helpers ───────────────────────────────────────────────
    @staticmethod
    def _row(r: sqlite3.Row) -> OutboxRow:
        return OutboxRow(
            id=r["id"], tenant_id=r["tenant_id"], connector_id=r["connector_id"],
            source=r["source"], source_event_id=r["source_event_id"],
            collection_method=r["collection_method"],
            parser_version=r["parser_version"],
            source_timestamp=r["source_timestamp"],
            collection_timestamp=r["collection_timestamp"],
            event_type=r["event_type"],
            raw=json.loads(r["raw_json"] or "{}"),
            canonical=json.loads(r["canonical_json"] or "{}"),
            status=r["status"], attempts=int(r["attempts"]),
            next_attempt_at=r["next_attempt_at"],
            last_error=r["last_error"],
            created_at=r["created_at"], updated_at=r["updated_at"],
        )

    def close(self) -> None:
        with self._lock:
            try:    self._conn.close()
            except Exception: pass
