#!/usr/bin/env python3
"""NivXForge EDR · LOCAL EVIDENCE JOURNAL (B5-GAP-1).

Why this module exists
----------------------
B5-GAP-1 proved that the Windows sensor could lose source telemetry
SILENTLY: acquisition read at most 100 records per channel per cycle, had
no pagination, and ran on the same serial thread as delivery, so a slow
backend starved acquisition until the circular Windows EVTX rotated past
the sensor's cursor. The sensor reported `collected: 100` throughout.

The fix is not a bigger `/c:` value. The fix is to make evidence DURABLY
OWNED BY NIVXFORGE as soon as practical after acquisition, and to make the
source cursor a consequence of that ownership rather than of a read.

    PRIMARY INVARIANT
    The source cursor MUST NEVER advance beyond the last source record
    durably owned by NivXForge.

This module enforces that invariant structurally: evidence rows, detected
acquisition gaps and the channel cursor are written in ONE SQLite
transaction. There is no code path that commits a cursor without the
evidence, because they are the same COMMIT.

This is an evidence store, not a cache and not a second data lake. It is
bounded, it is reclaimed only against a named acknowledgement authority,
and when it cannot accept more evidence it says so instead of pretending
acquisition is healthy.

Technology
----------
`sqlite3` from the Python standard library, WAL + `synchronous=FULL`.
Chosen because the endpoint artifact is a PyInstaller bundle
(`build/build_windows_installer.ps1`) and `sqlite3` needs no new
dependency, no new hidden import beyond this module, no service account
change and no broker. Nothing distributed is introduced on the endpoint.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

JOURNAL_VERSION = "1.0.0"
SCHEMA_VERSION = 1
JOURNAL_FILENAME = "evidence_journal.db"
INTEGRITY_FILENAME = "acquisition_integrity.json"
#: Written ONLY when the journal itself could not be opened. Never
#: silently swallowed: a sensor with no durable store must be visibly
#: broken, not quietly lossy.
FAULT_FILENAME = "journal_fault.json"

# ── evidence lifecycle. SENT != ACCEPTED, ACCEPTED != CANONICALIZED ──
ACQUIRED = "ACQUIRED"              # durable, not yet offered to transport
QUEUED = "QUEUED"                  # selected for a delivery attempt
BACKEND_ACCEPTED = "BACKEND_ACCEPTED"   # platform returned an accept
#: Reclamation is a DELETE of BACKEND_ACCEPTED rows. There is deliberately
#: no RECLAIMABLE row state: a state that means "safe to delete" invites a
#: future reader to delete something merely because it was sent.
DELIVERABLE_STATES = (ACQUIRED, QUEUED)

# ── health vocabulary. Every one of these is measured, never inferred ──
HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
ACQUISITION_LAGGING = "ACQUISITION_LAGGING"
ACQUISITION_GAP = "ACQUISITION_GAP"
ACQUISITION_HALTED_JOURNAL_FULL = "ACQUISITION_HALTED_JOURNAL_FULL"
JOURNAL_PRESSURE = "JOURNAL_PRESSURE"
JOURNAL_CRITICAL = "JOURNAL_CRITICAL"
JOURNAL_CORRUPT = "JOURNAL_CORRUPT"
DELIVERY_BACKLOG = "DELIVERY_BACKLOG"
BACKEND_UNREACHABLE = "BACKEND_UNREACHABLE"
CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
#: Emitted ONLY when the oldest record surviving in the source channel is
#: newer than our committed cursor — i.e. measured, not deduced from a
#: delivery backlog.
SOURCE_ROLLOVER_RISK = "SOURCE_ROLLOVER_RISK"

#: A source RecordID discontinuity is a CONTINUITY FACT. It is not proof
#: that every missing RecordID carried a security event, and it is not
#: proof of rollover. The cause stays NOT_PROVEN until proven elsewhere.
DISCONTINUITY = "SOURCE_RECORD_DISCONTINUITY"
CAUSE_NOT_PROVEN = "NOT_PROVEN"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    journal_sequence  INTEGER PRIMARY KEY AUTOINCREMENT,
    channel           TEXT    NOT NULL,
    source_provider   TEXT,
    source_record_id  INTEGER,
    source_event_id   TEXT,
    source_event_time TEXT,
    collected_at      TEXT    NOT NULL,
    endpoint_id       TEXT,
    tenant_id         TEXT,
    payload           TEXT    NOT NULL,
    payload_bytes     INTEGER NOT NULL,
    content_digest    TEXT    NOT NULL,
    state             TEXT    NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT,
    accepted_at       TEXT,
    updated_at        TEXT    NOT NULL
);
-- Idempotency across a crash between journal COMMIT and a later re-read:
-- the same source record can never be journaled twice. SQLite treats NULLs
-- as distinct, so a record without a RecordID is never deduplicated away.
CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_source
    ON evidence (channel, source_record_id);
CREATE INDEX IF NOT EXISTS ix_evidence_state
    ON evidence (state, journal_sequence);

CREATE TABLE IF NOT EXISTS cursors (
    channel                TEXT    PRIMARY KEY,
    committed_record_id    INTEGER NOT NULL,
    continuity_established INTEGER NOT NULL DEFAULT 0,
    updated_at             TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS acquisition_gaps (
    gap_id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    channel                  TEXT    NOT NULL,
    classification           TEXT    NOT NULL,
    position                 TEXT    NOT NULL,
    expected_next_record_id  INTEGER NOT NULL,
    first_observed_record_id INTEGER NOT NULL,
    missing_start_record_id  INTEGER NOT NULL,
    missing_end_record_id    INTEGER NOT NULL,
    missing_record_id_count  INTEGER NOT NULL,
    detected_at              TEXT    NOT NULL,
    cause                    TEXT    NOT NULL,
    reported                 INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_gaps_reported
    ON acquisition_gaps (reported, gap_id);

CREATE TABLE IF NOT EXISTS integrity (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _int_env(name: str, default: int) -> int:
    try:
        value = int(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def limits() -> dict:
    """Bounded-capacity policy. No finite journal can promise infinity, so
    the thresholds are explicit and configurable rather than implied."""
    return {
        "max_bytes": _int_env("NIVX_SENSOR_JOURNAL_MAX_BYTES",
                              512 * 1024 * 1024),
        "warn_pct": min(99, _int_env("NIVX_SENSOR_JOURNAL_WARN_PCT", 70)),
        "critical_pct": min(100, _int_env(
            "NIVX_SENSOR_JOURNAL_CRITICAL_PCT", 90)),
        "min_free_bytes": _int_env("NIVX_SENSOR_JOURNAL_MIN_FREE_BYTES",
                                   1024 * 1024 * 1024),
        "reclaim_batch": _int_env("NIVX_SENSOR_JOURNAL_RECLAIM_BATCH", 5000),
    }


def content_digest(payload: str) -> str:
    """Identity of the CONTENT. Deliberately not the identity of the
    OBSERVATION: two identical records observed twice remain two separately
    addressable rows, keyed by journal_sequence."""
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_gap(channel: str, expected_next: int, first_observed: int,
              position: str, detected_at: str | None = None) -> dict:
    """The structured acquisition-gap contract.

    `missing_record_id_count` is `first_observed - expected_next`, so for
    the production B5-GAP-1 observation (expected 8470186, first observed
    8496595) it is 26409 over the range 8470186..8496594.
    """
    return {
        "type": "acquisition_gap",
        "classification": DISCONTINUITY,
        "position": position,
        "channel": channel,
        "expected_next_record_id": int(expected_next),
        "first_observed_record_id": int(first_observed),
        "missing_start_record_id": int(expected_next),
        "missing_end_record_id": int(first_observed) - 1,
        "missing_record_id_count": int(first_observed) - int(expected_next),
        "detected_at": detected_at or _now(),
        "cause": CAUSE_NOT_PROVEN,
    }


class JournalUnavailable(RuntimeError):
    """The durable store could not be opened. Acquisition must not proceed
    as if it had, because the cursor could then advance over evidence
    nothing owns."""


class Journal:
    """Durable, ordered, transactional, crash-recoverable evidence store."""

    def __init__(self, state_dir: str | os.PathLike):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.state_dir / JOURNAL_FILENAME
        self._db = self._connect()
        self._halted = False
        self._halt_reason: str | None = None
        self._pressure_cache: tuple | None = None

    # ── open / recover ────────────────────────────────────────────
    def _connect(self) -> sqlite3.Connection:
        try:
            db = sqlite3.connect(str(self.path), timeout=30.0,
                                 isolation_level=None)
            db.row_factory = sqlite3.Row
            # auto_vacuum must be declared before the first table exists,
            # otherwise reclaimed pages are never returned to the OS and a
            # bounded journal would grow monotonically on disk.
            db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            db.execute("PRAGMA journal_mode=WAL")
            # FULL, not NORMAL: a COMMIT that survives only in the page
            # cache is not durable ownership, and the cursor advances on it.
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(_SCHEMA)
            db.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
                ("schema_version", str(SCHEMA_VERSION)))
            return db
        except sqlite3.DatabaseError as ex:
            self._quarantine(ex)
            raise JournalUnavailable(
                f"evidence journal unusable: {type(ex).__name__}: {ex}"
            ) from None

    def _quarantine(self, ex: Exception) -> None:
        """Corruption is made VISIBLE and the bytes are PRESERVED.

        The file is renamed, never deleted and never truncated: a corrupt
        journal may still contain recoverable evidence, and destroying it
        to get a clean start is exactly the silent loss this whole module
        exists to prevent.
        """
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        moved = None
        try:
            if self.path.exists():
                moved = self.path.with_suffix(f".corrupt-{stamp}")
                self.path.rename(moved)
        except OSError:
            pass
        try:
            (self.state_dir / FAULT_FILENAME).write_text(json.dumps({
                "state": JOURNAL_CORRUPT,
                "detected_at": _now(),
                "error": f"{type(ex).__name__}: {str(ex)[:300]}",
                "preserved_as": str(moved) if moved else None,
                "note": "bytes preserved; nothing was deleted or truncated",
            }, indent=2))
        except OSError:
            pass

    def close(self) -> None:
        try:
            self._db.close()
        except sqlite3.Error:
            pass

    # ── cursors ───────────────────────────────────────────────────
    def cursor(self, channel: str) -> int:
        row = self._db.execute(
            "SELECT committed_record_id FROM cursors WHERE channel=?",
            (channel,)).fetchone()
        return int(row["committed_record_id"]) if row else 0

    def continuity_established(self, channel: str) -> bool:
        """Whether this sensor has itself committed a cursor for the
        channel. Without it, a first acquisition would otherwise report the
        entire pre-install history as a gap — a fabricated finding."""
        row = self._db.execute(
            "SELECT continuity_established FROM cursors WHERE channel=?",
            (channel,)).fetchone()
        return bool(row and int(row["continuity_established"]))

    def cursors(self) -> dict:
        return {r["channel"]: int(r["committed_record_id"])
                for r in self._db.execute(
                    "SELECT channel, committed_record_id FROM cursors")}

    # ── the durability boundary ───────────────────────────────────
    def commit_page(self, channel: str, events: list[dict],
                    new_cursor: int, gaps: list[dict] | None = None,
                    endpoint_id: str | None = None,
                    tenant_id: str | None = None) -> dict:
        """ONE transaction: evidence + gaps + cursor.

        This is the durability boundary. Nothing here is best-effort: if
        the evidence INSERT fails the whole transaction rolls back and the
        cursor does NOT move, so the next cycle re-reads the same source
        range. The unique index makes that re-read idempotent.
        """
        now = _now()
        rows = [self._row(channel, event, now, endpoint_id, tenant_id)
                for event in events]
        before = self._db.total_changes
        self._db.execute("BEGIN IMMEDIATE")
        try:
            if rows:
                self._db.executemany(
                    "INSERT OR IGNORE INTO evidence ("
                    "channel, source_provider, source_record_id,"
                    "source_event_id, source_event_time, collected_at,"
                    "endpoint_id, tenant_id, payload, payload_bytes,"
                    "content_digest, state, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            for gap in gaps or []:
                self._db.execute(
                    "INSERT INTO acquisition_gaps ("
                    "channel, classification, position,"
                    "expected_next_record_id, first_observed_record_id,"
                    "missing_start_record_id, missing_end_record_id,"
                    "missing_record_id_count, detected_at, cause)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (gap["channel"], gap["classification"], gap["position"],
                     gap["expected_next_record_id"],
                     gap["first_observed_record_id"],
                     gap["missing_start_record_id"],
                     gap["missing_end_record_id"],
                     gap["missing_record_id_count"],
                     gap["detected_at"], gap["cause"]))
            # MAX() so a cursor can never regress, whatever a caller passes.
            self._db.execute(
                "INSERT INTO cursors(channel, committed_record_id,"
                " continuity_established, updated_at) VALUES(?,?,1,?)"
                " ON CONFLICT(channel) DO UPDATE SET"
                " committed_record_id=MAX(cursors.committed_record_id,"
                " excluded.committed_record_id),"
                " continuity_established=1, updated_at=excluded.updated_at",
                (channel, int(new_cursor), now))
            self._db.execute("COMMIT")
        except BaseException:
            try:
                self._db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        inserted = self._db.total_changes - before
        self._pressure_cache = None
        # total_changes counts the gap and cursor writes too; the evidence
        # figure is what the caller needs, so derive it honestly.
        evidence_inserted = max(0, inserted - len(gaps or []) - 1)
        return {"offered": len(rows), "journaled": evidence_inserted,
                "duplicates_ignored": len(rows) - evidence_inserted,
                "gaps_recorded": len(gaps or []),
                "cursor_committed": self.cursor(channel)}

    def _row(self, channel: str, event: dict, now: str,
             endpoint_id: str | None, tenant_id: str | None) -> tuple:
        winlog = event.get("winlog") or {}
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
        record_id = winlog.get("record_id")
        return (channel, winlog.get("provider"),
                int(record_id) if record_id is not None else None,
                winlog.get("event_id"), winlog.get("time_created"),
                event.get("observed_at") or now, endpoint_id, tenant_id,
                payload, len(payload.encode("utf-8")),
                content_digest(payload), ACQUIRED, now)

    def seed_cursor(self, channel: str, record_id: int,
                    continuity: bool) -> None:
        """Migration only: adopt a cursor WITHOUT replaying history."""
        self._db.execute(
            "INSERT INTO cursors(channel, committed_record_id,"
            " continuity_established, updated_at) VALUES(?,?,?,?)"
            " ON CONFLICT(channel) DO NOTHING",
            (channel, int(record_id), 1 if continuity else 0, _now()))

    # ── delivery ──────────────────────────────────────────────────
    def next_undelivered(self, limit: int = 50) -> list[sqlite3.Row]:
        """Strict journal order. Ordering is part of the evidence."""
        return list(self._db.execute(
            "SELECT journal_sequence, channel, payload, attempts"
            " FROM evidence WHERE state IN (?,?)"
            " ORDER BY journal_sequence LIMIT ?",
            (ACQUIRED, QUEUED, int(limit))))

    def mark_accepted(self, sequences: list[int]) -> None:
        """Only the platform's accept may set this. A send that merely left
        the host is not an acceptance and must never reach here."""
        now = _now()
        self._db.executemany(
            "UPDATE evidence SET state=?, accepted_at=?, updated_at=?,"
            " last_error=NULL WHERE journal_sequence=?",
            [(BACKEND_ACCEPTED, now, now, int(s)) for s in sequences])

    def mark_attempt_failed(self, sequence: int, error: str) -> None:
        now = _now()
        self._db.execute(
            "UPDATE evidence SET state=?, attempts=attempts+1,"
            " last_error=?, updated_at=? WHERE journal_sequence=?",
            (QUEUED, str(error)[:300], now, int(sequence)))

    def depth(self) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) AS n FROM evidence WHERE state IN (?,?)",
            DELIVERABLE_STATES).fetchone()
        return int(row["n"])

    def counts_by_state(self) -> dict:
        return {r["state"]: int(r["n"]) for r in self._db.execute(
            "SELECT state, COUNT(*) AS n FROM evidence GROUP BY state")}

    # ── gaps ──────────────────────────────────────────────────────
    def unreported_gaps(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM acquisition_gaps WHERE reported=0"
            " ORDER BY gap_id LIMIT ?", (int(limit),))]

    def gap_count(self) -> int:
        return int(self._db.execute(
            "SELECT COUNT(*) AS n FROM acquisition_gaps").fetchone()["n"])

    def last_gap(self) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM acquisition_gaps ORDER BY gap_id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def mark_gaps_reported(self, gap_ids: list[int]) -> None:
        self._db.executemany(
            "UPDATE acquisition_gaps SET reported=1 WHERE gap_id=?",
            [(int(g),) for g in gap_ids])

    # ── counters ──────────────────────────────────────────────────
    def bump(self, key: str, count: int = 1) -> None:
        self._db.execute(
            "INSERT INTO integrity(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET"
            " value = CAST(CAST(integrity.value AS INTEGER) + ? AS TEXT)",
            (key, str(int(count)), int(count)))

    def set_gauge(self, key: str, value) -> None:
        self._db.execute(
            "INSERT INTO integrity(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)))

    def gauges(self) -> dict:
        out = {}
        for row in self._db.execute("SELECT key, value FROM integrity"):
            try:
                out[row["key"]] = json.loads(row["value"])
            except ValueError:
                out[row["key"]] = row["value"]
        return out

    def observe_query(self, channel: str, elapsed_ms: int, ok: bool) -> None:
        """Query cost is RECORDED, not assumed.

        The read-only review flagged that `EventRecordID > N` is an
        unindexed scan that may grow expensive as the cursor falls behind.
        Rather than speculatively migrating to another Windows API, the
        sensor measures it so a later decision rests on evidence.
        """
        self.bump("query_total" if ok else "query_failures")
        gauges = self.gauges()
        self.set_gauge("query_ms_last", int(elapsed_ms))
        self.set_gauge("query_ms_max",
                       max(int(elapsed_ms), int(gauges.get("query_ms_max", 0))))
        self.set_gauge(f"query_ms_last:{channel}", int(elapsed_ms))

    # ── bounded capacity ──────────────────────────────────────────
    def bytes_used(self) -> int:
        """Bytes the store occupies on disk, WAL and shm included."""
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            try:
                total += candidate.stat().st_size
            except OSError:
                pass
        return total

    def live_bytes(self) -> int:
        """Bytes of evidence currently OWNED.

        Capacity is judged on this, not on the file size. SQLite reuses
        freed pages but cannot always return them to the filesystem, so a
        file that once held a large backlog stays at its high-water mark
        forever. Judging capacity on the file would leave such a sensor
        permanently 'full' and permanently halted while holding nothing —
        a fabricated outage. Real disk exhaustion is still caught, by
        `min_free_bytes` against the actual filesystem.
        """
        row = self._db.execute(
            "SELECT COALESCE(SUM(payload_bytes), 0) AS n FROM evidence"
        ).fetchone()
        return int(row["n"])

    def pressure(self) -> dict:
        # Recomputed only when something could have changed the answer:
        # `live_bytes()` is a full SUM and the acquisition loop asks before
        # every page. Keyed on the write counter and the configured limits,
        # so it can never authorise a write against stale capacity.
        cfg = limits()
        key = (self._db.total_changes, tuple(sorted(cfg.items())))
        if self._pressure_cache and self._pressure_cache[0] == key:
            return self._pressure_cache[1]
        live = self.live_bytes()
        used = self.bytes_used()
        pct = round(100.0 * live / cfg["max_bytes"], 2) if cfg["max_bytes"] \
            else 0.0
        try:
            free = shutil.disk_usage(str(self.state_dir)).free
        except OSError:
            free = None
        low_disk = free is not None and free < cfg["min_free_bytes"]
        value = {
            "journal_bytes": used, "journal_live_bytes": live,
            "journal_max_bytes": cfg["max_bytes"],
            "journal_pct": pct, "disk_free_bytes": free,
            "min_free_bytes": cfg["min_free_bytes"],
            "warning": pct >= cfg["warn_pct"] or low_disk,
            "critical": pct >= cfg["critical_pct"] or low_disk,
            "low_disk": low_disk}
        self._pressure_cache = (key, value)
        return value

    def reclaim(self) -> dict:
        """Delete ONLY rows the platform accepted, oldest first.

        Nothing unacknowledged is ever considered, at any pressure. When
        reclaiming cannot free enough, the answer is a visible integrity
        failure, not the destruction of evidence.
        """
        cfg = limits()
        before = self.bytes_used()
        self._pressure_cache = None
        self._db.execute("BEGIN IMMEDIATE")
        try:
            deleted = self._db.execute(
                "DELETE FROM evidence WHERE journal_sequence IN ("
                " SELECT journal_sequence FROM evidence WHERE state=?"
                " ORDER BY journal_sequence LIMIT ?)",
                (BACKEND_ACCEPTED, cfg["reclaim_batch"])).rowcount
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        if deleted:
            # Return what can be returned, and truncate the WAL. SQLite may
            # keep reusable free pages inside the file, so the file size is
            # a high-water mark; capacity is therefore judged on
            # `live_bytes` (see `pressure`).
            try:
                self._db.execute("PRAGMA incremental_vacuum(1000000)"
                                 ).fetchall()
                self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
        return {"reclaimed": int(deleted or 0), "bytes_before": before,
                "bytes_after": self.bytes_used()}

    def admits_acquisition(self) -> tuple[bool, str | None]:
        """May acquisition write more evidence right now?

        Called BEFORE a page is read so that a full journal stops the read
        rather than causing a read whose evidence cannot be stored.
        """
        state = self.pressure()
        if not state["critical"]:
            return True, None
        self.reclaim()
        state = self.pressure()
        if not state["critical"]:
            return True, None
        reason = ("local durable capacity exhausted: journal holds "
                  f"{state['journal_live_bytes']}B of evidence against a "
                  f"{state['journal_max_bytes']}B ceiling"
                  + (" and free disk is below the configured floor"
                     if state["low_disk"] else ""))
        self.bump("acquisition_halted_journal_full")
        self.set_gauge("acquisition_halted_at", _now())
        self.set_gauge("acquisition_halted_reason", reason)
        self._halted, self._halt_reason = True, reason
        return False, reason

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def halt_reason(self) -> str | None:
        return self._halt_reason

    # ── truthful health ───────────────────────────────────────────
    def health(self, *, channels_unavailable: dict | None = None,
               backend_unreachable: bool = False,
               caught_up: dict | None = None,
               source_tails: dict | None = None) -> dict:
        """States are additive facts, never a single cheerful summary."""
        states: list[str] = []
        pressure = self.pressure()
        depth = self.depth()
        gauges = self.gauges()
        lag: dict = {}
        rollover_risk: dict = {}
        for channel, tail in (source_tails or {}).items():
            committed = self.cursor(channel)
            newest, oldest = tail.get("newest"), tail.get("oldest")
            if isinstance(newest, int):
                lag[channel] = max(0, newest - committed)
            # Measured, not inferred: our cursor is behind the oldest
            # record the source still holds, so source records we never
            # acquired are provably gone.
            if isinstance(oldest, int) and committed and committed + 1 < oldest:
                rollover_risk[channel] = {"committed_record_id": committed,
                                          "source_oldest_record_id": oldest}
        if self._halted:
            states.append(ACQUISITION_HALTED_JOURNAL_FULL)
        if pressure["critical"]:
            states.append(JOURNAL_CRITICAL)
        elif pressure["warning"]:
            states.append(JOURNAL_PRESSURE)
        if channels_unavailable:
            states.append(CHANNEL_UNAVAILABLE)
        if backend_unreachable:
            states.append(BACKEND_UNREACHABLE)
        if depth:
            states.append(DELIVERY_BACKLOG)
        if self.gap_count():
            states.append(ACQUISITION_GAP)
        if caught_up and not all(caught_up.values()):
            states.append(ACQUISITION_LAGGING)
        if any(v for v in lag.values() if v > 0) and not (
                caught_up and all(caught_up.values())) and \
                ACQUISITION_LAGGING not in states:
            states.append(ACQUISITION_LAGGING)
        if rollover_risk:
            states.append(SOURCE_ROLLOVER_RISK)
        if not states:
            states.append(HEALTHY)
        elif states != [DELIVERY_BACKLOG]:
            states.append(DEGRADED)
        return {
            "journal_version": JOURNAL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "at": _now(),
            "states": states,
            "cursors": self.cursors(),
            "evidence_by_state": self.counts_by_state(),
            "delivery_queue_depth": depth,
            "acquisition_gap_count": self.gap_count(),
            "last_acquisition_gap": self.last_gap(),
            "acquisition_lag_records": lag,
            "source_rollover_risk": rollover_risk,
            "source_tails": source_tails or {},
            "channels_unavailable": channels_unavailable or {},
            "caught_up": caught_up or {},
            "counters": gauges,
            **pressure,
        }

    def write_integrity_snapshot(self, health: dict) -> Path:
        """Machine-readable, on disk, every cycle. A text log cannot be
        queried by an operator who needs to know whether an interval was
        trustworthy."""
        path = self.state_dir / INTEGRITY_FILENAME
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(health, indent=2, default=str))
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path


def migrate_legacy(journal: Journal, bookmark_file: Path) -> dict:
    """Adopt the legacy `channels.json` cursors ONCE, idempotently.

    Deliberately does NOT reset cursors, does NOT replay the Windows Event
    Log, does NOT delete or rewrite `outbox.jsonl` / `outbox.offset`, and
    does NOT touch `identity.json`. The legacy outbox stays deliverable and
    is drained by the sensor's legacy path until it is empty.
    """
    row = journal._db.execute(
        "SELECT value FROM meta WHERE key=?", ("legacy_migrated_at",)
    ).fetchone()
    if row:
        return {"migrated": False, "reason": "already migrated",
                "at": row["value"], "cursors": journal.cursors()}
    adopted = {}
    try:
        marks = json.loads(Path(bookmark_file).read_text())
    except (OSError, ValueError):
        marks = {}
    for channel, value in (marks or {}).items():
        try:
            record_id = int(value)
        except (TypeError, ValueError):
            continue
        # continuity=True: this cursor came from real prior acquisition, so
        # the next page legitimately participates in gap detection.
        journal.seed_cursor(channel, record_id, continuity=True)
        adopted[channel] = record_id
    now = _now()
    journal._db.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
        ("legacy_migrated_at", now))
    journal._db.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
        ("legacy_cursors_adopted", json.dumps(adopted)))
    return {"migrated": True, "at": now, "adopted": adopted,
            "cursors": journal.cursors()}


def open_journal(state_dir: str | os.PathLike,
                 bookmark_file: str | os.PathLike | None = None) -> Journal:
    journal = Journal(state_dir)
    if bookmark_file is not None:
        migrate_legacy(journal, Path(bookmark_file))
    return journal
