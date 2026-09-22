"""Durable per-channel Windows Event Log bookmark state.

W2-1 · Program B. This is the acquisition checkpoint for native Windows
Event Log subscriptions, and it exists because **EventRecordID alone is not
a durable checkpoint**:

  * record ids are per-channel and restart from 1 when a log is cleared;
  * they are not contiguous (a filtered subscription skips ids);
  * they say nothing about which subscription position produced them.

Windows itself answers this with a **bookmark** — an opaque XML document
that describes the exact resume position of a subscription. That bookmark is
the authority here. The highest seen record id is kept **only as evidence**
(identity, gap and log-cleared reasoning), never as the resume position.

Storage reuses the EXISTING durable boundary — the same SQLite database as
the outbox (`${XDR_STATE_DIR}/outbox.db`). No second database is
introduced, so a bookmark and the delivery acknowledgement that justifies
advancing it share one fsync domain.

Scope is always `(tenant_id, collector_id, channel)`. One tenant can never
read or advance another tenant's acquisition position, and two channels on
the same host never share a position.

State kept distinct — these are DIFFERENT facts and are never conflated:

    bookmark_xml        where the subscription resumes (authority)
    last_record_id      highest EventRecordID observed (evidence only)
    last_activity_at    the newest event's own instant (source clock)
    last_read_at        when this collector last READ the channel
    delivered_through   the bookmark whose events are all DELIVERED
"""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from framework import state_paths

#: Resume classification returned by `resume_for()`.
RESUME_BOOKMARK = "RESUME_FROM_BOOKMARK"
RESUME_FRESH = "NO_BOOKMARK_FIRST_COLLECTION"
RESUME_STALE = "BOOKMARK_STALE"
RESUME_LOG_CLEARED = "LOG_CLEARED"

#: A bookmark older than this is reported STALE. It is NOT discarded and it
#: is NOT silently replaced with "now": skipping forward would lose evidence
#: without saying so, so the decision is surfaced to the operator.
DEFAULT_STALE_AFTER_SECONDS = 24 * 3600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(v: Optional[str]) -> Optional[datetime]:
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    # Windows channels routinely write an instant with no offset. A naive
    # value is UTC by those sources' own contract; it is never compared
    # against an aware clock while still naive.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class WindowsBookmarkStore:
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS windows_channel_state (
        tenant_id          TEXT NOT NULL,
        collector_id       TEXT NOT NULL,
        channel            TEXT NOT NULL,
        origin_computer    TEXT,
        profile_id         TEXT,
        profile_version    TEXT,
        bookmark_xml       TEXT,
        bookmark_at        TEXT,
        last_record_id     INTEGER,
        last_activity_at   TEXT,
        last_read_at       TEXT,
        delivered_through  TEXT,
        reads              INTEGER NOT NULL DEFAULT 0,
        events_read        INTEGER NOT NULL DEFAULT 0,
        log_cleared_count  INTEGER NOT NULL DEFAULT 0,
        last_error         TEXT,
        PRIMARY KEY (tenant_id, collector_id, channel)
    );
    """

    def __init__(self, path: Optional[str] = None,
                 stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS):
        self._path = path or os.path.join(
            state_paths.state_dir(), "outbox.db")
        self._stale_after = int(stale_after_seconds)
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with self._conn() as c:
            c.executescript(self._SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    # ── read ──────────────────────────────────────────────────────
    def state_for(self, tenant_id: str, collector_id: str,
                  channel: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._conn() as c:
            r = c.execute(
                "SELECT * FROM windows_channel_state WHERE tenant_id=? "
                "AND collector_id=? AND channel=?",
                (tenant_id, collector_id, channel)).fetchone()
        return dict(r) if r else None

    def resume_for(self, tenant_id: str, collector_id: str,
                   channel: str) -> Dict[str, Any]:
        """The resume DECISION for a channel, with its reason.

        A caller never has to guess why it is starting where it is: the
        classification and the evidence behind it travel together.
        """
        st = self.state_for(tenant_id, collector_id, channel)
        if not st or not st.get("bookmark_xml"):
            return {
                "classification": RESUME_FRESH,
                "bookmark_xml": None,
                "reason": ("no bookmark exists for this tenant/collector/"
                           "channel — this is the first collection and the "
                           "subscription starts at the channel's oldest "
                           "retained record"),
                "last_record_id": (st or {}).get("last_record_id"),
            }
        age = None
        at = _parse_iso(st.get("bookmark_at"))
        if at:
            age = (_utcnow() - at).total_seconds()
        stale = age is not None and age > self._stale_after
        return {
            "classification": RESUME_STALE if stale else RESUME_BOOKMARK,
            "bookmark_xml": st.get("bookmark_xml"),
            "bookmark_age_seconds": age,
            "reason": (
                f"the bookmark for this channel is {int(age)}s old, which "
                f"exceeds the {self._stale_after}s staleness boundary — "
                "events may have aged out of the channel's retention while "
                "this collector was not reading it"
                if stale else
                "resuming exactly where the last acquisition stopped"),
            "last_record_id": st.get("last_record_id"),
            "delivered_through_matches_bookmark": (
                st.get("delivered_through") == st.get("bookmark_xml")),
        }

    # ── write ─────────────────────────────────────────────────────
    def record_read(self, *, tenant_id: str, collector_id: str, channel: str,
                    bookmark_xml: Optional[str], record_ids: List[int],
                    newest_activity_at: Optional[str] = None,
                    origin_computer: Optional[str] = None,
                    profile_id: Optional[str] = None,
                    profile_version: Optional[str] = None,
                    error: Optional[str] = None) -> Dict[str, Any]:
        """Record one READ of a channel.

        Returns the outcome including whether a LOG-CLEARED condition was
        detected: the channel handed us a record id LOWER than one we have
        already seen, which on Windows means the log was cleared or rolled
        over beneath us. That is evidence loss and is reported as such — the
        position still advances, because refusing to move would only stop
        collecting as well.
        """
        now = _iso(_utcnow())
        prev = self.state_for(tenant_id, collector_id, channel) or {}
        prev_max = prev.get("last_record_id")
        seen_max = max(record_ids) if record_ids else None
        seen_min = min(record_ids) if record_ids else None

        log_cleared = bool(
            prev_max is not None and seen_min is not None
            and seen_min < prev_max)

        new_max = seen_max if seen_max is not None else prev_max
        if prev_max is not None and new_max is not None and not log_cleared:
            new_max = max(prev_max, new_max)

        with self._lock, self._conn() as c:
            c.execute(
                """
                INSERT INTO windows_channel_state (
                    tenant_id, collector_id, channel, origin_computer,
                    profile_id, profile_version, bookmark_xml, bookmark_at,
                    last_record_id, last_activity_at, last_read_at,
                    reads, events_read, log_cleared_count, last_error)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
                ON CONFLICT(tenant_id, collector_id, channel) DO UPDATE SET
                    origin_computer  = COALESCE(excluded.origin_computer,
                                                windows_channel_state.origin_computer),
                    profile_id       = COALESCE(excluded.profile_id,
                                                windows_channel_state.profile_id),
                    profile_version  = COALESCE(excluded.profile_version,
                                                windows_channel_state.profile_version),
                    bookmark_xml     = COALESCE(excluded.bookmark_xml,
                                                windows_channel_state.bookmark_xml),
                    bookmark_at      = CASE WHEN excluded.bookmark_xml IS NOT NULL
                                            THEN excluded.bookmark_at
                                            ELSE windows_channel_state.bookmark_at END,
                    last_record_id   = excluded.last_record_id,
                    last_activity_at = COALESCE(excluded.last_activity_at,
                                                windows_channel_state.last_activity_at),
                    last_read_at     = excluded.last_read_at,
                    reads            = windows_channel_state.reads + 1,
                    events_read      = windows_channel_state.events_read
                                       + excluded.events_read,
                    log_cleared_count = windows_channel_state.log_cleared_count
                                       + excluded.log_cleared_count,
                    last_error       = excluded.last_error
                """,
                (tenant_id, collector_id, channel, origin_computer,
                 profile_id, profile_version, bookmark_xml, now,
                 new_max, newest_activity_at, now,
                 len(record_ids), 1 if log_cleared else 0, error))
        return {
            "channel": channel,
            "events_read": len(record_ids),
            "last_record_id": new_max,
            "log_cleared": log_cleared,
            "log_cleared_reason": (
                f"the channel returned record id {seen_min} after this "
                f"collector had already observed {prev_max}; on Windows this "
                "means the log was cleared or wrapped — events between the "
                "two positions were NOT collected and cannot be recovered"
                if log_cleared else None),
            "bookmark_recorded": bookmark_xml is not None,
            "read_at": now,
        }

    def commit_delivered(self, *, tenant_id: str, collector_id: str,
                         channel: str, bookmark_xml: str) -> None:
        """Mark the bookmark whose events are all DELIVERED to NivX.

        `bookmark_xml` advancing is acquisition; `delivered_through`
        advancing is accounting. Keeping them apart is what makes
        "acquired but not delivered" visible instead of invisible.
        """
        with self._lock, self._conn() as c:
            c.execute(
                "UPDATE windows_channel_state SET delivered_through=? "
                "WHERE tenant_id=? AND collector_id=? AND channel=?",
                (bookmark_xml, tenant_id, collector_id, channel))

    def channels(self, tenant_id: str,
                 collector_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT * FROM windows_channel_state WHERE tenant_id=?"
        args: List[Any] = [tenant_id]
        if collector_id:
            q += " AND collector_id=?"
            args.append(collector_id)
        with self._lock, self._conn() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]
