"""
Idempotency + execution state · Phase 1.

SQLite-backed store, keyed on
    (tenant_id, invoker_kind, invoker_id, execution_id).
Re-POSTing the same key returns the prior result verbatim.

Restart recovery: rows stuck in `in_progress` on boot flip to
`failed_recovered` with an explicit error message — the operator
sees them, unlike silently reviving mid-flight executions against
external systems.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime    import datetime, timezone
from typing      import Any, Dict, Optional


STATUS_SUCCEEDED   = "succeeded"
STATUS_FAILED      = "failed"
STATUS_IN_PROGRESS = "in_progress"
STATUS_REJECTED    = "rejected"
STATUS_RECOVERED   = "failed_recovered"
ALL_STATUSES = (STATUS_SUCCEEDED, STATUS_FAILED, STATUS_IN_PROGRESS,
                    STATUS_REJECTED, STATUS_RECOVERED)


def _iso(dt=None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()


class IdempotencyStore:
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS executions (
        key           TEXT PRIMARY KEY,           -- tenant|invoker_kind|invoker_id|execution_id
        tenant_id     TEXT NOT NULL,
        invoker_kind  TEXT NOT NULL,
        invoker_id    TEXT NOT NULL,
        execution_id  TEXT NOT NULL,
        action_id     TEXT NOT NULL,
        status        TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_exec_status ON executions(status);
    """

    def __init__(self, path: Optional[str] = None) -> None:
        state_dir = path or os.environ.get("XDR_RESPOND_STATE_DIR")
        self._db_path = ":memory:" if state_dir is None \
                          else os.path.join(state_dir, "executions.db")
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False,
                                          isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(self._SCHEMA)
        self._recover_stuck()

    @staticmethod
    def key_of(tenant_id: str, invoker_kind: str,
                 invoker_id: str, execution_id: str) -> str:
        return f"{tenant_id}|{invoker_kind}|{invoker_id}|{execution_id}"

    def _recover_stuck(self) -> None:
        """Restart-recovery: never silently re-execute an in_progress
        row.  Flip to `failed_recovered` so the operator can decide."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, response_json FROM executions WHERE status=?",
                (STATUS_IN_PROGRESS,)).fetchall()
            for r in rows:
                try:    resp = json.loads(r["response_json"] or "{}")
                except Exception: resp = {}
                resp["status"] = STATUS_RECOVERED
                resp["error"]  = "engine_restart_before_completion"
                self._conn.execute(
                    "UPDATE executions SET status=?, response_json=?, updated_at=? WHERE key=?",
                    (STATUS_RECOVERED, json.dumps(resp), _iso(), r["key"]))

    def find(self, tenant_id: str, invoker_kind: str,
                invoker_id: str, execution_id: str) -> Optional[Dict[str, Any]]:
        k = self.key_of(tenant_id, invoker_kind, invoker_id, execution_id)
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM executions WHERE key=?", (k,)).fetchone()
        if not r:
            return None
        return {**dict(r), "response": json.loads(r["response_json"])}

    def record_in_progress(self, tenant_id: str, invoker_kind: str,
                                invoker_id: str, execution_id: str,
                                action_id: str, response: Dict[str, Any]) -> None:
        k = self.key_of(tenant_id, invoker_kind, invoker_id, execution_id)
        now = _iso()
        with self._lock:
            self._conn.execute("""
                INSERT INTO executions
                (key, tenant_id, invoker_kind, invoker_id, execution_id,
                    action_id, status, response_json, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(key) DO NOTHING
            """, (k, tenant_id, invoker_kind, invoker_id, execution_id,
                    action_id, STATUS_IN_PROGRESS, json.dumps(response), now, now))

    def finalise(self, tenant_id: str, invoker_kind: str,
                    invoker_id: str, execution_id: str,
                    status: str, response: Dict[str, Any]) -> None:
        assert status in ALL_STATUSES, f"unknown status {status}"
        k = self.key_of(tenant_id, invoker_kind, invoker_id, execution_id)
        with self._lock:
            self._conn.execute(
                "UPDATE executions SET status=?, response_json=?, updated_at=? WHERE key=?",
                (status, json.dumps(response), _iso(), k))

    def metrics(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM executions GROUP BY status"
            ).fetchall()
        out = {s: 0 for s in ALL_STATUSES}
        for r in rows: out[r["status"]] = int(r["n"])
        return out

    def close(self) -> None:
        with self._lock:
            try:    self._conn.close()
            except Exception: pass
