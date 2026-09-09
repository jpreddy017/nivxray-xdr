"""
Execution store — dedicated SQLite database for the Response Engine.

Owns the FULL execution lifecycle (state machine, approval decisions,
adapter results, forwarding results).  This is the durable spine of
the engine: every state transition writes here first, so a crash mid-
flight leaves an inspectable record instead of a lost execution.

Boundary:
  * Response Engine owns this store.  Not shared with the Collector.
  * File path controlled by ``XDR_RESPOND_STATE_DIR``.  Defaults to
    ``<repo>/data`` so the engine still boots in test/dev without any
    environment.
  * Idempotency key: ``(tenant_id, invoker_kind, invoker_id, execution_id)``.
    Re-POSTing the same key returns the prior final response verbatim
    with ``idempotent_replay = true``.

State machine (see RESPONSE_CONTRACT.md):

    QUEUED
      ├── (no approval needed) ─→ RUNNING ─→ EXECUTING ─→ FORWARDING_EVIDENCE
      │                                                        ├── SUCCEEDED
      │                                                        └── FAILED_FORWARDING
      ├── (approval needed)    ─→ WAITING_APPROVAL
      │                              ├── (approve)  ─→ EXECUTING ─→ FORWARDING_EVIDENCE ─→ …
      │                              └── (reject)   ─→ FAILED_APPROVAL
      └── (validation error)   ─→ FAILED_TARGET / FAILED_EXECUTION / REJECTED

Restart recovery:  On boot, any row stuck in RUNNING / EXECUTING /
FORWARDING_EVIDENCE is flipped to ``FAILED_RECOVERED`` — the operator
sees exactly where the crash happened rather than the engine silently
re-firing side effects.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing   import Any, Dict, List, Optional


# ── Canonical states ────────────────────────────────────────────────
STATE_QUEUED             = "QUEUED"
STATE_RUNNING            = "RUNNING"
STATE_WAITING_APPROVAL   = "WAITING_APPROVAL"
STATE_EXECUTING          = "EXECUTING"
STATE_FORWARDING         = "FORWARDING_EVIDENCE"
STATE_SUCCEEDED          = "SUCCEEDED"
STATE_FAILED_APPROVAL    = "FAILED_APPROVAL"
STATE_FAILED_TARGET      = "FAILED_TARGET"
STATE_FAILED_EXECUTION   = "FAILED_EXECUTION"
STATE_FAILED_FORWARDING  = "FAILED_FORWARDING"
STATE_FAILED_RECOVERED   = "FAILED_RECOVERED"
STATE_REJECTED           = "REJECTED"

ALL_STATES = {
    STATE_QUEUED, STATE_RUNNING, STATE_WAITING_APPROVAL, STATE_EXECUTING,
    STATE_FORWARDING, STATE_SUCCEEDED, STATE_FAILED_APPROVAL,
    STATE_FAILED_TARGET, STATE_FAILED_EXECUTION, STATE_FAILED_FORWARDING,
    STATE_FAILED_RECOVERED, STATE_REJECTED,
}
TERMINAL_STATES = {
    STATE_SUCCEEDED, STATE_FAILED_APPROVAL, STATE_FAILED_TARGET,
    STATE_FAILED_EXECUTION, STATE_FAILED_FORWARDING, STATE_FAILED_RECOVERED,
    STATE_REJECTED,
}
ACTIVE_STATES = {STATE_RUNNING, STATE_EXECUTING, STATE_FORWARDING}


def _iso(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()


class ExecutionStore:
    """SQLite-backed execution lifecycle store."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS executions (
        key                 TEXT PRIMARY KEY,
        tenant_id           TEXT NOT NULL,
        invoker_kind        TEXT NOT NULL,
        invoker_id          TEXT NOT NULL,
        execution_id        TEXT NOT NULL,
        invoker_json        TEXT NOT NULL,
        action_id           TEXT NOT NULL,
        provider            TEXT,
        capability          TEXT,
        parameters_json     TEXT NOT NULL,
        canonical_json      TEXT,
        scopes_json         TEXT,
        state               TEXT NOT NULL,
        approval_required   INTEGER NOT NULL DEFAULT 0,
        approval_status     TEXT,             -- pending | approved | rejected
        approval_ref        TEXT,
        approved_by         TEXT,
        approved_at         TEXT,
        approval_reason     TEXT,
        rejected_by         TEXT,
        rejected_at         TEXT,
        rejection_reason    TEXT,
        adapter_ok          INTEGER,
        adapter_result_json TEXT,
        adapter_error       TEXT,
        evidence_ref        TEXT,
        audit_ref           TEXT,
        timeline_ref        TEXT,
        forwarding_state    TEXT,
        forwarding_error    TEXT,
        failure_reason      TEXT,
        dry_run             INTEGER NOT NULL DEFAULT 0,
        requested_at        TEXT NOT NULL,
        started_at          TEXT,
        completed_at        TEXT,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL,
        response_json       TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_exec_state   ON executions(state);
    CREATE INDEX IF NOT EXISTS ix_exec_tenant  ON executions(tenant_id);
    CREATE INDEX IF NOT EXISTS ix_exec_exec_id ON executions(execution_id);
    """

    def __init__(self, path: Optional[str] = None) -> None:
        state_dir = path or os.environ.get("XDR_RESPOND_STATE_DIR")
        if state_dir is None:
            self._db_path = ":memory:"
        else:
            os.makedirs(state_dir, exist_ok=True)
            self._db_path = os.path.join(state_dir, "executions.db")
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False,
                                          isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(self._SCHEMA)
        self._recover_stuck()

    # ── keying ──────────────────────────────────────────────────────
    @staticmethod
    def key_of(tenant_id: str, invoker_kind: str,
                 invoker_id: str, execution_id: str) -> str:
        return f"{tenant_id}|{invoker_kind}|{invoker_id}|{execution_id}"

    # ── restart recovery ────────────────────────────────────────────
    def _recover_stuck(self) -> None:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key FROM executions WHERE state IN (?,?,?)",
                (STATE_RUNNING, STATE_EXECUTING, STATE_FORWARDING)).fetchall()
            for r in rows:
                self._conn.execute("""
                    UPDATE executions SET state=?, failure_reason=?, updated_at=?
                     WHERE key=?
                """, (STATE_FAILED_RECOVERED,
                        "engine_restart_before_completion",
                        _iso(), r["key"]))

    # ── read ────────────────────────────────────────────────────────
    def find(self, tenant_id: str, invoker_kind: str,
                invoker_id: str, execution_id: str) -> Optional[Dict[str, Any]]:
        k = self.key_of(tenant_id, invoker_kind, invoker_id, execution_id)
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM executions WHERE key=?", (k,)).fetchone()
        return _row_to_dict(r) if r else None

    def find_by_execution_id(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Locate an execution when the caller only knows its execution_id.
        Used by approval endpoints — every execution_id we mint at intake
        is a UUID so single-row lookup is safe."""
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
        return _row_to_dict(r) if r else None

    def list_state(self, state: str, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM executions WHERE state=? ORDER BY created_at DESC LIMIT ?",
                (state, int(limit))).fetchall()
        return [_row_to_dict(r) for r in rows]

    def metrics(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, COUNT(*) AS n FROM executions GROUP BY state"
            ).fetchall()
        out = {s: 0 for s in ALL_STATES}
        for r in rows:
            out[r["state"]] = int(r["n"])
        return out

    # ── write · lifecycle ────────────────────────────────────────────
    def insert(self, row: Dict[str, Any]) -> None:
        """Insert a fresh execution row at intake.  Only used once per
        (tenant, invoker, execution_id); ON CONFLICT DO NOTHING lets
        idempotent replays land safely."""
        k = self.key_of(row["tenant_id"], row["invoker_kind"],
                            row["invoker_id"], row["execution_id"])
        now = _iso()
        with self._lock:
            self._conn.execute("""
                INSERT INTO executions
                (key, tenant_id, invoker_kind, invoker_id, execution_id,
                    invoker_json, action_id, provider, capability,
                    parameters_json, canonical_json, scopes_json,
                    state, approval_required, approval_status,
                    dry_run, requested_at, created_at, updated_at)
                VALUES (?,?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?, ?,?,?,?)
                ON CONFLICT(key) DO NOTHING
            """, (
                k, row["tenant_id"], row["invoker_kind"], row["invoker_id"],
                row["execution_id"],
                json.dumps(row.get("invoker") or {}),
                row["action_id"], row.get("provider"), row.get("capability"),
                json.dumps(row.get("parameters") or {}),
                json.dumps(row.get("canonical") or {}),
                json.dumps(row.get("scopes") or []),
                row["state"],
                1 if row.get("approval_required") else 0,
                row.get("approval_status"),
                1 if row.get("dry_run") else 0,
                now, now, now,
            ))

    def transition(self, key: str, *, state: str,
                     patch: Optional[Dict[str, Any]] = None) -> None:
        """Atomically move an execution to ``state`` with an optional
        column patch.  Never validates the transition graph here — the
        Executor owns transition legality; the store owns durability."""
        assert state in ALL_STATES, f"unknown state {state}"
        patch = patch or {}
        cols = ["state=?", "updated_at=?"]
        vals: List[Any] = [state, _iso()]
        for k, v in patch.items():
            if k in {"adapter_result_json", "response_json", "canonical_json",
                        "invoker_json", "parameters_json", "scopes_json"} \
                    and not isinstance(v, str):
                v = json.dumps(v)
            cols.append(f"{k}=?")
            vals.append(v)
        vals.append(key)
        with self._lock:
            self._conn.execute(
                f"UPDATE executions SET {', '.join(cols)} WHERE key=?", vals)

    def close(self) -> None:
        with self._lock:
            try:    self._conn.close()
            except Exception: pass


def _row_to_dict(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    for jk in ("invoker_json", "parameters_json", "canonical_json",
                 "scopes_json", "adapter_result_json", "response_json"):
        if d.get(jk):
            try:    d[jk.removesuffix("_json")] = json.loads(d[jk])
            except Exception: d[jk.removesuffix("_json")] = None
    return d
