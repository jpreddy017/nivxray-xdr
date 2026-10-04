#!/usr/bin/env python3
"""G1-R5 · Bounded delivery-only drain — DRY-RUN BY DEFAULT.

R4 closed the REQUEUE phase: 14,868 events dead-lettered by an unattributed
HTTP 404 are back in `queued`. Delivering them is a SEPARATE, bounded phase,
because starting the collector normally would also start ACQUISITION, and this
proof must not create new endpoint telemetry or move a single bookmark.

What this driver is
-------------------
The production delivery path and nothing else:

    Outbox  →  DeliveryWorker (R1/R2/R3/R3.1 semantics)  →  IngestClient

It NEVER imports or constructs `WindowsEventLogConnector`, never calls
`EvtSubscribe`, never reads an Event Log, and never touches
`windows_channel_state` or the `acquisition_*` tables — the run REFUSES to
report PASS unless those tables are byte-identical before and after.

Bounding (all ceilings are hard; reaching any one stops the run)
----------------------------------------------------------------
    --max-rows      exact delivery ceiling: the worker batch is resized every
                    tick to `min(batch_size, remaining)`, so the attempted
                    population can never exceed it
    --max-ticks     secondary ceiling on drain cycles
    --max-seconds   secondary wall-clock ceiling
    gate OPEN       hard stop with evidence (no cooldown, no HALF_OPEN probe)

Restart recovery is MEASURED, not hidden: constructing the Outbox resets rows
stranded in `delivering` back to `queued` (R3.1). The pre-construction
histogram is read over a `mode=ro` connection first, so the reset is reported
as its own number instead of disappearing into the queue depth.

Evidence artifacts (JSON, written to --evidence-dir)
----------------------------------------------------
    r5-drain-pre-snapshot.json    status histogram + gate row + table hashes,
                                  read BEFORE the Outbox is constructed
    r5-drain-identities.json      per-row delivery identity + endpoint outcome,
                                  the input to server-side reconciliation
    r5-drain-run.json             per-tick accounting, ceilings, stop reason
    r5-drain-post-snapshot.json   post histogram, deltas, invariants, PASS/FAIL

HTTP acceptance is NOT canonical ingestion. This driver deliberately reports
only what the ENDPOINT can prove; `delivery_key` is emitted per row so the
authoritative plane can be asked what it actually did with each delivery
(`POST /api/xdr/ingest/routing/reconcile`).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framework.delivery import IngestClient                  # noqa: E402
from framework.delivery_worker import DeliveryWorker          # noqa: E402
from framework.health_gate import GateState                   # noqa: E402
from framework.outbox import Outbox, OutboxStatus             # noqa: E402

#: Tables that prove no acquisition happened. Absent tables are reported as
#: absent — never as unchanged.
ACQUISITION_TABLES = ("windows_channel_state", "acquisition_batch",
                      "acquisition_window", "acquisition_terminal_record")

GATE_TABLE = "delivery_health_gate"

#: Byte-identical to `services.ingest_idempotency.event_identity` on the
#: authoritative side. The endpoint derives the SAME delivery identity from
#: fields it already holds, so reconciliation never depends on the server
#: handing out a key. Any drift is caught by
#: test_delivery_key_matches_the_authoritative_identity.
_IDENTITY_SEPARATOR = "\x1f"
_NO_SOURCE_EVENT_ID = "__no_source_event_id__"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def payload_digest(raw: Any) -> str:
    return hashlib.sha256(
        json.dumps(raw if raw is not None else {}, sort_keys=True,
                   default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def delivery_key(*, tenant_id: str, collector_id: str, source: Optional[str],
                 source_event_id: Optional[str], raw: Any) -> str:
    material = _IDENTITY_SEPARATOR.join([
        str(tenant_id or ""), str(collector_id or ""), str(source or ""),
        str(source_event_id if source_event_id else _NO_SOURCE_EVENT_ID),
        payload_digest(raw),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ── read-only snapshots ───────────────────────────────────────────
def _ro_connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_names(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]


def _table_fingerprint(conn: sqlite3.Connection, table: str) -> Dict[str, Any]:
    if table not in _table_names(conn):
        return {"table": table, "state": "ABSENT", "rows": None,
                "sha256": None}
    rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    material = json.dumps(
        [[(k, r[k]) for k in r.keys()] for r in rows],
        sort_keys=True, default=str, separators=(",", ":"))
    return {"table": table, "state": "PRESENT", "rows": len(rows),
            "sha256": hashlib.sha256(material.encode("utf-8")).hexdigest()}


def _status_histogram(conn: sqlite3.Connection) -> Dict[str, int]:
    out = {s: 0 for s in OutboxStatus.ALL}
    for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status"):
        out[str(r["status"])] = int(r["n"])
    return out


def _gate_row(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    if GATE_TABLE not in _table_names(conn):
        return None
    r = conn.execute(f"SELECT * FROM {GATE_TABLE}").fetchone()
    return None if r is None else {k: r[k] for k in r.keys()}


def snapshot(db_path: str) -> Dict[str, Any]:
    conn = _ro_connect(db_path)
    try:
        histogram = _status_histogram(conn)
        return {
            "at": _now_iso(),
            "db_path": db_path,
            "status_histogram": histogram,
            "total": sum(histogram.values()),
            "gate_row": _gate_row(conn),
            "acquisition_tables": [_table_fingerprint(conn, t)
                                   for t in ACQUISITION_TABLES],
        }
    finally:
        conn.close()


def _acquisition_unchanged(pre: Dict[str, Any], post: Dict[str, Any]
                           ) -> Dict[str, Any]:
    by_pre = {t["table"]: t for t in pre["acquisition_tables"]}
    by_post = {t["table"]: t for t in post["acquisition_tables"]}
    changed = [t for t in ACQUISITION_TABLES
               if (by_pre[t]["state"], by_pre[t]["sha256"],
                   by_pre[t]["rows"]) !=
                  (by_post[t]["state"], by_post[t]["sha256"],
                   by_post[t]["rows"])]
    return {"unchanged": not changed, "changed_tables": changed,
            "pre": pre["acquisition_tables"],
            "post": post["acquisition_tables"]}


# ── the drain ─────────────────────────────────────────────────────
def _row_identity(row: Any) -> Dict[str, Any]:
    env = row.to_envelope()
    return {
        "ref": row.id,
        "tenant_id": row.tenant_id,
        "connector_id": row.connector_id,
        "collector_id": env.collector_id,
        "source": row.source,
        "source_event_id": row.source_event_id,
        "declared_source": row.declared_source,
        "payload_digest": payload_digest(row.raw),
        "delivery_key": delivery_key(
            tenant_id=row.tenant_id, collector_id=env.collector_id,
            source=row.source, source_event_id=row.source_event_id,
            raw=row.raw),
        "attempts_before": row.attempts,
    }


def _ro_candidates(db_path: str, limit: int) -> List[Dict[str, Any]]:
    """The rows the worker WOULD claim, read without opening for write."""
    conn = _ro_connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM envelopes "
            " WHERE status IN ('queued','retrying') AND next_attempt_at <= ? "
            " ORDER BY next_attempt_at ASC, created_at ASC LIMIT ?",
            (_now_iso(), limit)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
    finally:
        conn.close()


def _ro_identity(row: Dict[str, Any], collector: str) -> Dict[str, Any]:
    raw = json.loads(row.get("raw_json") or "{}")
    return {
        "ref": row.get("id"),
        "tenant_id": row.get("tenant_id"),
        "connector_id": row.get("connector_id"),
        "collector_id": collector,
        "source": row.get("source"),
        "source_event_id": row.get("source_event_id"),
        "declared_source": row.get("declared_source"),
        "payload_digest": payload_digest(raw),
        "delivery_key": delivery_key(
            tenant_id=row.get("tenant_id"), collector_id=collector,
            source=row.get("source"),
            source_event_id=row.get("source_event_id"), raw=raw),
        "attempts_before": row.get("attempts"),
    }


async def run_drain(*, state_dir: str, max_rows: int, max_ticks: int,
                    max_seconds: float, batch_size: int, execute: bool,
                    expect_collector_id: Optional[str] = None,
                    ingest_client: Optional[Any] = None) -> Dict[str, Any]:
    """Bounded delivery-only drain. `execute=False` attempts nothing."""
    db_path = os.path.join(state_dir, "outbox.db")
    if not os.path.exists(db_path):
        raise SystemExit(f"outbox database not found: {db_path}")

    pre = snapshot(db_path)

    # The envelope's `collector_id` is resolved from the process environment
    # at delivery time (`framework.identity.collector_id`). It is part of the
    # authoritative delivery identity, so a drain that runs with a different
    # value would deliver — and reconcile — under a different identity than
    # the acquisition that produced the rows. Fail closed instead of guessing.
    declared_collector_id = os.environ.get("NIVX_COLLECTOR_ID") or ""
    if not declared_collector_id:
        raise SystemExit(
            "NIVX_COLLECTOR_ID is not set. The delivery identity depends on "
            "it, so the drain refuses to run rather than deliver under "
            "'collector-local'.")
    if expect_collector_id and declared_collector_id != expect_collector_id:
        raise SystemExit(
            f"collector identity mismatch: NIVX_COLLECTOR_ID="
            f"{declared_collector_id!r}, expected {expect_collector_id!r}. "
            "Nothing was attempted.")

    # Constructing the Outbox runs R3.1 restart recovery
    # (delivering → queued), which is a WRITE. A dry run must not perform it:
    # it reads candidates over a `mode=ro` connection instead, and reports
    # what the recovery WOULD do. Only --execute constructs the Outbox.
    ticks: List[Dict[str, Any]] = []
    identities: List[Dict[str, Any]] = []
    attempted = 0
    stop_reason = "MAX_ROWS_REACHED"
    started = time.monotonic()
    gate_opened = False

    if not execute:
        outbox = None
        gate_row = pre["gate_row"] or {}
        gate_status = {
            "state": gate_row.get("state") or GateState.CLOSED,
            "state_basis": ("persisted delivery_health_gate row"
                            if gate_row else
                            "no persisted row: a first boot starts CLOSED"),
            "consecutive_failures": gate_row.get("consecutive_failures"),
            "cooldown_until_epoch": gate_row.get("cooldown_until_epoch"),
            "last_reason": gate_row.get("last_reason"),
            "read_only": True,
        }
        recovery = {
            "state": "NOT_APPLIED_IN_DRY_RUN",
            "delivering_before": pre["status_histogram"][
                OutboxStatus.DELIVERING],
            "delivering_after": pre["status_histogram"][
                OutboxStatus.DELIVERING],
            "queued_before": pre["status_histogram"][OutboxStatus.QUEUED],
            "queued_after": pre["status_histogram"][OutboxStatus.QUEUED],
            "would_reset_to_queued": pre["status_histogram"][
                OutboxStatus.DELIVERING],
            "delivering_reset_to_queued": 0,
            "queued_delta": 0,
            "consistent": True,
            "note": ("a dry run never constructs the Outbox, so R3.1 restart "
                     "recovery is NOT performed and nothing is written; "
                     "`would_reset_to_queued` is what --execute will move"),
        }
        for row in _ro_candidates(db_path, min(batch_size, max_rows)):
            identities.append({
                **_ro_identity(row, declared_collector_id),
                "endpoint_outcome": row["status"],
                "endpoint_outcome_note": "DRY RUN — nothing was attempted",
            })
        stop_reason = "DRY_RUN"
        post = snapshot(db_path)
    else:
        outbox = Outbox(path=state_dir)
        post_recovery = snapshot(db_path)
        recovery = {
            "state": "APPLIED",
            "delivering_before": pre["status_histogram"][
                OutboxStatus.DELIVERING],
            "delivering_after": post_recovery["status_histogram"][
                OutboxStatus.DELIVERING],
            "queued_before": pre["status_histogram"][OutboxStatus.QUEUED],
            "queued_after": post_recovery["status_histogram"][
                OutboxStatus.QUEUED],
        }
        recovery["delivering_reset_to_queued"] = (
            recovery["delivering_before"] - recovery["delivering_after"])
        recovery["queued_delta"] = (recovery["queued_after"]
                                    - recovery["queued_before"])
        recovery["consistent"] = (recovery["queued_delta"]
                                  == recovery["delivering_reset_to_queued"])

        client = ingest_client if ingest_client is not None else IngestClient()
        worker = DeliveryWorker(outbox, client, batch_size=batch_size)

        while True:
            if attempted >= max_rows:
                stop_reason = "MAX_ROWS_REACHED"
                break
            if len(ticks) >= max_ticks:
                stop_reason = "MAX_TICKS_REACHED"
                break
            elapsed = time.monotonic() - started
            if elapsed >= max_seconds:
                stop_reason = "MAX_SECONDS_REACHED"
                break
            if worker.gate.state == GateState.OPEN:
                gate_opened = True
                stop_reason = "GATE_OPEN_BEFORE_TICK"
                break

            limit = min(batch_size, max_rows - attempted)
            worker.batch_size = limit
            candidates = outbox.next_batch(limit=limit)
            if not candidates:
                stop_reason = "QUEUE_EMPTY"
                break
            claimed = {r.id: _row_identity(r) for r in candidates}

            result = await worker.tick_once()
            drained = int(result.get("drained") or 0)
            attempted += drained

            for rid, ident in claimed.items():
                row = outbox.by_id(rid)
                if row is None:
                    ident["endpoint_outcome"] = "missing"
                    ident["endpoint_outcome_note"] = (
                        "row disappeared during the tick")
                    identities.append(ident)
                    continue
                ident["endpoint_outcome"] = row.status
                ident["attempts_after"] = row.attempts
                ident["last_error"] = row.last_error
                ident["failure_classification"] = (
                    (row.failure_detail or {}).get("classification"))
                ident["failure_status_code"] = (
                    (row.failure_detail or {}).get("status_code"))
                identities.append(ident)

            ticks.append({
                "tick": len(ticks) + 1,
                "at": _now_iso(),
                "limit": limit,
                "claimed": len(claimed),
                **{k: result.get(k) for k in
                   ("drained", "delivered", "retrying", "dead", "gate",
                    "gate_skipped", "probe", "seconds_until_probe")},
                "attempted_total": attempted,
            })

            if result.get("gate_skipped"):
                gate_opened = worker.gate.state == GateState.OPEN
                stop_reason = "GATE_BLOCKED_DELIVERY"
                break
            if worker.gate.state == GateState.OPEN:
                gate_opened = True
                stop_reason = "GATE_OPENED_DURING_DRAIN"
                break
            if drained == 0:
                stop_reason = "NO_ROWS_CLAIMED"
                break

        gate_status = worker.gate.status()

    post = snapshot(db_path) if execute else post
    if outbox is not None:
        outbox.close()

    outcomes: Dict[str, int] = {}
    for ident in identities:
        key = str(ident.get("endpoint_outcome"))
        outcomes[key] = outcomes.get(key, 0) + 1

    delivered = sum(int(t.get("delivered") or 0) for t in ticks)
    retrying = sum(int(t.get("retrying") or 0) for t in ticks)
    dead = sum(int(t.get("dead") or 0) for t in ticks)
    released = attempted - (delivered + retrying + dead)

    invariants = {
        "attempted_equals_worker_outcomes": {
            "equation": ("attempted = delivered + retrying + dead + "
                         "released_unattempted"),
            "attempted": attempted, "delivered": delivered,
            "retrying": retrying, "dead": dead,
            "released_unattempted": released,
            "holds": released >= 0,
        },
        "row_ceiling_respected": {
            "max_rows": max_rows, "attempted": attempted,
            "holds": attempted <= max_rows,
        },
        "total_rows_unchanged": {
            "pre": pre["total"], "post": post["total"],
            "holds": pre["total"] == post["total"],
            "note": ("no acquisition ran, so the envelope population cannot "
                     "grow during a delivery-only drain"),
        },
        "no_acquisition": _acquisition_unchanged(pre, post),
        "restart_recovery_accounted": recovery,
        "gate_never_opened": {
            "holds": not gate_opened,
            "state": gate_status.get("state"),
        },
        "windows_connector_never_imported": {
            "holds": not any(m.startswith("framework.windows_eventlog")
                             for m in sys.modules),
            "note": ("a delivery-only drain has no acquisition surface at "
                     "all — the module is never loaded"),
        },
    }

    passed = all(
        v.get("holds", v.get("unchanged", False)) if isinstance(v, dict)
        else False
        for k, v in invariants.items() if k != "restart_recovery_accounted")
    passed = passed and bool(recovery["consistent"])
    if execute:
        passed = passed and stop_reason in ("MAX_ROWS_REACHED", "QUEUE_EMPTY")

    return {
        "phase": "G1-R5 delivery drain",
        "mode": "EXECUTE" if execute else "DRY_RUN",
        "at": _now_iso(),
        "ceilings": {"max_rows": max_rows, "max_ticks": max_ticks,
                     "max_seconds": max_seconds, "batch_size": batch_size},
        "collector_identity": {
            "collector_id": declared_collector_id,
            "tenant_id_env": os.environ.get("NIVX_TENANT_ID") or "",
            "basis": ("NIVX_COLLECTOR_ID from the process environment; the "
                      "same value the acquisition ran under, verified "
                      "before any delivery was attempted"),
        },
        "stop_reason": stop_reason,
        "attempted": attempted,
        "worker_totals": {"delivered": delivered, "retrying": retrying,
                          "dead": dead,
                          "released_unattempted": released},
        "endpoint_outcomes": outcomes,
        "ticks": ticks,
        "gate": gate_status,
        "gate_opened": gate_opened,
        "pre_snapshot": pre,
        "post_snapshot": post,
        "invariants": invariants,
        "pass": passed,
        "identities_count": len(identities),
        "identities": identities,
        "honesty_note": (
            "HTTP 2xx is acceptance by the destination, NOT proof of "
            "canonical ingestion. Reconcile every identity against the "
            "authoritative plane before calling this population accounted."),
    }


def _write(evidence_dir: str, name: str, payload: Any) -> str:
    os.makedirs(evidence_dir, exist_ok=True)
    path = os.path.join(evidence_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="G1-R5 bounded delivery-only drain (dry run by default)")
    ap.add_argument("--state-dir", default=os.environ.get("XDR_STATE_DIR"),
                    help="directory holding outbox.db")
    ap.add_argument("--evidence-dir", default=None,
                    help="where the JSON evidence is written "
                         "(default: <state-dir>/g1_r5_evidence)")
    ap.add_argument("--max-rows", type=int, required=True,
                    help="exact delivery ceiling for this run")
    ap.add_argument("--max-ticks", type=int, default=200)
    ap.add_argument("--max-seconds", type=float, default=900.0)
    ap.add_argument("--batch-size", type=int, default=50)
    ap.add_argument("--execute", action="store_true",
                    help="actually attempt delivery; without it nothing is "
                         "sent and nothing is mutated")
    ap.add_argument("--expect-collector-id", default=None,
                    help="refuse to run unless NIVX_COLLECTOR_ID equals this")
    args = ap.parse_args(argv)

    if not args.state_dir:
        print("ERROR: --state-dir or XDR_STATE_DIR is required")
        return 2
    if args.max_rows <= 0:
        print("ERROR: --max-rows must be positive")
        return 2

    evidence_dir = args.evidence_dir or os.path.join(args.state_dir,
                                                     "g1_r5_evidence")
    report = asyncio.run(run_drain(
        state_dir=args.state_dir, max_rows=args.max_rows,
        max_ticks=args.max_ticks, max_seconds=args.max_seconds,
        batch_size=args.batch_size, execute=args.execute,
        expect_collector_id=args.expect_collector_id))

    identities = report.pop("identities")
    _write(evidence_dir, "r5-drain-pre-snapshot.json", report["pre_snapshot"])
    _write(evidence_dir, "r5-drain-post-snapshot.json",
           report["post_snapshot"])
    _write(evidence_dir, "r5-drain-identities.json",
           {"at": report["at"], "mode": report["mode"],
            "count": len(identities), "identities": identities})
    run_path = _write(evidence_dir, "r5-drain-run.json", report)

    print(json.dumps({
        "mode": report["mode"],
        "stop_reason": report["stop_reason"],
        "attempted": report["attempted"],
        "worker_totals": report["worker_totals"],
        "endpoint_outcomes": report["endpoint_outcomes"],
        "gate": report["gate"].get("state"),
        "gate_opened": report["gate_opened"],
        "restart_recovery": report["invariants"][
            "restart_recovery_accounted"],
        "acquisition_unchanged": report["invariants"]["no_acquisition"][
            "unchanged"],
        "total_rows_unchanged": report["invariants"][
            "total_rows_unchanged"]["holds"],
        "pass": report["pass"],
        "evidence": run_path,
    }, indent=2, default=str))
    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
